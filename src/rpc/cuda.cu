#include <cassert>
#include <cstdint>
#include <cstdio>
#include <cuda_runtime.h>
#include <vector>

// 256-bit数值（小端序，32位肢体）
typedef struct {
    uint32_t limb[8];
} uint256_t;

// secp256k1曲线参数（设备常量）
__constant__ uint256_t p = {
    0xFFFFFC2F, 0xFFFFFFFE, 0xFFFFFFFF, 0xFFFFFFFF,
    0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF};

__constant__ uint256_t N = {
    0xd0364141, 0xbfd25e8c, 0xaf48a03b, 0xbaaedce6,
    0xFFFFFFFE, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF};

// 预计算的蒙哥马利参数
__constant__ uint256_t R = {
    0x000003D1, 0x00000001, 0x00000000, 0x00000000,
    0x00000000, 0x00000000, 0x00000000, 0x00000000};

__constant__ uint256_t R_squared = {
    0x000e90a1, 0x000007a2, 0x00000001, 0x00000000,
    0x00000000, 0x00000000, 0x00000000, 0x00000000};

__constant__ uint32_t np = 0xD2253531;

// 预计算的蒙哥马利常量
__constant__ uint256_t two_mont = {
    0x000007A2, 0x00000002, 0x00000000, 0x00000000,
    0x00000000, 0x00000000, 0x00000000, 0x00000000};

__constant__ uint256_t three_mont = {
    0x00000B73, 0x00000003, 0x00000000, 0x00000000,
    0x00000000, 0x00000000, 0x00000000, 0x00000000};

// 点结构（仿射坐标）
typedef struct {
    uint256_t x;
    uint256_t y;
    bool infinity;
} AffinePoint;

// CUDA错误检查宏
#define CHECK_CUDA(call)                                                                                \
    do {                                                                                                \
        cudaError_t err = (call);                                                                       \
        if (err != cudaSuccess) {                                                                       \
            fprintf(stderr, "CUDA Error at %s:%d - %s\n", __FILE__, __LINE__, cudaGetErrorString(err)); \
            exit(EXIT_FAILURE);                                                                         \
        }                                                                                               \
    } while (0)

// ================== 基础算术函数 ==================
// 返回最终进位状态 (1表示溢出)
__device__ uint32_t add256(uint256_t* a, const uint256_t* b)
{
    uint64_t carry = 0;
    for (int i = 0; i < 8; ++i) {
        uint64_t sum = (uint64_t)a->limb[i] + b->limb[i] + carry;
        a->limb[i] = (uint32_t)sum;
        carry = sum >> 32;
    }
    return (carry != 0);
}

// 返回最终借位状态 (1表示结果为负)
__device__ uint32_t sub256(uint256_t* a, const uint256_t* b)
{
    uint64_t borrow = 0;
    for (int i = 0; i < 8; ++i) {
        uint64_t sub = (uint64_t)a->limb[i] - b->limb[i] - borrow;
        a->limb[i] = (uint32_t)sub;
        borrow = (sub >> 32) & 1;
    }
    return (borrow != 0);
}

__device__ int is_ge(const uint256_t* a, const uint256_t* b)
{
    for (int i = 7; i >= 0; --i) {
        if (a->limb[i] > b->limb[i]) return 1;
        if (a->limb[i] < b->limb[i]) return 0;
    }
    return 1;
}

__device__ int is_zero(const uint256_t* a)
{
    for (int i = 0; i < 8; ++i)
        if (a->limb[i] != 0) return 0;
    return 1;
}

// ================== 蒙哥马利运算 ==================
__device__ uint256_t mont_mul(const uint256_t a, const uint256_t b)
{
    uint64_t t[9] = {0}; // 扩展存储到288位（9*32）

    for (int i = 0; i < 8; ++i) {
        // 步骤1：计算a[i] * b并累加到t
        uint64_t carry = 0;
        for (int j = 0; j < 8; ++j) {
            uint64_t product = (uint64_t)a.limb[i] * b.limb[j] + t[j] + carry;
            t[j] = product & 0xFFFFFFFF; // 保留低32位
            carry = product >> 32;       // 记录进位
        }
        t[8] = carry; // 存储最高位进位

        // 步骤2：计算m = (t[0] * np) mod 2^32
        uint32_t m = (uint32_t)((t[0] * np) & 0xFFFFFFFF);

        // 步骤3：加m*p并处理进位
        carry = 0;
        for (int j = 0; j < 8; ++j) {
            uint64_t product = (uint64_t)m * p.limb[j] + t[j] + carry;
            t[j] = product & 0xFFFFFFFF; // 保留低32位
            carry = product >> 32;       // 记录进位
        }
        t[8] += carry; // 累加最终进位

        // 步骤4：右移32位
        for (int j = 0; j < 8; ++j) {
            t[j] = t[j + 1];
        }
        t[8] = 0; // 高位清零
    }

    // 将结果从uint64_t数组转换回uint256_t
    uint256_t result;
    for (int i = 0; i < 8; ++i) {
        result.limb[i] = (uint32_t)t[i];
    }

    // 最终模约简
    if ((t[7]&0xF00000000) || is_ge(&result, &p)) {
        sub256(&result, &p);
    }
    return result;
}

__device__ uint256_t mod_add(const uint256_t& a, const uint256_t& b, const uint256_t& p)
{
    uint256_t result = a;

    // 执行加法并检测进位
    uint32_t carry = add256(&result, &b);

    // 处理溢出情况：进位发生或结果 >= p
    if (carry || is_ge(&result, &p)) {
        sub256(&result, &p); // 减去模数p
    }
    return result;
}

__device__ uint256_t mod_sub(const uint256_t& a, const uint256_t& b, const uint256_t& p)
{
    uint256_t result = a;

    // 执行减法并检测借位
    uint32_t borrow = sub256(&result, &b);

    // 处理负数结果
    if (borrow) {
        add256(&result, &p); // 加上模数p
    }
    return result;
}

__device__ uint256_t mont_inv(const uint256_t a)
{
    uint256_t result = R; // 1 in Montgomery form
    uint256_t exponent = p;
    uint256_t two = {{2}};
    sub256(&exponent, &two); // p-2

    for (int i = 255; i >= 0; --i) {
        result = mont_mul(result, result);
        if ((exponent.limb[i / 32] >> (i % 32)) & 1)
            result = mont_mul(result, a);
    }
    return result;
}
// 转换到蒙哥马利域
__device__ uint256_t to_mont(const uint256_t a)
{
    return mont_mul(a, R_squared);
}
__device__ uint256_t from_mont(const uint256_t a)
{
    uint256_t one = {1};
    return mont_mul(a, one);
}
// ================== 点运算 ==================
__device__ AffinePoint point_add(AffinePoint P, AffinePoint Q)
{
    // 转换为蒙哥马利域
    P.x = to_mont(P.x);
    P.y = to_mont(P.y);
    Q.x = to_mont(Q.x);
    Q.y = to_mont(Q.y);

    AffinePoint R;
    R.x = {{0}};
    R.y = {{0}};
    R.infinity = true;

    if (P.infinity) {
        R = Q;
        goto convert_back;
    }
    if (Q.infinity) {
        R = P;
        goto convert_back;
    }

    uint256_t x_diff = mod_sub(Q.x, P.x, p);
    if (is_zero(&x_diff)) {
        uint256_t y_sum = mod_add(P.y, Q.y, p);
        if (is_zero(&y_sum)) {
            R.infinity = true;
            goto convert_back;
        }

        uint256_t x_sq = mont_mul(P.x, P.x);
        uint256_t numerator = mont_mul(x_sq, three_mont);
        uint256_t denominator = mod_add(P.y, P.y, p);
        uint256_t lambda = mont_mul(numerator, mont_inv(denominator));

        uint256_t lambda_sq = mont_mul(lambda, lambda);
        R.x = mod_sub(lambda_sq, mod_add(P.x, P.x, p), p);

        uint256_t temp = mont_mul(lambda, mod_sub(P.x, R.x, p));
        R.y = mod_sub(temp, P.y, p);
    } else {
        uint256_t y_diff = mod_sub(Q.y, P.y, p);
        uint256_t lambda = mont_mul(y_diff, mont_inv(x_diff));

        uint256_t lambda_sq = mont_mul(lambda, lambda);
        R.x = mod_sub(lambda_sq, P.x, p);
        R.x = mod_sub(R.x, Q.x, p);

        uint256_t temp = mont_mul(lambda, mod_sub(P.x, R.x, p));
        R.y = mod_sub(temp, P.y, p);
    }

    R.infinity = false;

convert_back:
    // 转换回普通形式
    R.x = from_mont(R.x);
    R.y = from_mont(R.y);
    return R;
}

// ================== Rho算法 ==================
#include "common.h"
__host__ __device__ void transfer(unsigned char* mp, const unsigned char* mp2)
{
    for (int i = 0; i < 32; i++) {
        mp[i] = mp2[31 - i];
    }
}
class RhoPoint_dev
{
public:
    uint256_t m = {0};
    uint256_t n = {0};
    AffinePoint x = {{0}};

    void from(const RhoPoint& r) {
        transfer((unsigned char*)&this->m, r.m);
        transfer((unsigned char*)&this->n, r.n);
        memcpy(&this->x, r.x.data, sizeof(r.x.data));
        x.infinity = false;
    }
    __device__ bool operator==(const RhoPoint_dev& other) const
    {
        const unsigned char* a = (const unsigned char*)&this->m;
        const unsigned char* b = (const unsigned char*)&other.m;
        for (size_t i = 0; i < /*sizeof(RhoPoint_dev)*/ 129; i++) {
            if (a[i] != b[i]) {
                //printf("%d ", i);
                return false;
            }
        }
        return true;
    }
} ;

// 设备常量内存存储 adds_pub_dev
__constant__ RhoPoint_dev adds_pub_dev[256];

// 可区分点判断 (设备端)
__device__ uint64_t distinguishable(const AffinePoint& x)
{
    uint64_t t = *reinterpret_cast<const uint64_t*>(x.x.limb);
    if ((t & 0xFFFFFFFF) == 0) {
        return *reinterpret_cast<const uint64_t*>(x.x.limb + 1);
    }
    return 0;
}

__device__ void fun_add(RhoPoint_dev& s, const RhoPoint_dev& a)
{
    RhoPoint_dev tmp = s;
    s.x = point_add(tmp.x, a.x);
    s.m = mod_add(tmp.m, a.m, N);
    s.n = mod_add(tmp.n, a.n, N);
}

// 可区分点缓冲区结构
struct DpBuffer {
    uint64_t d;
    SecPair sp;
};

// 设备端 DP 缓冲区管理
__device__ DpBuffer* dp_device_buffer = nullptr; // 设备缓冲区指针
__device__ unsigned int dp_buffer_count = 0;     // 缓冲区当前计数
__device__ bool break_flag_dev = false;

extern bool gameover;


RhoPoint_dev* RhoStates_host = nullptr;
__device__ RhoPoint_dev* RhoStates_dev = nullptr;

// 添加 DP 到缓冲区 (设备端)
__device__ void add_dp_to_buffer(uint64_t d, const RhoPoint_dev& r,
                                 DpBuffer* buffer, unsigned int max_size)
{
    // 原子递增获取缓冲区位置
    unsigned int index = atomicAdd(&dp_buffer_count, 1);

    /* if (index < max_size)*/ {
        buffer[index].d = d;
        transfer(buffer[index].sp.m , (const unsigned char*)&r.m);
        transfer(buffer[index].sp.n, (const unsigned char*)&r.n);
    }
    if (dp_buffer_count >= max_size)
        break_flag_dev = true;
}

void break_rho(bool f)
{
    CHECK_CUDA(cudaMemcpyToSymbol(break_flag_dev, &f, sizeof(f)));
}

void _saveDP(uint64_t index, const SecPair& sp);
// DP 管理器类
class DpManager
{
public:
    DpManager(size_t buffer_size) : buffer_size(buffer_size)
    {
        // 分配设备缓冲区
        CHECK_CUDA(cudaMalloc(&m_dp_device_buffer, buffer_size * sizeof(DpBuffer)));
        CHECK_CUDA(cudaMemset(m_dp_device_buffer, 0, buffer_size * sizeof(DpBuffer)));

        // 设置设备端全局指针
        CHECK_CUDA(cudaMemcpyToSymbol(::dp_device_buffer, &m_dp_device_buffer, sizeof(DpBuffer*)));

        // 重置计数器
        reset_counters();
    }

    ~DpManager()
    {
        CHECK_CUDA(cudaFree(m_dp_device_buffer));
    }



    void reset_counters()
    {
        unsigned int zero = 0;
        CHECK_CUDA(cudaMemcpyToSymbol(dp_buffer_count, &zero, sizeof(unsigned int)));
    }

    // 从设备复制 DP 到主机并保存
    void save_dps()
    {
        // 获取当前缓冲区计数
        unsigned int current_count;
        CHECK_CUDA(cudaMemcpyFromSymbol(&current_count, dp_buffer_count, sizeof(unsigned int)));

        if (current_count == 0) return;

        // 复制数据到主机
        std::vector<DpBuffer> host_buffer(current_count);
        CHECK_CUDA(cudaMemcpy(host_buffer.data(), m_dp_device_buffer,
                   current_count * sizeof(DpBuffer), cudaMemcpyDeviceToHost));

        for (const auto& dp : host_buffer) {
            // 调用原始 saveDP 函数
            _saveDP(dp.d, dp.sp);
        }
        printf("saved %d dp.\n", current_count);
        // 重置设备缓冲区计数
        reset_counters();
    }
private:
    DpBuffer* m_dp_device_buffer = nullptr;
    size_t buffer_size;
};

constexpr size_t dp_buffer_size = 100000; // DP 缓冲区大小
__global__ void rho()
{
    // 获取全局线程索引
    int idx = blockIdx.x * blockDim.x + threadIdx.x;
    RhoPoint_dev s = RhoStates_dev[idx];

    // 设备共享内存存储 adds_pub
    __shared__ RhoPoint_dev adds_pub[256];
    // 从全局内存复制adds_pub到共享内存
    if (threadIdx.x < 256) {
        adds_pub[threadIdx.x] = adds_pub_dev[threadIdx.x];
    }
    __syncthreads(); // 确保所有线程已完成加载
    while (break_flag_dev == false) {
        fun_add(s, adds_pub[(unsigned char) s.x.x.limb[0]]);
        // 检查是否可区分
        uint64_t d = distinguishable(s.x);
        if (d != 0) {
            // 保存可区分点
            add_dp_to_buffer(d, s, dp_device_buffer, dp_buffer_size - 10);
        }
    }
    RhoStates_dev[idx] = s;
}

// 获取最佳线程块大小
void get_optimal_block_size(int& multiProcessorCount, int& block_size)
{
    cudaDeviceProp prop;
    CHECK_CUDA(cudaGetDeviceProperties(&prop, 0));

    // 根据GPU架构特性选择最佳线程数
    switch (prop.major) {
    case 7: // Volta/Turing
        block_size = 1024;
        break;
    case 8: // Ampere
        block_size = 1024;
        break;
    case 9: // Hopper
        block_size = 1024;
        break;
    default: // 其他架构
        block_size = 256;
    }
    // 确保不超过硬件限制
    block_size = std::min(block_size, prop.maxThreadsPerBlock);
    multiProcessorCount = prop.multiProcessorCount;
}

extern RhoPoint adds_pub[2][256];

void init_adds_pub_dev()
{
    for (int i = 0; i < sizeof(adds_pub_dev) / sizeof(RhoPoint_dev); i++) {
        RhoPoint_dev t;
        t.from(adds_pub[0][i]);
        CHECK_CUDA(cudaMemcpyToSymbol(adds_pub_dev, &t, sizeof(RhoPoint_dev), sizeof(RhoPoint_dev) * i, cudaMemcpyHostToDevice));
    }
}

void init_RhoStates_dev(int total_points)
{
    //分配设备内存并复制初始状态
    CHECK_CUDA(cudaMalloc(&RhoStates_host, total_points * sizeof(RhoPoint_dev)));
    CHECK_CUDA(cudaMemcpyToSymbol(RhoStates_dev, &RhoStates_host, sizeof(RhoPoint_dev*)));
    for (int i = 0; i < total_points; i++) {
        RhoPoint r;
        r.rand();
        RhoPoint_dev t;
        t.from(r);
        CHECK_CUDA(cudaMemcpy(RhoStates_host + i, &t, sizeof(RhoPoint_dev), cudaMemcpyHostToDevice));
    }
}

extern secp256k1_context* ctx;
void init_RhoStates_test(int total_points)
{
    // 分配设备内存并复制初始状态
    CHECK_CUDA(cudaMalloc(&RhoStates_host, total_points * sizeof(RhoPoint_dev)));
    CHECK_CUDA(cudaMemcpyToSymbol(RhoStates_dev, &RhoStates_host, sizeof(RhoPoint_dev*)));
    RhoState r;
    set_int(r.m, 1);
    set_int(r.n, 1);
    create(ctx, &r.x, r.m, r.n);
    for (int i = 0; i < total_points; i++) {
        RhoPoint_dev t;
        t.from(r);
        rho_F(ctx, r);
        CHECK_CUDA(cudaMemcpy(RhoStates_host + i, &t, sizeof(RhoPoint_dev), cudaMemcpyHostToDevice));
    }
}

void rho_play() {
    // 创建 DP 管理器
    DpManager dp_manager(dp_buffer_size);
    int multiProcessorCount = 0;
    int blockSize = 0;
    get_optimal_block_size(multiProcessorCount, blockSize);
    printf("multiProcessorCount: %d, blockSize: %d\n", multiProcessorCount, blockSize);
    int total_points = multiProcessorCount * blockSize;
    init_RhoStates_dev(total_points);
    init_adds_pub_dev();
    while (!gameover) {
        break_rho(0);
        rho<<<multiProcessorCount, blockSize>>>();
        // 等待核函数完成
        cudaDeviceSynchronize();
        dp_manager.save_dps();
    }
    // 清理资源
    CHECK_CUDA(cudaFree(RhoStates_host));
    RhoStates_host = nullptr;
}

// ================== 验证测试 ==================
__constant__ AffinePoint G = {
    {{0x16F81798, 0x59F2815B, 0x2DCE28D9, 0x029BFCDB,
      0xCE870B07, 0x55A06295, 0xF9DCBBAC, 0x79BE667E}},
    {{0xFB10D4B8, 0x9C47D08F, 0xA6855419, 0xFD17B448,
      0x0E1108A8, 0x5DA4FBFC, 0x26A3C465, 0x483ADA77}},
    false
};

__global__ void validate()
{
    // 测试1：G + ∞ = G
    AffinePoint inf;
    inf.x = {{0}};
    inf.y = {{0}};
    inf.infinity = true;

    AffinePoint res1G = point_add(G, inf);
    assert(!res1G.infinity);
    for (int i = 0; i < 8; ++i) {
        assert(res1G.x.limb[i] == G.x.limb[i]);
        assert(res1G.y.limb[i] == G.y.limb[i]);
    }

    // 测试2：G + G的有效性
    AffinePoint res2G = point_add(G, G);
    assert(!res2G.infinity);
    assert(res2G.x.limb[7] == 0xC6047F94); // 2G的x坐标高位
    assert(res2G.y.limb[7] == 0x1ae168fe); // 2G的y坐标高位
        
    // 测试3：G + 2G的有效性
    AffinePoint res3G = point_add(G, res2G);
    assert(!res3G.infinity);
    assert(res3G.x.limb[7] == 0xf9308a01); // 2G的x坐标高位
    assert(res3G.y.limb[7] == 0x388f7b0f); // 2G的y坐标高位

    //测试 rho_f_dev
    RhoPoint_dev* rs = RhoStates_dev;
    for (int i = 1; i < 100; i++) {
        auto t = (unsigned char)rs->x.x.limb[0];
        //printf("%d ", t);
        fun_add(*rs, adds_pub_dev[t]);
        assert(*rs == RhoStates_dev[i]);
    }
}

void validate_test()
{
    init_RhoStates_test(100);
    init_adds_pub_dev();
    validate<<<1, 1>>>();
    CHECK_CUDA(cudaDeviceSynchronize());
    // 清理资源
    CHECK_CUDA(cudaFree(RhoStates_host));
    RhoStates_host = nullptr;
    printf("validate_test passed!\n");
}
