#include <cassert>
#include <cstdint>
#include <cstdio>
#include <cuda_runtime.h>
#include <vector>
#include <iostream>
#include <cstdio>

// 256-bit数值（小端序，32位肢体）
typedef struct {
    uint32_t limb[8];
} uint256_t;

#ifdef __CUDA_ARCH__
#define CONSTANT __constant__
#else
#define CONSTANT
#endif

// secp256k1曲线参数（设备常量）
CONSTANT uint256_t p = {
    0xFFFFFC2F, 0xFFFFFFFE, 0xFFFFFFFF, 0xFFFFFFFF,
    0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF};

CONSTANT uint256_t N = {
    0xd0364141, 0xbfd25e8c, 0xaf48a03b, 0xbaaedce6,
    0xFFFFFFFE, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF};

// 预计算的蒙哥马利参数
CONSTANT uint256_t R = {
    0x000003D1, 0x00000001, 0x00000000, 0x00000000,
    0x00000000, 0x00000000, 0x00000000, 0x00000000};

CONSTANT uint256_t R_squared = {
    0x000e90a1, 0x000007a2, 0x00000001, 0x00000000,
    0x00000000, 0x00000000, 0x00000000, 0x00000000};

CONSTANT uint256_t R_cube = {
    0x3795f671, 0x002bb1e3, 0x00000b73, 0x00000001,
    0x00000000, 0x00000000, 0x00000000, 0x00000000};

// 预计算的蒙哥马利常量

CONSTANT uint256_t three_mont = {
    0x00000B73, 0x00000003, 0x00000000, 0x00000000,
    0x00000000, 0x00000000, 0x00000000, 0x00000000};

// 点结构（仿射坐标）
typedef struct {
    uint256_t x = {0};
    uint256_t y = {0};
    bool infinity = true;
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
__host__ __device__ uint32_t add256(uint256_t& a, const uint256_t& b)
{
    uint32_t carry = 0;
    for (int i = 0; i < 8; ++i) {
        uint64_t sum = (uint64_t)a.limb[i] + b.limb[i] + carry;
        a.limb[i] = (uint32_t)sum;
        carry = (uint32_t)(sum >> 32);
    }
    return carry;
}

// 返回最终借位状态 (1表示结果为负)
__host__ __device__ uint32_t sub256(uint256_t& a, const uint256_t& b)
{
    uint32_t borrow = 0;
    for (int i = 0; i < 8; ++i) {
        uint64_t sub = (uint64_t)a.limb[i] - b.limb[i] - borrow;
        a.limb[i] = (uint32_t)sub;
        borrow = (uint32_t)((sub >> 32) & 1);
    }
    return borrow;
}

__host__ __device__ int is_ge(const uint256_t& a, const uint256_t& b)
{
    for (int i = 7; i >= 0; --i) {
        if (a.limb[i] > b.limb[i]) return 1;
        if (a.limb[i] < b.limb[i]) return 0;
    }
    return 1;
}

__host__ __device__ int is_zero(const uint256_t& a)
{
    for (int i = 0; i < 8; ++i)
        if (a.limb[i] != 0) return 0;
    return 1;
}

// ================== 蒙哥马利运算 ==================
__host__ __device__ uint256_t mont_mul(const uint256_t& a, const uint256_t& b)
{
    uint64_t t[9] = {0}; // 扩展存储到288位（9*32）

    for (int i = 0; i < 8; ++i) {
        // 步骤1：计算a[i] * b并累加到t
        uint64_t carry = 0;
        for (int j = 0; j < 8; ++j) {
            uint64_t product = (uint64_t)a.limb[i] * b.limb[j];
            uint64_t sum = product + t[j] + carry;
            t[j] = sum & 0xFFFFFFFF; // 保留低32位
            carry = (sum >> 32) + (sum >= product? 0 : 0x100000000); // 记录进位
        }
        t[8] = carry; // 存储最高位进位

        // 步骤2：计算m = (t[0] * np) mod 2^32
        // uint32_t np = 0xD2253531;
        uint32_t m = (uint32_t)((t[0] * 0xD2253531) & 0xFFFFFFFF);

        // 步骤3：加m*p并处理进位
        carry = 0;
        for (int j = 0; j < 8; ++j) {
            uint64_t product = (uint64_t)m * p.limb[j];
            uint64_t sum = product + t[j] + carry;
            t[j] = sum & 0xFFFFFFFF; // 保留低32位
            carry = (sum >> 32) + (sum >= product ? 0 : 0x100000000); // 记录进位
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
    if ((t[7]&0xF00000000) || is_ge(result, p)) {
        sub256(result, p);
    }
    return result;
}

__host__ __device__ uint256_t mod_add(const uint256_t& a, const uint256_t& b, const uint256_t& m)
{
    uint256_t result = a;

    // 执行加法并检测进位
    uint32_t carry = add256(result, b);

    // 处理溢出情况：进位发生或结果 >= m
    if (carry || is_ge(result, m)) {
        sub256(result, m); // 减去模数m
    }
    return result;
}

__host__ __device__ uint256_t mont_sub(const uint256_t& a, const uint256_t& b)
{
    uint256_t result = a;

    // 执行减法并检测借位
    uint32_t borrow = sub256(result, b);

    // 处理负数结果
    if (borrow) {
        add256(result, p); // 加上模数p
    }
    return result;
}

__host__ __device__ uint256_t mont_inv(const uint256_t a)
{
    uint256_t result = R; // 1 in Montgomery form
    uint256_t exponent = p;
    uint256_t two = {{2}};
    sub256(exponent, two); // p-2

    for (int i = 255; i >= 0; --i) {
        result = mont_mul(result, result);
        if ((exponent.limb[i / 32] >> (i % 32)) & 1)
            result = mont_mul(result, a);
    }
    return result;
}

// 扩展欧几里得算法求模逆 (普通域)
__host__ __device__ uint256_t mod_inv(const uint256_t& a, const uint256_t& mod)
{
    // 特殊情况处理：0 没有逆元
    if (is_zero(a)) {
        return a; // 返回 0
    }

    // 初始化变量
    uint256_t u = a;
    uint256_t v = mod;
    uint256_t x1 = {{1}}; // 初始系数: 1
    uint256_t x2 = {{0}}; // 初始系数: 0
    uint32_t carry;

    // 迭代直到 v 为 0
    while (!is_zero(v)) {
        // 检查提前退出条件：u == 1 或 v == 1
        if (u.limb[0] == 1 && u.limb[1] == 0 && u.limb[2] == 0 && u.limb[3] == 0 &&
            u.limb[4] == 0 && u.limb[5] == 0 && u.limb[6] == 0 && u.limb[7] == 0) {
            break; // u == 1，x1 就是逆元
        }

        if (v.limb[0] == 1 && v.limb[1] == 0 && v.limb[2] == 0 && v.limb[3] == 0 &&
            v.limb[4] == 0 && v.limb[5] == 0 && v.limb[6] == 0 && v.limb[7] == 0) {
            // v == 1，x2 就是逆元
            x1 = x2;
            break;
        }
        // 当 u 为偶数时
        if ((u.limb[0] & 1) == 0) {
            // u /= 2 (右移)
            for (int i = 0; i < 7; i++) {
                u.limb[i] = (u.limb[i] >> 1) | (u.limb[i + 1] << 31);
            }
            u.limb[7] >>= 1;

            // 处理 x1
            if ((x1.limb[0] & 1) == 0) {
                carry = 0;
            } else {
                // x1 = (x1 + mod)
                carry = add256(x1, mod);
            }
            // x1 /= 2 (右移)
            for (int i = 0; i < 7; i++) {
                x1.limb[i] = (x1.limb[i] >> 1) | (x1.limb[i + 1] << 31);
            }
            x1.limb[7] = (x1.limb[7] >> 1) | (carry << 31);
        }
        // 当 v 为偶数时
        else if ((v.limb[0] & 1) == 0) {
            // v /= 2 (右移)
            for (int i = 0; i < 7; i++) {
                v.limb[i] = (v.limb[i] >> 1) | (v.limb[i + 1] << 31);
            }
            v.limb[7] >>= 1;

            // 处理 x2
            if ((x2.limb[0] & 1) == 0) {
                carry = 0;
            } else {
                // x2 = (x2 + mod)
                carry = add256(x2, mod);
            }
            // x2 /= 2 (右移)
            for (int i = 0; i < 7; i++) {
                x2.limb[i] = (x2.limb[i] >> 1) | (x2.limb[i + 1] << 31);
            }
            x2.limb[7] = (x2.limb[7] >> 1) | (carry << 31);
        }
        // 当 u 和 v 都为奇数时
        else {
            if (is_ge(u, v)) {
                // u = u - v
                sub256(u, v);

                // x1 = x1 - x2
                if (is_ge(x1, x2)) {
                    sub256(x1, x2);
                } else {
                    uint256_t temp = mod;
                    sub256(temp, x2);
                    add256(x1, temp);
                }
            } else {
                // v = v - u
                sub256(v, u);

                // x2 = x2 - x1
                if (is_ge(x2, x1)) {
                    sub256(x2, x1);
                } else {
                    uint256_t temp = mod;
                    sub256(temp, x1);
                    add256(x2, temp);
                }
            }
        }
    }

    // 确保结果在 [0, mod-1] 范围内
    if (is_ge(x1, mod)) {
        sub256(x1, mod);
    }

    return x1;
}

// 转换到蒙哥马利域
__host__ __device__ uint256_t to_mont(const uint256_t& a)
{
    return mont_mul(a, R_squared);
}
__host__ __device__ uint256_t from_mont(const uint256_t& a)
{
    uint256_t one = {1};
    return mont_mul(a, one);
}
// 蒙哥马利域中的逆元计算
__host__ __device__ uint256_t mont_inv2(const uint256_t& a_mont)
{
    uint256_t inv = mod_inv(a_mont, p);

    return mont_mul(inv, R_cube);
}

// ================== 点运算 ==================
__host__ __device__ AffinePoint mont_point_add(const AffinePoint& P_mont, const AffinePoint& Q_mont)
{
    // 处理无穷点情况
    if (P_mont.infinity) return Q_mont;
    if (Q_mont.infinity) return P_mont;
    AffinePoint R;
    R.x = {{0}};
    R.y = {{0}};
    R.infinity = true;

    uint256_t x_diff = mont_sub(Q_mont.x, P_mont.x);
    if (is_zero(x_diff)) {
        uint256_t y_sum = mod_add(P_mont.y, Q_mont.y, p);
        if (is_zero(y_sum)) {
            return R;
        }

        uint256_t x_sq = mont_mul(P_mont.x, P_mont.x);
        uint256_t numerator = mont_mul(x_sq, three_mont); //改为加法的话，会产生负优化。
        uint256_t lambda = mont_mul(numerator, mont_inv2(y_sum));

        uint256_t lambda_sq = mont_mul(lambda, lambda);
        R.x = mont_sub(lambda_sq, mod_add(P_mont.x, P_mont.x, p));

        uint256_t temp = mont_mul(lambda, mont_sub(P_mont.x, R.x));
        R.y = mont_sub(temp, P_mont.y);
    } else {
        uint256_t y_diff = mont_sub(Q_mont.y, P_mont.y);
        uint256_t lambda = mont_mul(y_diff, mont_inv2(x_diff));

        uint256_t lambda_sq = mont_mul(lambda, lambda);
        R.x = mont_sub(lambda_sq, P_mont.x);
        R.x = mont_sub(R.x, Q_mont.x);

        uint256_t temp = mont_mul(lambda, mont_sub(P_mont.x, R.x));
        R.y = mont_sub(temp, P_mont.y);
    }

    R.infinity = false;
    return R;
}
__host__ __device__ AffinePoint point_add(AffinePoint P, AffinePoint Q)
{
    // 转换为蒙哥马利域
    P.x = to_mont(P.x);
    P.y = to_mont(P.y);
    Q.x = to_mont(Q.x);
    Q.y = to_mont(Q.y);

    AffinePoint R = mont_point_add(P, Q);

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
class RhoPoint_mont
{
public:
    uint256_t m = {0};
    uint256_t n = {0};
    AffinePoint x = {{0}};

    void from(const RhoPoint& r) {
        transfer((unsigned char*)&this->m, r.m);
        transfer((unsigned char*)&this->n, r.n);
        memcpy(&this->x, r.x.data, sizeof(r.x.data));
        x.x = to_mont(x.x);
        x.y = to_mont(x.y);
        x.infinity = false;
    }
    void to(RhoPoint& r)
    {
        AffinePoint x_ = {{0}};
        x_.x = from_mont(x.x);
        x_.y = from_mont(x.y);
        memcpy(r.x.data, &x_.x, sizeof(r.x.data));
        transfer(r.m, (unsigned char*)&this->m);
        transfer(r.n, (unsigned char*)&this->n);
    }
    __device__ bool operator==(const RhoPoint_mont& other) const
    {
        const unsigned char* a = (const unsigned char*)&this->m;
        const unsigned char* b = (const unsigned char*)&other.m;
        for (size_t i = 0; i < /*sizeof(RhoPoint_mont)*/ 129; i++) {
            if (a[i] != b[i]) {
                //printf("%d ", i);
                return false;
            }
        }
        return true;
    }
} ;

// 设备常量内存存储 adds_pub_dev
__constant__ RhoPoint_mont adds_pub_dev[256];

// 可区分点判断 (设备端)
__host__ __device__ uint64_t distinguishable(const uint256_t& x)
{
    if (x.limb[0] == 0) {
        uint64_t t2 = x.limb[1] + ((uint64_t)x.limb[2] << 32);
        return t2;
    }
    return 0;
}

__host__ __device__ void fun_add(RhoPoint_mont& s, const RhoPoint_mont& a)
{
    s.x = mont_point_add(s.x, a.x);
    s.m = mod_add(s.m, a.m, N);
    s.n = mod_add(s.n, a.n, N);
}

// 可区分点缓冲区结构
struct DpBuffer {
    uint64_t d;
    SecPair sp;
};

// 零拷贝内存管理
struct ZeroCopyMemory {
    volatile bool* break_flag; // 主机和设备共享的指针
    bool* host_ptr;            // 主机端指针
    bool* device_ptr;          // 设备端指针
};

ZeroCopyMemory zero_copy_mem;

// 设备端 DP 缓冲区管理
__device__ DpBuffer* dp_device_buffer = nullptr; // 设备缓冲区指针
__device__ unsigned int dp_buffer_count = 0;     // 缓冲区当前计数
__device__ volatile bool* break_flag_dev = nullptr;

extern bool gameover;


RhoPoint_mont* RhoStates_host = nullptr;
__device__ RhoPoint_mont* RhoStates_dev = nullptr;

// 添加 DP 到缓冲区 (设备端)
__device__ void add_dp_to_buffer(uint64_t d, const RhoPoint_mont& r,
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
        *break_flag_dev = true;
}

// 初始化零拷贝内存
void init_zero_copy_memory()
{
    // 分配页锁定内存（主机可访问）
    CHECK_CUDA(cudaHostAlloc((void**)&zero_copy_mem.host_ptr,
                             sizeof(bool),
                             cudaHostAllocMapped));

    // 获取设备可访问的指针
    CHECK_CUDA(cudaHostGetDevicePointer((void**)&zero_copy_mem.device_ptr,
                                        zero_copy_mem.host_ptr,
                                        0));

    // 设置初始值
    *zero_copy_mem.host_ptr = false;

    // 将设备指针复制到设备全局变量
    CHECK_CUDA(cudaMemcpyToSymbol(break_flag_dev,
                                  &zero_copy_mem.device_ptr,
                                  sizeof(volatile bool*)));
}

// 释放零拷贝内存
void free_zero_copy_memory()
{
    if (zero_copy_mem.host_ptr) {
        CHECK_CUDA(cudaFreeHost(zero_copy_mem.host_ptr));
        zero_copy_mem.host_ptr = nullptr;
        zero_copy_mem.device_ptr = nullptr;
    }
}

void break_rho(bool value)
{
    if (zero_copy_mem.host_ptr) {
        *zero_copy_mem.host_ptr = value;
    }
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

        if (current_count != 0) {
            // 复制数据到主机
            std::vector<DpBuffer> host_buffer(current_count);
            CHECK_CUDA(cudaMemcpy(host_buffer.data(), m_dp_device_buffer,
                                  current_count * sizeof(DpBuffer), cudaMemcpyDeviceToHost));

            for (const auto& dp : host_buffer) {
                // 调用原始 saveDP 函数
                _saveDP(dp.d, dp.sp);
            }
            // 重置设备缓冲区计数
            reset_counters();
        }

        std::cout << get_time() << " : saved " << current_count << " dp." << std::endl;
    }
private:
    DpBuffer* m_dp_device_buffer = nullptr;
    size_t buffer_size;
};

// 设备端辅助函数：将32位整数转换为大端序十六进制字符串
__host__ __device__ void uint32_to_hex_be(char* output, uint32_t value)
{
    const char hex_chars[] = "0123456789abcdef";
    for (int i = 0; i < 8; i++) {
        // 从最高位字节开始处理 (大端序)
        uint8_t byte = (value >> ((7 - i) * 4)) & 0xF;
        output[i] = hex_chars[byte];
    }
}

// 设备端辅助函数：将uint256_t转换为大端序十六进制字符串
__host__ __device__ void uint256_to_hex_be(char* output, const uint256_t& value)
{
    // 大端序：从最高位limb开始 (limb[7])
    for (int limb_idx = 7; limb_idx >= 0; limb_idx--) {
        uint32_to_hex_be(output + (7 - limb_idx) * 8, value.limb[limb_idx]);
    }
    output[64] = '\0'; // 终止字符串
}

// 设备端函数：打印RhoPoint_dev的大端序十六进制表示
__host__ __device__ void print_rho_point_dev(const RhoPoint_mont& point)
{
    // 缓冲区大小：4个256位值 * 64字符 + 分隔符 + 终结符
    constexpr int buf_size = 4 * 64 + 10;
    char buf[buf_size];
    char* ptr = buf;

    // 打印 m
    uint256_to_hex_be(ptr, point.m);
    ptr += 64;
    *ptr++ = '\n';

    // 打印 n
    uint256_to_hex_be(ptr, point.n);
    ptr += 64;
    *ptr++ = '\n';

    // 打印 x 坐标
    uint256_to_hex_be(ptr, point.x.x);
    ptr += 64;
    *ptr++ = '\n';

    // 打印 y 坐标
    uint256_to_hex_be(ptr, point.x.y);
    ptr += 64;

    // 添加无穷标志
    if (point.x.infinity) {
        *ptr++ = '\n';
        *ptr++ = 'I';
    }

    *ptr = '\0'; // 终结字符串

    // 打印结果
    printf("\nRhoPoint_dev:\n%s\n", buf);
}


constexpr size_t dp_buffer_size = 110; // DP 缓冲区大小
__global__ void rho()
{
    // 获取全局线程索引
    int idx = blockIdx.x * blockDim.x + threadIdx.x;
    RhoPoint_mont s = RhoStates_dev[idx];
    uint256_t x_ord = from_mont(s.x.x);
    uint64_t count_rho = 0;
    uint32_t count_dp = 0;
    // 设备共享内存存储 adds_pub
    __shared__ RhoPoint_mont adds_pub[256];
    // 共享内存产生的优化微乎其微， 2% 左右，但会多占用10个寄存器。
    // 从全局内存复制adds_pub到共享内存
    if (threadIdx.x == 0) {
        for (int i = 0; i < 256; i++)
            adds_pub[i] = adds_pub_dev[i];
    }
    __syncthreads(); // 确保所有线程已完成加载
    while (true) {
        fun_add(s, adds_pub[(unsigned char)x_ord.limb[0]]);
        count_rho++;
        // 检查是否可区分
        x_ord = from_mont(s.x.x);
        uint64_t d = distinguishable(x_ord);
        if (d != 0) {
            count_dp++;
            // 保存可区分点
            add_dp_to_buffer(d, s, dp_device_buffer, dp_buffer_size - 10);
            x_ord.limb[0] = (uint32_t)count_rho;
        }
        if ((count_rho & 0xFFFF) == 0) {
            if (*break_flag_dev)
                break;
        }
    }
    RhoStates_dev[idx] = s;
    if (idx == 0) {
        printf("count_rho:%llu count_dp:%d \n", count_rho, count_dp);
    }
}

// 获取最佳线程块大小
void get_optimal_block_size(int& multiProcessorCount, int& block_size)
{
    /*
    cudaDeviceProp prop;
    CHECK_CUDA(cudaGetDeviceProperties(&prop, 0));

    // 根据GPU架构特性选择最佳线程数
    int coresPerSM;
    int multiple = 2;
    switch (prop.major) {
    case 5: // Maxwell
        coresPerSM = 128;
        break;
    case 6: // Pascal
        coresPerSM = 128;
        multiple = 2;
        break;
    case 7: // Volta/Turing
        coresPerSM = 64;
        break;
    case 8: // Ampere
        coresPerSM = 128;
        break;
    case 9: // Hopper
        coresPerSM = 128;
        break;
    default: // 其他架构
        coresPerSM = 128;
    }
    // 确保不超过硬件限制
    block_size = std::min(coresPerSM * multiple, prop.maxThreadsPerBlock);
    multiProcessorCount = prop.multiProcessorCount;*/

    CHECK_CUDA(cudaOccupancyMaxPotentialBlockSize(
        &multiProcessorCount,
        &block_size,
        rho,
        0, // 无动态共享内存
        0 // 线程块大小上限
    ));

}

extern RhoPoint adds_pub[2][256];

void init_adds_pub_dev()
{
    for (int i = 0; i < sizeof(adds_pub_dev) / sizeof(RhoPoint_mont); i++) {
        RhoPoint_mont t;
        t.from(adds_pub[0][i]);
        CHECK_CUDA(cudaMemcpyToSymbol(adds_pub_dev, &t, sizeof(RhoPoint_mont), sizeof(RhoPoint_mont) * i, cudaMemcpyHostToDevice));
    }
}

static const std::string _RSFile2_name = "D:\\RhoState2.txt";
bool loadRhoState(RhoState* s, int num, const std::string& name);
bool saveRhoState(const RhoState* s, int num, const std::string& name);

void init_RhoStates_dev(int total_points, const std::string& name)
{
    //分配设备内存并复制初始状态
    CHECK_CUDA(cudaMalloc(&RhoStates_host, total_points * sizeof(RhoPoint_mont)));
    CHECK_CUDA(cudaMemcpyToSymbol(RhoStates_dev, &RhoStates_host, sizeof(RhoPoint_mont*)));
    std::vector<RhoState> rsv;
    rsv.resize(total_points);
    bool b = loadRhoState(rsv.data(), total_points, name);
    for (int i = 0; i < total_points; i++) {
        RhoPoint_mont t;
        if (b) {
            t.from(rsv[i]);
        } else {
            RhoPoint r;
            r.rand();
            t.from(r);
        }
        CHECK_CUDA(cudaMemcpy(RhoStates_host + i, &t, sizeof(RhoPoint_mont), cudaMemcpyHostToDevice));
    }
}

void save_RhoStates_dev(int total_points, const std::string& name)
{
    std::vector<RhoState> rsv;
    rsv.resize(total_points);
    for (int i = 0; i < total_points; i++) {
        RhoPoint_mont t;
        CHECK_CUDA(cudaMemcpy(&t, RhoStates_host + i, sizeof(RhoPoint_mont), cudaMemcpyDeviceToHost));
        t.to(rsv[i]);
        rsv[i].times = 0;
    }
    saveRhoState(rsv.data(), total_points, name);
    std::cout << get_time() << " : save_RhoStates_dev. " << std::endl;
}

extern secp256k1_context* ctx;
void init_RhoStates_test(int total_points)
{
    // 分配设备内存并复制初始状态
    CHECK_CUDA(cudaMalloc(&RhoStates_host, total_points * sizeof(RhoPoint_mont)));
    CHECK_CUDA(cudaMemcpyToSymbol(RhoStates_dev, &RhoStates_host, sizeof(RhoPoint_mont*)));
    RhoState r;
    set_int256(r.m, "569103012ff8d20291a62809f4ac5f6c8f88a13d4208a6a674cec68f1307254e");
    set_int256(r.n, "92ce814fc881620c4461460d5144b54780edbae642905b0b847eb34ea5688bd3");
    create(ctx, &r.x, r.m, r.n);
    RhoPoint_mont t;
    for (int i = 0; i < total_points - 1; i++) {
        t.from(r);
        CHECK_CUDA(cudaMemcpy(RhoStates_host + i, &t, sizeof(RhoPoint_mont), cudaMemcpyHostToDevice));
        rho_F(ctx, r);
    }
    set_int256(r.m, "4795cc3b02cfd7772a0f913b7cf18ed3cbff9c59b2c8899d0f719449c641e0a0");
    set_int256(r.n, "38468e1ca1ab59348d856b441274666059c1fc7fabf1fb267a80b0ff83eca274");
    create(ctx, &r.x, r.m, r.n);
    t.from(r);
    CHECK_CUDA(cudaMemcpy(RhoStates_host + total_points - 1, &t, sizeof(RhoPoint_mont), cudaMemcpyHostToDevice));
}

void rho_play() {
    // 创建 DP 管理器
    DpManager dp_manager(dp_buffer_size);
    int multiProcessorCount = 0;
    int blockSize = 0;
    get_optimal_block_size(multiProcessorCount, blockSize);
    std::cout << get_time() << " : multiProcessorCount: " << multiProcessorCount << ", blockSize : " << blockSize << std::endl;
    int total_points = multiProcessorCount * blockSize;
    init_RhoStates_dev(total_points, _RSFile2_name);
    init_adds_pub_dev();
    // 初始化零拷贝内存
    init_zero_copy_memory();
    while (!gameover) {
        break_rho(false);
        rho<<<multiProcessorCount, blockSize>>>();
        // 等待核函数完成
        CHECK_CUDA(cudaDeviceSynchronize());
        dp_manager.save_dps();
        save_RhoStates_dev(total_points, _RSFile2_name);
    }
    // 清理资源
    free_zero_copy_memory();
    CHECK_CUDA(cudaFree(RhoStates_host));
    RhoStates_host = nullptr;
    std::cout << "rho_play exit." << std::endl;
}

// ================== 验证测试 ==================
__constant__ AffinePoint G = {
    {{0x16F81798, 0x59F2815B, 0x2DCE28D9, 0x029BFCDB,
      0xCE870B07, 0x55A06295, 0xF9DCBBAC, 0x79BE667E}},
    {{0xFB10D4B8, 0x9C47D08F, 0xA6855419, 0xFD17B448,
      0x0E1108A8, 0x5DA4FBFC, 0x26A3C465, 0x483ADA77}},
    false
};

#define RHOSTATES_TEST_NUM  5120001
#define RHODP_TEST_NUM 102

__global__ void validate_1()
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

    // 测试1.1: G+(-G)
    AffinePoint res_1G;
    uint256_t _y = mont_sub({0}, G.y);
    res_1G.x = G.x;
    res_1G.y = _y;
    res_1G.infinity = false;
    AffinePoint res0G = point_add(G, res_1G);
    assert(res0G.infinity);

    // 测试2：G + G的有效性
    AffinePoint res2G = point_add(G, G);
    assert(!res2G.infinity);
    assert(res2G.x.limb[7] == 0xC6047F94); // 2G的x坐标高位
    assert(res2G.y.limb[7] == 0x1ae168fe); // 2G的y坐标高位
        
    // 测试3：G + 2G的有效性
    AffinePoint res3G = point_add(G, res2G);
    assert(!res3G.infinity);
    assert(res3G.x.limb[7] == 0xf9308a01); // 3G的x坐标高位
    assert(res3G.y.limb[7] == 0x388f7b0f); // 3G的y坐标高位

    //测试 distinguishable
    assert(distinguishable(from_mont(RhoStates_dev[0].x.x)) == 0);
    assert(distinguishable(from_mont(RhoStates_dev[RHOSTATES_TEST_NUM].x.x)) == 867600860383096976);

    assert(*break_flag_dev == true);
}

__global__ void validate_multi()
{
    //测试 rho_f_dev
    for (int i = 0; i < RHOSTATES_TEST_NUM / (blockDim.x * gridDim.x); i++) {
        int index = i * blockDim.x * gridDim.x + blockDim.x * blockIdx.x + threadIdx.x;
        RhoPoint_mont rs = RhoStates_dev[index];
        auto t = (unsigned char)from_mont(rs.x.x).limb[0];
        fun_add(rs, adds_pub_dev[t]);
        assert((rs == RhoStates_dev[index + 1]));
    }

    int idx = blockDim.x * blockIdx.x + threadIdx.x;
    if (idx < RHODP_TEST_NUM) {
        add_dp_to_buffer(867600860383096976, RhoStates_dev[RHOSTATES_TEST_NUM], dp_device_buffer, RHODP_TEST_NUM);
    }
}

__host__ __device__ uint64_t perf_fun(RhoPoint_mont& s, const RhoPoint_mont* adds)
{
    uint64_t count_rho = 0;
    uint32_t count_dp = 0;
    uint256_t x_ord = from_mont(s.x.x);
    while (count_rho < 800000) {
        fun_add(s, adds[(unsigned char)x_ord.limb[0]]);
        count_rho++;
        // 检查是否可区分
        x_ord = from_mont(s.x.x);
        uint64_t d = distinguishable(x_ord);
        if (d != 0) {
            count_dp++;
        }
    }
    return count_rho;
}

void perf_test_cpu() {
    RhoPoint_mont adds_pub_tmp[256];
    for (int i = 0; i < sizeof(adds_pub_tmp) / sizeof(RhoPoint_mont); i++) {
        adds_pub_tmp[i].from(adds_pub[0][i]);
    }
    RhoPoint_mont s = adds_pub_tmp[0];
    std::cout << get_time() << " :cpu test start" << std::endl;
    uint64_t count_rho = perf_fun(s, adds_pub_tmp);
    std::cout << get_time() << " :cpu test end with " << count_rho << " RhoPoint." << std::endl;
}

__global__ void perf_test_gpu_kernel()
{
    RhoPoint_mont s = adds_pub_dev[threadIdx.x % 256];
    __shared__ RhoPoint_mont adds_pub[256];
    // 从全局内存复制adds_pub到共享内存
    for (int i = 0; i < 256; i++)
        adds_pub[i] = adds_pub_dev[i];
    perf_fun(s, adds_pub);
}

void perf_test_gpu()
{
    std::cout << get_time() << " :gpu test start" << std::endl;
    perf_test_gpu_kernel<<<1, 1>>>();
    CHECK_CUDA(cudaDeviceSynchronize());
    std::cout << get_time() << " :gpu test end with  800000 RhoPoint." << std::endl;
}

void perf_test() {
    // 性能测试
    init_adds_pub_dev();
    perf_test_cpu();
    perf_test_gpu();
}

void validate_test()
{
    init_RhoStates_test(RHOSTATES_TEST_NUM + 1);
    init_adds_pub_dev();
    init_zero_copy_memory();
    DpManager dp_manager(RHODP_TEST_NUM + 10);
       
    validate_multi<<<10, 256>>>();
    CHECK_CUDA(cudaDeviceSynchronize());
    validate_1<<<1, 1>>>();
    CHECK_CUDA(cudaDeviceSynchronize());
    //dp_manager.save_dps();
    //TODDO: 然后手动检查dp文件！！

    //测试转换逻辑
    for (int i = 0; i < 4096; i++) {
        RhoPoint r, r2;
        r.rand();
        RhoPoint_mont t;
        t.from(r);
        DpBuffer buffer;
        transfer(buffer.sp.m, (const unsigned char*)&t.m);
        transfer(buffer.sp.n, (const unsigned char*)&t.n);
        assert(buffer.sp == r);
        t.to(r2);
        assert(memcmp(&r, &r2, sizeof(r2)) == 0);
    }

    // 清理资源
    CHECK_CUDA(cudaFree(RhoStates_host));
    RhoStates_host = nullptr;

    //测试init_RhoStates_dev 和 save_RhoStates_dev
    int points = 100 * 960;
    const std::string fn_ = "D:\\test_rs.txt";
    const std::string fn2_ = "D:\\test_rs2.txt";
    init_RhoStates_dev(points, fn_);
    save_RhoStates_dev(points, fn_);
    std::vector<RhoState> rsv, rsv2;
    rsv.resize(points);
    rsv2.resize(points);
    bool b = loadRhoState(rsv.data(), points, fn_);
    // 清理资源
    CHECK_CUDA(cudaFree(RhoStates_host));
    RhoStates_host = nullptr;
    init_RhoStates_dev(points, fn_);
    save_RhoStates_dev(points, fn2_);
    loadRhoState(rsv2.data(), points, fn2_);
    for (int i = 0; i < points; i++) {
        assert(check(ctx, &rsv[i].x, rsv[i].m, rsv[i].n));
        assert(memcmp(&rsv[i], &rsv2[i], sizeof(rsv[i])) == 0);
    }
    std::remove(fn_.c_str());
    std::remove(fn2_.c_str());

    // 清理资源
    CHECK_CUDA(cudaFree(RhoStates_host));
    RhoStates_host = nullptr;
    printf("validate_test passed!\n");
}
