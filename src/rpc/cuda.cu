#include <cassert>
#include <cstdint>
#include <cstdio>
#include <cuda_runtime.h>

// 256-bit数值（小端序，32位肢体）
typedef struct {
    uint32_t limb[8];
} uint256_t;

// secp256k1曲线参数（设备常量）
__constant__ uint256_t p = {
    0xFFFFFC2F, 0xFFFFFFFE, 0xFFFFFFFF, 0xFFFFFFFF,
    0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF};

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

__device__ uint256_t mont_add(const uint256_t a, const uint256_t b)
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

__device__ uint256_t mont_sub(const uint256_t a, const uint256_t b)
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

    uint256_t x_diff = mont_sub(Q.x, P.x);
    if (is_zero(&x_diff)) {
        uint256_t y_sum = mont_add(P.y, Q.y);
        if (is_zero(&y_sum)) {
            R.infinity = true;
            goto convert_back;
        }

        uint256_t x_sq = mont_mul(P.x, P.x);
        uint256_t numerator = mont_mul(x_sq, three_mont);
        uint256_t denominator = mont_add(P.y, P.y);
        uint256_t lambda = mont_mul(numerator, mont_inv(denominator));

        uint256_t lambda_sq = mont_mul(lambda, lambda);
        R.x = mont_sub(lambda_sq, mont_add(P.x, P.x));

        uint256_t temp = mont_mul(lambda, mont_sub(P.x, R.x));
        R.y = mont_sub(temp, P.y);
    } else {
        uint256_t y_diff = mont_sub(Q.y, P.y);
        uint256_t lambda = mont_mul(y_diff, mont_inv(x_diff));

        uint256_t lambda_sq = mont_mul(lambda, lambda);
        R.x = mont_sub(lambda_sq, P.x);
        R.x = mont_sub(R.x, Q.x);

        uint256_t temp = mont_mul(lambda, mont_sub(P.x, R.x));
        R.y = mont_sub(temp, P.y);
    }

    R.infinity = false;

convert_back:
    // 转换回普通形式
    R.x = from_mont(R.x);
    R.y = from_mont(R.y);
    return R;
}

// ================== 验证测试 ==================
__constant__ AffinePoint G = {
    {{0x16F81798, 0x59F2815B, 0x2DCE28D9, 0x029BFCDB,
      0xCE870B07, 0x55A06295, 0xF9DCBBAC, 0x79BE667E}},
    {{0xFB10D4B8, 0x9C47D08F, 0xA6855419, 0xFD17B448,
      0x0E1108A8, 0x5DA4FBFC, 0x26A3C465, 0x483ADA77}},
    false};

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
}

void validate_test()
{
    validate<<<1, 1>>>();
    CHECK_CUDA(cudaDeviceSynchronize());
    printf("validate_test passed!\n");
}
