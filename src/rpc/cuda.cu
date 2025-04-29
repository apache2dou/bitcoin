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
    0x000007A2, 0x00000002, 0x00000001, 0x00000000,
    0x00000000, 0x00000000, 0x00000000, 0x00000000};

__constant__ uint32_t np = 0xD2253531;

// 预计算的蒙哥马利常量
__constant__ uint256_t two_mont = {
    0x000007A2, 0x00000002, 0x00000001, 0x00000000,
    0x00000000, 0x00000000, 0x00000000, 0x00000000};

__constant__ uint256_t three_mont = {
    0x00000B73, 0x00000003, 0x00000001, 0x00000000,
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
__device__ void add256(uint256_t* a, const uint256_t* b)
{
    uint64_t carry = 0;
    for (int i = 0; i < 8; ++i) {
        uint64_t sum = (uint64_t)a->limb[i] + b->limb[i] + carry;
        a->limb[i] = (uint32_t)sum;
        carry = sum >> 32;
    }
}

__device__ void sub256(uint256_t* a, const uint256_t* b)
{
    uint64_t borrow = 0;
    for (int i = 0; i < 8; ++i) {
        uint64_t sub = (uint64_t)a->limb[i] - b->limb[i] - borrow;
        a->limb[i] = (uint32_t)sub;
        borrow = (sub >> 32) & 1;
    }
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
    uint256_t t = {{0}};
    for (int i = 0; i < 8; ++i) {
        uint64_t carry = 0;

        // 计算m = (a[i] * b[0] + t[0]) * np
        uint64_t product = (uint64_t)a.limb[i] * b.limb[0] + t.limb[0];
        uint32_t m = (uint32_t)(product * np);

        // 第一步：计算a[i] * b + t
        for (int j = 0; j < 8; ++j) {
            product = (uint64_t)a.limb[i] * b.limb[j] + t.limb[j] + carry;
            carry = product >> 32;
            t.limb[j] = (uint32_t)product;
        }

        // 第二步：加上m*p
        carry = 0;
        for (int j = 0; j < 8; ++j) {
            product = (uint64_t)m * p.limb[j] + t.limb[j] + carry;
            carry = product >> 32;
            t.limb[j] = (uint32_t)product;
        }

        // 第三步：右移32位
        for (int j = 7; j > 0; --j)
            t.limb[j] = t.limb[j - 1];
        t.limb[0] = (uint32_t)carry;
    }

    // 模约减
    if (is_ge(&t, &p))
        sub256(&t, &p);
    return t;
}

__device__ uint256_t mont_add(const uint256_t a, const uint256_t b)
{
    uint256_t result = a;
    add256(&result, &b);
    if (is_ge(&result, &p))
        sub256(&result, &p);
    return result;
}

__device__ uint256_t mont_sub(const uint256_t a, const uint256_t b)
{
    uint256_t result = a;
    sub256(&result, &b);
    if (result.limb[7] >= 0xFFFFFFFF) // 处理负结果
        add256(&result, &p);
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

// ================== 点运算 ==================
__device__ AffinePoint point_add(AffinePoint P, AffinePoint Q)
{
    AffinePoint R;
    R.x = {{0}};
    R.y = {{0}};
    R.infinity = true;

    // 处理无穷远点
    if (P.infinity) return Q;
    if (Q.infinity) return P;

    // 计算x1 - x2
    uint256_t x_diff = mont_sub(P.x, Q.x);
    if (is_zero(&x_diff)) {
        // 处理相同x坐标的情况
        uint256_t y_sum = mont_add(P.y, Q.y);
        if (is_zero(&y_sum))
            return R;

        // 点加倍公式：λ = (3x²)/(2y)
        uint256_t x_sq = mont_mul(P.x, P.x);
        uint256_t numerator = mont_mul(x_sq, three_mont);
        uint256_t denominator = mont_mul(P.y, two_mont);
        uint256_t lambda = mont_mul(numerator, mont_inv(denominator));

        // 计算新坐标
        uint256_t lambda_sq = mont_mul(lambda, lambda);
        R.x = mont_sub(lambda_sq, mont_add(P.x, P.x));
        R.x = mont_sub(R.x, P.x);

        uint256_t temp = mont_mul(lambda, mont_sub(P.x, R.x));
        R.y = mont_sub(temp, P.y);
    } else {
        // 普通加法公式：λ = (y2 - y1)/(x2 - x1)
        uint256_t y_diff = mont_sub(Q.y, P.y);
        uint256_t lambda = mont_mul(y_diff, mont_inv(x_diff));

        // 计算新坐标
        uint256_t lambda_sq = mont_mul(lambda, lambda);
        R.x = mont_sub(lambda_sq, P.x);
        R.x = mont_sub(R.x, Q.x);

        uint256_t temp = mont_mul(lambda, mont_sub(P.x, R.x));
        R.y = mont_sub(temp, P.y);
    }

    R.infinity = false;
    return R;
}

// ================== 验证测试 ==================
__constant__ AffinePoint G_mont = {
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

    AffinePoint res1 = point_add(G_mont, inf);
    assert(!res1.infinity);
    for (int i = 0; i < 8; ++i) {
        assert(res1.x.limb[i] == G_mont.x.limb[i]);
        assert(res1.y.limb[i] == G_mont.y.limb[i]);
    }

    // 测试2：G + G的有效性
    AffinePoint res2 = point_add(G_mont, G_mont);
    assert(!res2.infinity);
    assert(res2.x.limb[0] == 0xC6047F94); // 2G的x坐标低位
    assert(res2.y.limb[0] == 0x9F97DC76); // 2G的y坐标低位
}

void validate_test()
{
    validate<<<1, 1>>>();
    CHECK_CUDA(cudaDeviceSynchronize());
    printf("所有测试通过！\n");
}
