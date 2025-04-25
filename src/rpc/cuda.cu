#include <cassert>
#include <cstdint>
#include <cstdio>
#include <cuda_runtime.h>

#define CHECK_CUDA(call)                                                                                  \
    do {                                                                                                  \
        cudaError_t status = call;                                                                        \
        if (status != cudaSuccess) {                                                                      \
            fprintf(stderr, "CUDA error at %s:%d: %s\n", __FILE__, __LINE__, cudaGetErrorString(status)); \
            exit(EXIT_FAILURE);                                                                           \
        }                                                                                                 \
    } while (0)

typedef struct {
    uint64_t d[4]; // 小端序存储 [0]是最低位
} uint256_t;

typedef struct {
    uint256_t x;
    uint256_t y;
    bool is_infinity;
} EC_Point;

// secp256k1常数（小端序排列）
__constant__ uint256_t p = {{
    0xFFFFFFFEFFFFFC2F, // d[0] = LSB
    0xFFFFFFFFFFFFFFFF,
    0xFFFFFFFFFFFFFFFF,
    0xFFFFFFFFFFFFFFFF // d[3] = MSB
}};

__constant__ uint256_t uint256_zero = {{0, 0, 0, 0}};

// 预计算1/2 mod p ((p+1)/2)
__constant__ uint256_t two_inv = {{0x7FFFFFFF7FFFFE18,
                                   0xFFFFFFFFFFFFFFFF,
                                   0xFFFFFFFFFFFFFFFF,
                                   0x7FFFFFFFFFFFFFFF}};

// 函数声明
__device__ int compare_uint256(const uint256_t a, const uint256_t b);
__device__ uint256_t mod_add(uint256_t a, uint256_t b);
__device__ uint256_t mod_sub(uint256_t a, uint256_t b);
__device__ uint256_t mod_mult(uint256_t a, uint256_t b);
__device__ uint256_t mod_inv(uint256_t a);
__device__ uint256_t mod_div2(uint256_t a);

// 大数比较函数
__device__ int compare_uint256(const uint256_t a, const uint256_t b)
{
#pragma unroll
    for (int i = 3; i >= 0; --i) {
        if (a.d[i] > b.d[i]) return 1;
        if (a.d[i] < b.d[i]) return -1;
    }
    return 0;
}

// 模加（优化进位链）
__device__ uint256_t mod_add(uint256_t a, uint256_t b)
{
    uint256_t result;
    uint64_t carry = 0;

#pragma unroll
    for (int i = 0; i < 4; ++i) {
        uint64_t sum = a.d[i] + b.d[i] + carry;
        result.d[i] = sum;
        carry = (sum < a.d[i]) | ((sum == a.d[i]) & carry);
    }

    // 快速约减
    if (carry || compare_uint256(result, p) >= 0) {
        uint64_t borrow = 0;
#pragma unroll
        for (int i = 0; i < 4; ++i) {
            uint64_t temp = result.d[i] - p.d[i] - borrow;
            borrow = (result.d[i] < p.d[i] + borrow);
            result.d[i] = temp;
        }
    }
    return result;
}

// 模减（优化借位链）
__device__ uint256_t mod_sub(uint256_t a, uint256_t b)
{
    uint256_t result;
    uint64_t borrow = 0;

#pragma unroll
    for (int i = 0; i < 4; ++i) {
        uint64_t temp = a.d[i] - b.d[i] - borrow;
        borrow = (a.d[i] < b.d[i] + borrow);
        result.d[i] = temp;
    }
    return borrow ? mod_add(result, p) : result;
}

// 优化蒙哥马利模乘（使用CIOS方法）
__device__ uint256_t mod_mult(uint256_t a, uint256_t b)
{
    uint64_t product[8] = {0};
    const uint64_t np = 0x4B0D7B5618F5A7C5; // p^-1 mod 2^64

// CIOS方法计算
#pragma unroll
    for (int i = 0; i < 4; ++i) {
        uint64_t carry = 0;
#pragma unroll
        for (int j = 0; j < 4; ++j) {
            uint64_t hi = __umul64hi(a.d[j], b.d[i]);
            uint64_t lo = a.d[j] * b.d[i];

            uint64_t sum = lo + product[i + j] + carry;
            product[i + j] = sum;
            carry = hi + (sum < lo || (carry && sum == lo));
        }
        product[i + 4] = carry;
    }

// 蒙哥马利约减
#pragma unroll
    for (int i = 0; i < 4; ++i) {
        uint64_t m = product[i] * np;
        uint64_t carry = 0;
#pragma unroll
        for (int j = 0; j < 4; ++j) {
            uint64_t hi = __umul64hi(m, p.d[j]);
            uint64_t lo = m * p.d[j];

            uint64_t sum = lo + product[i + j] + carry;
            product[i + j] = sum;
            carry = hi + (sum < lo || (carry && sum == lo));
        }
// Propagate carry
#pragma unroll
        for (int j = i + 4; j < 8; ++j) {
            uint64_t sum = product[j] + carry;
            product[j] = sum;
            carry = sum < carry;
        }
    }

    // 最终结果处理
    uint256_t result;
#pragma unroll
    for (int i = 0; i < 4; ++i) {
        result.d[i] = product[i + 4];
    }
    return compare_uint256(result, p) >= 0 ? mod_sub(result, p) : result;
}

// 优化模逆（使用蒙哥马利算法）
__device__ uint256_t mod_inv(uint256_t a)
{
    uint256_t u = a, v = p;
    uint256_t x1 = {{1, 0, 0, 0}}, x2 = {{0, 0, 0, 0}};

    while (compare_uint256(u, uint256_zero) != 0) {
        // 使用预计算的1/2优化除法
        if ((u.d[0] & 1) == 0) {
            u = mod_div2(u);
            x1 = mod_mult(x1, two_inv);
        } else if ((v.d[0] & 1) == 0) {
            v = mod_div2(v);
            x2 = mod_mult(x2, two_inv);
        } else if (compare_uint256(u, v) >= 0) {
            u = mod_sub(u, v);
            u = mod_div2(u);
            x1 = mod_sub(x1, x2);
            x1 = mod_mult(x1, two_inv);
        } else {
            v = mod_sub(v, u);
            v = mod_div2(v);
            x2 = mod_sub(x2, x1);
            x2 = mod_mult(x2, two_inv);
        }
    }
    return x1;
}

// 右移1位（带符号扩展）
__device__ uint256_t mod_div2(uint256_t a)
{
    uint256_t result;
    uint64_t carry = 0;
#pragma unroll
    for (int i = 3; i >= 0; --i) {
        uint64_t val = a.d[i];
        result.d[i] = (val >> 1) | (carry << 63);
        carry = val & 1;
    }
    return result;
}

// 仿射坐标点加法（完全优化版）
__device__ EC_Point ec_add(EC_Point P, EC_Point Q)
{
    if (P.is_infinity) return Q;
    if (Q.is_infinity) return P;

    // 处理相同点的情况（倍点）
    if (compare_uint256(P.x, Q.x) == 0) {
        if (compare_uint256(P.y, Q.y) == 0) {
            // 计算3x² (secp256k1的a=0)
            uint256_t x_sq = mod_mult(P.x, P.x);
            uint256_t three_x_sq = mod_add(mod_add(x_sq, x_sq), x_sq);

            // 计算分母2y
            uint256_t denominator = mod_add(P.y, P.y);

            // 计算斜率λ = (3x²)/(2y)
            uint256_t lambda = mod_mult(three_x_sq, mod_inv(denominator));

            // 计算新坐标
            uint256_t x3 = mod_sub(mod_mult(lambda, lambda), mod_add(P.x, P.x));
            uint256_t y3 = mod_sub(mod_mult(lambda, mod_sub(P.x, x3)), P.y);
            return EC_Point{x3, y3, false};
        } else {
            return EC_Point{uint256_zero, uint256_zero, true}; // 无穷远点
        }
    }

    // 常规点加法
    uint256_t delta_x = mod_sub(Q.x, P.x);
    uint256_t delta_y = mod_sub(Q.y, P.y);

    // 计算斜率λ = Δy/Δx
    uint256_t lambda = mod_mult(delta_y, mod_inv(delta_x));

    // 计算新坐标
    uint256_t x3 = mod_sub(mod_sub(mod_mult(lambda, lambda), P.x), Q.x);
    uint256_t y3 = mod_sub(mod_mult(lambda, mod_sub(P.x, x3)), P.y);

    return EC_Point{x3, y3, false};
}

__global__ void ec_add_kernel(EC_Point* results, const EC_Point* pairs, int num_pairs)
{
    const int idx = blockIdx.x * blockDim.x + threadIdx.x;
    if (idx < num_pairs) {
        // 合并内存访问：连续读取两个点
        const EC_Point P = pairs[2 * idx];
        const EC_Point Q = pairs[2 * idx + 1];
        results[idx] = ec_add(P, Q);
    }
}

// 验证测试用例（使用标准secp256k1测试向量）
void validate_test()
{
    // secp256k1生成点G
    const EC_Point G = {
        // x坐标（小端序）
        {{0x59F2815B16F81798, 0x029BFCDB2DCE28D9,
          0x55A06295CE870B07, 0x79BE667EF9DCBBAC}},
        // y坐标（小端序）
        {{0x9C47D08FFB10D4B8, 0xFD17B448A6855419,
          0x5DA4FBFC0E1108A8, 0x483ADA7726A3C465}},
        false};

    // 预期结果2G
    const EC_Point expected_2G = {
        // x坐标（小端序）
        {{0xabac09b95c709ee5, 0x5c778e4b8cef3ca7,
          0x3045406e95c07cd8, 0xC6047F9441ED7D6D}},
        // y坐标（小端序）
        {{0x236431a950cfe52a, 0xf7f632653266d0e1,
          0xa3c58419466ceaee, 0x1ae168fea63dc339}},
        false};

    // 设备内存分配
    EC_Point *d_pairs, *d_results;
    CHECK_CUDA(cudaMalloc(&d_pairs, 2 * sizeof(EC_Point)));
    CHECK_CUDA(cudaMalloc(&d_results, sizeof(EC_Point)));

    // 准备测试数据
    EC_Point h_pairs[2] = {G, G};
    CHECK_CUDA(cudaMemcpy(d_pairs, h_pairs, 2 * sizeof(EC_Point), cudaMemcpyHostToDevice));

    // 启动核函数
    ec_add_kernel<<<1, 1>>>(d_results, d_pairs, 1);

    // 获取结果
    EC_Point h_result;
    CHECK_CUDA(cudaMemcpy(&h_result, d_results, sizeof(EC_Point), cudaMemcpyDeviceToHost));

    // 验证结果
    bool valid = true;
    for (int i = 0; i < 4; ++i) {
        valid &= (h_result.x.d[i] == expected_2G.x.d[i]);
        valid &= (h_result.y.d[i] == expected_2G.y.d[i]);
    }
    assert(valid);

    // 清理资源
    cudaFree(d_pairs);
    cudaFree(d_results);
}

