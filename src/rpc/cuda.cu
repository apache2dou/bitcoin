#include <cassert>
#include <chrono>
#include <cstdint>
#include <cstdio>
#include <cuda_runtime.h>
#include <vector>
#include <iostream>
#include <cstdio>

// 256-bit数值（小端序，32位肢体）
struct uint256_t {
    uint32_t limb[8];
};

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
struct AffinePoint {
    uint256_t x;
    uint256_t y;
    bool infinity;
};

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

// ================== safegcd 模逆 (移植自 libsecp256k1 的 modinv32_impl.h) ==================
// Bernstein-Yang divsteps 算法: 纯 int32/int64 整数运算, 无 CPU 专有指令, 天然适配 CUDA。
// - 设备端: 常量时间版本 divsteps30 (30 步循环完全无分支, 避免 warp 发散)
// - 主机端: 变量时间版本 divsteps30_var (平均提前退出, 更快)
#if defined(_MSC_VER) && !defined(__CUDA_ARCH__)
#include <intrin.h>
#endif

struct signed30 {
    int32_t v[9];
};

struct trans2x2 {
    int32_t u, v, q, r;
};

struct modinv32_modinfo_s {
    signed30 modulus;
    uint32_t modulus_inv30; // -modulus^-1 mod 2^30
};

// secp256k1 域参数 p = 2^256 - 0x1000003D1 的 signed30 表示 (与库中 secp256k1_const_modinfo_fe 一致)
CONSTANT modinv32_modinfo_s modinfo_p = {
    {{-0x3D1, -4, 0, 0, 0, 0, 0, 0, 65536}},
    0x2DDACACF};

__host__ __device__ static inline uint32_t ctz32(uint32_t x)
{
#if defined(__CUDA_ARCH__)
    /* __ctz 仅 CUDA 12.2+ 提供; __ffs 返回最低置位位(1-based), 所有版本均可用。
       调用处保证 x != 0 (divsteps30_var 的哨兵位使 g|mask 恒非零)。 */
    return (uint32_t)__ffs((int)x) - 1;
#elif defined(_MSC_VER)
    unsigned long i;
    _BitScanForward(&i, x);
    return (uint32_t)i;
#else
    return (uint32_t)__builtin_ctz(x);
#endif
}

// 常量时间版本: 计算 30 个 divsteps 的转移矩阵 (完全无分支, warp 友好)
__host__ __device__ static int32_t divsteps30(int32_t zeta, uint32_t f0, uint32_t g0, trans2x2* t)
{
    uint32_t u = 1, v = 0, q = 0, r = 1;
    uint32_t mask1, mask2, f = f0, g = g0, x, y, z;
    for (int i = 0; i < 30; ++i) {
        mask1 = (uint32_t)(zeta >> 31);
        mask2 = 0u - (g & 1); /* 无符号取负等价写法, 避免 MSVC C4146 */
        x = (f ^ mask1) - mask1;
        y = (u ^ mask1) - mask1;
        z = (v ^ mask1) - mask1;
        g += x & mask2;
        q += y & mask2;
        r += z & mask2;
        mask1 &= mask2;
        zeta = (zeta ^ (int32_t)mask1) - 1;
        f += g & mask1;
        u += q & mask1;
        v += r & mask1;
        g >>= 1;
        u <<= 1;
        v <<= 1;
    }
    t->u = (int32_t)u;
    t->v = (int32_t)v;
    t->q = (int32_t)q;
    t->r = (int32_t)r;
    return zeta;
}

// modinv32_inv256[i] = -(2*i+1)^-1 (mod 256)
static const uint8_t modinv32_inv256[128] = {
    0xFF, 0x55, 0x33, 0x49, 0xC7, 0x5D, 0x3B, 0x11, 0x0F, 0xE5, 0xC3, 0x59,
    0xD7, 0xED, 0xCB, 0x21, 0x1F, 0x75, 0x53, 0x69, 0xE7, 0x7D, 0x5B, 0x31,
    0x2F, 0x05, 0xE3, 0x79, 0xF7, 0x0D, 0xEB, 0x41, 0x3F, 0x95, 0x73, 0x89,
    0x07, 0x9D, 0x7B, 0x51, 0x4F, 0x25, 0x03, 0x99, 0x17, 0x2D, 0x0B, 0x61,
    0x5F, 0xB5, 0x93, 0xA9, 0x27, 0xBD, 0x9B, 0x71, 0x6F, 0x45, 0x23, 0xB9,
    0x37, 0x4D, 0x2B, 0x81, 0x7F, 0xD5, 0xB3, 0xC9, 0x47, 0xDD, 0xBB, 0x91,
    0x8F, 0x65, 0x43, 0xD9, 0x57, 0x6D, 0x4B, 0xA1, 0x9F, 0xF5, 0xD3, 0xE9,
    0x67, 0xFD, 0xDB, 0xB1, 0xAF, 0x85, 0x63, 0xF9, 0x77, 0x8D, 0x6B, 0xC1,
    0xBF, 0x15, 0xF3, 0x09, 0x87, 0x1D, 0xFB, 0xD1, 0xCF, 0xA5, 0x83, 0x19,
    0x97, 0xAD, 0x8B, 0xE1, 0xDF, 0x35, 0x13, 0x29, 0xA7, 0x3D, 0x1B, 0xF1,
    0xEF, 0xC5, 0xA3, 0x39, 0xB7, 0xCD, 0xAB, 0x01
};

// 变量时间版本: 计算 30 个 divsteps 的转移矩阵 (利用 ctz 批量处理除 2 步骤)
__host__ __device__ static int32_t divsteps30_var(int32_t eta, uint32_t f0, uint32_t g0, trans2x2* t)
{
    uint32_t u = 1, v = 0, q = 0, r = 1;
    uint32_t f = f0, g = g0, m;
    uint16_t w;
    int i = 30, limit, zeros;
    for (;;) {
        /* 借助哨兵位, 最多统计到第 i 位 */
        zeros = (int)ctz32(g | (UINT32_MAX << i));
        /* 连续 zeros 个 divsteps 都只是 g 除以 2, 一并完成 */
        g >>= zeros;
        u <<= zeros;
        v <<= zeros;
        eta -= zeros;
        i -= zeros;
        if (i == 0) break;
        /* eta 为负时, 交换 (f,g) 并取相反数 */
        if (eta < 0) {
            uint32_t tmp;
            eta = -eta;
            tmp = f; f = g; g = 0u - tmp; /* 无符号取负等价写法, 避免 MSVC C4146 */
            tmp = u; u = q; q = 0u - tmp;
            tmp = v; v = r; r = 0u - tmp;
        }
        /* 消去 g 的低端比特, 上限为 min(i, eta+1, 8) 位 (查表仅支持 8 位) */
        limit = ((int)eta + 1) > i ? i : ((int)eta + 1);
        m = (UINT32_MAX >> (32 - limit)) & 255U;
        w = (uint16_t)((g * modinv32_inv256[(f >> 1) & 127]) & m);
        g += f * w;
        q += u * w;
        r += v * w;
    }
    t->u = (int32_t)u;
    t->v = (int32_t)v;
    t->q = (int32_t)q;
    t->r = (int32_t)r;
    return eta;
}

// 计算 (t/2^30) * [d, e] mod modulus
__host__ __device__ static void update_de_30(signed30* d, signed30* e, const trans2x2* t, const modinv32_modinfo_s* modinfo)
{
    const int32_t M30 = (int32_t)0x3FFFFFFF;
    const int32_t u = t->u, v = t->v, q = t->q, r = t->r;
    int32_t di, ei, md, me, sd, se;
    int64_t cd, ce;

    /* [md,me] 初始为 0; d 为负时加 [u,q]; e 为负时加 [v,r] */
    sd = d->v[8] >> 31;
    se = e->v[8] >> 31;
    md = (u & sd) + (v & se);
    me = (q & sd) + (r & se);
    /* 开始计算 t*[d,e] */
    di = d->v[0];
    ei = e->v[0];
    cd = (int64_t)u * di + (int64_t)v * ei;
    ce = (int64_t)q * di + (int64_t)r * ei;
    /* 修正 md,me 使 t*[d,e]+modulus*[md,me] 低 30 位为 0 */
    md -= (int32_t)((modinfo->modulus_inv30 * (uint32_t)cd + (uint32_t)md) & (uint32_t)M30);
    me -= (int32_t)((modinfo->modulus_inv30 * (uint32_t)ce + (uint32_t)me) & (uint32_t)M30);
    cd += (int64_t)modinfo->modulus.v[0] * md;
    ce += (int64_t)modinfo->modulus.v[0] * me;
    cd >>= 30;
    ce >>= 30;
    /* 迭代计算 limb i=1..8, 右移 30 位存入输出 limb i-1 */
    for (int i = 1; i < 9; ++i) {
        di = d->v[i];
        ei = e->v[i];
        cd += (int64_t)u * di + (int64_t)v * ei;
        ce += (int64_t)q * di + (int64_t)r * ei;
        cd += (int64_t)modinfo->modulus.v[i] * md;
        ce += (int64_t)modinfo->modulus.v[i] * me;
        d->v[i - 1] = (int32_t)cd & M30; cd >>= 30;
        e->v[i - 1] = (int32_t)ce & M30; ce >>= 30;
    }
    d->v[8] = (int32_t)cd;
    e->v[8] = (int32_t)ce;
}

// 计算 (t/2^30) * [f, g] (固定 9 limbs, 配合常量时间版本)
__host__ __device__ static void update_fg_30(signed30* f, signed30* g, const trans2x2* t)
{
    const int32_t M30 = (int32_t)0x3FFFFFFF;
    const int32_t u = t->u, v = t->v, q = t->q, r = t->r;
    int32_t fi, gi;
    int64_t cf, cg;

    fi = f->v[0];
    gi = g->v[0];
    cf = (int64_t)u * fi + (int64_t)v * gi;
    cg = (int64_t)q * fi + (int64_t)r * gi;
    cf >>= 30;
    cg >>= 30;
    for (int i = 1; i < 9; ++i) {
        fi = f->v[i];
        gi = g->v[i];
        cf += (int64_t)u * fi + (int64_t)v * gi;
        cg += (int64_t)q * fi + (int64_t)r * gi;
        f->v[i - 1] = (int32_t)cf & M30; cf >>= 30;
        g->v[i - 1] = (int32_t)cg & M30; cg >>= 30;
    }
    f->v[8] = (int32_t)cf;
    g->v[8] = (int32_t)cg;
}

// 计算 (t/2^30) * [f, g] (变长 limbs, 配合变量时间版本)
__host__ __device__ static void update_fg_30_var(int len, signed30* f, signed30* g, const trans2x2* t)
{
    const int32_t M30 = (int32_t)0x3FFFFFFF;
    const int32_t u = t->u, v = t->v, q = t->q, r = t->r;
    int32_t fi, gi;
    int64_t cf, cg;

    fi = f->v[0];
    gi = g->v[0];
    cf = (int64_t)u * fi + (int64_t)v * gi;
    cg = (int64_t)q * fi + (int64_t)r * gi;
    cf >>= 30;
    cg >>= 30;
    for (int i = 1; i < len; ++i) {
        fi = f->v[i];
        gi = g->v[i];
        cf += (int64_t)u * fi + (int64_t)v * gi;
        cg += (int64_t)q * fi + (int64_t)r * gi;
        f->v[i - 1] = (int32_t)cf & M30; cf >>= 30;
        g->v[i - 1] = (int32_t)cg & M30; cg >>= 30;
    }
    f->v[len - 1] = (int32_t)cf;
    g->v[len - 1] = (int32_t)cg;
}

// 将 (-2*modulus, modulus) 范围的输入规格化到 [0, modulus), sign<0 时先取反
__host__ __device__ static void normalize_30(signed30* r, int32_t sign, const modinv32_modinfo_s* modinfo)
{
    const int32_t M30 = (int32_t)0x3FFFFFFF;
    int32_t r0 = r->v[0], r1 = r->v[1], r2 = r->v[2], r3 = r->v[3], r4 = r->v[4],
            r5 = r->v[5], r6 = r->v[6], r7 = r->v[7], r8 = r->v[8];
    int32_t cond_add, cond_negate;

    /* 负数时先加 modulus, 再按需取反 */
    cond_add = r8 >> 31;
    r0 += modinfo->modulus.v[0] & cond_add;
    r1 += modinfo->modulus.v[1] & cond_add;
    r2 += modinfo->modulus.v[2] & cond_add;
    r3 += modinfo->modulus.v[3] & cond_add;
    r4 += modinfo->modulus.v[4] & cond_add;
    r5 += modinfo->modulus.v[5] & cond_add;
    r6 += modinfo->modulus.v[6] & cond_add;
    r7 += modinfo->modulus.v[7] & cond_add;
    r8 += modinfo->modulus.v[8] & cond_add;
    cond_negate = sign >> 31;
    r0 = (r0 ^ cond_negate) - cond_negate;
    r1 = (r1 ^ cond_negate) - cond_negate;
    r2 = (r2 ^ cond_negate) - cond_negate;
    r3 = (r3 ^ cond_negate) - cond_negate;
    r4 = (r4 ^ cond_negate) - cond_negate;
    r5 = (r5 ^ cond_negate) - cond_negate;
    r6 = (r6 ^ cond_negate) - cond_negate;
    r7 = (r7 ^ cond_negate) - cond_negate;
    r8 = (r8 ^ cond_negate) - cond_negate;
    /* 进位传播, 使各 limb 回到 (-2^30, 2^30) */
    r1 += r0 >> 30; r0 &= M30;
    r2 += r1 >> 30; r1 &= M30;
    r3 += r2 >> 30; r2 &= M30;
    r4 += r3 >> 30; r3 &= M30;
    r5 += r4 >> 30; r4 &= M30;
    r6 += r5 >> 30; r5 &= M30;
    r7 += r6 >> 30; r6 &= M30;
    r8 += r7 >> 30; r7 &= M30;

    /* 仍为负则再加一次 modulus */
    cond_add = r8 >> 31;
    r0 += modinfo->modulus.v[0] & cond_add;
    r1 += modinfo->modulus.v[1] & cond_add;
    r2 += modinfo->modulus.v[2] & cond_add;
    r3 += modinfo->modulus.v[3] & cond_add;
    r4 += modinfo->modulus.v[4] & cond_add;
    r5 += modinfo->modulus.v[5] & cond_add;
    r6 += modinfo->modulus.v[6] & cond_add;
    r7 += modinfo->modulus.v[7] & cond_add;
    r8 += modinfo->modulus.v[8] & cond_add;
    r1 += r0 >> 30; r0 &= M30;
    r2 += r1 >> 30; r1 &= M30;
    r3 += r2 >> 30; r2 &= M30;
    r4 += r3 >> 30; r3 &= M30;
    r5 += r4 >> 30; r4 &= M30;
    r6 += r5 >> 30; r5 &= M30;
    r7 += r6 >> 30; r6 &= M30;
    r8 += r7 >> 30; r7 &= M30;

    r->v[0] = r0;
    r->v[1] = r1;
    r->v[2] = r2;
    r->v[3] = r3;
    r->v[4] = r4;
    r->v[5] = r5;
    r->v[6] = r6;
    r->v[7] = r7;
    r->v[8] = r8;
}

// 常量时间版本: 固定 20 轮 x 30 divsteps (590 步对 256 位输入已足够)
__host__ __device__ static void modinv32(signed30* x, const modinv32_modinfo_s* modinfo)
{
    signed30 d = {{0, 0, 0, 0, 0, 0, 0, 0, 0}};
    signed30 e = {{1, 0, 0, 0, 0, 0, 0, 0, 0}};
    signed30 f = modinfo->modulus;
    signed30 g = *x;
    int32_t zeta = -1;

    for (int i = 0; i < 20; ++i) {
        trans2x2 t;
        zeta = divsteps30(zeta, (uint32_t)f.v[0], (uint32_t)g.v[0], &t);
        update_de_30(&d, &e, &t, modinfo);
        update_fg_30(&f, &g, &t);
    }
    normalize_30(&d, f.v[8], modinfo);
    *x = d;
}

// 变量时间版本: 平均约 11 轮即可收敛
__host__ __device__ static void modinv32_var(signed30* x, const modinv32_modinfo_s* modinfo)
{
    signed30 d = {{0, 0, 0, 0, 0, 0, 0, 0, 0}};
    signed30 e = {{1, 0, 0, 0, 0, 0, 0, 0, 0}};
    signed30 f = modinfo->modulus;
    signed30 g = *x;
    int j, len = 9;
    int32_t eta = -1;
    int32_t cond, fn, gn;

    for (;;) {
        trans2x2 t;
        eta = divsteps30_var(eta, (uint32_t)f.v[0], (uint32_t)g.v[0], &t);
        update_de_30(&d, &e, &t, modinfo);
        update_fg_30_var(len, &f, &g, &t);
        /* g 最低 limb 为 0 时, 检查是否整个 g 为 0 (收敛) */
        if (g.v[0] == 0) {
            cond = 0;
            for (j = 1; j < len; ++j) {
                cond |= g.v[j];
            }
            if (cond == 0) break;
        }
        /* 最高 limb 为 0 或 -1 时缩短长度, 符号位并入下一 limb */
        fn = f.v[len - 1];
        gn = g.v[len - 1];
        cond = ((int32_t)len - 2) >> 31;
        cond |= fn ^ (fn >> 31);
        cond |= gn ^ (gn >> 31);
        if (cond == 0) {
            f.v[len - 2] |= (uint32_t)fn << 30;
            g.v[len - 2] |= (uint32_t)gn << 30;
            --len;
        }
    }
    normalize_30(&d, f.v[len - 1], modinfo);
    *x = d;
}

// 设备端走常量时间版本(无分支、warp 友好), 主机端走变量时间版本(平均更快)
__host__ __device__ static void modinv32_auto(signed30* x, const modinv32_modinfo_s* modinfo)
{
#ifdef __CUDA_ARCH__
    modinv32(x, modinfo);
#else
    modinv32_var(x, modinfo);
#endif
}

// uint256 (8x32 limbs) -> signed30 (9x30 limbs), 输入须为非负且 < 2^256
__host__ __device__ static void u256_to_s30(signed30* r, const uint256_t& a)
{
    uint32_t w[9];
    for (int i = 0; i < 8; ++i)
        w[i] = a.limb[i];
    w[8] = 0;
    int bit = 0;
    for (int i = 0; i < 9; ++i) {
        int wi = bit >> 5, off = bit & 31;
        uint32_t lo = w[wi] >> off;
        uint32_t hi = off ? (w[wi + 1] << (32 - off)) : 0;
        r->v[i] = (int32_t)((lo | hi) & 0x3FFFFFFF);
        bit += 30;
    }
}

// signed30 -> uint256, 输入须为非负规格化值 (< p)
__host__ __device__ static void s30_to_u256(uint256_t* r, const signed30* a)
{
    uint64_t acc = 0;
    int bits = 0, oi = 0;
    for (int i = 0; i < 9; ++i) {
        acc |= (uint64_t)(uint32_t)a->v[i] << bits;
        bits += 30;
        while (bits >= 32) {
            r->limb[oi++] = (uint32_t)acc;
            acc >>= 32;
            bits -= 32;
        }
    }
    if (oi < 8) {
        r->limb[oi++] = (uint32_t)acc;
    }
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
// 蒙哥马利域中的逆元计算 (safegcd/divsteps 版本, 移植自 libsecp256k1)
// modinv32 与 mod_inv 一样, 只把输入当作普通整数求逆, 不感知蒙哥马利域:
//   inv = (a*R)^-1 = a^-1 * R^-1
//   mont_mul(inv, R^3) = a^-1 * R^-1 * R^3 * R^-1 = a^-1 * R  (即 a^-1 的蒙哥马利形式)
// 故无需先转回普通域, 与 mont_inv2_euclid 保持同一形式。
__host__ __device__ uint256_t mont_inv2(const uint256_t& a_mont)
{
    signed30 s;
    u256_to_s30(&s, a_mont);
    modinv32_auto(&s, &modinfo_p);
    uint256_t inv;
    s30_to_u256(&inv, &s);
    return mont_mul(inv, R_cube);
}

// 旧版: 扩展欧几里得模逆 (保留用于 A/B 对比)
__host__ __device__ uint256_t mont_inv2_euclid(const uint256_t& a_mont)
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


constexpr size_t dp_buffer_size = 110; // DP 缓冲区大小
__constant__ RhoPoint_mont RhoStates_rand[dp_buffer_size];

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

// 设备端 DP 缓冲区管理
__device__ DpBuffer* dp_device_buffer = nullptr; // 设备缓冲区指针
__device__ unsigned int dp_buffer_count = 0;     // 缓冲区当前计数
__device__ volatile bool* break_flag_dev = nullptr;
bool* break_flag_host = nullptr;                // 主机端指针
extern bool gameover;


RhoPoint_mont* RhoStates_host = nullptr;
__device__ RhoPoint_mont* RhoStates_dev = nullptr;

// 添加 DP 到缓冲区 (设备端)
__device__ void add_dp_to_buffer(uint64_t d, RhoPoint_mont& r,
                                 DpBuffer* buffer, unsigned int max_size)
{
    // 原子递增获取缓冲区位置
    unsigned int index = atomicAdd(&dp_buffer_count, 1);

    /* if (index < max_size)*/ {
        buffer[index].d = d;
        transfer(buffer[index].sp.m , (const unsigned char*)&r.m);
        transfer(buffer[index].sp.n, (const unsigned char*)&r.n);
    }

    r = RhoStates_rand[index];

    if (dp_buffer_count >= max_size)
        *break_flag_dev = true;
}

// 初始化break_flag内存
void init_break_flag()
{
    // 分配页锁定内存（主机可访问）
    CHECK_CUDA(cudaHostAlloc((void**)&break_flag_host,
                             sizeof(bool),
                             cudaHostAllocMapped));

    // 获取设备可访问的指针
    bool* device_ptr = nullptr;
    CHECK_CUDA(cudaHostGetDevicePointer((void**)&device_ptr,
                                        break_flag_host,
                                        0));

    // 设置初始值
    *break_flag_host = false;

    // 将设备指针复制到设备全局变量
    CHECK_CUDA(cudaMemcpyToSymbol(break_flag_dev,
                                  &device_ptr,
                                  sizeof(volatile bool*)));
}

// 释放break_flag内存
void free_break_flag()
{
    if (break_flag_host) {
        CHECK_CUDA(cudaFreeHost(break_flag_host));
        break_flag_host = nullptr;
    }
}

void break_rho(bool value)
{
    if (break_flag_host) {
        *break_flag_host = value;
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


__global__ void rho()
{
    // 获取全局线程索引
    int idx = blockIdx.x * blockDim.x + threadIdx.x;
    RhoPoint_mont s = RhoStates_dev[idx];
    uint256_t x_ord = from_mont(s.x.x);
    uint64_t count_rho = 0;
    uint32_t count_dp = 0;
    /*
    // 设备共享内存存储 adds_pub
    __shared__ RhoPoint_mont adds_pub[256];
    // 共享内存产生的优化微乎其微， 2% 左右，但会多占用10个寄存器。
    // 从全局内存复制adds_pub到共享内存
    if (threadIdx.x == 0) {
        for (int i = 0; i < 256; i++)
            adds_pub[i] = adds_pub_dev[i];
    }
    __syncthreads(); // 确保所有线程已完成加载
    */
    while (true) {
        fun_add(s, adds_pub_dev[(unsigned char)x_ord.limb[0]]);
        count_rho++;
        // 检查是否可区分
        x_ord = from_mont(s.x.x);
        uint64_t d = distinguishable(x_ord);
        if (d != 0) {
            count_dp++;
            // 保存可区分点
            add_dp_to_buffer(d, s, dp_device_buffer, dp_buffer_size - 10);
            x_ord = from_mont(s.x.x);
        }
        if ((count_rho & 0x3FFFF) == 0) {
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
    cudaDeviceProp prop;
    CHECK_CUDA(cudaGetDeviceProperties(&prop, 0));

    // 根据GPU架构特性选择最佳线程数
    // 每个流处理器(SM)的 CUDA 核心数，参考 CUDA Samples 的 deviceQuery
    int coresPerSM;
    int multiple; // 每核心线程数：2 = 优先单线程速度；4 优先总吞吐
    switch (g_run_mode) {
    case 2: multiple = 1; break; // 模式2：每核心1线程，最快单线程速度
    case 4: multiple = 2; break; // 模式4走 occupancy 路径，此值不生效
    case 3:                        // 模式3（默认）
    default: multiple = 2; break; // 模式3：每核心2线程
    }
    switch (prop.major) {
    case 2: // Fermi
        coresPerSM = (prop.minor == 1) ? 48 : 32;
        break;
    case 3: // Kepler
        coresPerSM = 192;
        break;
    case 5: // Maxwell
        coresPerSM = 128;
        break;
    case 6: // Pascal: 6.0(GTX 10 以下/P100)=64, 6.1/6.2(GTX 10 系)=128
        coresPerSM = (prop.minor == 0) ? 64 : 128;
        break;
    case 7: // Volta(7.0/7.2)/Turing(7.5)
        coresPerSM = 64;
        break;
    case 8: // Ampere: 8.0(A100)=64, 8.6(RTX 30)/8.7(Orin)/8.9(Ada RTX 40)=128
        coresPerSM = (prop.minor == 0) ? 64 : 128;
        break;
    case 9: // Hopper
        coresPerSM = 128;
        break;
    case 10: // Blackwell
    case 12:
        coresPerSM = 128;
        break;
    default: // 未知架构，按当前主流估计
        coresPerSM = 128;
    }
    // 确保不超过硬件限制，且为 warp(32) 整数倍
    block_size = std::min(coresPerSM * multiple, (int)prop.maxThreadsPerBlock);
    block_size -= block_size % 32;
    if (block_size < 32) block_size = 32;
    multiProcessorCount = prop.multiProcessorCount;
    if (g_run_mode == 4) {
        // 模式4：使用 occupancy API 计算的 blockSize / gridSize
        CHECK_CUDA(cudaOccupancyMaxPotentialBlockSize(
            &multiProcessorCount,
            &block_size,
            rho,
            0, // 无动态共享内存
            0  // 线程块大小上限
            ));
    }
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

void init_RhoStates_rand() {
    for (int i = 0; i < sizeof(RhoStates_rand) / sizeof(RhoPoint_mont); i++) {
        RhoPoint_mont t;
        RhoPoint r;
        r.rand();
        t.from(r);
        CHECK_CUDA(cudaMemcpyToSymbol(RhoStates_rand, &t, sizeof(RhoPoint_mont), sizeof(RhoPoint_mont) * i, cudaMemcpyHostToDevice));
    }
}

static const std::string _RSFile2_name = "D:\\RhoState2.txt";
int loadRhoState(RhoState* s, int num, const std::string& name);
bool saveRhoState(const RhoState* s, int num, const std::string& name);

void init_RhoStates_dev(int total_points, const std::string& name)
{
    //分配设备内存并复制初始状态
    CHECK_CUDA(cudaMalloc(&RhoStates_host, total_points * sizeof(RhoPoint_mont)));
    CHECK_CUDA(cudaMemcpyToSymbol(RhoStates_dev, &RhoStates_host, sizeof(RhoPoint_mont*)));
    std::vector<RhoState> rsv;
    rsv.resize(total_points);
    int num = loadRhoState(rsv.data(), total_points, name);
    for (int i = 0; i < total_points; i++) {
        RhoPoint_mont t;
        if (i < num) {
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
    // 初始化break_flag
    init_break_flag();
    while (!gameover) {
        break_rho(false);
        init_RhoStates_rand();
        rho<<<multiProcessorCount, blockSize>>>();
        // 等待核函数完成
        CHECK_CUDA(cudaDeviceSynchronize());
        dp_manager.save_dps();
        save_RhoStates_dev(total_points, _RSFile2_name);
    }
    // 清理资源
    free_break_flag();
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

__global__ void validate_safegcd()
{
    // 测试 safegcd 模逆与旧欧几里得实现一致性
    uint256_t probe[4] = {
        {{0x5F8E52C7, 0xD3A21B04, 0x9C56B9AF, 0x6E1F3D82, 0x2A8C77D1, 0xB4E09F63, 0x1D5AC7E8, 0x7F3B29A0}},
        {{0x00000001, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000}},
        {{0xFFFFFC2E, 0xFFFFFFFE, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF}}, // p-1
        {{0x12345678, 0x9ABCDEF0, 0x0FEDCBA9, 0x87765432, 0x1A2B3C4D, 0x5E6F7081, 0x92A3B4C5, 0xD6E7F809}},
    };
    for (int i = 0; i < 4; ++i) {
        uint256_t m1 = mont_inv2(probe[i]);
        uint256_t m2 = mont_inv2_euclid(probe[i]);
        assert(memcmp(&m1, &m2, sizeof(uint256_t)) == 0); // 与旧实现结果一致

        // 直接验证: mont_mul(m1, to_mont(a)) 应等于 to_mont(1), 即 a * a^-1 == 1 (mod p)
        uint256_t one = {1};
        uint256_t a_ord = mont_mul(probe[i], one); // 转普通域
        uint256_t expect_one_mont = to_mont(one);
        uint256_t got = mont_mul(m1, to_mont(a_ord));
        assert(memcmp(&got, &expect_one_mont, sizeof(uint256_t)) == 0);
    }
}

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
    const auto start = std::chrono::steady_clock::now();
    uint64_t count_rho = perf_fun(s, adds_pub_tmp);
    const auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now() - start);
    double sec = elapsed.count() / 1000.0;
    std::cout << "cpu test elapsed: " << elapsed.count() << " ms, with " << count_rho
              << " RhoPoint, avg " << (uint64_t)(count_rho / sec) << " points/s." << std::endl;
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
    cudaEvent_t start;
    cudaEvent_t stop;
    CHECK_CUDA(cudaEventCreate(&start));
    CHECK_CUDA(cudaEventCreate(&stop));
    CHECK_CUDA(cudaEventRecord(start));
    perf_test_gpu_kernel<<<1, 1>>>();
    CHECK_CUDA(cudaEventRecord(stop));
    CHECK_CUDA(cudaEventSynchronize(stop));
    CHECK_CUDA(cudaDeviceSynchronize());
    float elapsed_ms = 0.0f;
    CHECK_CUDA(cudaEventElapsedTime(&elapsed_ms, start, stop));
    CHECK_CUDA(cudaEventDestroy(start));
    CHECK_CUDA(cudaEventDestroy(stop));
    double sec = elapsed_ms / 1000.0;
    std::cout << "gpu test elapsed: " << elapsed_ms << " ms, with 800000 RhoPoint, avg "
              << (uint64_t)(800000 / sec) << " points/s." << std::endl;
}

void perf_test() {
    // 性能测试
    init_adds_pub_dev();
    perf_test_cpu();
    perf_test_libsecp256k1();
    perf_test_rho_affine();
    perf_test_gpu();
}

void validate_test()
{
    init_RhoStates_test(RHOSTATES_TEST_NUM + 1);
    init_adds_pub_dev();
    init_break_flag();
    DpManager dp_manager(RHODP_TEST_NUM + 10);
       
    validate_multi<<<10, 256>>>();
    CHECK_CUDA(cudaDeviceSynchronize());
    validate_safegcd<<<1, 1>>>();
    CHECK_CUDA(cudaDeviceSynchronize());
    validate_1<<<1, 1>>>();
    CHECK_CUDA(cudaDeviceSynchronize());

    // 仿射点加 (libsecp256k1 内部 5x52 域实现) 的正确性验证
    validate_rho_affine();

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
