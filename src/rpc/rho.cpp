// rho.cpp
//
// 本文件包含两部分:
//
//   1) perf_fun_lib / perf_test_libsecp256k1
//      使用 libsecp256k1 的【公开 API】(secp256k1_ec_pubkey_combine +
//      secp256k1_ec_seckey_tweak_add) 做点加的性能基准, 与 cuda.cu 中的
//      perf_test_cpu / perf_test_gpu 对照。
//
//   2) rho_affine_add / rho_affine_step / perf_test_rho_affine
//      直接使用 libsecp256k1【内部】的 5x52 域实现 (field_impl.h) 手写的
//      "干净" 仿射点加。与公开 API 路径相比, 它去掉了:
//        - ge_storage(64B) <-> 5x52 的序列化往返
//        - 常量时间的退化处理 (fe_half / cmov / 多次 negate)
//        - m/n 标量的 大端 <-> 肢体 转换与清零
//        - pubkey_combine 从无穷远点开始的第一次冗余点加
//      并且每一步只做 3 次域乘 + 1 次 modinv64_var, 这正是 rho 随机游走的
//      最小工作量。
//
// 说明: libsecp256k1 内部头文件里的所有函数都是 static/inline, 会被直接内联
//       进本翻译单元, 不会与已链接的 libsecp256k1 静态库产生符号冲突。
#include "common.h"

#include <cassert>
#include <chrono>
#include <cstdint>
#include <cstring>
#include <iostream>

// ---------------------------------------------------------------------------
// libsecp256k1 内部实现 (C++ 兼容包装)
//
// 包含顺序有讲究: int128 的具体实现必须早于 field, 因为
// field_5x52_impl.h -> field_5x52_int128_impl.h 会调用 secp256k1_u128_*。
//
// 但 secp256k1/src/util.h 是纯 C 头文件, 其中
//
//     static SECP256K1_INLINE int secp256k1_memcmp_var(const void *s1, ...) {
//         const unsigned char *p1 = s1, *p2 = s2;   // C 合法, C++ 报 C2440
//
// 在 C++ 下无法编译, 而本项目约定不改动 secp256k1/。
//
// 解决办法: 先定义 util.h 的 include guard, 让真正的 util.h 被跳过; 然后在
// 本文件里补齐 "5x52 域运算 + 128 位乘法 + modinv64" 这条包含链真正用到的
// 定义。语义与 util.h 完全一致, 只把隐式的 void* -> unsigned char* 转换写成
// 显式转换。将来上游 util.h 变成 C++ 友好后, 删掉本段并把
// "#include "../secp256k1/src/util.h"" 加回来即可。
// ---------------------------------------------------------------------------
#include "../secp256k1/include/secp256k1.h"   // SECP256K1_GNUC_PREREQ 等
#include <cstdint>
#include <cstdlib>
#include <climits>

#define SECP256K1_UTIL_H  /* 让 secp256k1/src/util.h 失效 */

#ifndef __has_builtin
#define __has_builtin(x) 0
#endif

#define SECP256K1_INLINE inline

#if SECP256K1_GNUC_PREREQ(3, 0)
#define EXPECT(x,c) __builtin_expect((x),(c))
#else
#define EXPECT(x,c) (x)
#endif

#if defined(VERIFY)
#define CHECK(cond) do { if (EXPECT(!(cond), 0)) { std::abort(); } } while(0)
#define VERIFY_CHECK CHECK
#else
#define VERIFY_CHECK(cond)
#endif

/** 静态断言, 只能在函数内使用 (util.h 同名宏)。 */
#define STATIC_ASSERT(expr) do { \
    switch(0) { \
        case 0: \
        case (expr): \
        ; \
    } \
} while(0)

/** 断言 expr 是整型常量表达式后执行 stmt; field.h 的 fe_negate/fe_mul_int 依赖它。 */
#define ASSERT_INT_CONST_AND_DO(expr, stmt) do { \
    switch(42) { \
        case (expr): \
            break; \
        default: ; \
    } \
    stmt; \
} while(0)

#if defined(__BIGGEST_ALIGNMENT__)
#define ALIGNMENT __BIGGEST_ALIGNMENT__
#else
#define ALIGNMENT 16
#endif
#define CEIL_DIV(x, y) (1 + ((x) - 1) / (y))
#define ROUND_TO_ALIGN(size) (CEIL_DIV(size, ALIGNMENT) * ALIGNMENT)

#if defined(SECP256K1_BUILD) && defined(VERIFY)
# define SECP256K1_RESTRICT
#elif defined(_MSC_VER)
# define SECP256K1_RESTRICT __restrict
#elif defined(__GNUC__)
# define SECP256K1_RESTRICT __restrict__
#else
# define SECP256K1_RESTRICT
#endif

#if defined(__GNUC__)
# define SECP256K1_GNUC_EXT __extension__
#else
# define SECP256K1_GNUC_EXT
#endif

/* 与 util.h 相同的 WIDEMUL / int128 实现选择, 必须早于 int128.h。 */
#if defined(USE_FORCE_WIDEMUL_INT128_STRUCT)
# define SECP256K1_WIDEMUL_INT128 1
# define SECP256K1_INT128_STRUCT 1
#elif defined(USE_FORCE_WIDEMUL_INT128)
# define SECP256K1_WIDEMUL_INT128 1
# define SECP256K1_INT128_NATIVE 1
#elif defined(USE_FORCE_WIDEMUL_INT64)
# define SECP256K1_WIDEMUL_INT64 1
#elif defined(UINT128_MAX) || defined(__SIZEOF_INT128__)
# define SECP256K1_WIDEMUL_INT128 1
# define SECP256K1_INT128_NATIVE 1
#elif defined(_MSC_VER) && (defined(_M_X64) || defined(_M_ARM64))
# define SECP256K1_WIDEMUL_INT128 1
# define SECP256K1_INT128_STRUCT 1
#elif SIZE_MAX > 0xffffffff
# define SECP256K1_WIDEMUL_INT128 1
# define SECP256K1_INT128_STRUCT 1
#else
# define SECP256K1_WIDEMUL_INT64 1
#endif

/* 尾部零计数 (modinv64 需要)。MSVC 没有 __builtin_ctz*, 用内建指令。 */
#if defined(_MSC_VER)
#include <intrin.h>
static SECP256K1_INLINE int secp256k1_ctz32_var(uint32_t x) {
    unsigned long i = 0;
    _BitScanForward(&i, x);
    return (int)i;
}
static SECP256K1_INLINE int secp256k1_ctz64_var(uint64_t x) {
    unsigned long i = 0;
#if defined(_M_X64) || defined(_M_ARM64)
    _BitScanForward64(&i, x);
#else
    if ((uint32_t)x != 0) {
        _BitScanForward(&i, (uint32_t)x);
    } else {
        _BitScanForward(&i, (uint32_t)(x >> 32));
        i += 32;
    }
#endif
    return (int)i;
}
#else
static SECP256K1_INLINE int secp256k1_ctz32_var(uint32_t x) { return __builtin_ctz((unsigned)x); }
static SECP256K1_INLINE int secp256k1_ctz64_var(uint64_t x) { return __builtin_ctzll(x); }
#endif

/* 以下三个与 util.h 语义相同, 唯一的差别就是补上了显式转换 —— C2440 的修正处。 */
static SECP256K1_INLINE void secp256k1_memczero(void *s, size_t len, int flag) {
    unsigned char *p = (unsigned char *)s;
    volatile int vflag = flag;
    unsigned char mask = (unsigned char)(0 - (unsigned)vflag);
    while (len) {
        *p &= (unsigned char)~mask;
        p++;
        len--;
    }
}

static SECP256K1_INLINE int secp256k1_memcmp_var(const void *s1, const void *s2, size_t n) {
    const unsigned char *p1 = (const unsigned char *)s1, *p2 = (const unsigned char *)s2;
    size_t i;
    for (i = 0; i < n; i++) {
        int diff = p1[i] - p2[i];
        if (diff != 0) {
            return diff;
        }
    }
    return 0;
}

static SECP256K1_INLINE void secp256k1_int_cmov(int *r, const int *a, int flag) {
    unsigned int mask0, mask1, r_masked, a_masked;
    volatile int vflag = flag;
    VERIFY_CHECK(*r >= 0 && *a >= 0);
    mask0 = (unsigned int)vflag + ~0u;
    mask1 = ~mask0;
    r_masked = ((unsigned int)*r & mask0);
    a_masked = ((unsigned int)*a & mask1);
    *r = (int)(r_masked | a_masked);
}

// ---------------------------------------------------------------------------
// modinv64_impl.h:188 有 "mask2 = -c2;" (c2 为 volatile uint64_t)。MSVC 报
// C4146 "一元负运算符应用于无符号类型"。该写法在 C/C++ 中是良定义的 (按 2^64
// 取模), 是 secp256k1 有意为之的条件掩码技法, 不是 bug。
// modinv64_impl.h 由 field_5x52_impl.h 间接包含, 无法单独包一层 pragma,
// 所以这里把整段 "私有头包含" 都圈进抑制区。只屏蔽 4146, 且 push/pop 保证
// 出了本段立刻恢复, 不影响本工程其它代码。
// ---------------------------------------------------------------------------
#if defined(_MSC_VER)
#pragma warning(push)
#pragma warning(disable : 4146)
#endif

#include "../secp256k1/src/int128_impl.h"
#include "../secp256k1/src/field.h"
#include "../secp256k1/src/field_impl.h"

#if defined(_MSC_VER)
#pragma warning(pop)
#endif

// 由 rpc/blockchain.cpp 定义
extern secp256k1_context* ctx;
extern RhoPoint adds_pub[2][256];

// libsecp256k1 版本的点加测试循环: 与 cuda.cu 中 perf_fun 结构一致(80w 次点加 + DP 判定)
// 点加使用 secp256k1_ec_pubkey_combine + seckey tweak, 与 blockchain.cpp 中 rho_F/fun_add 完全一致
static uint64_t perf_fun_lib(RhoState& s, uint64_t iters)
{
    uint64_t count_rho = 0;
    uint32_t count_dp = 0;
    while (count_rho < iters) {
        // 与 rho_F 一致: 以 x 坐标首字节作为加数下标
        unsigned char t = s.x.data[0];
        secp256k1_pubkey pk = s.x;
        secp256k1_pubkey* ins[2] = {&pk, &adds_pub[0][t].x};
        int r = secp256k1_ec_pubkey_combine(ctx, &s.x, ins, 2);
        assert(r == 1);
        r = secp256k1_ec_seckey_tweak_add(ctx, s.m, adds_pub[0][t].m);
        assert(r == 1);
        r = secp256k1_ec_seckey_tweak_add(ctx, s.n, adds_pub[0][t].n);
        assert(r == 1);
        (void)r;
        count_rho++;

        // DP 判定: 对应设备端 distinguishable(x 低 32 位为 0 时取 bit32..95)
        // x 以 ge_storage 形式存放(5x52), 故:
        //   x mod 2^32        = n0 的低 32 位
        //   x 的 bit 64..95   = n1 的 bit 12..43
        uint64_t n0 = 0, n1 = 0;
        memcpy(&n0, s.x.data, sizeof(n0));
        memcpy(&n1, s.x.data + sizeof(n0), sizeof(n1));
        uint64_t d = 0;
        if ((uint32_t)n0 == 0) {
            d = (uint64_t)(uint32_t)(n0 >> 32) | ((uint64_t)(uint32_t)(n1 >> 12) << 32);
        }
        if (d != 0) {
            count_dp++;
        }
    }
    return count_rho;
}

void perf_test_libsecp256k1()
{
    RhoState s;
    s.x = adds_pub[0][0].x;
    memcpy(s.m, adds_pub[0][0].m, sizeof(s.m));
    memcpy(s.n, adds_pub[0][0].n, sizeof(s.n));
    s.times = 0;

    const auto start = std::chrono::steady_clock::now();
    uint64_t count_rho = perf_fun_lib(s, 800000);
    const auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now() - start);
    double sec = elapsed.count() / 1000.0;
    std::cout << "libsecp256k1 test elapsed: " << elapsed.count() << " ms, with " << count_rho
              << " RhoPoint, avg " << (uint64_t)(count_rho / sec) << " points/s." << std::endl;
}

// ===========================================================================
// 第二部分: 基于 libsecp256k1 内部 5x52 域运算的 "干净" 仿射点加
//
// 支持数据:
//   secp256k1_fe        : 5 x uint64_t, 基 2^52, 值 = sum(n[i] << (52*i)) mod p
//                         每步结束后 X 全规约(X < p), Y 只做 normalize_weak
//   secp256k1_fe_add    : 只做加法, 同时把 magnitude 累加 (VERIFY 模式下会断言)
//   secp256k1_fe_mul/sqr: 要求两个输入的 magnitude <= 8, 结果 magnitude = 1
//   secp256k1_fe_inv_var: 内部先 normalize_var 再走 modinv64_var, 结果 magnitude = 1
// 因此下面所有中间量的 magnitude 都控制在 8 以内。
// ===========================================================================
namespace {

// secp256k1_ge_storage 的等价布局 (这里没有包含 group.h, 按其公开定义自建)
struct RhoGeStorage {
    secp256k1_fe_storage x;
    secp256k1_fe_storage y;
};
static_assert(sizeof(secp256k1_fe_storage) == 32, "fe_storage 应为 4 个 64 位肢体");
static_assert(sizeof(RhoGeStorage) == 64, "ge_storage 应为 64 字节");

// secp256k1 群阶 N 的 4 x uint64_t 小端肢体
const uint64_t kOrderN[4] = {
    0xBFD25E8CD0364141ULL, 0xBAAEDCE6AF48A03BULL,
    0xFFFFFFFFFFFFFFFEULL, 0xFFFFFFFFFFFFFFFFULL};

// a < b (4 x uint64_t 小端)
inline bool lt256(const uint64_t* a, const uint64_t* b)
{
    for (int i = 3; i >= 0; --i) {
        if (a[i] != b[i]) return a[i] < b[i];
    }
    return false;
}

// r = (r + a) mod N; r, a 均为 < N 的 4 x uint64_t 小端肢体
inline void add_mod_N(uint64_t* r, const uint64_t* a)
{
    uint64_t t[4];
    uint64_t carry = 0;
    for (int i = 0; i < 4; ++i) {
        const uint64_t s = r[i] + a[i];
        const uint64_t c1 = (s < r[i]);
        const uint64_t s2 = s + carry;
        t[i] = s2;
        carry = c1 | (s2 < s);
    }
    // carry == 1 时 t = r + a - 2^256 (截断); 因为 r, a < N 且 r + a < 2N < 2^257,
    // 所以此时 t - N 的环绕结果恰好等于 r + a - N。
    if (carry || !lt256(t, kOrderN)) {
        uint64_t borrow = 0;
        for (int i = 0; i < 4; ++i) {
            const uint64_t d = t[i] - kOrderN[i];
            const uint64_t b1 = (t[i] < kOrderN[i]);
            const uint64_t d2 = d - borrow;
            t[i] = d2;
            borrow = b1 | (d < borrow);
        }
    }
    r[0] = t[0]; r[1] = t[1]; r[2] = t[2]; r[3] = t[3];
}

// 大端 32 字节 -> 4 x uint64_t 小端肢体
inline void be32_to_limbs(uint64_t* out, const unsigned char* be)
{
    for (int i = 0; i < 4; ++i) {
        const unsigned char* p = be + (3 - i) * 8;
        uint64_t v = 0;
        for (int j = 0; j < 8; ++j) {
            v = (v << 8) | p[j];
        }
        out[i] = v;
    }
}

// 4 x uint64_t 小端肢体 -> 大端 32 字节 (be32_to_limbs 的逆)
inline void limbs_to_be32(unsigned char* be, const uint64_t* in)
{
    for (int i = 0; i < 4; ++i) {
        unsigned char* p = be + (3 - i) * 8;
        uint64_t v = in[i];
        for (int j = 7; j >= 0; --j) {
            p[j] = (unsigned char)(v & 0xFF);
            v >>= 8;
        }
    }
}

// 预展开的加数表: affine 坐标 (普通域) + m/n (mod N 的肢体形式)
struct RhoAffineAdd {
    secp256k1_fe x;
    secp256k1_fe y;
    uint64_t m[4];
    uint64_t n[4];
};

RhoAffineAdd g_affine_adds[256];
bool g_affine_adds_ready = false;

// rho 随机游走状态: affine 坐标 (普通域, 非蒙哥马利域) + 两个 mod N 标量
struct RhoAffineState {
    secp256k1_fe X;
    secp256k1_fe Y;
    uint64_t m[4];
    uint64_t n[4];
};

// ---------------------------------------------------------------------------
// 核心: 仿射点加 (X, Y) += (A.x, A.y)
//
//   λ  = (A.y - Y) / (A.x - X)
//   x3 = λ² - X - A.x
//   y3 = λ(X - x3) - Y
//
// 入参 X, Y 必须已是 magnitude 1。
// 返回时 X 全规约 (X < p), 所以 X.n[0] 的低 32 位就是 x mod 2^32, 可直接用于
// 下一轮的索引; Y 只做 normalize_weak (mag 1), 足够满足下一轮的约束。
//
// 总计: 3 次 fe_mul/sqr + 1 次 modinv64_var + 若干 fe_add/negate/normalize。
// ---------------------------------------------------------------------------
inline void rho_affine_add(secp256k1_fe& X, secp256k1_fe& Y, const RhoAffineAdd& A)
{
    secp256k1_fe dx;

    // dx = A.x - X, magnitude 1 + 1 -> 3
    secp256k1_fe_negate(&dx, &X, 1);
    secp256k1_fe_add(&dx, &A.x);

    if (secp256k1_fe_normalizes_to_zero_var(&dx)) {
        // 概率约 2^-256: A.x == X, 必须走点倍分支
        // (若再发生 Y == -A.y 则结果应为无穷远点; 在 rho 中这同样不可达,
        //  此处按点倍公式处理, 不做额外特判)
        secp256k1_fe inv, lam, t, nx, ny;

        secp256k1_fe two_y = Y;
        secp256k1_fe_add(&two_y, &Y);           // 2Y            (mag 2)
        secp256k1_fe_inv_var(&inv, &two_y);     // 1/(2Y)        (mag 1)
        secp256k1_fe_sqr(&lam, &X);             // X²            (mag 1)
        secp256k1_fe_add(&lam, &lam);           // 2X²           (mag 2)
        secp256k1_fe_add(&lam, &X);             // 3X²           (mag 3)
        secp256k1_fe_mul(&lam, &lam, &inv);     // λ = 3X²/(2Y)  (mag 1)

        // x3 = λ² - 2X
        secp256k1_fe_negate(&t, &X, 1);         // -X            (mag 2)
        secp256k1_fe_add(&t, &t);               // -2X           (mag 4)
        secp256k1_fe_sqr(&nx, &lam);            // λ²            (mag 1)
        secp256k1_fe_add(&nx, &t);              // λ² - 2X       (mag 5)
        secp256k1_fe_normalize_var(&nx);

        // y3 = λ(X - x3) - Y
        secp256k1_fe_negate(&t, &nx, 1);        // -x3           (mag 2)
        secp256k1_fe_add(&t, &X);               // X - x3        (mag 3)
        secp256k1_fe_mul(&ny, &t, &lam);        // λ(X - x3)     (mag 1)
        secp256k1_fe_negate(&t, &Y, 1);         // -Y            (mag 2)
        secp256k1_fe_add(&ny, &t);              // y3            (mag 3)
        secp256k1_fe_normalize_weak(&ny);

        X = nx;
        Y = ny;
        return;
    }

    secp256k1_fe dy;
    // dy = A.y - Y, magnitude 1 + 1 -> 3
    secp256k1_fe_negate(&dy, &Y, 1);
    secp256k1_fe_add(&dy, &A.y);

    secp256k1_fe inv, lam, nx, ny, t;

    secp256k1_fe_inv_var(&inv, &dx);            // 1/(A.x - X)   (mag 1)
    secp256k1_fe_mul(&lam, &dy, &inv);          // λ             (mag 1)

    // x3 = λ² - X - A.x
    secp256k1_fe_sqr(&nx, &lam);                // λ²            (mag 1)
    secp256k1_fe_negate(&t, &X, 1);             // -X            (mag 2)
    secp256k1_fe_add(&nx, &t);                  //               (mag 3)
    secp256k1_fe_negate(&t, &A.x, 1);           // -A.x          (mag 2)
    secp256k1_fe_add(&nx, &t);                  // x3            (mag 5)
    secp256k1_fe_normalize_var(&nx);

    // y3 = λ(X - x3) - Y
    secp256k1_fe_negate(&t, &nx, 1);            // -x3           (mag 2)
    secp256k1_fe_add(&t, &X);                   // X - x3        (mag 3)
    secp256k1_fe_mul(&ny, &t, &lam);            // λ(X - x3)     (mag 1)
    secp256k1_fe_negate(&t, &Y, 1);             // -Y            (mag 2)
    secp256k1_fe_add(&ny, &t);                  // y3            (mag 3)
    secp256k1_fe_normalize_weak(&ny);

    X = nx;
    Y = ny;
}

// 一次性把 adds_pub[0][*] 转换成普通域 + 肢体形式
void rho_affine_init_adds()
{
    if (g_affine_adds_ready) return;
    for (int i = 0; i < 256; ++i) {
        RhoGeStorage st;
        memcpy(&st, adds_pub[0][i].x.data, sizeof(st));
        secp256k1_fe_from_storage(&g_affine_adds[i].x, &st.x);
        secp256k1_fe_from_storage(&g_affine_adds[i].y, &st.y);
        be32_to_limbs(g_affine_adds[i].m, adds_pub[0][i].m);
        be32_to_limbs(g_affine_adds[i].n, adds_pub[0][i].n);
    }
    g_affine_adds_ready = true;
}

// 用第 i 个加数作为随机游走起点
void rho_affine_set_start(RhoAffineState& s, int i)
{
    RhoGeStorage st;
    memcpy(&st, adds_pub[0][i].x.data, sizeof(st));
    secp256k1_fe_from_storage(&s.X, &st.x);
    secp256k1_fe_from_storage(&s.Y, &st.y);
    memcpy(s.m, g_affine_adds[i].m, sizeof(s.m));
    memcpy(s.n, g_affine_adds[i].n, sizeof(s.n));
}

// RhoPoint/存储形式 -> 优化状态
// rp.x.data 就是 secp256k1_ge_storage (x||y 各 32 字节), 可直接 memcpy 后展开。
void rho_affine_load(RhoAffineState& s, const RhoPoint& rp)
{
    RhoGeStorage st;
    memcpy(&st, rp.x.data, sizeof(st));
    secp256k1_fe_from_storage(&s.X, &st.x);
    secp256k1_fe_from_storage(&s.Y, &st.y);
    be32_to_limbs(s.m, rp.m);
    be32_to_limbs(s.n, rp.n);
}

// 优化状态 -> RhoPoint/存储形式 (供 distinguishable / saveDP / 存档使用)
// X 在 rho_affine_add 结束时已全规约, Y 只做了 normalize_weak, 这里补一次全规约,
// 保证打包出来的是 [0, p) 内的标准坐标 (pubkey 解析要求)。
void rho_affine_store(const RhoAffineState& s, RhoPoint& rp)
{
    secp256k1_fe x = s.X, y = s.Y;
    secp256k1_fe_normalize_var(&x);
    secp256k1_fe_normalize_var(&y);
    RhoGeStorage st;
    secp256k1_fe_to_storage(&st.x, &x);
    secp256k1_fe_to_storage(&st.y, &y);
    memcpy(rp.x.data, &st, sizeof(st));
    limbs_to_be32(rp.m, s.m);
    limbs_to_be32(rp.n, s.n);
}

// 一次完整的 rho 步进: 用当前 x 的低字节选加数, 再做一次仿射点加
// (与 blockchain.cpp 的 rho_F / cuda.cu 的 fun_add 语义一致)
inline void rho_affine_step(RhoAffineState& s)
{
    // s.X 上一轮结尾已全规约, 所以 X.n[0] 的低 8 位就是 x mod 256
    const unsigned t = (unsigned)(s.X.n[0] & 0xFF);
    const RhoAffineAdd& A = g_affine_adds[t];
    rho_affine_add(s.X, s.Y, A);
    add_mod_N(s.m, A.m);
    add_mod_N(s.n, A.n);
}

// 对应设备端 distinguishable(): x 低 32 位为 0 时返回 x 的 bit 32..95
inline uint64_t rho_affine_dp(const RhoAffineState& s)
{
    if ((uint32_t)s.X.n[0] != 0) return 0;
    // x mod 2^32      = X.n[0] 的低 32 位
    // x 的 bit 64..95 = X.n[1] 的 bit 12..43
    return (uint64_t)(uint32_t)(s.X.n[0] >> 32)
         | ((uint64_t)(uint32_t)(s.X.n[1] >> 12) << 32);
}

// 正确性自检: 与库公开 API 路径逐步对拍 (点坐标 + m/n 标量)
bool rho_affine_selfcheck(int steps)
{
    RhoState lib;
    lib.x = adds_pub[0][0].x;
    memcpy(lib.m, adds_pub[0][0].m, sizeof(lib.m));
    memcpy(lib.n, adds_pub[0][0].n, sizeof(lib.n));
    lib.times = 0;

    RhoAffineState aff;
    rho_affine_set_start(aff, 0);

    for (int i = 0; i < steps; ++i) {
        const unsigned t_lib = (unsigned)lib.x.data[0];
        const unsigned t_aff = (unsigned)(aff.X.n[0] & 0xFF);
        if (t_lib != t_aff) {
            std::cout << "rho-affine selfcheck: 第 " << i << " 步索引不一致 ("
                      << t_lib << " vs " << t_aff << ")" << std::endl;
            return false;
        }

        secp256k1_pubkey pk = lib.x;
        secp256k1_pubkey* ins[2] = {&pk, &adds_pub[0][t_lib].x};
        if (!secp256k1_ec_pubkey_combine(ctx, &lib.x, ins, 2) ||
            !secp256k1_ec_seckey_tweak_add(ctx, lib.m, adds_pub[0][t_lib].m) ||
            !secp256k1_ec_seckey_tweak_add(ctx, lib.n, adds_pub[0][t_lib].n)) {
            std::cout << "rho-affine selfcheck: 库调用失败 @" << i << std::endl;
            return false;
        }

        rho_affine_step(aff);

        // 对比点坐标 (affine 侧 Y 只做了 normalize_weak, 比较前先全规约)
        secp256k1_fe x = aff.X, y = aff.Y;
        secp256k1_fe_normalize_var(&x);
        secp256k1_fe_normalize_var(&y);
        RhoGeStorage st;
        secp256k1_fe_to_storage(&st.x, &x);
        secp256k1_fe_to_storage(&st.y, &y);
        if (memcmp(&st, lib.x.data, sizeof(st)) != 0) {
            std::cout << "rho-affine selfcheck: 第 " << i << " 步点坐标不一致" << std::endl;
            return false;
        }

        // 对比 m/n
        uint64_t ml[4], nl[4];
        be32_to_limbs(ml, lib.m);
        be32_to_limbs(nl, lib.n);
        if (memcmp(ml, aff.m, sizeof(ml)) != 0 || memcmp(nl, aff.n, sizeof(nl)) != 0) {
            std::cout << "rho-affine selfcheck: 第 " << i << " 步标量不一致" << std::endl;
            return false;
        }
    }
    return true;
}

}  // namespace

// 仿射点加的性能基准: 与 perf_test_libsecp256k1 / perf_test_cpu / perf_test_gpu 同样的
// 80w 次点加 + DP 判定循环。
void perf_test_rho_affine()
{
    rho_affine_init_adds();

    RhoAffineState s;
    rho_affine_set_start(s, 0);

    const auto start = std::chrono::steady_clock::now();
    uint64_t count_rho = 0;
    uint32_t count_dp = 0;
    while (count_rho < 800000) {
        rho_affine_step(s);
        count_rho++;
        if (rho_affine_dp(s) != 0) {
            count_dp++;
        }
    }
    const auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now() - start);
    const double sec = elapsed.count() / 1000.0;
    std::cout << "rho-affine test elapsed: " << elapsed.count() << " ms, with " << count_rho
              << " RhoPoint, avg " << (uint64_t)(count_rho / sec) << " points/s." << std::endl;
}

// 仿射点加的正确性验证, 由 validate_test() 调用。
// 以库里公开 API 的点加为基准, 逐步对拍本实现 (点坐标 + m/n 标量)。
void validate_rho_affine()
{
    rho_affine_init_adds();

    const bool ok = rho_affine_selfcheck(2000);
    std::cout << "rho-affine selfcheck (2000 steps vs libsecp256k1 public API): "
              << (ok ? "PASS" : "FAIL") << std::endl;
    assert(ok);
}

// ---------------------------------------------------------------------------
// 供 blockchain.cpp 的 class Rho 使用的对外接口
// ---------------------------------------------------------------------------

// 初始化加数表。必须在启动 worker 线程之前 (即 PLAYER::prepare() 里) 调用一次,
// 否则多线程首次并发进入时会同时写 g_affine_adds。
void rho_affine_prepare()
{
    rho_affine_init_adds();
}

// 仿射点加版的 rho_F: 语义与 blockchain.cpp 里的 rho_F 完全一致
//   —— 以 x 的首字节选取加数, 做一次仿射点加, m/n 各累加一次并 mod N, times++。
//
// 区别只在于状态表示: rho_F 每步都把 secp256k1_pubkey 重新解析成内部表示,
// 这里把 fe 形式的状态缓存在线程局部变量里, 每步只做 fe 运算 + 一次回写。
//
// 回写是必要的: distinguishable(rs.x) / saveDP / saveRhoState 都直接读 rs。
// 回写开销 (两次 fe_normalize_var + 打包) 相对一次仿真点加里的模逆可以忽略。
void rho_affine_F(RhoState& rs)
{
    assert(g_affine_adds_ready);

    // 每线程一份 fe 状态。若 rs 被外部重置 (loadRhoState / rand 等), times 会对不上,
    // 此时重新从 rs 同步一次。
    static thread_local RhoAffineState st;
    static thread_local bool inited = false;
    static thread_local uint64_t synced_times = 0;

    if (!inited || synced_times != rs.times) {
        rho_affine_load(st, rs);
        inited = true;
    }

    rho_affine_step(st);

    rs.times++;
    synced_times = rs.times;
    rho_affine_store(st, rs);
}
