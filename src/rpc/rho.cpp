// rho.cpp
//
// 本文件包含两部分:
//
//   1) perf_fun_lib / perf_test_libsecp256k1
//      使用 libsecp256k1 的【公开 API】(secp256k1_ec_pubkey_combine +
//      secp256k1_ec_seckey_tweak_add) 做点加的性能基准, 与 cuda.cu 中的
//      perf_test_cpu / perf_test_gpu 对照。
//
//   2) rho_affine_FW<W> / rho_affine_step_batch<W> (同线程多 walker 批量求逆)
//      直接使用 libsecp256k1【内部】的 5x52 域实现 (field_impl.h) 手写的
//      "干净" 仿射点加, 同一线程内 W 个 walker 的模逆凑成一批只求一次。
//      与公开 API 路径相比, 它去掉了:
//        - ge_storage(64B) <-> 5x52 的序列化往返
//        - 常量时间的退化处理 (fe_half / cmov / 多次 negate)
//        - m/n 标量的 大端 <-> 肢体 转换与清零
//        - pubkey_combine 从无穷远点开始的第一次冗余点加
//      并且每个 walker 每步只做 3 次域乘, 模逆由整批平摊 (每点 1/W 次)。
//      点倍 (A.x == X) 只出现在整批求逆失败后退回的逐点路径里, 见 rho_affine_add。
//
// 说明: libsecp256k1 内部头文件里的所有函数都是 static/inline, 会被直接内联
//       进本翻译单元, 不会与已链接的 libsecp256k1 静态库产生符号冲突。
#include "common.h"

#include <cassert>
#include <chrono>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <fstream>
#include <iostream>
#include <sstream>
#include <string>
#include <vector>

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

#include <bit>          // std::popcount / std::countr_zero

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

        // DP 判定: 对应 distinguishable(x 的 bit 0..39 全 0 时返回 bit 40..103)。
        // s.x.data 是 ge_storage (4 x 64 位存储字, 不是 5x52 肢体), 按字节看:
        //   x 的 bit 0..63   = 存储字 w0
        //   x 的 bit 64..127 = 存储字 w1
        // 所以
        //   x 的 bit 0..39   = w0 的低 40 位
        //   x 的 bit 40..63  = w0 的高 24 位
        //   x 的 bit 64..95  = w1 的低 32 位
        //   x 的 bit 96..103 = w1 的 bit 32..39
        uint64_t w0 = 0, w1 = 0;
        memcpy(&w0, s.x.data, sizeof(w0));
        memcpy(&w1, s.x.data + sizeof(w0), sizeof(w1));
        uint64_t d = 0;
        if ((w0 & 0xFFFFFFFFFFULL) == 0) {
            d = (w0 >> 40) | (w1 << 24);
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
// 仿射点加 (X, Y) += (A.x, A.y) 的公式 —— rho_affine_step_batch 里逐 walker 展开:
//
//   λ  = (A.y - Y) / (A.x - X)
//   x3 = λ² - X - A.x
//   y3 = λ(X - x3) - Y
//
// A.x == X 时上式分母为 0 (概率约 2^-256), 必须换成点倍公式:
//
//   λ  = 3X² / (2Y)
//   x3 = λ² - 2X
//   y3 = λ(X - x3) - Y
//
// 批量路径按一般加法展开 (热路径上不做这个判定), 所以只在 A.x != X 时成立;
// 一旦某个分母是 0, fe_batch_inv 让整批失效, 由 rho_affine_add 逐点重算, 点倍
// 补在那里。
//
// 入参 X, Y 必须已是 magnitude 1。
// 步进结束时 X 全规约 (X < p), 所以 X.n[0] 的低 32 位就是 x mod 2^32, 可直接
// 用于下一轮的索引; Y 只做 normalize_weak (mag 1), 足够满足下一轮的约束。
//
// 总计: 3 次 fe_mul/sqr + 1 次 modinv64_var (批量路径里整批共用 1 次) + 若干
//       fe_add/negate/normalize。
// ---------------------------------------------------------------------------

// 单点仿射点加, 自己求一次逆:
//   A.x != X -> 一般加法 (上面的公式)
//   A.x == X -> 点倍
// 只服务于 rho_affine_step_batch 的零分母兜底 (见那里); 热路径走批量求逆,
// 不做这个判定, 所以这里的分支不影响每点成本。
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
        secp256k1_fe_mul_int(&lam, 3);          // 3X²           (mag 3)
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
// X 在 rho_affine_step_batch 结束时已全规约, Y 只做了 normalize_weak, 这里补一次
// 全规约, 保证打包出来的是 [0, p) 内的标准坐标 (pubkey 解析要求)。
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

// 对应 distinguishable(): x 的 bit 0..39 全 0 时, 返回 x 的 bit 40..103 (连续 64 位)。
//
// distinguishable 是按字节读的: *(uint64_t*)(x.data + 5), 也就是 x 的 bit 40..103
// 这一段连续 64 位。这里要在 5x52 肢体上取出同一段, 分两段拼接:
//   bit 40..51  = X.n[0] 的 bit 40..51   (n[0] 只覆盖到 bit 51)
//   bit 52..103 = X.n[1] 的 bit 0..51    (n[1] 的 bit 0 即 x 的 bit 52)
// 合并即 (X.n[0] >> 40) | (X.n[1] << 12): n[0] >> 40 只有 12 位有效,
// n[1] 的 52 位整体左移 12 位后正好对接其上端, 合计 64 位。
//
// 注意: 这里假定 X 已全规约 (rho_affine_step_batch 每步结尾保证), 否则 limb 与
//       x 的二进制位对不上。
inline uint64_t rho_affine_dp(const RhoAffineState& s)
{
    // x bit 0..39 != 0 -> 不构成 DP (n[0] 的 bit 40..51 不参与判定)
    if ((s.X.n[0] & 0xFFFFFFFFFFULL) != 0) return 0;
    return (s.X.n[0] >> 40) | (s.X.n[1] << 12);
}

// ===========================================================================
// 同线程多 walker
//
// 一次仿射点加倍价: 3 次域乘 + 1 次域模逆。模逆 (modinv64_var, 实测平均 ~18 轮
// divsteps) 是唯一的瓶颈, 比一次域乘贵约一两个数量级; 而同一个线程里 W 个互相
// 独立的 walker, 它们的模逆分母彼此无关, 可以先乘成一个总积只求一次逆, 再沿前缀
// 逐个还原 (Montgomery 批量求逆)。于是每点的模逆成本从 1 次降到 1/W 次:
//
//     W=1:  1 逆 +  3 乘
//     W=4:  1 逆 + 18 乘  -> 每点 ≈ 1/4 逆 + 4.5 乘
//
// 这正是"同线程多 walker"相对于"多开线程"唯一的额外收益 —— 跨线程没法把分母
// 凑成一批一起求逆。W 越大摊得越薄, 但收益迅速递减, 在哪一档最划算靠实测
// (perf_test_rho_affine_walkers) 决定。
// ===========================================================================

// Montgomery 批量求逆: inv[i] = 1 / d[i] (mod p)。
// W == 1 时就是一次普通求逆。
//
// 某个 d[i] == 0 时整条前缀积为 0 (域无零因子), 返回 false。这样 W 次零检查
// 合并成了整批一次 (对积检查), 概率仍约 W * 2^-256; 调用方此时退回逐点路径
// (见 rho_affine_step_batch), 点倍分支在那条路上。
template <int W>
bool fe_batch_inv(secp256k1_fe (&inv)[W], const secp256k1_fe (&d)[W])
{
    secp256k1_fe prefix[W];
    secp256k1_fe acc = d[0];
    for (int i = 1; i < W; ++i) {
        prefix[i] = acc;                        // 前缀积 d[0..i-1]
        secp256k1_fe_mul(&acc, &acc, &d[i]);    // acc = d[0..i]
    }
    if (secp256k1_fe_normalizes_to_zero_var(&acc)) return false;
    secp256k1_fe_inv_var(&acc, &acc);           // 整批唯一的一次模逆
    for (int i = W - 1; i > 0; --i) {
        secp256k1_fe_mul(&inv[i], &acc, &prefix[i]);  // inv[i] = 1/d[i]
        secp256k1_fe_mul(&acc, &acc, &d[i]);          // acc = 1/d[0..i-1]
    }
    inv[0] = acc;
    return true;
}

// 一次推进 W 个 walker 各一步。每个 walker 的仿射公式见上文, 区别只有一处:
// 分母 1/dx 不再各自求逆, 而是整批一次求出来。
//
// 返回 DP 命中的 walker 掩码 (bit i = walker i 的 x 低 40 位全 0)。命中者由
// rho_affine_FW 写回 rs 并按需重置; 未命中者 fe 状态留在 cache 里, 完全不碰
// rs 的 136 字节 —— rs 只有 DP 判定 (概率 2^-40) 和存档 (每 2^30 步) 才需要,
// 每步全量写回是纯浪费 (实测占每点成本的 1/3)。
//
// 零分母 (概率约 W * 2^-256) 由 fe_batch_inv 对整批一次检出: 那是 A.x == X 的
// walker, 该按点倍算, 整批共用一个分母的前提不成立。这一批改走逐点路径
// (rho_affine_add 各自求逆, 点倍分支在那里), 代价只落在这一批上, 热路径无分支。
template <int W>
inline uint32_t rho_affine_step_batch(RhoAffineState (&st)[W])
{
    unsigned char t[W];
    secp256k1_fe dx[W], dy[W];

    for (int i = 0; i < W; ++i) {
        // st[i].X 上一轮结尾已全规约, 低 8 位就是 x mod 256
        t[i] = (unsigned char)(st[i].X.n[0] & 0xFF);
        const RhoAffineAdd& A = g_affine_adds[t[i]];
        secp256k1_fe_negate(&dx[i], &st[i].X, 1);
        secp256k1_fe_add(&dx[i], &A.x);    // dx = A.x - X   (mag 3)
        secp256k1_fe_negate(&dy[i], &st[i].Y, 1);
        secp256k1_fe_add(&dy[i], &A.y);     // dy = A.y - Y   (mag 3)
    }

    secp256k1_fe inv[W];
    if (fe_batch_inv<W>(inv, dx)) {
        // 常规路径: 整批只求一次逆, 逐 walker 套一般加法公式
        for (int i = 0; i < W; ++i) {
            const RhoAffineAdd& A = g_affine_adds[t[i]];
            secp256k1_fe lam, nx, ny, tt;

            secp256k1_fe_mul(&lam, &dy[i], &inv[i]);    // λ             (mag 1)
            secp256k1_fe_sqr(&nx, &lam);                // λ²            (mag 1)
            secp256k1_fe_negate(&tt, &st[i].X, 1);
            secp256k1_fe_add(&nx, &tt);                 //               (mag 3)
            secp256k1_fe_negate(&tt, &A.x, 1);
            secp256k1_fe_add(&nx, &tt);                 // x3            (mag 5)
            secp256k1_fe_normalize_var(&nx);
            secp256k1_fe_negate(&tt, &nx, 1);
            secp256k1_fe_add(&tt, &st[i].X);            // X - x3        (mag 3)
            secp256k1_fe_mul(&ny, &tt, &lam);           // λ(X - x3)     (mag 1)
            secp256k1_fe_negate(&tt, &st[i].Y, 1);
            secp256k1_fe_add(&ny, &tt);                 // y3            (mag 3)
            secp256k1_fe_normalize_weak(&ny);

            st[i].X = nx;
            st[i].Y = ny;
            add_mod_N(st[i].m, A.m);
            add_mod_N(st[i].n, A.n);
        }
    } else {
        // dx 里有 0 (A.x == X, 概率约 W * 2^-256): 那个 walker 该按点倍算, 整批
        // 共用分母的前提不成立, inv[] 也没写出 —— 整批退回逐点路径, 每个 walker
        // 自己求一次逆 (点倍分支在 rho_affine_add 里)。
        // 这条路径同样逐点维护 X 全规约, 后面的 DP 判定照常可用。
        for (int i = 0; i < W; ++i) {
            const RhoAffineAdd& A = g_affine_adds[t[i]];
            rho_affine_add(st[i].X, st[i].Y, A);
            add_mod_N(st[i].m, A.m);
            add_mod_N(st[i].n, A.n);
        }
    }

    // DP 判定在 fe 域做 (rho_affine_dp 已与 distinguishable 对拍过), 不再经过
    // rs 的存储字节。X 此时全规约。
    uint32_t dp_mask = 0;
    for (int i = 0; i < W; ++i) {
        if (rho_affine_dp(st[i]) != 0) {
            dp_mask |= (uint32_t)1 << i;
        }
    }
    return dp_mask;
}

// 一批 walker 的线程局部 fe 缓存: slot i 与外部 rs[i] 一一对应
// (同一线程内始终传同一个 rs 基址, 映射才稳定)。
//
// rs[i] 不再每步写回 (只有 DP 命中 / flush 才写), 所以 x/m/n 平时是陈旧的,
// 真状态在 st[i] 里; rs[i].times 仍每步递增, 用来检测外部重置:
// 调用方重置某个 walker 后把 times 清零 (play() 的约定), 下一次调用自动重载。
template <int W>
struct RhoCache {
    RhoAffineState st[W];
    bool inited[W] = {};
    uint64_t synced_times[W] = {};
};

// 每个线程每份宽度一份 cache。FW / flush / 内部共用, 必须走同一个对象。
template <int W>
RhoCache<W>& rho_affine_cache()
{
    static thread_local RhoCache<W> cache;
    return cache;
}

// 批量路径自检: 同一批 W 个 walker, 一路用 rho_affine_FW<W> (批量求逆) 推进,
// 另一路逐个用库公开 API 推进 (secp256k1_ec_pubkey_combine + seckey_tweak_add,
// 与生产 rho_F 的 fun_add 同一条路径), 每步逐项对比
// 四元组 (x 存储字节 / m / n / times)。
//
// 参考侧直接在 RhoState 上步进 (每步一次库公开 API 点加), 与批量路径共用
// 同一个 "以 x 首字节选加数" 的约定, 所以两边逐位可比。
template <int W>
bool rho_affine_batch_selfcheck(int steps)
{
    RhoState batch[W] = {};
    RhoState ref[W] = {};

    for (int i = 0; i < W; ++i) {
        batch[i].x = adds_pub[0][i].x;
        memcpy(batch[i].m, adds_pub[0][i].m, sizeof(batch[i].m));
        memcpy(batch[i].n, adds_pub[0][i].n, sizeof(batch[i].n));
        batch[i].times = 0;
        ref[i] = batch[i];
    }

    for (int s = 0; s < steps; ++s) {
        rho_affine_FW<W>(batch);
        rho_affine_flush<W>(batch);      // rs 平时只有 times 是新的, 对拍前写真
        for (int i = 0; i < W; ++i) {
            // 加数索引与生产路径同口径: data[0] 即 x mod 256 (fe_storage 首字节)
            const unsigned t = (unsigned)ref[i].x.data[0];
            secp256k1_pubkey pk = ref[i].x;
            secp256k1_pubkey* ins[2] = {&pk, &adds_pub[0][t].x};
            if (!secp256k1_ec_pubkey_combine(ctx, &ref[i].x, ins, 2) ||
                !secp256k1_ec_seckey_tweak_add(ctx, ref[i].m, adds_pub[0][t].m) ||
                !secp256k1_ec_seckey_tweak_add(ctx, ref[i].n, adds_pub[0][t].n)) {
                std::cout << "rho-affine batch selfcheck: W=" << W << " step " << s
                          << " walker " << i << " lib call failed" << std::endl;
                return false;
            }
            ++ref[i].times;

            const char* what = nullptr;
            if (memcmp(batch[i].x.data, ref[i].x.data, sizeof(batch[i].x.data)) != 0) {
                what = "x";
            } else if (memcmp(batch[i].m, ref[i].m, sizeof(batch[i].m)) != 0) {
                what = "m";
            } else if (memcmp(batch[i].n, ref[i].n, sizeof(batch[i].n)) != 0) {
                what = "n";
            } else if (batch[i].times != ref[i].times) {
                what = "times";
            }
            if (what != nullptr) {
                std::cout << "rho-affine batch selfcheck: W=" << W << " step " << s
                          << " walker " << i << " mismatch on " << what << std::endl;
                return false;
            }
        }
    }
    return true;
}

}  // namespace

// ---------------------------------------------------------------------------
// 同线程多 walker 的对外入口
// ---------------------------------------------------------------------------

// 一次推进同一线程内连续的 W 个 walker。每个 walker 走恰好一步, 语义与
// blockchain.cpp 的 rho_F 一致 (以 x 首字节选加数, 做一次仿射点加, m/n 各累加
// 一次并 mod N, times++)。与逐点实现相比有两处不同:
//   1. W 个模逆被摊成了一次 (批量求逆);
//   2. rs[i] 只在 DP 命中时写回 (概率 2^-40), 未命中步完全不碰那 136 字节 ——
//      rs 的唯一消费者是 DP 判定和存档, 而存档走 flush 路径。
//
// 返回 DP 命中的 walker 掩码 (bit i = walker i 命中)。调用方对命中者做
// saveDP 等后处理即可, 不需要额外重置。
//
// 缓存同步靠 times: 外部若重置某个 walker (loadRhoState / rand), 必须同时
// 改变它的 times (如清零), 否则缓存察觉不到。当前所有重置都发生在线程启动
// 之前, 线程运行中无人重置。
//
// 前提是同一线程始终传同一段 rs。
template <int W>
uint32_t rho_affine_FW(RhoState* rs)
{
    static_assert(W >= 1 && W <= RHO_WALKERS_MAX, "walker 数超出已实例化的范围");
    assert(g_affine_adds_ready);

    RhoCache<W>& cache = rho_affine_cache<W>();

    for (int i = 0; i < W; ++i) {
        if (!cache.inited[i] || cache.synced_times[i] != rs[i].times) {
            rho_affine_load(cache.st[i], rs[i]);
            cache.inited[i] = true;
        }
    }

    const uint32_t dp_mask = rho_affine_step_batch<W>(cache.st);

    for (int i = 0; i < W; ++i) {
        ++rs[i].times;
        cache.synced_times[i] = rs[i].times;
    }
    if (dp_mask != 0) {
        for (int i = 0; i < W; ++i) {
            if (dp_mask & ((uint32_t)1 << i)) {
                rho_affine_store(cache.st[i], rs[i]);
            }
        }
    }
    return dp_mask;
}

// 把 W 个 walker 的真状态整体写回 rs (存档前调用, 如 saveRhoState 之前 / 线程
// 退出前)。平时 rs 只有 times 是新鲜的, x/m/n 只在 DP 命中时才是新值。
template <int W>
void rho_affine_flush(RhoState* rs)
{
    RhoCache<W>& cache = rho_affine_cache<W>();
    for (int i = 0; i < W; ++i) {
        if (cache.inited[i]) {
            rho_affine_store(cache.st[i], rs[i]);
        }
    }
}

// 显式实例化: 可选 walker 数就是下面这些, 别的值会链接失败。
// 全部展开成编译期宽度固定的循环, 这样 d[]/dy[]/inv[] 这些中间量留在寄存器里。
template uint32_t rho_affine_FW<1>(RhoState* rs);
template uint32_t rho_affine_FW<2>(RhoState* rs);
template uint32_t rho_affine_FW<4>(RhoState* rs);
template uint32_t rho_affine_FW<8>(RhoState* rs);
template uint32_t rho_affine_FW<16>(RhoState* rs);
template uint32_t rho_affine_FW<32>(RhoState* rs);
template void rho_affine_flush<1>(RhoState* rs);
template void rho_affine_flush<2>(RhoState* rs);
template void rho_affine_flush<4>(RhoState* rs);
template void rho_affine_flush<8>(RhoState* rs);
template void rho_affine_flush<16>(RhoState* rs);
template void rho_affine_flush<32>(RhoState* rs);

namespace {

// 在同一个线程里跑 W 个 walker 的基准。走的是生产路径 rho_affine_FW<W>,
// DP 判定已内含在返回掩码里, 数出来的就是真实吞吐。
template <int W>
void bench_rho_walkers(uint64_t steps)
{
    RhoState rs[W] = {};
    for (int i = 0; i < W; ++i) {
        rs[i].x = adds_pub[0][i].x;
        memcpy(rs[i].m, adds_pub[0][i].m, sizeof(rs[i].m));
        memcpy(rs[i].n, adds_pub[0][i].n, sizeof(rs[i].n));
        rs[i].times = 0;
    }

    uint64_t count_dp = 0;
    const auto start = std::chrono::steady_clock::now();
    for (uint64_t s = 0; s < steps; ++s) {
        count_dp += std::popcount(rho_affine_FW<W>(rs));
    }
    const auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now() - start);
    const double sec = elapsed.count() / 1000.0;
    const uint64_t points = steps * W;
    std::cout << "rho-affine walkers=" << W << " : " << elapsed.count() << " ms, "
              << points << " points, " << count_dp << " dp, avg "
              << (uint64_t)(points / sec) << " points/s." << std::endl;
}

}  // namespace

// 扫描每个线程 1/2/4/8/16/32 个 walker 的吞吐, 用来选 common.h 里的 RHO_WALKERS。
// 总点数固定 (800000), 与 cuda.cu 的 perf_test_cpu (同样 800000 点) 同口径,
// 可直接对比。
// 最后一档 W=1 再跑一次作为漂移对照: 同一进程内的首尾两个 W=1 读数应该很接近。
void perf_test_rho_affine_walkers()
{
    rho_affine_init_adds();
    constexpr uint64_t kTotal = 800000;
    bench_rho_walkers<1>(kTotal / 1);
    bench_rho_walkers<2>(kTotal / 2);
    bench_rho_walkers<4>(kTotal / 4);
    bench_rho_walkers<8>(kTotal / 8);
    bench_rho_walkers<16>(kTotal / 16);
    bench_rho_walkers<32>(kTotal / 32);
    bench_rho_walkers<1>(kTotal / 1);
}

// 仿射点加的正确性验证, 由 validate_test() 调用。
// 以库里公开 API 的点加为基准, 逐步对拍本实现 (点坐标 + m/n 标量)。
void validate_rho_affine()
{
    rho_affine_init_adds();

    // rho_affine_dp 与 distinguishable() 的对拍。
    //
    // 随机游走中 x 低 40 位全 0 的概率约 2^-40, 随机步进自检不可能触发 DP
    // 分支, 所以这里用构造值专门覆盖它。参考值走生产回写路径
    // (rho_affine_store -> rs.x.data), 再按 distinguishable 的读法取
    // x.data[5..13), 即 x 的 bit 40..103。
    bool dp_ok = true;
    {
        // 32 字节大端, 低 5 字节 (40 位) 均为 0 时构成 DP; 值均 < p
        static const char* const kDpBe[] = {
            "0000000000000000000000000000000000000000000000000000000000000000", // x = 0 -> 索引 0
            "0000000000000000000000000000000000000000000000000000010000000000", // x = 2^40 -> 索引 1
            "000000000000000000000000000000000000000000000000fff0000000000000", // x = 0xFFF<<52 -> 索引 0xFFF000
            "00000000000000000000000000000000000000deadbeefcafebabe0000000000", // bit 40..103 填满 -> 索引 0xdeadbeefcafebabe
            "0000000000000000000000000000000000000000000000000000000100000000", // x = 2^32: 低 32 位为 0 但 bit 32..39 非 0 -> 非 DP
            "0000000000000000000000000000000000000000000000000000000012345678", // 低 32 位非 0 -> 非 DP
        };

        for (const char* be : kDpBe) {
            unsigned char b32[32];
            for (int k = 0; k < 32; ++k) {
                const int hi = (be[2 * k] <= '9') ? be[2 * k] - '0' : be[2 * k] - 'a' + 10;
                const int lo = (be[2 * k + 1] <= '9') ? be[2 * k + 1] - '0' : be[2 * k + 1] - 'a' + 10;
                b32[k] = (unsigned char)((hi << 4) | lo);
            }

            RhoAffineState s;
            secp256k1_fe_set_b32_mod(&s.X, b32);
            secp256k1_fe_normalize_var(&s.X);
            s.Y = s.X;   // 与 DP 判定无关
            memset(s.m, 0, sizeof(s.m));
            memset(s.n, 0, sizeof(s.n));

            RhoPoint rp;
            rho_affine_store(s, rp);
            uint64_t t0 = 0, t1 = 0;
            memcpy(&t0, rp.x.data, sizeof(t0));
            memcpy(&t1, rp.x.data + 5, sizeof(t1));
            const uint64_t want = ((t0 & 0xFFFFFFFFFFULL) == 0) ? t1 : 0;

            const uint64_t got = rho_affine_dp(s);
            if (got != want) {
                std::cout << "rho-affine dp mismatch: be=" << be << " got=" << got
                          << " want=" << want << std::endl;
                dp_ok = false;
            }
        }
    }
    std::cout << "rho-affine dp vs distinguishable (6 values): " << (dp_ok ? "PASS" : "FAIL")
              << std::endl;
    if (!dp_ok) exit(EXIT_FAILURE);

    // 同线程多 walker 的对拍: W 个 walker 交错推进 vs 库公开 API 逐点推进。
    // 步数取得短, 但上千步已经足够暴露批量求逆的任何下标错位。
    bool batch_ok = true;
    batch_ok &= rho_affine_batch_selfcheck<4>(1000);
    batch_ok &= rho_affine_batch_selfcheck<32>(1000);
    std::cout << "rho-affine batch selfcheck (W=4/32 vs lib public API): "
              << (batch_ok ? "PASS" : "FAIL") << std::endl;
    if (!batch_ok) exit(EXIT_FAILURE);

    // 点倍分支 (A.x == X) 的构造测试。
    //
    // 随机游走命中它的概率约 2^-256, 逐步自检不可能触发, 所以手工构造:
    //
    //   (a) 直接喂 rho_affine_add: X, Y 取表项 j 的点, A 也取表项 j 的点 (P + P),
    //       期望 2P。库公开 API 的 combine 走 Brier-Joye 统一公式, 支持倍点。
    //
    //   (b) 端到端喂 rho_affine_step_batch<2>: walker 的加数表项由 X 的首字节决定,
    //       所以先把槽位 k = P.x 首字节 的 x 换成 P.x (用完立即还原), 那个 walker
    //       选中的 A 就满足 A.x == X —— 分母为 0, 整批求逆失败, 走进逐点兜底路径。
    //       同批的第二个 walker 是普通加法, 用来验证兜底路径对非退化 walker 也
    //       算对, 而不是靠 "整批跳过" 蒙过去。
    //
    //   m/n 一律从 0 起, 所以期望值就是各自加数表项的一次累加, 不必做 mod N 参考运算。
    bool doubling_ok = true;
    {
        constexpr int kJ = 7;   // 倍点用的表项: P = 表项 j 的点
        // P 会选中的槽位, 也是 (b) 里要被覆盖的那一项
        const unsigned k = (unsigned)(g_affine_adds[kJ].x.n[0] & 0xFF);

        // (a) 单点: P + P = 2P
        {
            secp256k1_fe X = g_affine_adds[kJ].x;
            secp256k1_fe Y = g_affine_adds[kJ].y;
            rho_affine_add(X, Y, g_affine_adds[kJ]);

            RhoAffineState s;
            s.X = X;
            s.Y = Y;
            memset(s.m, 0, sizeof(s.m));
            memset(s.n, 0, sizeof(s.n));
            RhoPoint rp;
            rho_affine_store(s, rp);

            // combine 会先 memset 输出, 所以输出不能是输入之一
            secp256k1_pubkey p = adds_pub[0][kJ].x, q = p, want;
            secp256k1_pubkey* ins[2] = {&p, &q};
            if (!secp256k1_ec_pubkey_combine(ctx, &want, ins, 2) ||
                memcmp(rp.x.data, want.data, sizeof(want.data)) != 0) {
                std::cout << "rho-affine doubling: P + P mismatch" << std::endl;
                doubling_ok = false;
            }
        }

        // (b) 端到端: 覆盖槽位 k 的 x, 让 walker 0 的 dx 为 0
        const RhoAffineAdd saved_k = g_affine_adds[k];
        g_affine_adds[k].x = g_affine_adds[kJ].x;   // A.x == X; A.y / A.m / A.n 不动

        // 普通 walker 的起点: 表项 j1, 要求它的槽位既不是 k (否则加数也被覆盖),
        // 也不是 j1 自己 (否则它也变成倍点)
        int j1 = 0;
        while (j1 < 256) {
            const unsigned s = (unsigned)(g_affine_adds[j1].x.n[0] & 0xFF);
            if (s != k && s != (unsigned)j1) break;
            ++j1;
        }

        if (j1 == 256) {
            g_affine_adds[k] = saved_k;
            cprint() << "rho-affine doubling: 找不到可用的普通表项" << std::endl;
            doubling_ok = false;
        } else {
            const unsigned t1 = (unsigned)(g_affine_adds[j1].x.n[0] & 0xFF);

            RhoAffineState st[2];
            st[0].X = g_affine_adds[kJ].x;      // A.x == X -> 倍点
            st[0].Y = g_affine_adds[kJ].y;
            st[1].X = g_affine_adds[j1].x;      // 普通加法
            st[1].Y = g_affine_adds[j1].y;
            for (int i = 0; i < 2; ++i) {
                memset(st[i].m, 0, sizeof(st[i].m));
                memset(st[i].n, 0, sizeof(st[i].n));
            }

            rho_affine_step_batch<2>(st);
            g_affine_adds[k] = saved_k;         // 立即还原

            // 期望: walker 0 = 2P, 标量取槽位 k 的 (覆盖只动了 x);
            //       walker 1 = 表项 j1 的点 + 表项 t1 的点, 标量取表项 t1 的
            secp256k1_pubkey p0 = adds_pub[0][kJ].x, q0 = p0, want0;
            secp256k1_pubkey p1 = adds_pub[0][j1].x, want1;
            secp256k1_pubkey* ins0[2] = {&p0, &q0};
            secp256k1_pubkey* ins1[2] = {&p1, &adds_pub[0][t1].x};
            const unsigned tidx[2] = {k, t1};
            const secp256k1_pubkey* want[2] = {&want0, &want1};
            if (!secp256k1_ec_pubkey_combine(ctx, &want0, ins0, 2) ||
                !secp256k1_ec_pubkey_combine(ctx, &want1, ins1, 2)) {
                std::cout << "rho-affine doubling: lib reference failed" << std::endl;
                doubling_ok = false;
            }

            for (int i = 0; i < 2 && doubling_ok; ++i) {
                RhoPoint rp;
                rho_affine_store(st[i], rp);
                unsigned char be_m[32], be_n[32];
                limbs_to_be32(be_m, st[i].m);
                limbs_to_be32(be_n, st[i].n);
                const bool x_ok = memcmp(rp.x.data, want[i]->data, sizeof(want[i]->data)) == 0;
                const bool m_ok = memcmp(be_m, adds_pub[0][tidx[i]].m, sizeof(be_m)) == 0;
                const bool n_ok = memcmp(be_n, adds_pub[0][tidx[i]].n, sizeof(be_n)) == 0;
                if (!x_ok || !m_ok || !n_ok) {
                    std::cout << "rho-affine doubling: walker " << i << " mismatch"
                              << " (x/m/n ok = " << x_ok << "/" << m_ok << "/" << n_ok << ")"
                              << std::endl;
                    doubling_ok = false;
                }
            }
        }
    }
    std::cout << "rho-affine doubling (P+P; batch fallback vs lib public API): "
              << (doubling_ok ? "PASS" : "FAIL") << std::endl;
    if (!doubling_ok) exit(EXIT_FAILURE);
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

// ===========================================================================
// 预备队 (RhoStates_reserve) 的来源与账本
//
// 位置说明: 这一整段都是纯主机侧逻辑, 不需要一行 CUDA 代码, 所以就在 rho.cpp;
// 设备侧 (cuda.cu) 只留 RhoStates_reserve 那份常量内存 + 一个上传函数
// upload_RhoStates_reserve。池子的用途见 common.h 的 ReserveSource 那段。
//
// 三类来源里只有 2、3 类需要账本:
//
//   1 类 Random   每轮整池换新随机点。不需要账本 —— 这正是改造前的行为, 所以全池
//                 用 Random 时, 行为与改造前一致。
//   2 类 Special  先吃步进表 adds_pub[0][*] 的 256 条, 吃完再按 k = 1, 2, 3, ... 现算
//                 k*G 接上。阶梯不预生成也没有上限, 所以 2 类取不完。
//   3 类 Dp       旧的可区分点 (从 DP 存档里取), 相当于把以前被切断的轨迹接上。
//
// 2、3 类为什么要账本 (1 类为什么不要):
//
//   (i)  步进表是确定性的: 起点定死则整条轨迹定死 (走到的点、累计的 m/n 全可预测)。
//        同一个点入池两次, 走的轨迹连 (m,n) 都完全相同, 产出的 DP 记录逐字节重复;
//        而碰撞判定要的是"同一个 x 配不同的 (m,n)", 重复记录一条都排不上用场。所以
//        每个**点**最多入池一次, 用过即退役; 槽位可以重复用, 但里面换成新点。
//   (ii) 池子每轮开跑前要重填, 而该填哪些槽位取决于上一轮谁被征调过 —— 不记账就
//        无从判断; 整池乱换又会把还没用上的好点丢掉。
//
// 于是账本就记两件事: 槽位现在装着谁 (slot_serial_), 以及这位队员的履历
// (members_: 入池轮号 / 有没有被征调)。**没被征调过的队员无限期留用** —— 既没
// 浪费库存, 也不必为了"再确认一次"把它换掉。
//
// 履历不能直接挂在槽位上 (槽位会被补员, 而"这位点以前干过什么"要一直记得), 所以
// 槽位通过只增不减的流水号间接指向履历; 流水号 0 是哨兵, 表示"这个槽位没有队员"
// (也就是随机点占位 —— 1 类不进账本)。
//
// 池子大小是 dp_buffer_size, 而 add_dp_to_buffer 取用的下标不止到 max_size - 1:
// 它先写入再判 break, 所以下标还会往上走一点 —— 同一批里每线程 W 个 walker 最多各
// 命中一次, 而 break_flag 要等各线程轮询到才生效 (轮询间隔 2^18 批), 超出的量都是
// 个位数, 数组比 max_size 多留的 10 项就是给这段的。
//
// 库存要够首轮一次性填满 dp_buffer_size 个槽位 (之后每轮只补被征调的): 2 类的 256 条
// + 无上限阶梯绰绰有余, 3 类看存档有多少。真取不到时走 begin_round 的耗尽处理 ——
// 那些槽位**永久**回退随机点 (只有 3 类会走到, 2 类的阶梯取不完)。
//
// (i) 那条要求是**跨进程**成立的: 游标和账本都是生产状态, 所以每轮落盘一份 (见下面
// 的"进程级状态落盘"一节)。不落盘就等于每次重启把游标退回起点, 头几批点跟上一次 run
// 逐字节重复, 顺带把整池还没用上的留用队员丢掉重抽。
// ===========================================================================

// 流水号 0 = "没有队员"。
constexpr uint64_t RESERVE_NONE = 0;

// 名字给日志用。cuda.cu 的 validate_test 也要打它, 所以不 static。
const char* reserve_source_name(ReserveSource s)
{
    switch (s) {
    case ReserveSource::Special: return "Special";
    case ReserveSource::Dp:      return "Dp";
    default:                     return "Random";
    }
}

// 反过来 (读状态存档用)。认不出来返回 false, 由调用方整份丢弃。
static bool reserve_source_by_name(const std::string& s, ReserveSource& out)
{
    if (s == "Random")  { out = ReserveSource::Random;  return true; }
    if (s == "Special") { out = ReserveSource::Special; return true; }
    if (s == "Dp")      { out = ReserveSource::Dp;      return true; }
    return false;
}

// 当前用哪一类来源。来源是按槽位存的, 这里只是"全池统一"的开关 —— 要换来源就改
// 这一行 (不提供运行期切换: 换了之后池子里已有的队员怎么算, 是另一回事)。
//
// 当前配置 = 3 类 (Dp): 队员从 D:\DpSource32.bin 的源库按槽位游标现取, 库取完
// (或库不在盘上) 就整池逐槽回退随机点。换来源前先确认两件事:
//   1. 源库/已征召库在盘上 (不在就静默回退随机, 见 reserve_load_dp —— 池子照跑,
//      只是又变回"全随机起点");
//   2. D:\RhoReserve.txt 里的 "supply Dp <游标>" 还指得准。游标存的是源库**槽位号**,
//      而源库是离线脚本一次生成的快照 (应用内没有重建入口), 所以重新离线建库之后槽位
//      会整体挪位, 那时要把这个游标清零。
static ReserveSource g_reserve_source = ReserveSource::Dp;

// 给 cuda.cu 的 validate_test 用: 池子里"该不该有队员"随来源变 (1 类不留履历,
// 2/3 类每槽都是队员), 那一段自检不能写死成"全随机池"。
ReserveSource reserve_configured_source() { return g_reserve_source; }

// 2 类来源的物化库存: 就是步进表 adds_pub[0][*] 那 256 条 (条数由声明数出来)。
// 阶梯 (k*G) 不进这里 —— 它由供应器按需现算, 见 reserve_supply_default。
constexpr size_t RHO_RESERVE_STEPS = sizeof(adds_pub[0]) / sizeof(adds_pub[0][0]);
// 3 类来源的库存: 32 位 DP 的**源库** (DpSource32.bin, 格式见 common.h)。库存不物化
// 进内存 —— 按槽位游标在库里现取, 见 reserve_load_dp / reserve_take。

// 预备队的**进程级状态**落盘路径 (货源游标 + 账本, 格式见下面的存档一节)。
// 只有生产路径 (rho_play) 读写它, validate 一律不碰。
static const std::string RHO_RESERVE_STATE_FILE = "D:\\RhoReserve.txt";

// 一位预备队员的履历。只有 source != Random 才建 (1 类不需要账本)。
struct ReserveMember {
    size_t        slot = 0;            // 入池时占的槽位
    ReserveSource source = ReserveSource::Random;
    RhoPoint      point;               // 入池的点 (x 与 m/n 自洽)
    uint64_t      placed_round = 0;    // 第几轮入池 (轮号从 1 起)
    bool          drafted = false;     // 有没有被征调过
    uint64_t      drafted_round = 0;
};

// 供应器: 按需给池子供点。取不到 (库存耗尽 / 点不自洽) 返回 false, 池子回退随机点。
// 做成函数指针是为了 validate 能塞一个合成供应器, 把状态转移直接逼出来。
using ReserveSupplyFn = bool (*)(ReserveSource src, RhoPoint& out);

// 库存。游标只增不减: 用过的点不再回收 (见上面第 (i) 条理由)。只存 (m, n) 标量对
// —— x 等到真正入池时再算 (create), 免得为一条只用一次的点提前付标量乘法的代价。
//
// 三种形态共用**同一个游标**, 不另存"阶梯走到第几级""取到库里第几条"这类状态:
//   from_lib == true       源库段 (3 类): 库存不物化, 游标就是 32 位 DP 源库的**槽位
//                          号**, 每次现查下一条活记录 (墓碑跳过)。
//   cursor <  list.size()  物化段: 事先备好的有限清单 (2 类 = adds_pub 那 256 条),
//                          直接按游标取。
//   cursor >= list.size()  阶梯段: 只有 ladder == true 的供应器有 (2 类)。**不物化**
//                          而是现算, 级数 k = cursor - list.size() + 1 直接由游标推出来
//                          —— 于是阶梯没有上限, 2 类来源不存在"用完"这回事。
//   ladder == false        取完物化段就真没有了, 池子回退随机点。
struct ReserveSupply {
    std::vector<SecPair> list;
    size_t   cursor = 0;        // 已取条数 (源库段: 源库槽位号); 越过 list.size() 就进阶梯
    bool     ladder = false;    // 物化段取完之后是否接无限阶梯
    bool     from_lib = false;  // 3 类: 库存不在内存里, 直接查 32 位 DP 源库
    bool     tried = false;
};

static ReserveSupply g_supply_special;
static ReserveSupply g_supply_dp;
// 是否读写状态存档 = 是不是生产路径 (只有 rho_play 打开; validate 一律不碰盘)。
static bool g_reserve_persistent = false;

// 十六进制 -> 字节。本翻译单元不引 util/strencodings.h (那是 bitcoin 的头, 与这里
// 的 secp256k1 内部头部混在一起容易打架), 所以自带一个只认定长十六进制的小解析器。
static bool reserve_hex_to_bytes(const std::string& s, unsigned char* out, size_t n)
{
    if (s.size() != n * 2) return false;
    const auto nib = [](char c) -> int {
        if (c >= '0' && c <= '9') return c - '0';
        if (c >= 'a' && c <= 'f') return c - 'a' + 10;
        if (c >= 'A' && c <= 'F') return c - 'A' + 10;
        return -1;
    };
    for (size_t i = 0; i < n; ++i) {
        const int hi = nib(s[2 * i]);
        const int lo = nib(s[2 * i + 1]);
        if (hi < 0 || lo < 0) return false;
        out[i] = (unsigned char)((hi << 4) | lo);
    }
    return true;
}

// 反过来: n 字节 -> 2n 字符小写 hex + 结尾 NUL (写状态存档用)。
static void reserve_hex_from_bytes(const unsigned char* src, size_t n, char* dst)
{
    static const char D[] = "0123456789abcdef";
    for (size_t i = 0; i < n; ++i) {
        *dst++ = D[src[i] >> 4];
        *dst++ = D[src[i] & 0x0F];
    }
    *dst = '\0';
}

// 2 类库存: 只物化步进表那 256 条, 阶梯交给取点函数现算 (见 reserve_take)。
// 注意这里只搬标量, 不现算 x —— 真入池时由 reserve_take 算。
// 按参数装货: validate 用独立实例装一遍做自检, 免得动到生产那份的游标。
// 全局那份只在启动时调一次 (tried 守卫): 重调等于把同一批点又搬一遍。
// **不动 cursor**: 游标是跨进程的生产状态, 由存档回读 (见存档一节), 装货时清零就
// 等于每重启一次把库存头一段重发一遍。
static void reserve_load_special(ReserveSupply& sup)
{
    sup.list.clear();
    sup.list.reserve(RHO_RESERVE_STEPS);
    for (size_t i = 0; i < RHO_RESERVE_STEPS; ++i) {
        // adds_pub[0][i] 的 (x, m, n) 三者自洽 (blockchain.cpp 装载时验过), 所以
        // 一条就是一个可以直接入池的队员。
        SecPair sp;
        memcpy(sp.m, adds_pub[0][i].m, sizeof(sp.m));
        memcpy(sp.n, adds_pub[0][i].n, sizeof(sp.n));
        sup.list.push_back(sp);
    }
    sup.ladder = true;   // 物化段吃完接阶梯 (k 由游标现算)
    sup.tried = true;
    std::cout << get_time() << " : reserve supply Special loaded: " << sup.list.size()
              << " points (adds_pub) + ladder 1G, 2G, 3G, ... on demand (cursor "
              << sup.cursor << ")" << std::endl;
}

// 3 类库存: 32 位 DP 的源库 (DpSource32.bin, 由离线脚本从 data 目录下的
// DistinguishablePoints*.txt 语料合并而来 —— 应用内没有重建入口)。**不物化**: 取点时
// 按槽位游标在库里往前找下一条活记录 (墓碑由 src_next 跳过), 所以磁盘上那 88.7 万条就是
// 库存本身, 而且被征召销账立了墓碑的点自然不会再发出去。
//
// 与 2 类同一约定: 按参数装货, 全局那份只在启动时调一次 (tried 守卫); 不动 cursor ——
// 游标是**生产状态** (这里是源库槽位号), 由存档一节按同一字段存盘。槽位只增不减、
// 墓碑不移位, 所以同一个游标跨进程总指同一条记录。
// 前提: 源库在两次 run 之间没被重建过 (重建会移动槽位; 那之后游标至多指偏 —— 不崩,
// 只是可能重复发出几条已经用过的点)。
static void reserve_load_dp(ReserveSupply& sup)
{
    sup.list.clear();
    sup.ladder = false;    // 3 类没有阶梯: 源库取完就真没了
    sup.from_lib = true;   // 库里现取 (见 reserve_take)
    sup.tried = true;
    // 载入是幂等的: 第一个来取货的地方载入, 载入结果印在控制台上 (见 dp32_store_init)。
    if (!dp32_store_init()) {
        cprint() << get_time() << " : reserve supply Dp: 32 位源库不可用 ("
                 << DP32_SOURCE_FILE << "), 该类回退随机点" << std::endl;
        return;
    }
    const Dp32Store& lib = dp32_store();
    cprint() << get_time() << " : reserve supply Dp: 源库 " << lib.src_count() << " 条 (墓碑 "
             << lib.src_dead_count() << "), 按槽位游标取 (cursor " << sup.cursor << ")"
             << std::endl;
}

// 从一份库存里取下一个没用过的 (m, n) 并现算 x。两段都由**同一个游标**推进:
// 物化段按游标取, 越过 list.size() 之后按 ladder 现算阶梯的第 k = cursor - size + 1 级。
static bool reserve_take(ReserveSupply& sup, RhoPoint& out)
{
    SecPair sp;                    // SecPair 自带 {0} 初值, 阶梯段的 n 天然是 0
    if (sup.from_lib) {
        // 3 类: 源库按槽位取。游标就是槽位号, 只增不减; 墓碑由 src_next 跳过。
        // 库没载入 (文件缺失/损坏) 一律当作"库存为空" -> 池子回退随机点。
        if (sup.cursor > 0xFFFFFFFFULL) return false;   // 存档被改坏了: 别截断成另一个槽位
        const Dp32Store& lib = dp32_store();
        if (!lib.loaded()) return false;
        Dp32Record rec;
        uint32_t slot = (uint32_t)sup.cursor;
        if (!lib.src_next(slot, rec)) return false;     // 源库取完了
        sup.cursor = slot;                              // 推到该槽位之后
        memcpy(sp.m, rec.m, sizeof(sp.m));
        memcpy(sp.n, rec.n, sizeof(sp.n));
    } else if (sup.cursor < sup.list.size()) {
        sp = sup.list[sup.cursor++];
    } else if (sup.ladder) {
        // 阶梯: k = 1, 2, 3, ... 现算 k*G (create(m, n) = m*G + n*MVP, 取 n = 0)。
        // k 不另存, 直接由游标推出来; 游标只增不减, 所以每一级都是新点 (第 (i) 条),
        // 也没有上限。
        const uint64_t k = (uint64_t)(sup.cursor - sup.list.size()) + 1;
        set_int(sp.m, (int64_t)k);
        ++sup.cursor;
    } else {
        return false;   // 物化段取完又没有阶梯 = 真没有了, 池子回退随机点
    }
    // 全零的 (m, n) 会算出一个非法的 x, 而 check() 比的是"自己算出来的那个", 这种
    // 情况它看不出来, 所以这里先挡一道。
    static const unsigned char zeros[32] = {0};
    if (memcmp(sp.m, zeros, 32) == 0 && memcmp(sp.n, zeros, 32) == 0) return false;

    memcpy(out.m, sp.m, sizeof(out.m));
    memcpy(out.n, sp.n, sizeof(out.n));
    create(ctx, &out.x, out.m, out.n);
    return true;
}

// 阶梯段下一级的 k (不在阶梯段则为 0)。这就是"由游标现算"那条规则本身, 抽出来
// 只给日志和自检读。
static uint64_t reserve_next_ladder_k(const ReserveSupply& sup)
{
    if (!sup.ladder || sup.cursor < sup.list.size()) return 0;
    return (uint64_t)(sup.cursor - sup.list.size()) + 1;
}

// 默认供应器: 从对应库存里取下一个点 (首次调用时懒装货)。
static bool reserve_supply_default(ReserveSource src, RhoPoint& out)
{
    if (src == ReserveSource::Special) {
        if (!g_supply_special.tried) reserve_load_special(g_supply_special);
        return reserve_take(g_supply_special, out);
    }
    if (src == ReserveSource::Dp) {
        if (!g_supply_dp.tried) reserve_load_dp(g_supply_dp);
        return reserve_take(g_supply_dp, out);
    }
    return false;   // 随机点不走供应器
}

// 被征召的 3 类队员销账: 这个点已经用掉了 —— 源库里那条立墓碑 + 追加进已征召库。
//
// 两个库记的是**同一批点**: 源库里被立墓碑的那条, 就是已征召库里追加的那条。所以
// 必须一起做 —— 只立墓碑会让这个点从两个库里凭空消失, 只追加会让源库把用过的点再
// 发给下一个 walker。顺序: 先追加, 后立墓碑 (中间崩了记录还在, 能补)。
//
// 判等用队员自己的 x 复算出来的 32 位索引 (源库按索引唯一), 不认别的字段。
// 单线程前提: 只在轮边界调 (note_reserve_dps -> note_drafted), 与 rho_play
// 里其他读写这两个库的代码同线程 (已征召库的桶没有加锁, 见 common.h)。
// who: 销账的是谁 (写生产日志用 —— 两个库的条数变了, 得能回溯是哪个槽位的事)。
enum class RetireResult {
    Done,        // 立了墓碑 + 追加了已征召库
    DryRun,      // 非持久模式 (自测): 绝不碰生产那两个 .bin
    NoLib,       // 库没载入: 降级模式, 槽位本来就回退随机点
    NotDp32,     // 这个点本身不满足 32 位条件: 不可能是源库里的东西 (2 类 / 随机点)
    Absent,      // 源库里没有这个索引
    AlreadyDead, // 库里那条已经是墓碑: 这笔账早销过了 (幂等命中, 正常)
    ReadFail,    // 读不出源库那条记录
    WriteFail,   // 已征召库追加不上, 什么都没改
};

// 日志里"这一笔账"的说法。Done 之外的都带上原因 —— 只印一句"没销账"看不出是幂等
// 命中 (正常) 还是"这个点根本不在源库里" (说明取点那条路出了问题)。
static const char* retire_result_note(RetireResult r)
{
    switch (r) {
    case RetireResult::Done:        return " [源库立墓碑 + 已征召库追加]";
    case RetireResult::DryRun:      return " [自测模式, 不碰两个库]";
    case RetireResult::NoLib:       return " [源库未载入, 不销账]";
    case RetireResult::NotDp32:     return " [不是 32 位点, 不销账]";
    case RetireResult::Absent:      return " [源库里没有这个点, 不销账]";
    case RetireResult::AlreadyDead: return " [源库里那条已是墓碑, 早销过账]";
    case RetireResult::ReadFail:    return " [源库那条读不出来, 不销账]";
    case RetireResult::WriteFail:   return " [已征召库写盘失败, 不销账]";
    }
    return "";
}

static RetireResult retire_dp_member(const RhoPoint& p, const std::string& who)
{
    if (!g_reserve_persistent) return RetireResult::DryRun;   // 自测一律不动真库
    Dp32Store& lib = dp32_store();
    if (!lib.loaded()) return RetireResult::NoLib;
    uint64_t idx32 = 0;
    if (!dp32_test(p.x, idx32)) return RetireResult::NotDp32;     // 复算不上 32 位点
    uint32_t slot = 0;
    const Dp32Hit hit = lib.src_find(idx32, slot);
    if (hit == Dp32Hit::Absent) return RetireResult::Absent;
    if (hit == Dp32Hit::Tombstone) return RetireResult::AlreadyDead;
    Dp32Record rec;
    if (!lib.read(Dp32File::Source, slot, rec)) return RetireResult::ReadFail;
    if (!lib.drf_append(idx32, rec.m, rec.n)) return RetireResult::WriteFail;
    lib.src_tombstone(slot);                                  // 先追加后立墓碑
    ilog_line("Dp32 征召销账: " + who + " -> 源库槽位 " + std::to_string(slot) +
              " 立墓碑 + 已征召库追加 (源库墓碑 " + std::to_string(lib.src_dead_count()) +
              " 条 / 已征召库 " + std::to_string(lib.drf_count()) + " 条)");
    return RetireResult::Done;
}

// 落盘的那两样"货源游标" (= ReserveSupply::cursor 本身, 与装没装货无关)。
struct ReserveCursors {
    uint64_t special = 0;
    uint64_t dp = 0;
};

// 预备队账本。只跑在主机侧, 设备端看不见它 —— 设备端只需要 RhoStates_reserve
// 这份常量内存, 以及"DP 记录的下标就是被征调的槽位"这条对应关系。
class ReservePool
{
public:
    ReservePool(size_t slots, ReserveSource src = ReserveSource::Random,
                ReserveSupplyFn fn = reserve_supply_default)
        : slot_source_(slots, src),
          slot_serial_(slots, RESERVE_NONE),
          slot_point_(slots),
          members_(1),                          // 0 号是哨兵, 不指向任何队员
          supply_(fn)
    {
    }

    // 每轮开跑前调用一次: 决定各槽位这一轮放什么点 (纯主机侧, 不碰设备内存)。
    void begin_round()
    {
        ++round_;
        for (size_t i = 0; i < slot_source_.size(); ++i) {
            const ReserveSource src = slot_source_[i];
            const uint64_t serial = slot_serial_[i];
            const bool have = (serial != RESERVE_NONE);

            // 这个槽位要不要换点:
            //   Random      -> 每轮都换 (老行为: 110 个槽位每轮全是新随机点)
            //   Special/Dp  -> 只在"还没有队员"或"队员已被征调"时换。没被征调过的点
            //                  继续留用 (无限期), 既没浪费库存, 也不必凭空多一条履历。
            if (src != ReserveSource::Random && have && !members_[serial].drafted) continue;

            if (have && members_[serial].drafted) {
                std::cout << get_time() << " : reserve: slot " << i << " replenished (member #"
                          << serial << " retired, drafted in round "
                          << members_[serial].drafted_round << ")" << std::endl;
            }

            RhoPoint p;
            if (src == ReserveSource::Random) {
                p.rand();
                place(i, ReserveSource::Random, p);
                continue;
            }

            // 2、3 类: 先跟供应器要, 要不到就**永久**回退成随机点。永久而不是每轮
            // 重试, 是因为库存游标只增不减 —— 重试不会有新结果, 只会每轮刷同一行日志。
            if (supply_(src, p) && check(ctx, &p.x, p.m, p.n) == 1) {
                place(i, src, p);
            } else {
                std::cout << get_time() << " : reserve: no more " << reserve_source_name(src)
                          << " supply for slot " << i << ", falls back to random" << std::endl;
                slot_source_[i] = ReserveSource::Random;
                p.rand();
                place(i, ReserveSource::Random, p);
            }
        }
    }

    size_t               size() const { return slot_point_.size(); }
    const RhoPoint&      point(size_t i) const { return slot_point_[i]; }
    ReserveSource        source_of(size_t i) const { return slot_source_[i]; }
    uint64_t             serial_of(size_t i) const { return slot_serial_[i]; }
    uint64_t             round() const { return round_; }
    const ReserveMember& member(uint64_t serial) const { return members_[serial]; }
    size_t               member_count() const { return members_.size(); }

    // ---- 只有回读状态存档时才用 (见存档一节) ----
    void set_round(uint64_t r) { round_ = r; }
    void set_slot_source(size_t i, ReserveSource src) { slot_source_[i] = src; }
    // 把一位"留用队员"放回槽位 i, 并补一条履历。点是存档里读回来的 (m, n), x 由
    // 调用方现算并验过, 所以这里只认账。
    void restore_member(size_t i, ReserveSource src, const RhoPoint& p, uint64_t placed_round)
    {
        slot_source_[i] = src;
        slot_point_[i] = p;
        members_.push_back(ReserveMember());
        ReserveMember& m = members_.back();
        m.slot = i;
        m.source = src;
        m.point = p;
        m.placed_round = placed_round;
        slot_serial_[i] = (uint64_t)(members_.size() - 1);
    }

    // 记账: 记录下标 j 就是被征调的槽位。随机点占位的槽位没有队员, 直接跳过;
    // 已经登记过的队员不重复记 (同一轮同一槽位只会被征调一次, 但这里不依赖它)。
    void note_drafted(size_t j)
    {
        const uint64_t serial = slot_serial_[j];
        if (serial == RESERVE_NONE) return;
        ReserveMember& m = members_[serial];
        if (m.drafted) return;
        m.drafted = true;
        m.drafted_round = round_;
        // 3 类队员的点是从源库取出来的: "被征召" = 这个点用掉了, 所以源库那条立墓碑 +
        // 追加进已征召库 (两个库记同一批点, 见 retire_dp_member)。2 类的货源是 adds_pub
        // 那 256 条, 库里没有它们的记录, 不销账。
        const char* acct = "";
        if (m.source == ReserveSource::Dp) {
            const std::string who = "预备队员 #" + std::to_string(serial) + " (槽位 " +
                                    std::to_string(j) + ") 被征召";
            acct = retire_result_note(retire_dp_member(m.point, who));
        }
        std::cout << get_time() << " : reserve: member #" << serial
                  << " (slot " << j << ", " << reserve_source_name(m.source)
                  << ") drafted in round " << round_ << acct << std::endl;
    }

private:
    // 把点放进槽位 i。src == Random 时不留履历 (1 类不需要账本)。
    void place(size_t i, ReserveSource src, const RhoPoint& p)
    {
        slot_point_[i] = p;
        if (src == ReserveSource::Random) {
            slot_serial_[i] = RESERVE_NONE;
            return;
        }
        members_.push_back(ReserveMember());
        ReserveMember& m = members_.back();
        m.slot = i;
        m.source = src;
        m.point = p;
        m.placed_round = round_;
        slot_serial_[i] = (uint64_t)(members_.size() - 1);
    }

    std::vector<ReserveSource> slot_source_;   // 槽位 -> 配的来源 (耗尽后会被改成 Random)
    std::vector<uint64_t>      slot_serial_;   // 槽位 -> 当前队员流水号 (0 = 无队员)
    std::vector<RhoPoint>      slot_point_;    // 槽位 -> 待上传的点
    std::vector<ReserveMember> members_;       // 流水号 -> 履历 (0 号哨兵)
    ReserveSupplyFn            supply_;
    uint64_t                   round_ = 0;
};

// 生产用的账本。建一次, 之后一直复用 —— 轮号与履历都必须跨轮存活。槽位数 = 设备
// DP 缓冲区的槽位数, 由 rho_play 传进来 (dp_buffer_size 定义在 cuda.cu 里)。
static ReservePool* g_reserve_pool = nullptr;
// g_reserve_persistent 定义在上面货源一节 (自测要不要写生产日志也看它)。

// ============================ 进程级状态落盘 ============================
//
// 为什么必须落盘: "点用过即退役"完全靠库存游标保证 (第 (i) 条), 而游标原本只在内存里
// —— 进程一重启就归零, 头几批点跟上一次 run **逐字节重复**。重复的危害不是多算了几条
// ——两者算出来的 x 完全相同, 于是 DP 记录里 m/n 也完全相同, 而碰撞要的是"同一个 x
// 配不同的 (m, n)", 这种记录一条都排不上用场, 纯属白烧算力。留用队员同理: 不落盘就
// 等于每次重启都把整池还没用上的点丢掉重抽。
//
// 存档 (纯文本, D:\RhoReserve.txt, 每轮 rho_play 落一次):
//     RhoReserve 1                                     版本号, 不认就整份丢掉
//     round <n>                                        当前轮号 (日志轮号跨进程连续)
//     supply <来源名> <游标>                            货源游标 = 已经发出去的条数
//     slots <n>                                        槽位数 (跟 dp_buffer_size 不符就丢)
//     slot <i> <来源> empty                            空槽 (队外随机 / 待补员 / 已退役)
//     slot <i> <来源> held <入池轮号> <m-hex> <n-hex>    留用队员 (m/n 各 64 字符 hex)
//
// 只存"还没被征调过"的队员: 被征调过的槽位下一轮 begin_round 一定会换新点, 存了也用
// 不上。x 不存, 回读时由 (m, n) 用 create() 现算, 顺带立刻 check() 一遍 —— 存档小一半,
// 还把"标量 -> 点"的口径验了一次。
//
// 游标存的是 ReserveSupply::cursor 本身, 与供应器装没装货无关 (装货不动游标), 所以
// 换来源跑一轮再换回来, 进度也不会丢。

// 当前该落盘的游标。
static void reserve_cursors(ReserveCursors& out)
{
    out.special = g_supply_special.cursor;
    out.dp = g_supply_dp.cursor;
}

// 落盘。先写临时文件再 rename —— 存档自己若被写到一半打断就报废, 那它防的"意外关机"
// 就白防了。Windows 上 rename 不覆盖已存在的目标, 所以先撞一次, 撞不动再删一次重试。
static bool reserve_state_write(const ReservePool& pool, const ReserveCursors& cur,
                                const std::string& path)
{
    const std::string tmp = path + ".tmp";
    {
        std::ofstream out(tmp, std::ios::trunc);
        if (!out.is_open()) {
            std::cout << get_time() << " : reserve state: cannot write " << tmp << std::endl;
            return false;
        }
        out << "RhoReserve 1\n";
        out << "round " << pool.round() << '\n';
        out << "supply Special " << cur.special << '\n';
        out << "supply Dp " << cur.dp << '\n';
        out << "slots " << pool.size() << '\n';
        for (size_t i = 0; i < pool.size(); ++i) {
            const uint64_t serial = pool.serial_of(i);
            out << "slot " << i << ' ' << reserve_source_name(pool.source_of(i)) << ' ';
            if (serial == RESERVE_NONE || pool.member(serial).drafted) {
                out << "empty\n";
                continue;
            }
            const ReserveMember& m = pool.member(serial);
            char hex_m[65];
            char hex_n[65];
            reserve_hex_from_bytes(m.point.m, sizeof(m.point.m), hex_m);
            reserve_hex_from_bytes(m.point.n, sizeof(m.point.n), hex_n);
            out << "held " << m.placed_round << ' ' << hex_m << ' ' << hex_n << '\n';
        }
        out.flush();
        if (!out) return false;
    }
    if (std::rename(tmp.c_str(), path.c_str()) != 0) {
        std::remove(path.c_str());
        if (std::rename(tmp.c_str(), path.c_str()) != 0) {
            std::cout << get_time() << " : reserve state: cannot replace " << path << std::endl;
            std::remove(tmp.c_str());
            return false;
        }
    }
    return true;
}

// 回读。任何一处不合 (版本号不认 / 槽位数不符 / 下标越界 / hex 长度不对 / 来源名不认 /
// 点不自洽) 都整份放弃 —— 存档担的是"别重复用点", 不该把一次坏存档变成一次崩溃, 或者
// 更糟: 变成一批错点。所以宁可从头开始 (游标归 0, 重新发一遍), 也不"尽力恢复"。
static bool reserve_state_read(ReservePool& pool, const std::string& path, ReserveCursors& cur)
{
    std::ifstream in(path);
    if (!in.is_open()) return false;

    const auto discard = [&](const char* why) -> bool {
        std::cout << get_time() << " : reserve state: discarded (" << why
                  << "), starting fresh" << std::endl;
        return false;
    };

    std::string line;
    if (!std::getline(in, line) || line != "RhoReserve 1") return discard("header");

    bool have_round = false;
    bool have_slots = false;
    uint64_t round = 0;
    while (std::getline(in, line)) {
        if (line.empty()) continue;
        std::istringstream ls(line);
        std::string what;
        if (!(ls >> what)) continue;
        if (what == "round") {
            if (!(ls >> round)) return discard("round");
            have_round = true;
        } else if (what == "supply") {
            std::string name;
            uint64_t cursor = 0;
            if (!(ls >> name >> cursor)) return discard("supply");
            if (name == "Special") {
                cur.special = cursor;
            } else if (name == "Dp") {
                cur.dp = cursor;
            } else {
                return discard("supply name");
            }
        } else if (what == "slots") {
            size_t slots = 0;
            if (!(ls >> slots)) return discard("slots");
            // 槽位数=设备 DP 缓冲区大小 (dp_buffer_size)。对不上说明这份存档来自另一套
            // 配置, 下标全都不作数了。
            if (slots != pool.size()) return discard("slots mismatch");
            have_slots = true;
        } else if (what == "slot") {
            size_t i = 0;
            std::string src_name;
            std::string state;
            if (!(ls >> i >> src_name >> state)) return discard("slot");
            if (i >= pool.size()) return discard("slot index");
            ReserveSource src = ReserveSource::Random;
            if (!reserve_source_by_name(src_name, src)) return discard("slot source");
            if (state == "empty") {
                pool.set_slot_source(i, src);
                continue;
            }
            if (state != "held") return discard("slot state");
            uint64_t placed = 0;
            std::string hex_m;
            std::string hex_n;
            if (!(ls >> placed >> hex_m >> hex_n)) return discard("held fields");
            RhoPoint p;
            if (!reserve_hex_to_bytes(hex_m, p.m, sizeof(p.m))) return discard("m hex");
            if (!reserve_hex_to_bytes(hex_n, p.n, sizeof(p.n))) return discard("n hex");
            // 全零的 (m, n) 算出来是个非法点, 而 check() 比的是"照 m/n 现算的那个 x"
            // —— 它自己算的自己, 这种情况看不出来 (reserve_take 里有同一道挡)。
            // 合法存档不会有这种条目, 只有手改出来的才有。
            static const unsigned char zero32[32] = {0};
            if (memcmp(p.m, zero32, sizeof(zero32)) == 0 &&
                memcmp(p.n, zero32, sizeof(zero32)) == 0) {
                return discard("zero point");
            }
            create(ctx, &p.x, p.m, p.n);
            if (check(ctx, &p.x, p.m, p.n) != 1) return discard("point");
            pool.restore_member(i, src, p, placed);
        } else {
            return discard("unknown key");
        }
    }
    if (!have_round || !have_slots) return discard("missing fields");
    pool.set_round(round);
    return true;
}

// 只有持久化模式才调 (启动时一次)。回读成功就把游标交回给全局供应器 —— 游标是"生产
// 状态", 供应器装货时不动它, 所以这里直接赋值即可。返回 false 时池子可能已经被塞进
// 半份旧状态, 由调用方重建。
static bool reserve_state_restore(ReservePool& pool)
{
    ReserveCursors cur;
    if (!reserve_state_read(pool, RHO_RESERVE_STATE_FILE, cur)) return false;
    g_supply_special.cursor = cur.special;
    g_supply_dp.cursor = cur.dp;
    std::cout << get_time() << " : reserve state restored from " << RHO_RESERVE_STATE_FILE
              << ": round " << pool.round() << ", " << (pool.member_count() - 1)
              << " held members, cursor Special " << cur.special << ", Dp " << cur.dp
              << std::endl;
    return true;
}

void init_reserve_pool(size_t slots, bool persistent)
{
    delete g_reserve_pool;
    g_reserve_pool = new ReservePool(slots, g_reserve_source);
    g_reserve_persistent = persistent;
    if (!persistent) return;

    // 回读失败 (存档不存在 / 坏掉) 时 reserve_state_read 可能已经往池子里塞了半份,
    // 所以整份丢掉重建 —— 要么是整份旧状态, 要么是干净起点, 不留半真半假的中间态。
    if (!reserve_state_restore(*g_reserve_pool)) {
        std::cout << get_time() << " : reserve state: starting fresh (no usable archive at "
                  << RHO_RESERVE_STATE_FILE << ")" << std::endl;
        delete g_reserve_pool;
        g_reserve_pool = new ReservePool(slots, g_reserve_source);
    }
}

// 落一次盘 (每轮 loop 末了一次, 紧跟 note_reserve_dps)。
void save_reserve_state()
{
    if (g_reserve_pool == nullptr || !g_reserve_persistent) return;
    ReserveCursors cur;
    reserve_cursors(cur);
    reserve_state_write(*g_reserve_pool, cur, RHO_RESERVE_STATE_FILE);
}

// 重填预备队 (每轮 loop 开跑前一次): 账本补员 (主机侧) + 整块上传 (设备常量内存)。
void init_RhoStates_reserve()
{
    if (g_reserve_pool == nullptr) init_reserve_pool(0);
    g_reserve_pool->begin_round();
    std::vector<RhoPoint> staging(g_reserve_pool->size());
    for (size_t i = 0; i < staging.size(); ++i) staging[i] = g_reserve_pool->point(i);
    upload_RhoStates_reserve(staging.data(), staging.size());
}

// 账本记账: 这一轮设备写出去 dp_count 条 DP 记录。记录下标 j 就是被征调的槽位 ——
// add_dp_to_buffer 里 r = RhoStates_reserve[index], 而 index 同时就是 buffer 下标,
// 所以设备端不需要额外回传任何东西, 只要记录条数。
void note_reserve_dps(unsigned int dp_count)
{
    if (g_reserve_pool == nullptr) return;
    for (unsigned int j = 0; j < dp_count; ++j) {
        // index 可以超出槽位数 (add_dp_to_buffer 先写入再判 break, 最多超 W-1 项),
        // 那些超界的记录只是写进了备用项, 没有槽位对应, 自然不记账。
        if (j >= g_reserve_pool->size()) break;
        g_reserve_pool->note_drafted(j);
    }
}

// 载入存档之后的对账: 把"游标已经推过、当前又不在池子里"的那几条源库记录销账。
//
// 为什么需要它: 被征召过的队员不进存档 (reserve_state_write 只存"还没被征调过"的),
// 所以一个点被征召之后留下的只有"游标推过去了"这一个痕迹。销账本身是随每轮 rho_play
// 现做的 (retire_dp_member), 而这一步在旧版代码里根本没有, 中途崩在"征召了但还没落盘"
// 之间也一样会漏。所以载完存档按同一个口径补一次:
//
//   源库槽位号 < 游标 且 池子里没有队员占着这个点 且 库里那条还是活的 ⇒ 立墓碑 + 追加
//
// 槽位号 < 游标 = 这个槽位已经被取出去过; 池子里没队员占着 = 那位队员已经退役 (被征召);
// 库里还是活的 = 这笔账还没销过 (上一轮销掉的那些已是墓碑, 跳过)。三条合起来,
// 剩下的正好就是"取出去又被征召掉、还没销账"的点。幂等: 销过账的下次不再进来。
// 库没载入 / 没回过存档 (非持久模式) / 存档游标与库对不上 (库被重建过) ⇒ 什么都不做。
//
// ⚠ "池子里有没有队员占着"**只能按点判, 不能按槽位号判** —— 池子槽位号和源库槽位号
// 是两套编号, 只在最开始重合: 队员被征召后空出来的池子槽位 i 会被**下一个**取出来的
// 点填上, 而下一个点来自源库槽位 j (j 一般 != i)。实测池子槽位 1 装的就是源库槽位 112
// 的点。早先按号对号的那一版两个方向都错: 把"还占着"的 112 误销成墓碑 (点还在池子里
// 用), 又漏掉了"真没占"的 1。所以改成按点判: 拿每个队员占着的 x 复算出 32 位索引,
// 回源库查出它的槽位号 (墓碑也算占着 —— 点还在池子里), 标进位图; 游标以内没被标到的,
// 才是真没占的。
void reserve_retire_consumed()
{
    if (g_reserve_pool == nullptr || !g_reserve_persistent) return;
    Dp32Store& lib = dp32_store();
    if (!lib.loaded()) return;
    const uint64_t cursor = g_supply_dp.cursor;
    if (cursor > lib.src_count()) return;   // 库被重建过: 槽位号已经不作数, 宁可不动账
    if (cursor == 0) return;                // 游标还没推过: 一个点都没取

    std::vector<char> held((size_t)cursor, 0);
    for (size_t j = 0; j < g_reserve_pool->size(); ++j) {
        if (g_reserve_pool->serial_of(j) == RESERVE_NONE) continue;   // 随机点占位
        uint64_t idx32 = 0;
        if (!dp32_test(g_reserve_pool->point(j).x, idx32)) continue;  // 不是源库里的点
        uint32_t slot = 0;
        if (lib.src_find(idx32, slot) == Dp32Hit::Absent) continue;
        if (slot < cursor) held[(size_t)slot] = 1;   // 这条还在池子里用着
    }

    uint64_t retired = 0;
    for (uint64_t s = 0; s < cursor; ++s) {
        if (held[(size_t)s]) continue;          // 有队员占着: 这个点还没被征召
        Dp32Record rec;
        if (!lib.read(Dp32File::Source, (uint32_t)s, rec)) continue;
        if (dp32_is_tombstone(rec)) continue;   // 已经销过账
        RhoPoint p;
        memcpy(p.m, rec.m, sizeof(p.m));
        memcpy(p.n, rec.n, sizeof(p.n));
        create(ctx, &p.x, p.m, p.n);
        const std::string who = "源库槽位 " + std::to_string(s) +
                                " (游标已推过, 池子里没队员占着: 载档补账)";
        if (retire_dp_member(p, who) == RetireResult::Done) ++retired;
    }
    if (retired != 0) {
        cprint() << get_time() << " : reserve: 补齐 " << retired
                 << " 个已征召但没销账的 3 类队员 (源库立墓碑 + 已征召库追加), 源库墓碑 "
                 << lib.src_dead_count() << " 条 / 已征召库 " << lib.drf_count() << " 条"
                 << std::endl;
    }
}

// 槽位当前有没有队员 (随机点占位 = 没有)。validate 用它, 生产代码不用。
bool reserve_slot_tracked(size_t slot)
{
    return g_reserve_pool != nullptr && slot < g_reserve_pool->size() &&
           g_reserve_pool->serial_of(slot) != RESERVE_NONE;
}

// ===========================================================================
// 验证 (由 cuda.cu 的 validate_test 调用; 纯主机侧, 不碰 GPU)
// ===========================================================================

// 本文件不引 cuda.cu 的 HOST_ASSERT, 自己来一个同语义的 (打印表达式 + 位置后退出)。
#define RESERVE_CHECK(cond) \
    do { \
        if (!(cond)) { \
            std::cout << "reserve check FAILED: " << #cond << " (" << __LINE__ << ")" \
                      << std::endl; \
            exit(EXIT_FAILURE); \
        } \
    } while (0)

// 账本状态机的自测。
//
// 关键转移在真实运行里"上千轮才走一步" (DP 平均 2^40 步, 一轮才 2^26), 生产里等不
// 出来, 所以这里塞一个合成供应器和合成记录条数, 把转移直接逼出来:
//   (a) 没被征调过的槽位不补员 -> 跨轮原样保留 (不整池乱换, 无限期留用)
//   (b) 被征调过的槽位补员     -> 换新队员, 老队员退役但履历留着
//   (c) 库存耗尽               -> 该槽位永久回退随机点, 且不留履历
//   (d) 随机点占位的槽位不进账本
void validate_reserve_pool_state()
{
    // 合成库存: 给 32 条就够这几轮用 (逼出"库存耗尽"的那条另开一个小池子验)。
    const auto supply = [](ReserveSource, RhoPoint& out) -> bool {
        static int fed = 0;
        if (fed >= 32) return false;
        ++fed;
        out.rand();
        return true;
    };

    constexpr size_t SLOTS = 4;
    ReservePool pool(SLOTS, ReserveSource::Special, supply);

    // ---- 第 1 轮: 4 个槽位都还没有队员 -> 全部入池, 各建一条履历 ----
    pool.begin_round();
    RESERVE_CHECK(pool.round() == 1);
    const uint64_t s0 = pool.serial_of(0);
    const uint64_t s1 = pool.serial_of(1);
    const uint64_t s2 = pool.serial_of(2);
    const uint64_t s3 = pool.serial_of(3);
    RESERVE_CHECK(s0 != RESERVE_NONE && s1 != RESERVE_NONE && s2 != RESERVE_NONE &&
                  s3 != RESERVE_NONE);
    RESERVE_CHECK(pool.member_count() == 5);   // 4 位队员 + 0 号哨兵
    RESERVE_CHECK(pool.member(s0).source == ReserveSource::Special);
    RESERVE_CHECK(pool.member(s0).placed_round == 1);
    RESERVE_CHECK(pool.member(s0).slot == 0);
    RESERVE_CHECK(!pool.member(s0).drafted);

    // ---- 第 1 轮的 DP: 4 条记录 -> 记录下标 0/1/2/3 = 4 个槽位各征调一位 ----
    for (size_t j = 0; j < SLOTS; ++j) pool.note_drafted(j);
    RESERVE_CHECK(pool.member_count() == 5);   // 征调本身不新增履历
    RESERVE_CHECK(pool.member(s0).drafted && pool.member(s1).drafted &&
                  pool.member(s2).drafted && pool.member(s3).drafted);
    RESERVE_CHECK(pool.member(s0).drafted_round == 1);

    // ---- 第 2 轮: 4 个槽位都被征调过 -> 全部补员, 老队员退役 (履历还在) ----
    pool.begin_round();
    RESERVE_CHECK(pool.round() == 2);
    const uint64_t s0b = pool.serial_of(0);
    const uint64_t s1b = pool.serial_of(1);
    RESERVE_CHECK(s0b != RESERVE_NONE && s0b != s0);
    RESERVE_CHECK(s1b != RESERVE_NONE && s1b != s1);
    RESERVE_CHECK(pool.serial_of(2) != s2 && pool.serial_of(3) != s3);
    RESERVE_CHECK(pool.member_count() == 9);       // 哨兵 + 4 位老队员 + 4 位新队员
    RESERVE_CHECK(pool.member(s0b).placed_round == 2);
    RESERVE_CHECK(pool.member(s0).drafted);        // 履历留着

    // ---- 第 2 轮的 DP: 只有 1 条记录 -> 只征调槽位 0 ----
    pool.note_drafted(0);
    RESERVE_CHECK(pool.member(s0b).drafted);
    RESERVE_CHECK(!pool.member(s1b).drafted);

    // ---- 第 3 轮: 只有槽位 0 补员; 1/2/3 没被征调过 -> 原样保留 (无限期留用) ----
    pool.begin_round();
    RESERVE_CHECK(pool.round() == 3);
    RESERVE_CHECK(pool.serial_of(0) != s0b);
    RESERVE_CHECK(pool.serial_of(1) == s1b);
    RESERVE_CHECK(pool.member_count() == 10);      // 只多了槽位 0 的新队员
    RESERVE_CHECK(pool.member(pool.serial_of(0)).placed_round == 3);
    RESERVE_CHECK(pool.member(s1b).placed_round == 2);

    // ---- 库存耗尽: 供应器直接说"没有了" -> 槽位**永久**回退随机点, 不留履历 ----
    {
        ReservePool p2(2, ReserveSource::Dp,
                       [](ReserveSource, RhoPoint&) -> bool { return false; });
        p2.begin_round();
        RESERVE_CHECK(p2.serial_of(0) == RESERVE_NONE);
        RESERVE_CHECK(p2.serial_of(1) == RESERVE_NONE);
        RESERVE_CHECK(p2.source_of(0) == ReserveSource::Random);   // 已永久回退
        RESERVE_CHECK(p2.member_count() == 1);                     // 只有哨兵
        p2.begin_round();
        RESERVE_CHECK(p2.source_of(0) == ReserveSource::Random);
        RESERVE_CHECK(p2.source_of(1) == ReserveSource::Random);
        RESERVE_CHECK(p2.member_count() == 1);
    }

    // ---- 随机点占位的槽位不进账本: 记录落在随机槽位的下标上, 什么都不记 ----
    {
        ReservePool p3(2, ReserveSource::Random);
        p3.begin_round();
        p3.note_drafted(0);
        RESERVE_CHECK(p3.member_count() == 1);
        RESERVE_CHECK(p3.serial_of(0) == RESERVE_NONE);
    }

    std::cout << "reserve pool state machine: ok (draft / replenish / exhausted / random)"
              << std::endl;
}

// 两类真货源各装一次货, 并抽样确认"标量 -> 点"的换算口径没跑偏。
// 装货本身只搬标量 (x 等真正入池时再算), 所以很便宜。
//
// ⚠ 这里一律用**独立实例**装货自检, 不碰全局供应器: 全局那份的游标是**生产状态**,
// 来源配成 2/3 类时, 上面 init_RhoStates_reserve 已经把整池灌满, 游标早就不是 0 了
// (写死"刚装好"的断言等于假定池子必为随机)。
void validate_reserve_supplies()
{
    ReserveSupply sup;
    reserve_load_special(sup);
    // 物化段只有 adds_pub 那 256 条; 阶梯不预生成, 游标停在物化段开头。
    RESERVE_CHECK(sup.list.size() == RHO_RESERVE_STEPS);
    RESERVE_CHECK(sup.cursor == 0);
    RESERVE_CHECK(reserve_next_ladder_k(sup) == 0);   // 还在物化段, 没进阶梯

    // 取点函数从物化段抽一条: 现算的 x 也得自洽 (check 拿 m/n 重算并与 x 对拍)。
    {
        RhoPoint p;
        RESERVE_CHECK(reserve_take(sup, p));
        RESERVE_CHECK(check(ctx, &p.x, p.m, p.n) == 1);
        RESERVE_CHECK(sup.cursor == 1);                   // 只增不减
        RESERVE_CHECK(reserve_next_ladder_k(sup) == 0);   // 还没进阶梯
    }

    // 阶梯段: 把游标一次推过物化段, 连抽三级 (k = 1, 2, 3), 验"k 由游标现算"、
    // set_int 的大端字节序、"n = 0 就得到 k*G"的口径、以及游标只增不减 (第 (i) 条:
    // 点不重复)。"create(1,0) 就是设备常量里的 G"那条对拍要拿设备常量比, 放在 cuda.cu。
    {
        sup.cursor = sup.list.size();
        for (unsigned char k = 1; k <= 3; ++k) {
            RhoPoint p;
            RESERVE_CHECK(reserve_next_ladder_k(sup) == k);   // 级数就是游标算出来的
            RESERVE_CHECK(reserve_take(sup, p));
            RESERVE_CHECK(check(ctx, &p.x, p.m, p.n) == 1);
            RESERVE_CHECK(p.m[31] == k && p.m[30] == 0);   // 大端: k 落在最后一个字节
            for (int i = 0; i < 32; ++i) RESERVE_CHECK(p.n[i] == 0);   // n = 0 -> k*G
            RESERVE_CHECK(sup.cursor == sup.list.size() + k);
        }
        RESERVE_CHECK(reserve_next_ladder_k(sup) == 4);
    }

    std::cout << get_time() << " : reserve supply Special: " << sup.list.size()
              << " points (adds_pub) + ladder on demand (k from cursor), next ladder k = "
              << reserve_next_ladder_k(sup) << std::endl;

    // 3 类来源靠外部库存 (32 位 DP 源库): 库不在就只印一行; 在就必须取出下一条活记录,
    // 且现算的 x 与 (m, n) 自洽、确实是 32 位可区分点。
    ReserveSupply dp;
    reserve_load_dp(dp);
    RESERVE_CHECK(!dp.ladder);            // 3 类没有阶梯, 取完就是取完
    RESERVE_CHECK(dp.cursor == 0);
    RESERVE_CHECK(dp.tried);              // 装货只做一次 (tried 守卫)
    if (dp32_store().loaded() && dp32_store().src_count() > dp32_store().src_dead_count()) {
        RhoPoint p;
        RESERVE_CHECK(reserve_take(dp, p));
        RESERVE_CHECK(check(ctx, &p.x, p.m, p.n) == 1);
        RESERVE_CHECK(dp.cursor > 0);                    // 游标 = 槽位号, 只增不减
        RESERVE_CHECK(reserve_next_ladder_k(dp) == 0);   // 没有阶梯 -> 永远是 0
        uint64_t idx = 0;
        RESERVE_CHECK(dp32_test(p.x, idx));              // 源库里的记录都是 32 位 DP
        cprint() << get_time() << " : reserve supply Dp: 源库抽样 ok (取到槽位 "
                 << (dp.cursor - 1) << " 的记录, 32 位索引 " << idx << ")" << std::endl;
    } else {
        cprint() << get_time() << " : reserve supply Dp: 源库不可用, 跳过抽样" << std::endl;
    }
}

// 状态存档自测: 建池 -> 灌满 -> 征调一位 -> 落盘 -> 新池回读 -> 逐项对拍 -> 续跑一轮。
// 用合成供应器 (每槽一个真随机点, 不吃真库存), 写路径 + ".selftest", 绝不碰生产存档
// (D:\RhoReserve.txt)。
void validate_reserve_state_file()
{
    const std::string path = RHO_RESERVE_STATE_FILE + ".selftest";
    const ReserveSupplyFn supply = [](ReserveSource, RhoPoint& out) -> bool {
        out.rand();
        return true;
    };
    const size_t SLOTS = 4;

    // 游标: 假装 2 类已经吃掉 366 条、3 类 7 条。
    ReserveCursors cur;
    cur.special = 366;
    cur.dp = 7;

    ReservePool p1(SLOTS, ReserveSource::Special, supply);
    p1.begin_round();                            // 首轮 -> 4 个槽位都进队员
    RESERVE_CHECK(p1.member_count() == SLOTS + 1);
    p1.note_drafted(2);                          // 只征调槽位 2 -> 存档里它该是 empty
    RESERVE_CHECK(reserve_state_write(p1, cur, path));

    // 回读: 轮号 / 槽位来源 / 留用队员 / 游标 逐项对拍。
    ReservePool p2(SLOTS, ReserveSource::Special, supply);
    ReserveCursors cur2;
    RESERVE_CHECK(reserve_state_read(p2, path, cur2));
    RESERVE_CHECK(cur2.special == 366 && cur2.dp == 7);
    RESERVE_CHECK(p2.round() == p1.round());
    RESERVE_CHECK(p2.member_count() == SLOTS);   // 哨兵 + 3 位留用 (被征调那位不存)
    for (size_t i = 0; i < SLOTS; ++i) {
        RESERVE_CHECK(p2.source_of(i) == p1.source_of(i));
        if (i == 2) {
            RESERVE_CHECK(p2.serial_of(i) == RESERVE_NONE);   // 已退役 -> 下一轮补员
            continue;
        }
        const uint64_t s1 = p1.serial_of(i);
        const uint64_t s2 = p2.serial_of(i);
        RESERVE_CHECK(s2 != RESERVE_NONE);
        RESERVE_CHECK(p2.member(s2).placed_round == p1.member(s1).placed_round);
        RESERVE_CHECK(memcmp(p1.point(i).m, p2.point(i).m, 32) == 0);
        RESERVE_CHECK(memcmp(p1.point(i).n, p2.point(i).n, 32) == 0);
        // x 不落盘, 回读时从 (m, n) 现算 —— 顺手验一下口径没跑偏。
        RESERVE_CHECK(check(ctx, &p2.point(i).x, p2.point(i).m, p2.point(i).n) == 1);
    }

    // 续跑一轮 (就当是重启之后接着跑): 只有被征调过的槽位换新点, 其余原样留用。
    uint64_t kept[4];
    for (size_t i = 0; i < SLOTS; ++i) kept[i] = p2.serial_of(i);
    p2.begin_round();
    RESERVE_CHECK(p2.round() == p1.round() + 1);
    RESERVE_CHECK(p2.serial_of(2) != RESERVE_NONE && p2.serial_of(2) != kept[2]);
    for (size_t i = 0; i < SLOTS; ++i) {
        if (i == 2) continue;
        RESERVE_CHECK(p2.serial_of(i) == kept[i]);
        RESERVE_CHECK(memcmp(p2.point(i).m, p1.point(i).m, 32) == 0);
    }

    // 游标是跨进程状态, 装货**不能**把它冲掉 —— 冲掉就等于每次启动把库存头一段重发
    // 一遍 (这正是要修的那个 bug)。这里把游标推过物化段, 验取出来的是阶梯而不是
    // adds_pub[0]。
    {
        ReserveSupply sup;
        sup.cursor = RHO_RESERVE_STEPS + 7;      // 存档里是"已经吃掉 263 条"
        reserve_load_special(sup);
        RESERVE_CHECK(sup.cursor == RHO_RESERVE_STEPS + 7);
        RESERVE_CHECK(reserve_next_ladder_k(sup) == 8);
        RhoPoint p;
        RESERVE_CHECK(reserve_take(sup, p));
        RESERVE_CHECK(p.m[31] == 8);             // 大端: 阶梯第 8 级
        RESERVE_CHECK(sup.cursor == RHO_RESERVE_STEPS + 8);
    }

    // 坏存档必须**整份**丢弃, 而不是"尽力恢复"成一批半真半假的点。
    {
        const std::string bad = path + ".bad";
        ReservePool p3(SLOTS, ReserveSource::Special, supply);
        ReserveCursors cur3;
        {
            std::ofstream out(bad, std::ios::trunc);
            out << "RhoReserve 2\n";                              // 版本号不认
        }
        RESERVE_CHECK(!reserve_state_read(p3, bad, cur3));
        {
            std::ofstream out(bad, std::ios::trunc);
            out << "RhoReserve 1\nround 1\nslots 4\n"
                << "slot 0 Special held 1 00 00\n";               // hex 长度不对
        }
        RESERVE_CHECK(!reserve_state_read(p3, bad, cur3));
        {
            std::ofstream out(bad, std::ios::trunc);
            out << "RhoReserve 1\nround 1\nslots 5\n";            // 槽位数与池子不符
        }
        RESERVE_CHECK(!reserve_state_read(p3, bad, cur3));
        {
            // 格式全对但点是 (0, 0): check() 自己算的自己, 看不出来, 得靠显式的全零挡。
            const std::string z(64, '0');
            std::ofstream out(bad, std::ios::trunc);
            out << "RhoReserve 1\nround 1\nslots 4\n"
                << "slot 0 Special held 1 " << z << ' ' << z << '\n';
        }
        RESERVE_CHECK(!reserve_state_read(p3, bad, cur3));
        std::remove(bad.c_str());
    }

    std::remove(path.c_str());
    std::cout << "reserve state file: ok (round-trip / discard on corrupt)" << std::endl;
}

#undef RESERVE_CHECK

