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

#include <algorithm>
#include <cassert>
#include <chrono>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <sstream>
#include <string>
#include <system_error>
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

// 对应 cuda.cu 的 glv_dp_indices(): 对 p / beta*p / beta^2*p 三个代表**分别**判定,
// 返回"第一个命中的代表的索引" (顺序固定为 p, beta*p, beta^2*p); 都不命中返回 0。
//
// 与设备端 glv_dp_indices 同一口径: 三个代表各自判定, 任一命中就把这个 walker 的
// DP 掩码置位 (一步只占一个 bit, 不因命中三个而变三份); 具体记哪几条、每条存谁的
// (m, n) 由调用方 (blockchain.cpp 的 Rho::shoot) 再算一遍 glv_orbit 决定。
//
// 返回第一个命中的索引而不只是 p 自己的, 是为了让"掩码为真 ⟺ 有代表命中" 与
// 设备端 dp[0]/dp[1]/dp[2] 三格完全对应; 索引值本身在这里只当布尔用。
//
// 只要 1 次域乘: beta^2 + beta + 1 = 0 (mod p)  =>  beta^2*x = -(beta*x + x)。
// bx / b2x 必须 normalize 之后才能读肢体 (bit 0..39)。
//
// 取索引时在 5x52 肢体上分两段拼接 (该代表已全规约):
//   bit 40..51  = c.n[0] 的 bit 40..51   (n[0] 只覆盖到 bit 51)
//   bit 52..103 = c.n[1] 的 bit 0..51    (n[1] 的 bit 0 即 x 的 bit 52)
// 合并即 (c.n[0] >> 40) | (c.n[1] << 12): 合计 64 位。
inline uint64_t rho_affine_dp(const RhoAffineState& s)
{
    // 单点判据: 该代表自己的 bit 0..39 全 0 时返回 bit 40..103。
    auto one = [](const secp256k1_fe& c) -> uint64_t {
        if ((c.n[0] & 0xFFFFFFFFFFULL) != 0) return 0;
        return (c.n[0] >> 40) | (c.n[1] << 12);
    };

    // s.X 已全规约 (rho_affine_step_batch 每步结尾保证) —— 它自己不用再 normalize,
    // 省掉这份热路径上的开销。bx / b2x 必须 normalize 之后才能读肢体。
    secp256k1_fe bx, b2x, t;
    secp256k1_fe_mul(&bx, &s.X, &secp256k1_const_beta);   // mag 1
    t = bx;
    secp256k1_fe_add(&t, &s.X);                           // 原地加: t = bx + x, mag 2
    secp256k1_fe_negate(&b2x, &t, 2);                     // b2x = -(bx + x)
    secp256k1_fe_normalize_var(&bx);
    secp256k1_fe_normalize_var(&b2x);

    if (const uint64_t d = one(s.X)) return d;   // dp[0]: p 自己
    if (const uint64_t d = one(bx)) return d;    // dp[1]: beta*p
    return one(b2x);                             // dp[2]: beta^2*p
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

// 扫描每个线程 1/8/16/32 个 walker 的吞吐, 用来选 common.h 里的 RHO_WALKERS。
// (早期还扫过 2 和 4 两档; 那两档的数字在选定 8 之后就没再用过, 已从跑批里去掉 ——
//  要复现直接加回 bench_rho_walkers<2>/<4> 即可, 函数本身是模板。)
// 总点数固定 (800000), 与 cuda.cu 的 perf_test_cpu (同样 800000 点) 同口径,
// 可直接对比。
// 最后一档 W=1 再跑一次作为漂移对照: 同一进程内的首尾两个 W=1 读数应该很接近。
void perf_test_rho_affine_walkers()
{
    rho_affine_init_adds();
    constexpr uint64_t kTotal = 800000;
    bench_rho_walkers<1>(kTotal / 1);
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
    //
    // 注: rho_affine_dp 现在会对 p / beta*p / beta^2*p 三个代表分别判定, 返回第一个
    // 命中的索引。下面这 6 个构造值都远小于 p (最大的约 2^104), 而 beta*x / beta^2*x
    // 是满宽的, 所以只有 x 自己可能命中 —— 与这里"按 x 原样"写的参考值必然一致。
    // 三个代表与 beta/lambda 的正确性由 cuda.cu 的 validate_glv 覆盖。
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
// 预备队 (RhoStates_reserve) 的来源 —— 没有账本
//
// 位置说明: 这一整段都是纯主机侧逻辑, 不需要一行 CUDA 代码, 所以就在 rho.cpp;
// 设备侧 (cuda.cu) 只留 RhoStates_reserve 那份常量内存 + 一个上传函数
// upload_RhoStates_reserve。池子的用途见 common.h 的 ReserveSource 那段。
//
// 三条来源都不建账本: **每一轮现从来源处取一窗点**, 取完就上传, 不记"谁在哪个槽位",
// 也不留履历。池子就是一扇滑动的窗 —— 与起点漫游路 (cuda.cu 的 dp32_edge_session)
// 铺起点池是同一个套路。
//
//   1 类 Random   每轮整窗换新随机点 (改造前的行为)。
//   2 类 Special  序列 = adds_pub[0][*] 的 256 条, 之后接无限阶梯 1G, 2G, 3G, ...
//                 第 pos 条直接由 pos 现算 (阶梯不物化、没有上限, 所以取不完)。
//   3 类 Dp       源库 DpSource32.bin 的活记录: **每轮从槽位 0 起扫, 墓碑跳过**。
//
// 只有 2 类需要跨进程的游标 (序列走到第几条), 因为它的"用过即退役"是**靠位置**保证的,
// 位置丢了就只能重发。步进是确定性的: 起点定死则整条轨迹定死, 同一个点入池两次走出的
// (m, n) 完全相同, 产出的 DP 记录逐字节重复 —— 而碰撞判定要的是"同一个 x 配不同的
// (m, n)", 重复记录一条都排不上用场。所以游标必须落盘。
//
// 3 类**什么游标都不需要** —— 源库的墓碑位图本身就是账本:
//   · 被征调用掉的点当场立墓碑 (retire_dp_slot), 墓碑 = "这个点用过了";
//   · 活着的记录 = "还没用过": 还没发出去, 或者发出去了但没被征调;
//   · 于是"从 0 起取前 N 条活记录"恰好就是把所有没用过的点排成一队、取前 N 个。
//   上一轮取了但没被征调的那几个本轮仍在队首, 原样重发, 一条不丢 (这就是"不浪费");
//   被征调的下轮已变墓碑, 自然被扫过 (这就是"不重发")。所以 3 类既不需要账本, 也不需要
//   游标 —— 旧版存档里那 109 条"取过但一直没被征调"的留用点也会因此自动回到队里。
//
// 2 类的游标怎么推进 —— 这是"不记账也不浪费"的关键:
//   设备端每轮换起点的次数 = dp_reset_count, 而 DpManager::save_dps 读完就把它清零,
//   reset_start_point 里的 pi 又是从 0 起 atomicAdd, 所以一轮内被消费的池位**集合恰好
//   是 {0, 1, ..., r-1}** (顺序不定, 但无重复无空洞)。于是下一轮的座标只要推到"本轮
//   第 r 条取出来的点"那里就行 —— 没被消费的那些下轮原样再取一次; 它们没用过, 重取
//   不会让轨迹重复, 所以既不浪费库存, 也不会重发。
//
// 于是 2、3 类的**来源数据一点不浪费**:
//   · 2 类: 座标推过的每个点都已经真被用掉, 没推到的下轮原样重发, 一条不丢;
//   · 3 类: 活记录一条不丢 (下轮仍在队里), 跳过的墓碑都是**以前**被征调用掉的。
// 1 类是唯一"整窗换新"的来源, 但它的来源是随机数, 没有可浪费的库存。
//
// 池子大小是 dp_buffer_size, 而 reset_start_point 取用的池位下标不止到 max_size - 1
// (max_size = dp_buffer_size - 20, 见 cuda.cu 的 edge_pool_size 那段):
// 池位消费量 (dp_reset_count) 的上界是记录条数, 而记录是**先写入再判 break** 的,
// 所以下标还会往上走一点 —— 同一批里每线程 W 个 walker 最多各命中一次, 而
// break_flag 要等各线程轮询到才生效 (轮询间隔 RHO_POLL_BATCHES 批), 超出的量都是个
// 位数 (期望 ~3 条), 数组比 max_size 多留的 20 项就是给这段的。
// ===========================================================================

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

// 当前用哪一类来源。要换来源就改这一行 (不提供运行期切换)。
//
// 当前配置 = 1 类 (Random): 每轮整窗换新随机点, 不碰 RhoReserve.txt 的货源游标,
// 也不载 32 位 DP 库 (cuda.cu 的 rho_play 按这个来源跳过 dp32_store_init, 见那边
// EDGE=false 那一支)。这样生产路与 32 位 DP 库彻底解耦: 库只归起点漫游用。
//
// 换回 3 类 (Dp) 时的前提 (改下面那一行即可, 其余代码不用动): 点从 DpSource32.bin
// 的源库从 0 起扫活记录取, 库取完 (或库不在盘上) 就整窗回退随机点。换之前只需确认
// 源库/已征召库在盘上 (不在就静默回退随机 —— 池子照跑, 只是又变回"全随机起点")。
//
// ⚠ 3 类**没有游标可对**: 状态就是源库的墓碑位图 + 已征召库。重新离线建库之后, 新库
//   里没有旧墓碑, 于是旧进度就丢了 (那些点会被再发一遍) —— 要么别重建库, 要么重建后
//   接受这一遍重发 (它不会被立墓碑, 只是白走一趟)。1、2 类与库完全无关, 不受影响。
static ReserveSource g_reserve_source = ReserveSource::Random;

// 给 cuda.cu 的 validate_test 用。
ReserveSource reserve_configured_source() { return g_reserve_source; }

// 2 类序列里物化段的条数 = 步进表 adds_pub[0][*] 那 256 条 (由声明数出来)。
// 越过物化段就是阶梯 (k*G), 不物化也不预生成, 由座标现算。
constexpr size_t RHO_RESERVE_STEPS = sizeof(adds_pub[0]) / sizeof(adds_pub[0][0]);

// 预备队的**进程级状态**落盘路径 (只有游标 + 轮号, 格式见下面的存档一节)。
// 只有生产路径 (rho_play) 读写它, validate 一律不碰。
static const std::string RHO_RESERVE_STATE_FILE = data_file("RhoReserve.txt");

// 只需要一个跨进程游标: 2 类序列 (address 表 + 阶梯) 的"已经发出去多少条"。
// 3 类**不需要游标** —— 源库的墓碑位图本身就是账本 (见 reserve_pull 的注释)。
//   取值越大表示 2 类序列走得越远 (物化段与阶梯共用同一座标)。
struct ReserveCursors {
    uint64_t special = 0;
};
static ReserveCursors g_cursors;

// 槽位没有对应的源库记录 (1、2 类 / 3 类回退的随机点)。
constexpr uint32_t RESERVE_NO_SLOT = 0xFFFFFFFFu;

// 本轮这一窗点。三份记录各管一件事, 不能合并:
//   slot_of      只有 3 类有值 (轮末销账要知道"这个槽位的点取自源库哪一条");
//   from_source  三类都要能回答 (validate 靠它区分"真取到了"和"回退成随机点");
//   points       实际灌进设备常量内存的那一窗点。
// 1、2 类的座标直接由游标算得出来, 所以不需要 slot_of。
struct ReserveWindow {
    std::vector<RhoPoint> points;                // 槽位 -> 点
    std::vector<uint32_t> slot_of;               // 槽位 -> 源库槽位 (非 3 类恒 RESERVE_NO_SLOT)
    std::vector<char>     from_source;           // 槽位 -> 这一轮的点是否真来自来源 (回退随机 = 0)
    ReserveSource         source = ReserveSource::Random;
};
static ReserveWindow g_window;
// 池子槽位数 (0 = 没建池)。轮号跨轮存活, 只为日志连续。
static size_t   g_slots = 0;
static uint64_t g_round = 0;
// 是否读写状态存档 = 是不是生产路径 (只有 rho_play 打开; validate 一律不碰盘)。
// 另外: 来源配成 Random 时即使传 persistent = true 也一律关掉 (见 init_reserve_pool) ——
// 这个池子没有货源游标, 存档里那一项对它没意义, 读写只是在糟鸥别人的进度。
static bool g_reserve_persistent = false;

// (m, n) -> 点: 现算 x 并自检。全零的 (m, n) 算出来是个非法点, 而 check() 比的是
// "照 m/n 重算出来的那个 x" —— 自己验自己, 这种情况看不出来, 所以先挡一道。
static bool reserve_point_from_mn(const unsigned char* m, const unsigned char* n, RhoPoint& out)
{
    static const unsigned char zeros[32] = {0};
    if (memcmp(m, zeros, 32) == 0 && memcmp(n, zeros, 32) == 0) return false;
    memcpy(out.m, m, sizeof(out.m));
    memcpy(out.n, n, sizeof(out.n));
    create(ctx, &out.x, out.m, out.n);
    return check(ctx, &out.x, out.m, out.n) == 1;
}

// 2 类序列的第 pos 条 (pos 从 0 起):
//   pos < 256   物化段: 步进表 adds_pub[0][pos] (它的 x/m/n 三者自洽, 装载时验过)
//   pos >= 256  阶梯第 k = pos - 255 级, 即 k*G (create(m = k, n = 0), 大端)
// 阶梯由 pos 现算, 不另存"走到第几级", 也没有上限 —— 所以 2 类取不完。
static bool special_point(uint64_t pos, RhoPoint& out)
{
    if (pos < RHO_RESERVE_STEPS) {
        return reserve_point_from_mn(adds_pub[0][pos].m, adds_pub[0][pos].n, out);
    }
    const uint64_t k = pos - RHO_RESERVE_STEPS + 1;
    if (k > 0x7FFFFFFFFFFFFFFFULL) return false;   // 存档被改坏了, 别让 set_int 截断
    unsigned char m[32] = {0};
    unsigned char n[32] = {0};
    set_int(m, (int64_t)k);
    return reserve_point_from_mn(m, n, out);
}

// 3 类: 从源库槽位 *scan 起往后找下一条活记录 (墓碑跳过), 找到就把 *scan 推到它之后。
// **库见底 / 库没载入**才返回 false (该槽位本轮回退随机点)。
//
// 单条记录读不出来或算不出点属于"这条永远用不了" (载库时已经对过'条数 == 文件长度',
// 所以只会是坏盘/坏记录): 当墓碑跳过并印一行, 不返回 false —— 否则一个坏槽位会让它
// 之后的整窗都退化成随机点, 那才是真的把后面的来源数据浪费掉。
static bool dp_point(uint64_t& scan, RhoPoint& out, uint32_t* got_slot)
{
    const Dp32Store& lib = dp32_store();
    if (!lib.loaded()) return false;
    while (scan < lib.src_count()) {
        const uint32_t slot = (uint32_t)scan;
        ++scan;
        if (lib.src_dead(slot)) continue;                      // 墓碑: 这个点已经用掉了
        Dp32Record rec;
        if (!lib.read(Dp32File::Source, slot, rec)) {
            cprint() << get_time() << " : reserve: 源库槽位 " << slot
                     << " 读不出来, 跳过 (当墓碑)" << std::endl;
            continue;
        }
        if (!reserve_point_from_mn(rec.m, rec.n, out)) {
            cprint() << get_time() << " : reserve: 源库槽位 " << slot
                     << " 的 (m, n) 算不出合法点, 跳过 (当墓碑)" << std::endl;
            continue;
        }
        if (got_slot != nullptr) *got_slot = slot;
        return true;
    }
    return false;
}

// 启动对账: "已征召库里有的点, 源库里必须已经是墓碑"。
//
// 为什么需要: 销账 retire_dp_slot 是**两步写** —— 先在已征召库追加这条记录, 再在源库里
// 立墓碑 (顺序不能反: 只有追加成功才敢抹掉源库, 否则这个点会从两个库里凭空消失)。
// 两步之间若断电/被杀, 盘上就是"已征召库有这条, 源库仍是活的", 于是下一轮从 0 扫时
// 这个点会被**再发一遍** —— 走出完全相同的轨迹、产出逐字节重复的 DP 记录, 白烧算力。
//
// 对账只按索引比 (已征召库里每条记录的 index 回源库查槽位), 与游标无关, 天然幂等:
// 已经是墓碑的直接跳过。条数只有几千 (已征召库 240 KB / 72 B ≈ 3334 条), 启动跑一次,
// 代价可忽略。
static void reserve_reconcile_drafted()
{
    Dp32Store& lib = dp32_store();
    if (!lib.loaded()) return;
    const uint64_t n = lib.drf_count();
    if (n == 0) return;

    uint64_t fixed = 0;
    for (uint64_t s = 0; s < n; ++s) {
        Dp32Record rec;
        if (!lib.read(Dp32File::Drafted, (uint32_t)s, rec)) continue;
        if (dp32_is_tombstone(rec)) continue;       // 已征召库理论上没有墓碑, 防手改
        uint32_t slot = 0;
        // 源库里已经是墓碑 (正常情况) / 不在源库 (无从销账) 都跳过
        if (lib.src_find(rec.index, slot) != Dp32Hit::Live) continue;
        if (lib.src_tombstone(slot)) ++fixed;
    }
    if (fixed != 0) {
        std::cout << get_time() << " : reserve: 启动对账补立 " << fixed
                  << " 个源库墓碑 (已征召库里有、源库还是活的: 上次在两步写之间被打断)"
                  << std::endl;
        ilog_line("Dp32 启动对账: 补立 " + std::to_string(fixed) +
                  " 个源库墓碑 (已征召库有记录、源库仍活的; 源库墓碑 " +
                  std::to_string(lib.src_dead_count()) + " 条 / 已征召库 " +
                  std::to_string(lib.drf_count()) + " 条)");
    }
}

// 3 类的库载入**只尝试一次**: 库不在盘上就是不在, 每轮重试只会把同一行字反复印到
// 控制台并重复扫一遍 64 MB 库的索引。载入成功之后 dp32_store_init 本身是幂等的
// (loaded() 直接返回 true), 所以这里只需把"失败"这个结论记住。
//
// 载入成功之后顺手跑一次启动对账 (只在生产路径: 自测一律不碰那两个 .bin)。
static bool reserve_dp_lib_ready()
{
    static bool tried = false;
    static bool ok = false;
    if (tried) return ok;
    tried = true;
    ok = dp32_store_init();
    if (!ok) {
        cprint() << get_time() << " : reserve: 32 位源库不可用 ("
                 << data_file(DP32_SOURCE_NAME) << "), 3 类回退随机点" << std::endl;
        return false;
    }
    if (g_reserve_persistent) reserve_reconcile_drafted();
    return true;
}

// 从来源现取一窗点填进 g_window。
//
//   1 类 Random  整窗新随机点, 不看任何状态。
//   2 类 Special 从游标 g_cursors.special 按序取, 取不到的槽位回退随机点。
//   3 类 Dp      **每轮都从源库槽位 0 开始扫**, 墓碑跳过, 取前 g_slots 条活记录。
//
// 3 类为什么从 0 扫而不延续上轮的扫描位置 —— 这就是"不建账本也不浪费"的全部奥妙:
//   · 被征调用掉的点**当场立墓碑** (见 retire_dp_slot), 所以墓碑 = "这个点用过了";
//   · 活着的记录 = "还没用过": 还没发出去, 或者发出去了但没被征调;
//   · 于是"从 0 起取前 N 条活记录"恰好就是"把还没用过的点全部排成一队, 取前 N 个"。
//   上一轮取了但没被征调的那几个活记录, 本轮仍然排在队首 —— **原样重发, 一条不丢**;
//   这一轮被征调的当场变墓碑, 下一轮自然被扫过。历史上那 109 条 "取过但一直没被
//   征调" 的留用点也因此自动回到队里 (旧版靠账本留用它们, 账本没了靠墓碑反过来认)。
//   代价是每轮要从头走一遍墓碑前缀 —— 那个前缀只含位图读取 (src_dead 是纯内存),
//   而墓碑总是集中在库首 (我们一直从最低的活槽开始取), 所以是一小段顺序位图扫描。
static void reserve_pull()
{
    ReserveWindow& w = g_window;
    w.points.assign(g_slots, RhoPoint());
    w.slot_of.assign(g_slots, RESERVE_NO_SLOT);
    w.from_source.assign(g_slots, 0);
    w.source = g_reserve_source;

    if (w.source == ReserveSource::Dp) {
        // 3 类的库存是盘上的源库: 载不进来就整窗回退随机点 (池子照跑, 不崩)。
        (void)reserve_dp_lib_ready();
    }

    uint64_t scan = 0;                     // 3 类: 本轮的扫描位置 (每轮从 0 起)
    for (size_t i = 0; i < g_slots; ++i) {
        bool ok = false;
        if (w.source == ReserveSource::Special) {
            ok = special_point(g_cursors.special + i, w.points[i]);
        } else if (w.source == ReserveSource::Dp) {
            uint32_t slot = RESERVE_NO_SLOT;
            ok = dp_point(scan, w.points[i], &slot);
            if (ok) w.slot_of[i] = slot;
        }
        // ⚠ 这两个记录必须分开: slot_of 只有 3 类有值, 而"是不是真来自来源"三类都要能
        // 回答 (validate 靠它判断 2 类会不会整窗都回退成随机点)。
        w.from_source[i] = ok ? 1 : 0;
        if (!ok) w.points[i].rand();
    }
}

// 被征召的 3 类点销账: 这个点已经用掉了 —— 源库里那条立墓碑 + 追加进已征召库。
//
// 两个库记的是**同一批点**: 源库里被立墓碑的那条, 就是已征召库里追加的那条。所以
// 必须一起做 —— 只立墓碑会让这个点从两个库里凭空消失, 只追加会让源库把用过的点再
// 发给下一个 walker。顺序: 先追加, 后立墓碑 (中间崩了记录还在, 能补)。
//
// 判等**用源库槽位号**, 不再拿点的 x 复算 32 位索引去反查: 池子里的点就是从这条槽位
// 取出来的, 一一对应 (slot_of[] 记着), 比反查可靠也便宜。
// 单线程前提: 只在轮边界调 (note_reserve_dps), 与 rho_play 里其他读写这两个库的代码
// 同线程 (已征召库的桶没有加锁, 见 common.h)。
// who: 销账的是谁 (写生产日志用 —— 两个库的条数变了, 得能回溯是哪个槽位的事)。
enum class RetireResult {
    Done,        // 立了墓碑 + 追加了已征召库
    DryRun,      // 非持久模式 (自测): 绝不碰生产那两个 .bin
    NoLib,       // 库没载入: 降级模式, 这些槽位本来就回退随机点
    AlreadyDead, // 库里那条已经是墓碑: 这笔账早销过了 (幂等命中, 正常)
    ReadFail,    // 读不出源库那条记录
    WriteFail,   // 已征召库追加不上, 什么都没改
};

// 日志里"这一笔账"的说法。Done 之外的都带上原因 —— 只印一句"没销账"看不出是幂等
// 命中 (正常) 还是真出了问题。
static const char* retire_result_note(RetireResult r)
{
    switch (r) {
    case RetireResult::Done:        return " [源库立墓碑 + 已征召库追加]";
    case RetireResult::DryRun:      return " [自测模式, 不碰两个库]";
    case RetireResult::NoLib:       return " [源库未载入, 不销账]";
    case RetireResult::AlreadyDead: return " [源库里那条已是墓碑, 早销过账]";
    case RetireResult::ReadFail:    return " [源库那条读不出来, 不销账]";
    case RetireResult::WriteFail:   return " [已征召库写盘失败, 不销账]";
    }
    return "";
}

static RetireResult retire_dp_slot(uint32_t slot, const std::string& who)
{
    if (!g_reserve_persistent) return RetireResult::DryRun;   // 自测一律不动真库
    Dp32Store& lib = dp32_store();
    if (!lib.loaded()) return RetireResult::NoLib;
    if (lib.src_dead(slot)) return RetireResult::AlreadyDead;
    Dp32Record rec;
    if (!lib.read(Dp32File::Source, slot, rec)) return RetireResult::ReadFail;
    if (!lib.drf_append(rec.index, rec.m, rec.n)) return RetireResult::WriteFail;
    lib.src_tombstone(slot);                                  // 先追加后立墓碑
    ilog_line("Dp32 征召销账: " + who + " -> 源库槽位 " + std::to_string(slot) +
              " 立墓碑 + 已征召库追加 (源库墓碑 " + std::to_string(lib.src_dead_count()) +
              " 条 / 已征召库 " + std::to_string(lib.drf_count()) + " 条)");
    return RetireResult::Done;
}

// ============================ 进程级状态落盘 ============================
//
// 为什么必须落盘: 2 类序列的座标 ("已经发出去多少条") 只在内存里, 进程一重启就归零,
// 头几段点跟上一次 run **逐字节重复**。重复的危害不是多算了几条 —— 两者算出来的 x
// 完全相同, 于是 DP 记录里 m/n 也完全相同, 而碰撞要的是"同一个 x 配不同的 (m, n)",
// 这种记录一条都排不上用场, 纯属白烧算力。
//
// 3 类**不需要这个存档**: 它的状态就是源库的墓碑位图 + 已征召库, 两者每轮已经落盘。
// 1 类也不需要 (随机点没有"进度"可丢)。
//
// 存档 (纯文本, RhoReserve.txt, 每轮 rho_play 落一次):
//     RhoReserve 2                        版本号, 不认就整份丢掉
//     round <n>                           当前轮号 (日志轮号跨进程连续)
//     supply Special <n>                  2 类序列已经发出去的条数
//     slots <n>                           槽位数 (只做告警: 与 dp_buffer_size 不符时提示)
//
// 向后兼容: 读侧只接受 1、2 两个版本 (没有 v3 —— 账本取消时直接把当时那份升成 2,
// 因为"两个游标"的中间版本从未落过盘)。旧版 v1 还会写
//     supply Dp <游标>                     —— 已无意义, 读到就忽略 (但名字得认得)
//     slot <i> <来源> empty|held ...       —— 账本行, 读到就跳过
// 所以已经跑了一段时间的来源 3 的进度**不需要靠游标继承** —— 墓碑位图本身就是进度,
// 而从 0 起扫活记录的取点法会自然把旧版那些 "取过但没被征调" 的留用点重新排回队里。
static bool reserve_state_write(const std::string& path, const ReserveCursors& cur,
                                uint64_t round, size_t slots)
{
    const std::string tmp = path + ".tmp";
    {
        std::ofstream out(tmp, std::ios::trunc);
        if (!out.is_open()) {
            std::cout << get_time() << " : reserve state: cannot write " << tmp << std::endl;
            return false;
        }
        out << "RhoReserve 2\n";
        out << "round " << round << '\n';
        out << "supply Special " << cur.special << '\n';
        out << "slots " << slots << '\n';
        out.flush();
        if (!out) return false;
    }
    // close() 之后先把它刷到物理介质, 再改名 —— 否则断电时可能出现"名字换了、内容还在
    // 页缓存里"的中间态, 读回来是空档或旧档。落不进盘就当这一轮没落 (游标留在旧值,
    // 下轮重试), 宁可重复几条也不假装成功。
    if (!fsync_path(tmp)) {
        std::cout << get_time() << " : reserve state: fsync failed on " << tmp << std::endl;
        std::remove(tmp.c_str());
        return false;
    }
    // 先写临时文件再原子替换 —— 存档自己若被写到一半打断就报废, 那它防的"意外关机"
    // 就白防了。
    //
    // 用 std::filesystem::rename 而不是 std::rename: 前者在 Windows 上是
    // MoveFileEx(MOVEFILE_REPLACE_EXISTING), **一步覆盖、没有中间态**; std::rename
    // 目标已存在会直接失败 (EACCES), 那就只能"先删旧的再改名", 而那个窗口里如果改名
    // 也失败了, 存档就真没了 (游标归零 = 2 类序列从头重发一遍)。这是唯一可能丢进度的
    // 路径, 所以必须堵住。
    {
        std::error_code ec;
        std::filesystem::rename(tmp, path, ec);
        if (ec) {
            // 极少数文件系统不支持覆盖式改名: 退回到"旧档挪走 -> 新档就位"。
            // ⚠ 这里**绝不删旧档**: 旧档里那个游标是唯一能让 2 类序列不重发的凭据,
            //   为了这一次落盘把它删掉是本末倒置。挪不动就放弃这一轮 (下轮重试),
            //   最多重复几条点, 绝不会丢进度。
            const std::string bak = path + ".bak";
            std::error_code ec2;
            std::filesystem::rename(path, bak, ec2);      // 旧档移到 .bak
            if (ec2) {
                std::error_code ecr;
                std::filesystem::remove(tmp, ecr);        // 只清临时档, 不动旧档
                std::cout << get_time() << " : reserve state: cannot move old archive aside ("
                          << ec2.message() << "), skip this round" << std::endl;
                return false;
            }
            std::error_code ec3;
            std::filesystem::rename(tmp, path, ec3);
            if (ec3) {
                // 新档就位失败: 把旧档还原回去, 宁可这一轮不落盘也不能把进度弄丢。
                std::error_code ec4;
                std::filesystem::rename(bak, path, ec4);
                std::error_code ec5;
                std::filesystem::remove(tmp, ec5);
                std::cout << get_time() << " : reserve state: cannot replace " << path
                          << " (" << ec3.message() << ")" << std::endl;
                return false;
            }
            std::error_code ec6;
            std::filesystem::remove(bak, ec6);
        }
    }
    return true;
}

// 回读。任何一处不合都整份放弃 —— 存档担的是"别重复用点", 不该把一次坏存档变成一次
// 崩溃, 也不该把游标读成另一个值。宁可从头开始 (游标归 0), 也不"尽力恢复"。
static bool reserve_state_read(const std::string& path, ReserveCursors& cur,
                               uint64_t& round, size_t slots)
{
    std::ifstream in(path);
    if (!in.is_open()) return false;

    const auto discard = [&](const char* why) -> bool {
        std::cout << get_time() << " : reserve state: discarded (" << why
                  << "), starting fresh" << std::endl;
        return false;
    };

    std::string line;
    if (!std::getline(in, line)) return discard("header");
    // 1 = 最早那版 (后面跟账本行), 2 = 现在这份 (只有 2 类游标)。两种都认。
    if (line != "RhoReserve 1" && line != "RhoReserve 2") return discard("header");

    bool have_round = false;
    uint64_t r = 0;
    ReserveCursors c;
    while (std::getline(in, line)) {
        if (line.empty()) continue;
        std::istringstream ls(line);
        std::string what;
        if (!(ls >> what)) continue;
        if (what == "round") {
            if (!(ls >> r)) return discard("round");
            have_round = true;
        } else if (what == "supply") {
            std::string name;
            uint64_t cursor = 0;
            if (!(ls >> name >> cursor)) return discard("supply");
            ReserveSource src = ReserveSource::Random;
            if (!reserve_source_by_name(name, src)) return discard("supply name");
            // 只有 2 类还有游标。旧版写的 "supply Dp <游标>" 已无意义 (3 类的状态
            // 就是墓碑位图), 读到就忽略 —— 但名字要认得, 否则整份存档会被当成坏的。
            if (src == ReserveSource::Special) {
                c.special = cursor;
                // 座标大得离谱说明存档被改坏了: 别让它变成一次巨大的 set_int。
                if (c.special > (1ULL << 62)) return discard("cursor range");
            }
        } else if (what == "slots") {
            size_t n = 0;
            if (!(ls >> n)) return discard("slots");
            // 槽位数对不上只是提示: 账本没了, 游标跟槽位数无关, 不该因此丢进度。
            if (n != slots) {
                std::cout << get_time() << " : reserve state: slots " << n
                          << " != dp_buffer_size " << slots << " (游标照用)" << std::endl;
            }
        } else if (what == "slot") {
            continue;   // 旧版的账本行: 已经没有账本了, 跳过 —— 兼容就靠这一行
        } else {
            return discard("unknown key");
        }
    }
    if (!have_round) return discard("missing fields");
    cur = c;
    round = r;
    return true;
}

void init_reserve_pool(size_t slots, bool persistent)
{
    g_slots = slots;
    g_round = 0;
    g_cursors = ReserveCursors();
    g_window = ReserveWindow();
    g_window.points.assign(slots, RhoPoint());
    g_window.slot_of.assign(slots, RESERVE_NO_SLOT);
    g_window.from_source.assign(slots, 0);
    // 来源是 Random 时**整条存档通道关掉**: 这类池子没有货源游标, 读写只会踩别人的
    // 进度。那份存档**原样留着**, 换回 Dp/Special 时接着用 (只改 g_reserve_source)。
    g_reserve_persistent = persistent && g_reserve_source != ReserveSource::Random;
    if (!g_reserve_persistent) return;

    if (!reserve_state_read(RHO_RESERVE_STATE_FILE, g_cursors, g_round, slots)) {
        std::cout << get_time() << " : reserve state: starting fresh (no usable archive at "
                  << RHO_RESERVE_STATE_FILE << ")" << std::endl;
        g_cursors = ReserveCursors();
        g_round = 0;
        return;
    }
    std::cout << get_time() << " : reserve state restored from " << RHO_RESERVE_STATE_FILE
              << ": round " << g_round << ", cursor Special " << g_cursors.special
              << std::endl;
}

// 落一次盘 (每轮 loop 末了一次, 紧跟 note_reserve_dps)。
// Random 来源下 g_reserve_persistent 恒为 false (见 init_reserve_pool), 这里直接返回 ——
// 不打开 RhoReserve.txt, 也不写它的 .tmp。
void save_reserve_state()
{
    if (!g_reserve_persistent) return;
    reserve_state_write(RHO_RESERVE_STATE_FILE, g_cursors, g_round, g_slots);
}

// 重填预备队 (每轮 loop 开跑前一次): 从来源现取一窗点 + 整块上传 (设备常量内存)。
void init_RhoStates_reserve()
{
    if (g_slots == 0) return;
    ++g_round;
    reserve_pull();
    upload_RhoStates_reserve(g_window.points.data(), g_window.points.size());
}

// 轮末结算: 这一轮设备实际**换了 dp_count 次起点** (= 被消费的池位数), 于是
//   1) 3 类: 被消费的那些池位对应的源库记录销账 (立墓碑 + 追加已征召库);
//   2) 2 类: 游标只推被消费的那几条 —— 没被征调的 [consumed, slots) 下轮原样再取。
// 1、3 类都不推游标: 1 类每轮整窗随机; 3 类的状态就是墓碑位图本身。
// 不能传记录条数: GLV 之后每步判 p / beta*p / beta^2*p 三个代表, 每个命中各记一条,
// 但只有 p 自己命中才换起点 (reset_start_point), 所以记录条数 >= 换起点次数。
// 调用方传 DpManager::last_reset_count()。
void note_reserve_dps(unsigned int dp_count)
{
    if (g_slots == 0) return;
    const ReserveWindow& w = g_window;
    // 池位下标可以超出槽位数: 消费量的上界是记录条数, 而记录是"先写入再判 break"的
    // (最多超 W-1 项), 那些超界的池位只是从备用项里取了点, 没有对应的事要记。
    const size_t consumed = std::min<size_t>((size_t)dp_count, g_slots);

    // 1) 3 类销账。判据是 slot_of[] —— 池子里的点就是从那条槽位取出来的, 一一对应。
    if (w.source == ReserveSource::Dp) {
        for (size_t j = 0; j < consumed; ++j) {
            if (w.slot_of[j] == RESERVE_NO_SLOT) continue;   // 回退的随机点: 不销账
            const std::string who = "槽位 " + std::to_string(j) + " (源库槽位 " +
                                    std::to_string(w.slot_of[j]) + ") 被征召";
            const RetireResult rr = retire_dp_slot(w.slot_of[j], who);
            if (rr != RetireResult::Done) {
                std::cout << get_time() << " : reserve: " << who << " 不销账"
                          << retire_result_note(rr) << std::endl;
            }
        }
    }

    // 2) 推游标。2 类只推被消费的那几条: 池位 {0..consumed-1} 才是真正上了 walker 的,
    //    所以下轮从"座标 + consumed"接着取 —— 没被征调的 [consumed, slots) 原样再取
    //    一次, 它们没用过, 重取不会让轨迹重复。于是 2 类也**不会浪费来源**:
    //    游标推过的每一个点都已经真被用掉, 没推到的点一条不丢。
    if (w.source == ReserveSource::Special) {
        g_cursors.special += consumed;
    }
    // 1 类不动游标: 每轮整窗换新随机点, 没有"用过即退役"这回事。
    // 3 类不动游标 (已没有游标): 被征调的那几条当场变墓碑, 下一轮从 0 扫时自然跳过。

    if (consumed != 0) {
        std::cout << get_time() << " : reserve: " << consumed << " slot(s) consumed ("
                  << reserve_source_name(w.source) << ")";
        if (w.source == ReserveSource::Special) std::cout << ", cursor Special " << g_cursors.special;
        if (w.source == ReserveSource::Dp) {
            const Dp32Store& lib = dp32_store();
            std::cout << ", 源库墓碑 " << lib.src_dead_count() << " 条 / 已征召库 "
                      << lib.drf_count() << " 条";
        }
        std::cout << std::endl;
    }
}

// 槽位这一轮的点是不是真来自来源 (而不是回退的随机点)。validate 用它, 生产代码不用。
// 1 类恒 false; 2 类恒 true (阶梯无上限); 3 类源库见底时才会是 false。
bool reserve_slot_sourced(size_t slot)
{
    return slot < g_window.from_source.size() && g_window.from_source[slot] != 0;
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

// 两条真货源各取几条, 验"座标 -> 点"的口径 (x/m/n 自洽) 与序列不重复。
// 一律用**局部游标**, 不碰全局 g_cursors —— 那是生产状态。
void validate_reserve_supplies()
{
    // ---- 2 类: 物化段 256 条 + 无限阶梯, 座标直接算出点 ----
    {
        RhoPoint p;
        // 物化段首条就是 adds_pub[0][0] (x/m/n 三者自洽, 装载时验过)
        RESERVE_CHECK(special_point(0, p));
        RESERVE_CHECK(check(ctx, &p.x, p.m, p.n) == 1);
        RESERVE_CHECK(memcmp(p.m, adds_pub[0][0].m, 32) == 0);
        RESERVE_CHECK(memcmp(p.n, adds_pub[0][0].n, 32) == 0);
        // 物化段末条
        RESERVE_CHECK(special_point(RHO_RESERVE_STEPS - 1, p));
        RESERVE_CHECK(memcmp(p.m, adds_pub[0][RHO_RESERVE_STEPS - 1].m, 32) == 0);
        RESERVE_CHECK(memcmp(p.n, adds_pub[0][RHO_RESERVE_STEPS - 1].n, 32) == 0);

        // 阶梯第 k 级 = k*G: 连取三级 (k = 1, 2, 3), 验"k 由座标现算"、set_int 的
        // 大端字节序、"n = 0 就得到 k*G"的口径。"create(1,0) 就是设备常量里的 G"
        // 那条对拍要拿设备常量比, 放在 cuda.cu。
        for (unsigned char k = 1; k <= 3; ++k) {
            RESERVE_CHECK(special_point(RHO_RESERVE_STEPS + k - 1, p));
            RESERVE_CHECK(check(ctx, &p.x, p.m, p.n) == 1);
            RESERVE_CHECK(p.m[31] == k && p.m[30] == 0);                // 大端: k 落在最后一个字节
            for (int i = 0; i < 32; ++i) RESERVE_CHECK(p.n[i] == 0);    // n = 0 -> k*G
        }

        // 相邻两级必须不同 (游标只增不减 => 序列不重复)
        RhoPoint a, b;
        RESERVE_CHECK(special_point(RHO_RESERVE_STEPS, a));
        RESERVE_CHECK(special_point(RHO_RESERVE_STEPS + 1, b));
        RESERVE_CHECK(memcmp(&a, &b, sizeof(a)) != 0);

        std::cout << get_time() << " : reserve supply Special: " << RHO_RESERVE_STEPS
                  << " points (adds_pub) + ladder on demand (k from cursor) ok" << std::endl;
    }

    // ---- 3 类: 源库从 0 起扫活记录。库不在就只印一行 ----
    {
        if (!dp32_store_init() || !dp32_store().loaded()) {
            cprint() << get_time() << " : reserve supply Dp: 源库不可用, 跳过抽样" << std::endl;
            return;
        }
        uint64_t scan = 0;                 // 局部扫描位置: 绝不碰生产用的状态
        RhoPoint p;
        uint32_t slot = RESERVE_NO_SLOT;
        if (!dp_point(scan, p, &slot)) {
            cprint() << get_time() << " : reserve supply Dp: 源库全是墓碑, 跳过抽样" << std::endl;
            return;
        }
        RESERVE_CHECK(slot != RESERVE_NO_SLOT);
        RESERVE_CHECK(!dp32_store().src_dead(slot));      // 交出来的都是活记录
        RESERVE_CHECK(scan == (uint64_t)slot + 1);        // 扫描位置推到取出那条之后
        RESERVE_CHECK(check(ctx, &p.x, p.m, p.n) == 1);
        uint64_t idx = 0;
        RESERVE_CHECK(dp32_test(p.x, idx));               // 源库里的记录都是 32 位 DP
        // 库内按索引唯一: 复算出来的索引必须与记录自己的 index 字段一致
        Dp32Record rec;
        RESERVE_CHECK(dp32_store().read(Dp32File::Source, slot, rec));
        RESERVE_CHECK(rec.index == idx);

        // 从 0 起扫的**确定性**: 同一位置再扫一次必须拿到同一条 (这是"不浪费"的前提
        // —— 上轮取了没被征调的点下轮必须原样再出现)。
        uint64_t scan2 = 0;
        RhoPoint p2;
        uint32_t slot2 = RESERVE_NO_SLOT;
        RESERVE_CHECK(dp_point(scan2, p2, &slot2));
        RESERVE_CHECK(slot2 == slot);
        RESERVE_CHECK(memcmp(&p2, &p, sizeof(p)) == 0);

        cprint() << get_time() << " : reserve supply Dp: 源库抽样 ok (取到槽位 "
                 << slot << " 的记录, 32 位索引 " << idx << ")" << std::endl;
    }
}

// 状态存档自测: 写 -> 读 -> 逐项对拍, 再验"旧版 (带账本行) 的存档照样读得进来"。
// 全程用 ".selftest" 临时路径, 绝不碰生产存档 RhoReserve.txt。
void validate_reserve_state_file()
{
    const std::string path = RHO_RESERVE_STATE_FILE + ".selftest";
    const auto write = [&](const ReserveCursors& c, uint64_t r, size_t n) {
        return reserve_state_write(path, c, r, n);
    };
    const auto read = [&](ReserveCursors& c, uint64_t& r, size_t n) {
        return reserve_state_read(path, c, r, n);
    };
    const auto put = [&](const std::string& body) {
        std::ofstream out(path, std::ios::trunc);
        out << body;
    };

    // ---- 往返: 游标与轮号一个不差 ----
    {
        ReserveCursors c1;
        c1.special = 366;                 // 假装 2 类已经吃掉 366 条
        RESERVE_CHECK(write(c1, 12, 4));
        ReserveCursors c2;
        uint64_t round = 0;
        RESERVE_CHECK(read(c2, round, 4));
        RESERVE_CHECK(c2.special == 366);
        RESERVE_CHECK(round == 12);
    }

    // ---- 旧版兼容: 已经跑了一段时间的来源 3 (RhoReserve 1 + 账本行) ----
    // 账本行与 "supply Dp" 都必须被**忽略**, 而 2 类游标照读。3 类的进度不靠这份
    // 存档继承 (源库墓碑位图就是进度), 所以读不进来也不影响"不浪费"。
    {
        const std::string hexm(64, 'a');
        const std::string hexn(64, 'b');
        put("RhoReserve 1\n"
            "round 9\n"
            "supply Special 0\n"
            "supply Dp 122\n"
            "slots 4\n"
            "slot 0 Dp empty\n"
            "slot 1 Dp held 8 " + hexm + " " + hexn + "\n"
            "slot 2 Dp empty\n");
        ReserveCursors c3;
        uint64_t round = 0;
        RESERVE_CHECK(read(c3, round, 4));
        RESERVE_CHECK(c3.special == 0);
        RESERVE_CHECK(round == 9);

        // 槽位数不符只告警、不丢进度
        ReserveCursors c3b;
        uint64_t round3b = 0;
        RESERVE_CHECK(read(c3b, round3b, 7));
        RESERVE_CHECK(round3b == 9);

        // 现在的写格式 (v2) 只有 2 类游标, 而且自己写得进读得出
        ReserveCursors c5;
        c5.special = 12345;
        RESERVE_CHECK(write(c5, 7, 4));
        ReserveCursors c6;
        uint64_t round6 = 0;
        RESERVE_CHECK(read(c6, round6, 4));
        RESERVE_CHECK(c6.special == 12345 && round6 == 7);
    }

    // ---- 坏存档必须**整份**丢弃, 而不是"尽力恢复"成一批半真半假的游标 ----
    {
        ReserveCursors c4;
        uint64_t r4 = 0;

        put("RhoReserve 9\nround 1\n");                                // 版本号不认
        RESERVE_CHECK(!read(c4, r4, 4));

        // v3 从未落过盘 (账本取消时直接把它升成了 2), 所以必须当坏档拒掉
        put("RhoReserve 3\nround 1\n");
        RESERVE_CHECK(!read(c4, r4, 4));

        put("RhoReserve 2\n");                                        // 缺 round
        RESERVE_CHECK(!read(c4, r4, 4));

        put("RhoReserve 2\nround 1\nsupply Bogus 5\n");                // 来源名不认
        RESERVE_CHECK(!read(c4, r4, 4));

        put("RhoReserve 2\nround 1\nwhat 1\n");                        // 未知键
        RESERVE_CHECK(!read(c4, r4, 4));

        put("RhoReserve 2\nround 1\nsupply Special 5000000000000000000\n"); // 游标 > 2^62
        RESERVE_CHECK(!read(c4, r4, 4));

        put("RhoReserve 2\nround 1\nsupply Special\n");                // 游标缺失
        RESERVE_CHECK(!read(c4, r4, 4));
    }

    std::remove(path.c_str());
    std::cout << "reserve state file: ok (round-trip / v1 compat / discard on corrupt)"
              << std::endl;
}

#undef RESERVE_CHECK

