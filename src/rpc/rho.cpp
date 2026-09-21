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
// 入参 X, Y 必须已是 magnitude 1。
// 步进结束时 X 全规约 (X < p), 所以 X.n[0] 的低 32 位就是 x mod 2^32, 可直接
// 用于下一轮的索引; Y 只做 normalize_weak (mag 1), 足够满足下一轮的约束。
//
// 总计: 3 次 fe_mul/sqr + 1 次 modinv64_var (批量路径里整批共用 1 次) + 若干
//       fe_add/negate/normalize。
// ---------------------------------------------------------------------------

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
// 合并成了整批一次 (对积检查), 概率仍约 W * 2^-256; 调用方不再为它保留逐点
// 回退路径 (见 rho_affine_step_batch)。
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
// 零分母 (概率约 W * 2^-256) 由 fe_batch_inv 对整批一次检出。该情形不可达,
// 不再为它维护一条逐点回退路径 (原来会退到单 walker 的点倍分支), 检出即放弃
// 本步。
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
    if (!fe_batch_inv<W>(inv, dx)) {
        // dx 里有 0 (A.x == X, 概率约 W * 2^-256): inv[] 未写出, 直接放弃本步
        // (状态不动, 也不报 DP)。该情形不可达, 不再为它保留逐点回退路径。
        return 0;
    }

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
    batch_ok &= rho_affine_batch_selfcheck<2>(1000);
    batch_ok &= rho_affine_batch_selfcheck<4>(1000);
    batch_ok &= rho_affine_batch_selfcheck<8>(1000);
    batch_ok &= rho_affine_batch_selfcheck<16>(1000);
    batch_ok &= rho_affine_batch_selfcheck<32>(1000);
    std::cout << "rho-affine batch selfcheck (W=2/4/8/16/32 vs lib public API): "
              << (batch_ok ? "PASS" : "FAIL") << std::endl;
    if (!batch_ok) exit(EXIT_FAILURE);
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
