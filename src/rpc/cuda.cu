#include <algorithm>
#include <chrono>
#include <cmath>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <cuda_runtime.h>
#include <fstream>
#include <string>
#include <thread>
#include <vector>
#include <iostream>

// 256-bit数值（小端序，32位肢体）
//
// alignas(16) 是性能关键, 不是洁癖: 设备端能不能走 128 位访存全靠它 —— 它出现在
// 全局步进表 adds_pub_dev[]、本地内存的 s[W] / 批量求逆的 den[W]、prefix[W]。
// 对齐不够时编译器证不出 16 字节对齐, 只能拆成 32 位标量访存; 量化对账见下面
// RhoPoint_dev 那节, 底部的 static_assert 保证布局被改坏时编译失败。
struct alignas(16) uint256_t {
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

// 域实现:
// p = 2^256 - 0x1000003D1 是伪梅森素数, 于是 2^256 ≡ M = 0x1000003D1 (mod p)。
// 模乘只需要做 512 位乘积再按这个关系折叠即可。
// M = 0x1000003D1 = 2^32 + 977, 低 32 位为 PSEUDO_MERSENNE_M0, 高 32 位为 1。
#define PSEUDO_MERSENNE_M0 0x000003D1u

// 域中的常量 3
CONSTANT uint256_t three_mod = {
    0x00000003, 0x00000000, 0x00000000, 0x00000000,
    0x00000000, 0x00000000, 0x00000000, 0x00000000};

// fun_add_w 里两个 W 循环**不写** `#pragma unroll`, 由 ptxas 自行全展开。
//
// 已实测 (OPT-4): 手工限制展开因子 4 是净损失, W>=8 档掉 42~45%。当 W>=8 时
// local 足迹几乎没变 (2656->2688 @W8, 13648->13648 @W32), 掉的**全是 ILP**:
// 限制展开等于限制同时活跃的 walker 链数, 而本内核纯延迟受限 (实测 IPC ~= 0.02),
// 只能靠链间重叠掩盖依赖延迟。只有 W<=4 时"少溢出"才划算, 而那几档本来也不缺
// 寄存器 (local 528->72 @W2, 960->240 @W4)。
// 要再扫就把 `#pragma unroll` 直接写进循环上方 —— 值必须写死, 预处理器不展开
// #pragma 里的宏。

// 本文件里引用的历史实测都带口径 (batch 数 / warps per SM / 轮数)。跨会话比绝对
// pts/s 没有意义: GPU 时钟在 1410~1785 MHz 之间随温度功耗浮动, 同一份二进制隔
// 一段时间重跑, 整张表会整体平移 (实测某次 +9%)。可比的是同一轮内交错 A/B 的
// 相对值。

// 点结构（仿射坐标）。uint256_t 已经 alignas(16), 本结构自然也是 16 字节对齐、
// 大小 80 字节 (x 0..31, y 32..63, infinity 64, 尾部填充到 80)。
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

// HOST_ASSERT: host 侧校验。Release 构建带 -DNDEBUG, assert 会被整个编译掉
// (表现为 nvcc/MSVC 的 "variable ... was set but never used" 告警), 等于没检查,
// 所以 host 侧一律用 HOST_ASSERT: 失败就打印文件/行号/条件并退出。
// 设备端对应 DEV_ASSERT (见 g_validate_fail)。
#define HOST_ASSERT(cond)                                                   \
    do {                                                                    \
        if (!(cond)) {                                                      \
            printf("[HOST_ASSERT] %s:%d  %s\n", __FILE__, __LINE__, #cond); \
            exit(EXIT_FAILURE);                                             \
        }                                                                   \
    } while (0)

// 默认策略下 cudaDeviceSynchronize() 是自旋忙等（spin），会让调用线程 100% 占满一个 CPU 核。
// 改为阻塞式等待（Windows 上走 WaitForSingleObject），把该核让给 CPU 工作线程。
// 注意：必须在任何会创建 CUDA context 的调用之前执行，否则返回 cudaErrorSetOnActiveProcess 且不生效。
static void enable_blocking_sync()
{
    static bool done = false;
    if (done) return;
    done = true;
    cudaError_t err = cudaSetDeviceFlags(cudaDeviceScheduleBlockingSync);
    if (err != cudaSuccess) {
        fprintf(stderr, "cudaSetDeviceFlags(cudaDeviceScheduleBlockingSync) failed: %s\n",
                cudaGetErrorString(err));
    }
    (void)cudaGetLastError(); // 清除残留的错误状态，避免污染后续 CHECK_CUDA
}

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

// 设备端可用的 256 位相等判断 (device 代码里不能调用 memcmp)
__host__ __device__ int u256_equal(const uint256_t& a, const uint256_t& b)
{
    for (int i = 0; i < 8; ++i)
        if (a.limb[i] != b.limb[i]) return 0;
    return 1;
}

// ================== 域模运算 ==================
// 一次 2^256 折叠, 利用 2^256 ≡ M = 2^32 + 0x3D1 (mod p):
//     dst[0..7]  =  src[0..7] + (src[8 .. 8+hn-1]) * M
// 输入 src 的低 8+hn 个肢体必须是归一化的 (每个 < 2^32); src 与 dst 不得重叠。
// dst 需至少 12 个肢体 (折叠后最高只会到下标 9)。
//
// hn 必须是模板参数: 运行期参数会让 a[12]/b[12] 局部数组带可变下标寻址,
// nvcc 直接把数组降级到本地内存 (LDL/STL, 实测 ~540 条/点, 占指令数 39%);
// 模板参数配合调用点的常量循环界可完全展开, 数组留在寄存器里。
//
// ⚠ 进位传播是 fold256 唯一出过真 bug、也是唯一"看着对但慢 24%"的地方 ——
//   动它之前先看 reduce_product 上面的注释。
//
//   这段的写法是 7 个变体 A/B 出来的 (满宽乘 micro MODE 4, mul_mod(x,x),
//   cycles/op, 4 / 16 warps/SM):
//     只补 2 格 (旧版, 快但错, 见 reduce_product)    734 / 1691
//     独立循环 (带/不带 break)、if constexpr 递归、
//       进位并进主循环、每格 'if (c==0) return 0'     922~1094 / 1811~2284
//     每格一个真分支 + 32 位进位 (现用)              897 / 1811
//   cuobjdump -sass 显示以上变体 **全部 0 条 LDL/STL** —— "数组落到本地内存"的
//   猜测是错的, 静态指令数 (400 vs 432) 也不是模型。真正的差别在**串行依赖链**:
//   被 if-convert 成 ISETP.NE + SEL 的写法, 112 条新指令全压在依赖链上
//   (SEL +30 / IMAD.X +26 / ISETP.NE.U32 +34 => +357 cyc); 换成真分支虽然
//   BRA 2 -> 18, 但省掉了选通链。教训: 只压指令数没用, 要压**依赖链长度**; 而一
//   旦引入真分支, 就再也回不到零分支、可全局调度的状态。
//   代价在真实内核上已实测 (rhoperf, RHO_PERF_BATCHES=5000, 3 轮交叉): W=16
//   -1.5%, W=32/64 完全在噪声内。**+21% 的满宽乘是这笔正确性修复的固有代价**,
//   除非把进位传播改成无分支的 O(1) 形式 (试过, 没成功)。
//
// 单格进位吸收: dst[k] += c, 返回新的进位。k 是编译期常量 => 调用点完全展开、
// dst 留在寄存器。进位恒为 0/1 (见 fold256 里的取值范围推导), 所以用 32 位算术,
// 不要 uint64_t —— 后者会让 nvcc 每格生成 IMAD.MOV.U32 + IMAD.X 两条 64 位加法。
template <int k>
__host__ __device__ static inline uint32_t fold_step(uint32_t* dst, uint32_t c)
{
    const uint32_t t = dst[k] + c;
    dst[k] = t;
    return t < c ? 1u : 0u;
}

template <int hn>
__host__ __device__ static void fold256(const uint32_t* src, uint32_t* dst)
{
    for (int k = 0; k < 8; ++k) dst[k] = src[k];
    for (int k = 8; k < 12; ++k) dst[k] = 0;

    uint64_t c = 0;
    // hi[i]*M = hi[i]*0x3D1 + hi[i]*2^32 , 分别落在位置 i 与 i+1
    // (0x3D1 = 977, 故 hi*977 <= 2^42, c 最大 ~978*2^32, 不会溢出 64 位)
    for (int i = 0; i <= hn; ++i) {
        if (i < hn) c += (uint64_t)src[8 + i] * PSEUDO_MERSENNE_M0;
        if (i >= 1) c += (uint64_t)src[7 + i];
        uint64_t cur = c + (uint64_t)dst[i];
        dst[i] = (uint32_t)cur;
        c = cur >> 32;
    }

    // ── 进位传播 (v6) ────────────────────────────────────────────────────────
    // 三条硬约束, 每条都是实测换来的:
    //   1) 必须一路走到下标 8 (hn=8 时是下标 9)。dst[hn+1..7] 由拷贝循环填成
    //      src[hn+1..7], 那是正确的"低位肢体"值, 但 c=1 撞上一串 0xFFFFFFFF 会
    //      一直穿过去; r168 那版只补两格, 于是丢掉 2^256 ≡ M 的那一份
    //      (reduce_product 上面有构造用例)。dst[8]/dst[9] 初值 0, 进位必停在那里。
    //   2) 不能独立成循环/递归。v1/v2/v4 都试过, 循环体或递归体没被内联进主线,
    //      实测比 r168 慢 24%~49%, 且 SASS 里 LDL/STL 是 0 —— 不是本地内存问题。
    //   3) 不能无条件执行。v3 把整条链并进主循环, 指令最少却最慢 (950 cyc):
    //      静态指令数不是模型, 串行依赖链长度才是。
    //   所以这里把整段套在**一个** if 里, 用编译期下标手写展开: 公共路径
    //   (c == 0) 上是一条跳过的分支, 静态代价 ~2 条指令; 只有真的出进位时
    //   才走进去 —— 而进位本身几乎不可能出现 (下面推导 c 恒为 0 或 1,
    //   且为 1 的概率 < 2^-30)。
    //
    // 取值范围推导 (保证 c ∈ {0,1}, 所以 32 位进位够用):
    //   记 c_i 为主循环第 i 轮结束后的进位, 恒有 c_i < 2^11:
    //     c_0 = src[8]*977 >> 32 < 2^10; 之后每轮 c += (2^32-1)*977 + (2^32-1),
    //     而每轮都 >>32, 故 c_i < 2^10 + 2^10 < 2^11 恒定成立。
    //   末轮 (i = hn): hn=8 只加 src[15] < 2^32, 且 dst[8] 此时初值 0,
    //     cur < 2^32 + 2^11  =>  c_8 <= 1;
    //     hn=2 只加 src[9] <= 1, dst[2] < 2^32  =>  cur < 2^32 + 2^11  =>  c_2 <= 1;
    //     hn=1 同理 c_1 <= 1。
    //   (fold256 的入参已经归一化, 所以主循环里 c 永远是"纯进位", 不会有别的量。)
    {
        if constexpr (hn == 8) {
            // hn = 8: 主循环已经写完 dst[0..8], dst[9..11] 还是 0。进位落在下标 9
            // 就必然被吸收 (c <= 1 < 2^32), 所以一条赋值就够, **不需要分支** ——
            // 少一个分支区域就少一份流水线气泡。
            dst[9] = (uint32_t)c;
        } else {
            const uint32_t c0 = (uint32_t)c;   // 由上推导 c <= 1, 截断无损
            if (c0 != 0) {
                uint32_t cy = c0;
                if constexpr (hn == 2) {
                    cy = fold_step<3>(dst, cy);
                    cy = fold_step<4>(dst, cy);
                    cy = fold_step<5>(dst, cy);
                    cy = fold_step<6>(dst, cy);
                    cy = fold_step<7>(dst, cy);
                    cy = fold_step<8>(dst, cy);
                } else {
                    static_assert(hn == 1, "fold256 只实例化 hn = 1 / 2 / 8");
                    cy = fold_step<2>(dst, cy);
                    cy = fold_step<3>(dst, cy);
                    cy = fold_step<4>(dst, cy);
                    cy = fold_step<5>(dst, cy);
                    cy = fold_step<6>(dst, cy);
                    cy = fold_step<7>(dst, cy);
                    cy = fold_step<8>(dst, cy);
                }
                (void)cy;   // 下标 8 初值为 0 => 到那里进位必然被吸收
            }
        }
    }
}

// 512 位归一化乘积 prod[0..15] 归约到 [0, p)
// 折叠链 16 肢体 -> 10 有效 -> 9 有效 -> 9 有效 -> < 2^256
//
// todo: 本函数 (及其 fold256 的进位传播) 是唯一被 validate 抓出过真 bug 的地方,
// 改它之前先看下面这段历史。
//
// ── 进位传播 bug 的历史 (不读这节不要动它) ───────────────────────────────
// 旧版只补 dst[hn+1] / dst[hn+2] 两格, 当时判断"主循环结束后的 c 最多 ~1, 不会
// 形成长进位链"。**这个判断是错的**: c=1 遇到 dst[hn+1..] 连续 0xFFFFFFFF 时会
// 一路穿到底。实例: prod 全 0xFFFFFFFF 时正确值 2^512-1 ≡ M^2-1 =
// 2^64 + 0x7A2*2^32 + 0xE90A0, 旧代码给出 2^64 + 0x7A1*2^32 + 0xE8CCF, 正好少了
// 那个落在全 f 串上的 M。该 bug 随机触发概率 ~2^-64, 只有构造输入能稳定复现 ——
// 这就是 validate 里那几个"全 f"用例存在的理由。
//
// 顺带记一个被否决的方向 (OPT-9): "一趟写 10 个肢体 + 数据相关 3 趟回折", 前提是
// "第二折几乎不执行"; 对满宽乘积 hi 近似均匀, 回折其实是常态。实测 mul_mod(x,x)
// 735.9 -> 908.0 cyc (4 warps) / 1716.8 -> 1864.7 (16 warps), 弃用。
//
// 正确性: validate 里用**完全独立**的教科书式逐位移位归约 ref_mod_p (512 次
// r = 2r + bit) 做对拍, 覆盖随机 + 4 个构造极端输入 (全 f / hi全f / lo全f / 全0),
// host 6/6 + 设备 2048 线程全部一致。
// 其中三个构造用例可与手推解析解对照 (M = 2^32 + 977):
//     全 f      -> V = 2^512 - 1     ≡ M^2 - 1 = 2^64 + 0x7A2*2^32 + 0xE90A0
//     hi全f/lo0 -> V = 2^512 - 2^256 ≡ M^2 - M = 2^64 + 0x7A1*2^32 + 0xE8CD0
//     lo全f/hi0 -> V = 2^256 - 1     ≡ M - 1   = 2^32 + 0x3D0
// 这三个解析解是手推的, 不要改。插曲: 期间 ref_mod_p 自己的三态比较写错过
// (判到"小于"后没停下, 低位把 ge 又翻回 true, 多减一次 p 并让 r[8] 下溢),
// 一度表现为 "1024 failed"; 修好之后才发现生产代码**确实**有 bug。
// 教训: 对拍有两个方向 —— 参考错会误报, 参考对就会抓到真错, 两边都得看。
//
// 历史教训 (保留): 折叠的每次迭代的位宽必须是**编译期常量**, 否则 nvcc 会把
// 结果数组带可变下标寻址而降级到本地内存 (实测 ~540 条 LDL/STL 每点, 占指令 39%)。
__host__ __device__ static uint256_t reduce_product(const uint32_t* prod)
{
    uint32_t a[12], b[12];
    fold256<8>(prod, a); // a < 2^289 + 2^256, 有效下标 0..9
    fold256<2>(a, b);    // b < 2^256 + 2^66,  有效下标 0..8
    fold256<1>(b, a);    // a < 2^256 + 2^33,  有效下标 0..8
    fold256<1>(a, b);    // b < 2^256,         有效下标 0..7

    uint256_t r;
    for (int i = 0; i < 8; ++i) r.limb[i] = b[i];
    // b < 2^256 且 p = 2^256 - M, 故至多需要减一次 p
    if (is_ge(r, p)) sub256(r, p);
    return r;
}

// 域模乘: r = a*b mod p (a, b 均视为 < p 的普通整数)
__host__ __device__ uint256_t mul_mod(const uint256_t& a, const uint256_t& b)
{
    uint32_t t[16];
    for (int i = 0; i < 16; ++i) t[i] = 0;

    // 256x256 -> 512 位学校乘法
    for (int i = 0; i < 8; ++i) {
        uint64_t carry = 0;
        for (int j = 0; j < 8; ++j) {
            uint64_t cur = (uint64_t)a.limb[i] * b.limb[j] + t[i + j] + carry;
            t[i + j] = (uint32_t)cur;
            carry = cur >> 32;
        }
        t[i + 8] = (uint32_t)carry; // 位置 i+8 之前未被写过, 可直接赋值
    }
    return reduce_product(t);
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

__host__ __device__ uint256_t mod_sub(const uint256_t& a, const uint256_t& b)
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

// ================== safegcd 模逆 (移植自 libsecp256k1 的 modinv32_impl.h) ==================
// Bernstein-Yang divsteps 算法: 纯 int32/int64 整数运算, 无 CPU 专有指令, 天然适配 CUDA。
// - 设备端与主机端默认都走变量时间版本 divsteps30_var: 平均 ~11 轮收敛,
//   并用 ctz 把连续的除 2 步骤批量处理, 纯算术开销约为常量时间版本的 1/4。
//   rho 每一步点加都要做一次模逆, 模逆是热路径上最大的单项成本, 故优先选变量时间版本。
//   代价: 同一 warp 内各线程轮数略有差异会有一定发散, 但轮数集中在 11 附近,
//         远小于常量时间版本固定多出来的那 9 轮开销。
// - 定义 USE_CONSTTIME_MODINV=1 可切回常量时间版本 (30 步完全无分支, warp 绝对无发散),
//   用于在真实多线程场景下做 A/B 对比。
#ifndef USE_CONSTTIME_MODINV
#define USE_CONSTTIME_MODINV 0
#endif
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

#if USE_CONSTTIME_MODINV
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
#endif // USE_CONSTTIME_MODINV

// modinv32_inv256[i] = -(2*i+1)^-1 (mod 256)
// 设备端用常量数组; 主机端退化为普通常量数组
CONSTANT uint8_t modinv32_inv256[128] = {
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

#if USE_CONSTTIME_MODINV
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
#endif // USE_CONSTTIME_MODINV

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

#if USE_CONSTTIME_MODINV
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
#endif // USE_CONSTTIME_MODINV

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

// 设备端与主机端统一走变量时间版本 (见文件上方 USE_CONSTTIME_MODINV 的说明)
__host__ __device__ static void modinv32_auto(signed30* x, const modinv32_modinfo_s* modinfo)
{
#if USE_CONSTTIME_MODINV
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

// 域中的逆元计算 (safegcd/divsteps 版本, 移植自 libsecp256k1)
// modinv32 只把输入当作普通整数求逆, 输入输出都在同一域, 不需要任何域转换。
__host__ __device__ uint256_t mod_inv_p(const uint256_t& a)
{
    signed30 s;
    u256_to_s30(&s, a);
    modinv32_auto(&s, &modinfo_p);
    uint256_t inv;
    s30_to_u256(&inv, &s);
    return inv;
}

// ================== 点运算 (仿射坐标) ==================
//
// 仿射点加唯一的一处实现, 拆成"判定分支 / 应用公式"两步。拆开的唯一动机是
// 多 walker 批量求逆: W 个 walker 的**分母**必须先凑齐, 做一次 Montgomery
// 批量求逆, 才能回头各自套公式。拆开之后:
//
//   fun_add_w<W>  —— 生产路径。表索引出发, W 个分母一次求逆。
//   point_step    —— 给定任意 (P, Q) 的单步入口, 每步一次 mod_inv_p。
//                    生产不跑它, 只用于验证三个分支 (点倍 / 无穷远 / 一般
//                    加法): 这三个分支的触发条件由具体操作数决定, 没法用
//                    表索引构造出来。
//
// 以前这里是一份独立的 point_add (单点) + fun_add_w 里另一份逐字重复的分支
// 判定, 两份代码必须同步维护 —— 已经删掉, 分支判定只剩这一份。
//
// 合并后实测 (perf, W 扫描, block=128, batches=20000):
//   W=1:  regs 140->114, local 144B->72B, occBlocks 3->4 (12->16 warps/SM),
//         grid 138->184, 总吞吐 +5.6% (同轮交错 A/B 钉死, 见下)
//   W=2..64: 全部在 ±0.5% 内 (regs/local/occ 均未变 —— 生产路径 (W=4) 的指令流
//         完全没动, 这次清理的收益就是少一份必须同步维护的重复代码)
// W=1 的处置细节: 删掉的 fun_add 在 W=1 时多留 26 个寄存器和 72B 本地内存, 所以
// 合并压缩了 W=1 的占用 (12 -> 16 warps/SM), 顺手吃到一个吞吐增量。
//
// W=1 那部分收益的确切因果 (不要读成"每点变快了") —— 用 (已删的) RHO_PERF_WS
// 仪器=1:138,1:184 在同一份二进制、同一轮运行里交错 A/B 4 组钉死的 (两档跑的是同一份代码, 只有驻留
// 量不同, 所以这是纯并发度实验):
//     grid=138 (12 warps/SM): 210.66M pts/s   130,289 cyc/pt
//     grid=184 (16 warps/SM): 222.51M pts/s   157,343 cyc/pt
//   => 吞吐 +5.6%, 而**每点周期数反而 +20.8%**。两件事同时成立: 同一份代码多塞
//      1/3 的 warp, 延迟隐藏变好所以总吞吐涨; 但每 SM 内部更挤, 单线程的依赖链
//      走得更慢。这是"总吞吐随占位率上升、每线程延迟同时上升"的典型交易。
//      (表里那句跨运行的 "+7.0%" 混了机器态漂移, 同轮交错读出的 +5.6% 才干净。)
//
// 口径: 上面这些对照的噪声底 —— 同一会话内两次运行, 未被改动的 W=2..64 的 cyc/pt
// 只漂 +0.2~1.0%, 所以 W=1 的差异是真实的。
//
// mode 取值 (由 step_prepare 返回):
//   0 = 一般加法,  den = Qx - Px        (非零)
//   1 = 倍点,      den = Py + Qy        (非零, Px == Qx 且 Py + Qy != 0)
//   2 = P = -Q,    结果为无穷远         (den 无意义)
//   3 = P 或 Q 为无穷远, 结果取另一个   (den 无意义)
//
// mode 2/3 下 den 必须置 1 而不是 0: 批量路径的前缀积要把被跳过的 walker 乘上
// 中性元, 否则整批前缀积变 0, 一次 mod_inv_p(0) 会把整批的逆全部毁掉。置 1 之后
// 分母恒非零, fun_add_w 里就不需要任何兜底路径 (CPU 侧 rho.cpp 的 fe_batch_inv
// 靠对整批积做零检查 + 整批回退逐点路径, 这里用分类消掉了这个兜底)。
//
// 判定只算分母, 不碰点坐标 —— 前向循环里 P 还是旧值, 回代循环里才推进。
__host__ __device__ static int step_prepare(const AffinePoint& P, const AffinePoint& Q, uint256_t* den)
{
    if (P.infinity || Q.infinity) {
        *den = uint256_t{{1}};
        return 3;
    }
    uint256_t x_diff = mod_sub(Q.x, P.x);
    if (is_zero(x_diff)) {
        uint256_t y_sum = mod_add(P.y, Q.y, p);
        if (is_zero(y_sum)) {
            *den = uint256_t{{1}}; // P = -Q, 结果无穷远
            return 2;
        }
        *den = y_sum;
        return 1;
    }
    *den = x_diff;
    return 0;
}

// 用分母的逆 inv_den 把 P 推进到 P + Q。公式与 step_prepare 的判定严格配套。
__host__ __device__ static void step_apply(AffinePoint& P, const uint256_t& inv_den, int mode, const AffinePoint& Q)
{
    if (mode == 3) {
        if (P.infinity) P = Q; // P+∞ = P; Q=∞ 时 P 不变 (∞+Q=Q 亦覆盖)
        return;
    }
    if (mode == 2) {
        // 坐标清零, 避免残留值误触发 DP 判定
        P.x = uint256_t{{0}};
        P.y = uint256_t{{0}};
        P.infinity = true;
        return;
    }

    // λ = num / den; mode 1 的 num = 3X², mode 0 的 num = Qy - Py
    const uint256_t num = (mode == 1) ? mul_mod(mul_mod(P.x, P.x), three_mod)
                                      : mod_sub(Q.y, P.y);
    const uint256_t lambda = mul_mod(num, inv_den);
    const uint256_t lambda_sq = mul_mod(lambda, lambda);

    AffinePoint R;
    R.x = (mode == 1) ? mod_sub(lambda_sq, mod_add(P.x, P.x, p))
                      : mod_sub(mod_sub(lambda_sq, P.x), Q.x);
    R.y = mod_sub(mul_mod(lambda, mod_sub(P.x, R.x)), P.y);
    R.infinity = false;
    P = R;
}

// 给定任意 (P, Q) 走一步 (每步一次 mod_inv_p)。仅验证用, 生产路径走 fun_add_w<W>。
__host__ __device__ static AffinePoint point_step(const AffinePoint& P, const AffinePoint& Q)
{
    AffinePoint R = P;
    uint256_t den;
    const int mode = step_prepare(R, Q, &den);
    step_apply(R, mod_inv_p(den), mode, Q);
    return R;
}

// ========== 关于 "把 rho.cpp 的 rho_affine_FW 写法移植到 CUDA 侧" ==========
//
// 结论: 不能, 而且没有东西可移。rho_affine_FW 里只有两件事, 第一件**已经**
// 移植了 (它就是 fun_add_w), 第二件在 CUDA 侧根本没有对应物。逐条给实测。
//
// (A) "W 个分母凑一批, 一次求逆" —— 已移植, 就是本文件的 fun_add_w<W>。
//     数学结构与 rho_affine_FW<W> 完全同构: 前缀积 -> 一次 Montgomery 逆 -> 回代。
//     收益也已吃到: 总吞吐随 W 单调升到 W=32 见顶 (W=64 只差 0.03%), 曲线形状
//     (1->2 最大跳变, 16 后平坦) 与 CPU 侧 rho_affine walkers 扫描
//     (0.74M -> 1.30M -> 2.05M -> 2.96M -> 3.77M -> 4.12M) 同形 —— 说明"批量
//     求逆"这条优化在 GPU 上已经用尽, 再调 W 没有剩余空间。
//     具体数值看上面两张表 (基准核 W 扫描 / 生产核资源占用); 早期一轮 W 扫描
//     因为口径不同 (不同驻留额度, 且 W=1 后来因点加合并降了寄存器) 数值偏高，
//     不要和那两张表混引。
//
// (B) "状态缓存在 thread_local RhoCache<W>, 只在 DP 命中 / 定期 flush 才写回"
//     —— CUDA 侧没有对应物, 所以无从移植。rho_w<W> 的热循环里**一次都不碰**
//     RhoStates_dev: W 个 walker 全程只活在寄存器 + 本地内存里, 直到 kernel
//     退出才写回一次 (见 rho_w 尾部, 循环外)。
//     量化: 生产核每线程一轮 2^20 点, W=4 时写回 4*144 = 576 B = 5.5e-4 B/点;
//     而每点光读步进表就是 144 B。写回占访存量的 4e-6, 已经是噪声底。
//     那 CPU 的 RhoCache 到底在解决什么? 在解决"状态装不进寄存器, 每步都得按
//     RhoState 地址回内存读写 136 B"。GPU 这边装不下时就溢出到本地内存
//     (实测 localSizeBytes: W=4 -> 1104 B, W=8 -> 3024 B), 而本地内存由 L1
//     承载、偏移是编译期常量、全 warp 地址一致 —— RhoCache 想要的效果 (状态常驻
//     L1、不回 L2/DRAM) 在 GPU 上是硬件默认行为, 不需要写代码。
//     唯一还留在内存里的**每步**访问是那张 36 KB 步进表, 那已单独量过
//     (结论: 生产路径不碰共享内存, 见 perf_test_gpu_kernel 上方)。
//
//     这条不是靠读源码推的, 是数 SASS 数出来的。cuobjdump -sass -fun
//     '_Z5rho_wILi4EEvv' (即 rho_w<4>, sm_86, -maxrregcount=168) 之后定位到
//     热循环 (后向分支 0x13220 -> 0x5c80, 跨 3418 条静态指令), 循环体内:
//         IMAD  1459   IADD3 1145   ISETP 289   LOP3 122   SHF 1
//            -> 整数 ALU 合计 3016 = 88.2%
//         LDG     13   (这就是那 4 个 walker 各读一次 144B 步进表)
//         ST/STG   0   (整个热循环一条全局写都没有)
//         LDL     20   STL   19   (状态溢出到本地内存的读写)
//         LDS/STS  0             (没有共享内存)
//     即: 全局访存占热循环指令数的 14/3418 = 0.4%, 且读多写零。这是"算术 +
//     ALU 依赖延迟bound"最直接的证据 —— 也正因为如此, 所有针对访存的优化
//     (共享内存、RhoCache 式缓存) 在这里都没有着力点。
//
// (C) 那 GPU 每点到底慢在哪? 慢在域算术的实现形式, 不在访存结构。
//     同一台机器、同一轮 perf、同样 W=4 批量求逆:
//         perf_test_cpu()      : 8x32 肢 (本文件 uint256_t)      1.2539M pts/s
//         rho-affine walkers=4 : 5x52 肢 (libsecp256k1 手写 asm) 2.0460M pts/s
//     同一颗 CPU 上, libsecp256k1 的表示比本文件这份实现快 1.60~1.63 倍 —— 这
//     1.6x 就是"表示形式"的价格, 与批量求逆的写法无关 (两边都是 W=4 批量)。
//     (两轮实测: 1.2539M/2.0460M = 1.63x, 1.2559M/2.0101M = 1.60x。)
//     换成单线程跨机器对比更明显:
//         GPU 1 线程 W=4: 17234 cyc/pt   (1/102924 pts/s = 9.72 us, @1.77 GHz)
//         CPU 1 线程 W=4: ~2100 cyc/pt   (1/2.0460M pts/s = 489 ns, @4.3 GHz)
//     GPU 单线程每点周期数是 CPU 的 8.2 倍。结合 (B), 这 8.2x 里几乎没有
//     访存成分, 主要是 8x32 肢 + 每步一次显式归约 (mul_mod) 的结构成本。
//     所以要再快, 该做的是给 device 侧换一套归约更省的表示 (例如 5x52 或
//     延迟归约的 8x32'), 而不是搬 rho_affine_FW 的外壳。
//     注: GPU 最终仍比 CPU 快得多 —— 生产配置 (8 warps/SM) 实测 414.8M pts/s,
//     满额 24 warps/SM 时 591.9M, 对应 CPU 单核 2.0M, 那 200~300 倍完全来自
//     1.2~3.5 万线程的并行度, 与单点效率无关。
// ==========================================================================

// ================== Rho算法 ==================
#include "common.h"
__host__ __device__ void transfer(unsigned char* mp, const unsigned char* mp2)
{
    for (int i = 0; i < 32; i++) {
        mp[i] = mp2[31 - i];
    }
}
// 设备端 walker 状态 / 步进表元素。m(32) n(32) x.AffinePoint(80) = 144 字节,
// alignas(16) 让每个 uint256_t 成员都落在 16 的整数倍偏移上, 于是表项与本地
// 内存里的 s[W] 都能走 128 位访存 (一条表项 9 条访存, 而不是 33 条)。
class alignas(16) RhoPoint_dev
{
public:
    uint256_t m = {0};
    uint256_t n = {0};
    AffinePoint x = {{0}};

    void from(const RhoPoint& r) {
        transfer((unsigned char*)&this->m, r.m);
        transfer((unsigned char*)&this->n, r.n);
        // pubkey 字节即坐标, 直接拷入
        memcpy(&this->x, r.x.data, sizeof(r.x.data));
        x.infinity = false;
    }
    void to(RhoPoint& r)
    {
        // x.x 与 x.y 在 AffinePoint 中连续, 正好是 64 字节的未压缩坐标
        memcpy(r.x.data, &this->x.x, sizeof(r.x.data));
        transfer(r.m, (unsigned char*)&this->m);
        transfer(r.n, (unsigned char*)&this->n);
    }
    __device__ bool operator==(const RhoPoint_dev& other) const
    {
        // 比较前 129 字节 = m(32) + n(32) + x 的有效部分 (x.x 32 + x.y 32 +
        // infinity 1)。AffinePoint 尾部还有 15 字节 alignas(16) 填充, 不参与
        // 比较, 所以这里不能写 sizeof(RhoPoint_dev)。
        const unsigned char* a = (const unsigned char*)&this->m;
        const unsigned char* b = (const unsigned char*)&other.m;
        for (size_t i = 0; i < 129; i++) {
            if (a[i] != b[i]) {
                return false;
            }
        }
        return true;
    }
} ;

// 布局不变量: 往 uint256_t / AffinePoint 里加成员一旦破坏上面那套对齐与大小, 这里
// 直接编译失败, 而不是悄悄退回标量访存(性能掉 5% 而没人发现)。
// 注意: 本文件的字符串字面量只能用 ASCII, 中文会让 cudafe++ 报 missing closing quote。
static_assert(alignof(uint256_t) >= 16, "uint256_t needs 16B alignment");
static_assert(sizeof(uint256_t) == 32, "uint256_t should stay 8x32-bit");
static_assert(offsetof(AffinePoint, x) % 16 == 0, "AffinePoint.x needs 16B alignment");
static_assert(offsetof(AffinePoint, y) % 16 == 0, "AffinePoint.y needs 16B alignment");
static_assert(offsetof(RhoPoint_dev, m) % 16 == 0, "RhoPoint_dev.m needs 16B alignment");
static_assert(offsetof(RhoPoint_dev, n) % 16 == 0, "RhoPoint_dev.n needs 16B alignment");
static_assert(offsetof(RhoPoint_dev, x) % 16 == 0, "RhoPoint_dev.x needs 16B alignment");
static_assert(alignof(RhoPoint_dev) >= 16, "RhoPoint_dev alignment too small (scalar loads)");
static_assert(sizeof(RhoPoint_dev) % 16 == 0, "array stride must be 16B or only [0] is aligned");

// 设备全局内存存储 adds_pub_dev
__device__ RhoPoint_dev adds_pub_dev[256];

constexpr size_t dp_buffer_size = 110; // DP 缓冲区大小
__constant__ RhoPoint_dev RhoStates_rand[dp_buffer_size];

// GPU 多 walker: 每线程 walker 数。批量求逆每点多付 ~3 次模乘, 换掉
// (1-1/W) 次 safegcd 模逆。
//
// ==== W 扫描 (RTX 3070 Ti Laptop, r168, 同一段内的干净 sweep, RHO_PERF_BATCHES=5000) ====
// 基准核 perf_rho_w_kernel<W>, block=128, grid 由各 W 的真实驻留额度定。
//   W   grid×block  threads   regs  local    warps/SM  总吞吐      每线程     每 walker
//   1   184x128      23552     114     72B     16     231.4M       9,823      9,823
//   2   184x128      23552     112    512B     16     378.8M      16,083      8,042
//   4   138x128      17664     168   1104B     12     520.4M      29,460      7,365
//   5   138x128      17664     168   1632B     12     577.7M      32,706      6,541
//   6   138x128      17664     168   2144B     12     625.5M      35,414      5,902
//   7   138x128      17664     168   2528B     12     660.8M      37,409      5,344
//   8   138x128      17664     168   3024B     12     689.8M      39,050      4,881
//   16  138x128      17664     168   6928B     12     779.1M      44,107      2,757
//   32  138x128      17664     168  13824B     12     803.5M      45,489      1,422
//   64  138x128      17664     168  26224B     12     794.5M      44,977        703
//   (W>=4 的 grid×block 恒定 17664 线程 = 552 warp, 即 12 warps/SM 一路不变 ——
//    所以这一段里每档的收益**纯粹**来自批量求逆的摊薄, 没有驻留量的变化混在里面。
//    W=1 行是点加合并后的复测值 (删掉重复实现后它降到 16 warps/SM), 所以
//    W=1->W=2 的比值跨了两次运行, 不要引用。)
//
// 重复性: W=8/16/32 三次独立进程实测 692.1/780.7/804.3、694.5/779.4/802.6、
// 689.8/779.1/803.5, 两两相差 <0.6%。W=1 工作量只有 1/4, 受升频影响大, 只作量级参考。
//
// ==== 基准 sweep 的边际账 (W>=4 段) ====
// 总吞吐单调递增到 W=32 见顶 (803.5M), W=64 回落;
// 每 walker 速度单调下降 (7,365 @W4 -> 703 @W64) —— 每一档"总吞吐的增量"都是拿
// "单个 walker 变慢" 换的。两个维度一起看:
//   +1 walker ->  总吞吐     每 walker     多占 states
//   4 -> 5        +11.0%       -11.2%       +35,328  (+25.0%)
//   5 -> 6         +8.3%        -9.8%       +35,328  (+20.0%)
//   6 -> 7         +5.6%        -9.5%       +35,328  (+16.7%)
//   7 -> 8         +4.4%        -8.7%       +35,328  (+14.3%)
// 即往大 W 走: 总吞吐收益递减 (11.0 -> 4.4) 而单 walker 速度固定掉 ~9~11%。
// 往小 W 走则是每一档都便宜地买到单 walker 速度:
//   8 -> 7: 总吞吐 -4.2%   每 walker +9.5%   states -12.5%
//   8 -> 6: 总吞吐 -9.3%   每 walker +20.9%  states -25.0%
//   8 -> 5: 总吞吐 -16.3%  每 walker +34.0%  states -37.5%
// 注意 4->5 还有 +11.0%, 说明 W=5~8 之间摊薄**尚未饱和**, 每一档都是真收益;
//
// ==== 生产核 rho_w<W> 的资源占用 (实测, RHO_PROD_ATTRS=1, block=128) ====
// 生产核和基准核是两份独立编译产物, 资源画像完全不同, 选 W 必须看这张表:
//   W   regs  local      maxThreads  occBlocks  fillGrid×block  threads  states      warps/SM
//   1   124     96B        512          4       184x128         23552     23552         16
//   2    76    544B        768          6       276x128         35328     70656         24
//   4    76    960B        768          6       276x128         35328    141312         24
//   5    76   1168B        768          6       276x128         35328    176640         24
//   6    76   1376B        768          6       276x128         35328    211968         24
//   7    76   1584B        768          6       276x128         35328    247296         24
//   8    76   1792B        768          6       276x128         35328    282624         24
//   16   76   3472B        768          6       276x128         35328    565248         24
//   32   76   6832B        768          6       276x128         35328   1130496         24
// 两个关键事实:
//   (1) 生产核 W>=2 的**驻留额度**都是 6 block/SM = 24 warps/SM, 满额 grid 276,
//       满额 threads 35,328; 基准核是 168 regs / occ 3 / grid 138 / 12 warps/SM
//       —— 差一倍。(生产实际只用 8 warps/SM = grid 92, 见 "warps/SM 定档"。)
//       两边每点的算术量相同 (基准核也调 distinguishable), 绝对吞吐两边都已实测,
//       同一 warps/SM 下只差 7~13% (见 "生产核 vs 基准核")。
//   (2) W>=4 段两边**驻留额度**都**与 W 无关** (生产恒 24 warps, 基准恒 12 warps),
//       所以 "换 W 能换到多少相对收益" 可以从基准表搬过来;
//       只有 W<=2 那一档两边形状不同, 不能搬。
// 寄存器恒 76 (W>=2) 说明生产核不溢出; local ≈ 128B + 208B*W
// (= 状态 144B + den 32B + prefix 32B 每 walker 一份), 随 W 线性
// (W<=8 精确吻合, W=16/32 略高: 3472/6832 —— 给编译器留的重排余量)。
// 这张表用 RHO_PROD_ATTRS=1 rhoperf 就能重打, 不必为每个 W 各编译一次。
//
// 成本随 states = threads*W 线性增长 (生产核实测 grid 276x128 = 35,328 线程, W>=2 恒定):
//   W     states     设备态     文本态    落盘(每轮)
//   2     70,656     10 MB     18 MiB     0.28 s
//   4    141,312     20 MB     36 MiB     0.56 s
//   5    176,640     25 MB     45 MiB     0.69 s
//   6    211,968     31 MB     54 MiB     0.83 s
//   7    247,296     36 MB     63 MiB     0.97 s
//   8    282,624     41 MB     71 MiB     1.11 s
//   16   565,248     81 MB    143 MiB     2.22 s
//   32 1,130,496    163 MB    286 MiB     4.44 s
//   (设备态 = states x 144 B, 文本态 = states x 256 B, 落盘按
//    save_RhoStates_dev_fast 实测 3.93 us/条。) 这一列随 states 线性, 可外推。
// 启动补点另行记账: 只在 states 超过 D:\RhoState2.txt 现有条数时发生, 耗时是
// (states - 现有条数) x 单点耗时, 单点由 RhoPoint::rand() 在多线程 CPU 上算,
// 实测 ~0.045 ms/点 (16 线程)。**这一列的绝对值随文件大小和 CPU 负载变, 不要
// 记成常数**; 只记两件不变的事: 它随 W 线性增长, 且完全发生在 kernel 之外
// (补点期间 GPU 全程空转)。例: 文件 188,416 条时 W<=5 一个缺口都不用补, W=32
// 要补 942,080 个 (实测 ~42 s)。
//
// ==== OPT-7: 寄存器上限 (nvcc -maxrregcount), 已设 168 ====
// ⚠ 这条设置**没有**写进受版本控制的 src/CMakeLists.txt —— 它只存在于构建目录的
//   build\src\bitcoin_node.vcxproj (Release|x64 <CudaCompile><MaxRegCount>)。
//   也就是说重新跑一次 cmake 配置就可能把它丢掉, 一丢下面这一整节的数字和结论
//   全部失效 (回到 255 regs / 8 warps/SM)。要固化就在 CMakeLists 的 CUDA 段里加
//   $<$<COMPILE_LANGUAGE:CUDA>:-maxrregcount=168>。
// 为什么要设: W>=4 时 nvcc 默认吃满 255 个寄存器, 每 SM 只能驻留
//   warp/SM = 4*floor(16384/(align8(regs)*32))  =>  255 -> 8, 168 -> 12, 128 -> 16。
// 关键认识: 本内核是 **latency-bound 不是吞吐-bound** —— r168 的 cycles/point 反而
// 更高 (18.8k -> 25.7k), 但靠 +50% 驻留线程 (256 -> 384 threads/SM) 把墙钟赚回来。
// 3 轮交错 A/B (RHO_PERF_BATCHES=5000, W=8/16/32/64, 每轮两二进制交替), points/s:
//            W=16              W=32              W=64
//   255r 775.3M (21,121) 831.6M (19,382) 858.7M (18,807)   <- 无 cap
//   168r 870.6M (25,980) 898.9M (25,672) 893.1M (26,325)   <- 保留
//        +12.3%           +8.1%            +4.0%
// 注意 255r W=16/64 那两行的第 1 轮明显偏低 (冷启动/升频), 所以只取第 2/3 轮对比。
// 结论: (a) 保留 168; (b) 12-warp 带是 regs in [136,168], 168 是带宽内 spill 最少的点,
// 所以不需要试 144/152/160。
//
// ==== 生产核 rho_w<W> 的真实吞吐 (W=4, block=128, RHO_CONC_CURVE=1) ====
// 之前从没测过生产核的吞吐 —— 这里用"预置 break_flag=true, 让内核跑完第一个
// poll 段 (2^18 批 = 每线程 2^20 点) 就返回"的办法量出纯生产循环的稳态吞吐:
//   k   grid  threads  warps/SM    总吞吐 pts/s     每线程 pts/s    s/一轮
//   1     46    5,888      4        263,566,679       44,763       23.4
//   2     92   11,776      8        414,780,612       35,222       29.8
//   3    138   17,664     12        504,393,445       28,554       36.7
//   4    184   23,552     16        554,997,499       23,564       44.5
//   5    230   29,440     20        584,268,676       19,846       52.8
//   6    276   35,328     24        591,945,207       16,755       62.6  <- 当前取值
// 边际: 1->2 +57.4%, 2->3 +21.6%, 3->4 +10.0%, 4->5 +5.3%, 5->6 +1.3%
// 结论: (a) grid=276 (6 block/SM, 24 warps/SM) 是**纯总吞吐**最优, 到顶了;
//         但它每线程只有单线程参照的 18.9%, 被交换比判据否决 —— 生产改用
//         8 warps/SM (grid=92), 见下面 "warps/SM 定档" 一节。
//       (b) 5->6 只换 +1.3% 总吞吐, 却让每线程掉 15.6%、单轮时间涨 18.6% ——
//           若外部把 -pl 压得很紧, k=5 是几乎等价但省电得多的一档。
//
// ==== 生产核 vs 基准核: 同 warps/SM 下逐线程吞吐接近 (run-17 复核) ====
//   warps/SM   基准核 perf_rho_w_kernel   生产核 rho_w
//        4            42,762 pts/s            48,151 pts/s   (+12.6%)
//       12            28,320 pts/s            30,385 pts/s   (+7.3%)
// 两者是两份独立编译 (78 regs / 6 block/SM  vs  168 regs / 3 block/SM)。
// 差的这 7~13% 是**运行长度**造成的, 不是几何: 基准 sweep 固定 batches=20,000
// (W=4 -> 80,000 点/线程, 约 2.3 s), [prod] 固定 points/thread=1,048,576
// (W=4 -> 8,388,608 点/线程, 约 28 s), 短的那次把启动/尾部开销摊得更重。
// 同 warps/SM 的**相对排名**两者一致, 所以基准 sweep 的 W 排名可以外推;
// 但绝对数值必须连运行长度一起读。唯一的结构差别: 基准核顶到 12 warps/SM,
// 生产核可顶到 24 warps/SM —— 不过生产只用 8 (见 RHO_PROD_WARPS_PER_SM), 见下一节。
//
// ==== 单线程参照值 与 并发度 (回答"grid/block 该选多大") ====
//   perf_test_gpu (1 block x 1 thread, W=4) = 91,768 pts/s = 17,867 cycles/point
//   并发后每线程 (生产核 rho_w, 即下面表格里的 [prod] 行):
//       4 warps/SM   48,151 pts/s (51.5% of 单线程参照)   21.7 s/round
//       8 warps/SM   37,499 pts/s (40.1%)                 27.9 s/round
//      12 warps/SM   30,385 pts/s (32.5%)                 34.7 s/round
// 每点周期从 17,867 涨到 4.6e4 (2.6x) **不是**算法变慢, 也**不是**降频:
// 用 pts/s * cyc/pt 反解时钟, 三档都是 1.64~1.65 GHz。原因是单线程时整条
// 依赖链只占 1 个 warp (IPC≈0.08, 发射槽大量空转), 12 warps 时许多 warp 抢同一批
// 执行单元, 每线程被拉长, 但总吞吐从 93k 涨到 536.7M (x5740)。
// 所以 "并发时每线程低于单线程参照" 是**必然**的。判据必须同时看两个量 ——
// 取 max(总吞吐 x 每线程速度) 的驻点, 等价于下面这个**无量纲**判据:
//       交换比 = log(总吞吐倍率) / log(1 / 每线程倍率)
//   交换比 > 1 : 加并发这一档"值" —— 每线程掉 1 倍, 总吞吐赚回超过 1 倍;
//   交换比 < 1 : 净亏, 已过拐点。不需要给两个量人为配权重。
//
// ================== warps/SM 定档: 8 (run-17 实测) ==================
// 口径: [prod] W=4, block=128, SM=46, points/thread=1,048,576,
//       reps=2 交错重复 (压机器态漂移), 取两轮均值。
//   档  warps/SM  grid   总吞吐       每线程     % of 1x1   总x每线程       交换比
//   k=0    1        1       93,497     93,497     100.0%       --            --
//   k=1    4       46  283,511,977     48,151      51.5%   1.365e13       12.08  值得
//   k=2    8       92  441,592,933     37,499      40.1%   1.656e13 (峰)   1.77  值得  <- 生产档
//   k=3   12      138  536,714,835     30,385      32.5%   1.631e13 (-1.5%) 0.93  拐点
//   k=4   16      184  595,313,051     25,277      27.0%   1.505e13 (-9.1%) 0.56
//   k=5   20      230  615,989,545     20,924      22.4%   1.289e13 (-22%)  0.18
//   k=6   24      276  624,284,137     17,671      18.9%   1.103e13 (-33%)  0.08
//   拐点落在 8->12 之间 (交换比 1.77 -> 0.93 穿过 1.0), 乘积峰值在 **8 warps/SM**。
//   k=6 (24 warps/SM, grid=276) 是"取满驻留额度"的行为, 即纯吞吐优先:
//   改成 8 的代价是总吞吐 -29.3%, 换来每线程 +112%、单轮 59.7 s -> 27.9 s。
//   spread: k=1..6 都 <= 1.2% (可复现); 唯 k=0 单线程档 spread 16.8% —— 单线程没有
//   并发把调度抖动平均掉, 这一档只能读量级, 但 k=1..6 的比值已经稳定。
//
// 【这条拐点与 W 无关】run-17 用基准核在 grid=92 (8 warps/SM) vs grid=138 (12 warps/SM)
//   上把同一个 8->12 步骤复测了一遍 (同进程交错, 每档 2 轮):
//       W=4   交换比 0.93     W=8   0.97     W=16  0.60     W=32  0.37
//   即在 W=4/8 上这一步恰好压线、在 W=16/32 上明确为亏 => 定 8 对所有 W 都安全。
//
// 实现: get_optimal_block_size() 按 RHO_PROD_WARPS_PER_SM 直接算出生产 <grid, block>
//       (与内核寄存器数无关, 不需要 occupancy 查询); 基准 sweep 故意**不夹**,
//       它要的就是全档原始数据。
//
// ==== 逐点成本分解: mod_inv_p 是最大单项 ====
//   micro (block=128, cycles/op, 依赖链口径):
//        mul_mod        509.8 (4 warps/SM)    750.5 (16 warps/SM)
//        mod_inv_p   39,255.9                69,205.5
//        mod_sub        142.5                  174.0
//        mod_add        147.5                  187.3
//   W=4 每点 5.25 次 mul_mod + 0.25 次 mod_inv (前缀 3 次/批 + 回代 6 次/批 + 每点 3 次):
//        5.25*509.8 + 0.25*39255.9 = 2,678 + 9,814 = 12,492 cyc
//   模逆一项占 79%; 单线程实测 18,048 cyc/pt, 同量级 (差在点加自身的状态依赖链)。
//   => 降逐点成本的现实杠杆就是 **加大 W** (每点摊到的模逆 = 1/W), 这正是
//      W 扫描曲线的成因。run-18 实测 (grid=92 = 8 warps/SM, 11,776 线程):
//        W        1        2        4        8       16       32
//        总吞吐  164.7M   262.2M   399.7M   539.1M   665.7M   745.7M  pts/s
//        cyc/pt 114,854  67,068   41,732   29,433   23,229   20,622
//        单walker 13,989  11,134    8,485    5,722    3,533    1,979  pts/s
//      (每 walker 速度 = 总吞吐 / (线程数 x W); grid=138 的同口径曲线形状相同)
//   => 另一个一度以为可能的杠杆是缩短 mul_mod: 已否决。reduce_product 顶上那段
//      "进位传播 bug 的历史"里提到的 OPT-9 就是干这个的, 实测更慢 (mul_mod(x,x) 735.9->908.0)。
//      mul_mod 本身 (8x8 学校乘法 + 4 趟折叠) 已经是该路径上实测最优的写法。
//
// ==== W 轴: 拐点在 W=4, 生产取值 = 4 (两条判据一致) ====
// 用上面同一条判据扫 W 轴。这里"单点速度"必须是**单 walker** 速度
// (总吞吐 / (线程数 x W)); 不能用"每线程速度" —— 在固定 grid 下
// 每线程速度 = 总吞吐 / 线程数, 与总吞吐恒同向, 交换比会退化成恒等于 1, 判据失效。
// run-18 实测 (grid=92, RHO_PERF_BATCHES=150000, 同进程交错 2 轮取均值):
//   step      总吞吐倍率   单walker倍率   交换比   结论
//   1 -> 2       1.592        0.796        2.04   值得
//   2 -> 4       1.524        0.762        1.55   值得
//   4 -> 8       1.349        0.674        0.76   净亏      <- 拐点
//   8 -> 16      1.234        0.617        0.44   净亏
//   16 -> 32     1.120        0.560        0.20   净亏
// 口径: batches=150000 把各档墙钟从 10.7 s (W=1) 拉到 80 s (W=32), 启动/升频
//   开销摊平, 所以这张表**不含运行长度混淆**。与 batches=20000 的短程表逐档
//   只差 <= 1.4% (W=4 404.8M -> 399.7M, W=8 547.2M -> 539.1M), 即低 W 档
//   "短程偏乐观"在本机上很小; 4->8 在两套口径下都是净亏 (0.77 / 0.76),
//   **拐点在 W=4 是稳的**。
// ⚠ run-17 曾把 4->8 记成 1.27 / 拐点在 8, 源头是当时 W=8 读到 601.6M 这个
//   复现不出来的高值; 反复复测 W=8 只在 539~558M (差 ~9%), 该记录已作废。
// ⚠ W=16/32 档两轮间漂移 5% / 11% (机器升频); 16->32 离 1 很远, 不受影响。
// 即: **W 轴的最优点与 warps/SM 轴的最优点重合在生产配置上
//   (W=4 + cap 8 warps/SM), 不需要为 W 单独记账。**
// W=4 保留的另外两个理由:
//   开销见上面 "成本随 states" 那张表: W=4 的 141,312 states 小于
//   D:\RhoState2.txt 现有条数, 所以它是**第一轮零补点**的最大档;
//   W=8 要补点, W=32 的 states 是它的 8 倍 (设备态 20 MB -> 163 MB,
//   每轮落盘 0.56 s -> 4.44 s)。
// 相对 W=8: 总吞吐 -25.9%, 单 walker +48.3%, states -50%, 补点由零变正。
// 相对 W=32: 总吞吐 53.6%, 单 walker 4.29x, states 1/8。
// 注意: W=1 之所以不能选, 除了吞吐低, 还因为 W=1 每点都要做一次 safegcd 模逆
// (批量求逆只摊掉 (1-1/W)); W=1->2 的 +59.2% 就是这段收益最陡的地方。
constexpr int RHO_GPU_WALKERS = 4;

// 生产几何的每 SM warp 数 —— 单线程速度与总吞吐的**权衡档位**, 不是极值:
// 8 -> 12 这一步总吞吐 +22% 而每线程 -19%, 已经换不过来; 单看总吞吐 24 才是极值,
// 但那要牺牲 2.1x 的单线程速度。定档依据见上面那节 [prod] 的交换比表。
constexpr int RHO_PROD_WARPS_PER_SM = 8;

// 可区分点 (DP) 判断 (设备端): x 的低 40 位 (bit 0..39) 全 0 即为 DP,
// 返回其后连续 64 位 (bit 40..103) 作为索引; 否则返回 0。
// 约定: 索引 0 与"非 DP"同值 (x 恰为 2^40 的倍数时无法区分, 概率可忽略)。
__host__ __device__ uint64_t distinguishable(const uint256_t& x)
{
    // limb[0] = x bit 0..31, limb[1] 低 8 位 = x bit 32..39
    if (x.limb[0] == 0 && (x.limb[1] & 0xFF) == 0) {
        // limb[1] 高 24 位 -> 索引 bit 0..23  (x bit 40..63)
        // limb[2] 整体     -> 索引 bit 24..55 (x bit 64..95)
        // limb[3] 低 8 位  -> 索引 bit 56..63 (x bit 96..103)
        return (uint64_t)(x.limb[1] >> 8) |
               ((uint64_t)x.limb[2] << 24) |
               ((uint64_t)(x.limb[3] & 0xFF) << 56);
    }
    return 0;
}

// ================== 同线程多 walker 批量求逆 ==================
//
// 动机与 CPU 版 (rho.cpp 的 rho_affine_FW) 相同: 仿射点加每步一次域模逆,
// 同一线程的 W 个 walker 的分母可以凑一批, 用 Montgomery 批量求逆
// (前缀积 -> 求一次逆 -> 回代) 把每点模逆成本降到 1/W 次。
//
// GPU 特有的三点差异:
// 1. 模逆是 safegcd 32 位肢版本 (平均 ~11 轮 divsteps), 远比 CPU 的
//    5x52 版本便宜; 而模乘 (mul_mod) 是 schoolbook 64 次 IMAD + 4 次折叠,
//    相对更贵。批量每点多付 ~3 次模乘, 换掉 (1 - 1/W) 次模逆, 划不划算
//    只有实测能回答 (perf_test_rho_gpu_walkers)。
// 2. 寄存器压力: 生产核里 s[W]/den[W]/prefix[W] 全落 local memory, 所以 W 到 32
//    也只吃 76 个寄存器, 不在寄存器上受限 (实测见上面 RHO_PROD_ATTRS 表)。
//    真正随 W 线性增长的是 local 用量 (= 128B + 208B*W) 和 states 数。
// 3. 表读取: 发散索引下设备全局表是唯一实现路径，避免常量内存串行化。

// 注: fun_add_w **必须 host 也能跑**。perf_test_cpu / perf_test_gpu_kernel 两个
// 基准的唯一价值就是"在同一算法上比 CPU 与 GPU"、以及"给出该算法的 GPU
// 单线程参照值"; 如果它们走别的点加实现, 两边比的就是两套不同算法, 数字没有
// 可比性。所以表一律通过参数传入 (adds), 不在函数体里直接引用 adds_pub_dev。

// 用分母逆元 inv_den 推进一个 walker 一步 (标量 m/n 同步累加)。
// 分支判定已在前向循环里由 step_prepare 完成, 这里只套模式应用公式; 这里
// 不再有任何分支分类, 也就不会再和别的实现各持一份公式。
__host__ __device__ static void step_walker(RhoPoint_dev& s, const uint256_t& inv_den, int mode, const RhoPoint_dev* a)
{
    step_apply(s.x, inv_den, mode, a->x);
    s.m = mod_add(s.m, a->m, N);
    s.n = mod_add(s.n, a->n, N);
}

// 一步批量仿射点加: W 个 walker 各走一步, 只做一次域模逆。
// 分母构造上恒非零: 被跳过的 walker (无穷远 / P=-Q) 用 1 凑前缀积,
// 倍点分母 Py+Qy != 0, 一般加法分母 Qx-Px != 0, 故无需兜底路径。
template <int W>
__host__ __device__ void fun_add_w(RhoPoint_dev* s, const RhoPoint_dev* adds)
{
    // den[k]: 该 walker 本步的分母; prefix[k] = d[0]*...*d[k]
    uint256_t den[W], prefix[W];
    // 每个 walker 的"这一步用哪个表项 / 走哪个分支"打包进一个 unsigned short:
    //   bit 0..7  = adds_pub_dev 下标, bit 8..9 = mode (0..3)
    // 原来是 `const RhoPoint_dev* a[W]` + `int mode[W]`, 两个数组合计 12*W 字节
    // 局部内存, 而且让 W 个 64 位指针在整个批量求逆期间保持活跃 —— 全展开时
    // 直接把这些指针挤进栈帧。打包成一个 2 字节的标量后, 指针只在用到的
    // 那一次迭代里临时生成, 不再跨越模逆存活。
    // 实测 (W=8/16/32 交错 A/B): +0.8% / +1.4% / +3.7%; W=32 的 localSizeBytes
    // 13648 -> 13328 B。
    unsigned short code[W];
    // 不写 pragma unroll: 全展开最优 (见文件头 OPT-4 一节)。
    for (int k = 0; k < W; ++k) {
        const AffinePoint& P = s[k].x;
        const unsigned int idx = (unsigned char)P.x.limb[0];
        code[k] = (unsigned short)idx;
        const AffinePoint& Q = adds[idx].x;
        code[k] |= (unsigned short)(step_prepare(P, Q, &den[k]) << 8);
        if (k == 0) prefix[0] = den[0];
        else prefix[k] = mul_mod(prefix[k - 1], den[k]);
    }

    // 一次模逆求整批的逆: u = 1/prefix[W-1]
    uint256_t u = mod_inv_p(prefix[W - 1]);

    // 回代 (从最后一个 walker 往前):
    //   inv(d[k]) = u * prefix[k-1]  (k>0),  inv(d[0]) = u;
    //   处理完 k 后 u = u * d[k] = 1/prefix[k-1]
    for (int k = W - 1; k >= 0; --k) {
        uint256_t inv_den = (k > 0) ? mul_mod(u, prefix[k - 1]) : u;
        step_walker(s[k], inv_den, code[k] >> 8, &adds[(unsigned char)(code[k] & 0xFF)]);
        if (k > 0) u = mul_mod(u, den[k]);
    }
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


RhoPoint_dev* RhoStates_host = nullptr;
__device__ RhoPoint_dev* RhoStates_dev = nullptr;

// ---------------------------------------------------------------------------
// 验证内核的失败上报机制
//
// Release 构建带 -DNDEBUG, 设备端的 assert 会被完全编译掉 (看 nvcc 的
// "variable ... was set but never used" 告警就知道), 所以验证内核里不能再写
// assert —— 那等于没检查。统一改成:
//   DEV_ASSERT(cond)  失败时原子累加 g_validate_fail, 打印 __FILE__/__LINE__;
//   host 侧           validate_reset() 清零, validate_ok() 读回并在有失败时退出。
// ---------------------------------------------------------------------------
__device__ unsigned long long g_validate_fail = 0;

// 同一轮里只打印前若干次失败, 避免多线程内核刷屏
#define DEV_ASSERT(cond)                                                        \
    do {                                                                        \
        if (!(cond)) {                                                          \
            unsigned long long _dev_fail_n = atomicAdd(&g_validate_fail, 1ULL);  \
            if (_dev_fail_n < 16)                                               \
                printf("[DEV_ASSERT] %s:%d  %s\n", __FILE__, __LINE__, #cond);  \
        }                                                                       \
    } while (0)

// 添加 DP 到缓冲区 (设备端)
__device__ void add_dp_to_buffer(uint64_t d, RhoPoint_dev& r,
                                 DpBuffer* buffer, unsigned int max_size)
{
    // 原子递增获取缓冲区位置
    unsigned int index = atomicAdd(&dp_buffer_count, 1);

    // 调用方保证不越界: 唯一的调用点传 max_size = dp_buffer_size - 10。
    buffer[index].d = d;
    transfer(buffer[index].sp.m , (const unsigned char*)&r.m);
    transfer(buffer[index].sp.n, (const unsigned char*)&r.n);

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
__host__ __device__ void print_rho_point_dev(const RhoPoint_dev& point)
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

// ================== 多 walker 内核 ==================
//
// 每线程推进 W 个 walker, 每批一次批量求逆 (fun_add_w)。状态按
// idx*W + k 交错存放。DP 命中的 walker 由 add_dp_to_buffer 原地换成
// RhoStates_rand 池里的随机点, 与单 walker 语义一致。
template <int W>
__global__ void rho_w()
{
    int idx = blockIdx.x * blockDim.x + threadIdx.x;
    RhoPoint_dev s[W];
#pragma unroll
    for (int k = 0; k < W; ++k) s[k] = RhoStates_dev[idx * W + k];

    uint64_t count_rho = 0;
    uint32_t count_dp = 0;
    while (true) {
        fun_add_w<W>(s, adds_pub_dev);
        count_rho ++;
#pragma unroll
        for (int k = 0; k < W; ++k) {
            uint64_t d = distinguishable(s[k].x.x);
            if (d != 0) {
                count_dp++;
                add_dp_to_buffer(d, s[k], dp_device_buffer, dp_buffer_size - 10);
            }
        }
        // 周期性返回, 让 rho_play 能定期落盘 (意外关机最多丢这一段):
        //   每 2^18 批 poll 一次外部 break_flag;
        //   第 2^24 批无条件返回 (W=4 时 = 2^26 = 67,108,864 点/线程)。
        // 时长对齐: 时间目标取 CPU 侧 play() 同一件事的周期 —— 0 号线程 (W0=2)
        //   在 count_try = 2^30 批 (= 2^31 点) 时 pause 落盘 (blockchain.cpp),
        //   按其 ~1.29M pts/s 约 30 分钟。GPU 侧 2^24 批 x 4 = 2^26 点/线程,
        //   生产几何 (grid 92 = 8 warps/SM) 实测 37,499 pts/s => 1789 s = 29.8 分钟,
        //   两边落盘间隔对齐到同一档 (改成 2^23 批时只有 14.9 分钟, 差一倍)。
        // 注意: 内层判断被外层 (count_rho & 0x3FFFF) == 0 短路, 所以 2^24 必须
        //       是 2^18 的整数倍 (2^24 = 64 x 2^18, 成立), 否则这一支永远不会被求值。
        // 注意: count_rho 是批数, 而 printf 打的是点数, 两套单位不要混。
        if ((count_rho & 0x3FFFF) == 0) {
            if (*break_flag_dev || (count_rho & 0xFFFFFF) == 0) break;
        }
    }
#pragma unroll
    for (int k = 0; k < W; ++k) RhoStates_dev[idx * W + k] = s[k];
    if (idx == 0) {
        printf("rho_w<W=%d> count_rho:%llu count_dp:%d\n", W, count_rho * W, count_dp);
    }
}

// 验证内核 validate_multi_w 定义在 "验证测试" 区 (依赖 RHOSTATES_TEST_NUM)

// 每 SM 的 CUDA core 数 (按计算能力查表; CUDA 没有直接查询核数的 API)。
// 用于定 block: 一个 core 一个线程。
static int cores_per_sm(int major)
{
    switch (major) {
    case 5:  // Maxwell
    case 6:  // Pascal
    case 8:  // Ampere
    case 9:  // Hopper
        return 128;
    case 7:  // Volta / Turing
        return 64;
    default:
        return 128;
    }
}

// 选择 rho kernel 的 <grid, block> 配置 —— 生产几何的唯一定档处。
//
// 单个 walker 是 ILP≈0 的长依赖链, 只能靠 warp 并行掩盖延迟: 每 SM 只有 1 个 warp
// 时执行单元大面积空转; warp 太多则只是抢功率 (固定 -pl 下会触发降频), 总吞吐涨得
// 越来越少而每线程速度掉得越来越快。所以这里选的是**两个量之间的权衡档位**,
// 不是把总吞吐或每线程速度任何一个最大化 —— 只按每 SM warp 数
// RHO_PROD_WARPS_PER_SM 定 grid, 与内核寄存器数无关, 不需要 occupancy 查询。
//
// block 取的是**该架构每 SM 的 CUDA core 数** (cores_per_sm(), 一个 core 一个线程),
// 不是写死的 128: 本机 cc8.6 是 128, 到别的架构上跟着核数走 (Volta/Turing 是 64)。
// 块形本身没有收益差异 —— 92x128 与 46x256 的线程总数与 warps/SM 完全相同, 同进程
// 交错 A/B 的每线程吞吐差在噪声内 (已删的 perf_block_ab 仪器实测); 真正定档的是上面那个
// warps/SM 目标, block 只决定要发几块才能凑齐它 (所以下面按 ceil 算 blocks/SM)。
// 核数远低于所有 W 的内核上限 (最小的一个是 W>=8 的 256, ptxas 因 255 寄存器
// 上限压下来的), 所以不必再查 cudaFuncGetAttributes。
void get_optimal_block_size(int& grid_size, int& block_size)
{
    cudaDeviceProp prop;
    CHECK_CUDA(cudaGetDeviceProperties(&prop, 0));

    const int cores = cores_per_sm(prop.major);
    block_size = std::min(cores, (int)prop.maxThreadsPerBlock);
    const int wpb = std::max(1, block_size / 32);   // 每块提供的 warp 数
    const int blocks_per_sm = std::max(1, (RHO_PROD_WARPS_PER_SM + wpb - 1) / wpb);
    grid_size = prop.multiProcessorCount * blocks_per_sm;

    std::cout << get_time() << " : GPU " << prop.name << " cc" << prop.major << "." << prop.minor
              << " grid " << grid_size << " x block " << block_size
              << " (" << blocks_per_sm << " blocks/SM = " << blocks_per_sm * wpb
              << " warps/SM, SM=" << prop.multiProcessorCount << ", cores/SM=" << cores
              << ")" << std::endl;
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

void init_RhoStates_rand() {
    for (int i = 0; i < sizeof(RhoStates_rand) / sizeof(RhoPoint_dev); i++) {
        RhoPoint_dev t;
        RhoPoint r;
        r.rand();
        t.from(r);
        CHECK_CUDA(cudaMemcpyToSymbol(RhoStates_rand, &t, sizeof(RhoPoint_dev), sizeof(RhoPoint_dev) * i, cudaMemcpyHostToDevice));
    }
}

static const std::string _RSFile2_name = "D:\\RhoState2.txt";
int loadRhoState(RhoState* s, int num, const std::string& name);
bool saveRhoState(const RhoState* s, int num, const std::string& name);

void init_RhoStates_dev(int total_points, const std::string& name)
{
    //分配设备内存并复制初始状态 (批量传输, 逐条 cudaMemcpy 在万级条目下不可接受)
    CHECK_CUDA(cudaMalloc(&RhoStates_host, total_points * sizeof(RhoPoint_dev)));
    CHECK_CUDA(cudaMemcpyToSymbol(RhoStates_dev, &RhoStates_host, sizeof(RhoPoint_dev*)));
    static std::vector<RhoPoint_dev> staging;
    staging.resize(total_points);

    std::vector<RhoState> rsv;
    rsv.resize(total_points);
    int num = loadRhoState(rsv.data(), total_points, name);
    if (num < 0) num = 0;

    // ---------------- 缺口补点 ----------------
    // 缺口槽位各造一条独立记录 (RhoPoint::rand()): ρ 走步的步长下标
    // idx = (unsigned char)s.x.limb[0] 由点自身的 x 决定, 所以起点必须逐点不同,
    // 绝不能复用已加载的点 (起点相同 => 轨迹逐点重合 => 产出记录完全相同)。
    // 缺口是一次性的: 本轮 save_RhoStates_dev() 会整体写回, 下一轮缺口为 0。
    for (int i = 0; i < total_points; i++) {
        if (i < num) {
            staging[i].from(rsv[i]);
        } else {
            RhoPoint r;
            r.rand();
            staging[i].from(r);
        }
    }

    CHECK_CUDA(cudaMemcpy(RhoStates_host, staging.data(), total_points * sizeof(RhoPoint_dev), cudaMemcpyHostToDevice));
}

static inline void hex_encode(char* dst, const unsigned char* src, int n)
{
    static const char D[] = "0123456789abcdef";
    for (int i = 0; i < n; ++i) {
        *dst++ = D[src[i] >> 4];
        *dst++ = D[src[i] & 0x0F];
    }
}

// GPU 侧状态存盘。与 saveRhoState 的文本格式**逐字节相同**, 但为百万级记录重写。
//
// 为什么不能用 saveRhoState: 实测 1,130,496 条 (299 MB 文本) 要 24.7 秒, 全程阻塞
// 在两次 kernel 之间。三个热点 (见 build/save_bench1/2.log):
//   1. 每行一次 std::endl -> 4,521,984 次 flush / 写系统调用;
//   2. 每行一次 HexStr  -> 4,521,984 次 std::string 堆分配;
//   3. 回读整个旧文件构造 tail -> 4,521,984 行全塞进 vector<std::string> (250 MB
//      的多读实测要 5.1 秒, 而且稳态下 tail 恒为空, 纯属白读)。
// 这里: 每个线程把自己那段并行格式化成一个大缓冲, 然后顺序大块 write(); tail 只
// 扫描不存储; 文件以二进制打开并显式写 \r\n, 避开 CRT 文本模式逐字节翻译。
// 单条记录布局 (times=0 时恰好 265 字节):
//   x(64B)->128 hex + \r\n, m(32B)->64 hex + \r\n, n(32B)->64 hex + \r\n, times + \r\n
static void save_RhoStates_dev_fast(const RhoState* s, int num, const std::string& name)
{
    // 1) 保留 num*4 行之后的 tail, 语义与 saveRhoState 一致, 但不再把前面的行存下来
    std::string tail;
    {
        std::ifstream in(name); // 文本模式: \r\n -> \n, getline 拿到的行是干净的
        if (in.is_open()) {
            std::string line;
            const size_t skip = (size_t)num * 4;
            for (size_t i = 0; i < skip; ++i) {
                if (!std::getline(in, line)) break;
            }
            std::string t;
            t.reserve(1 << 20);
            while (std::getline(in, line)) { t += line; t += '\n'; }
            tail.swap(t);
        }
    }

    // 2) 并行格式化 (rand/hex 转换之间无依赖)
    unsigned hw = std::thread::hardware_concurrency();
    if (hw == 0) hw = 1;
    if ((int)hw > num) hw = (unsigned)num;
    if (hw > 64) hw = 64; // 再多的线程只会抢内存带宽

    std::vector<std::string> chunks(hw);
    auto fmt = [&](unsigned t) {
        const int begin = (int)((long long)num * t / hw);
        const int end = (int)((long long)num * (t + 1) / hw);
        std::string& out = chunks[t];
        out.reserve((size_t)(end - begin) * 272 + 128);
        char h[128];
        char numbuf[24];
        for (int i = begin; i < end; ++i) {
            const RhoState& r = s[i];
            hex_encode(h, r.x.data, 64);
            out.append(h, 128).append("\r\n", 2);
            hex_encode(h, r.m, 32);
            out.append(h, 64).append("\r\n", 2);
            hex_encode(h, r.n, 32);
            out.append(h, 64).append("\r\n", 2);
            const int nd = std::snprintf(numbuf, sizeof(numbuf), "%llu", (unsigned long long)r.times);
            out.append(numbuf, nd).append("\r\n", 2);
        }
    };
    std::vector<std::thread> pool;
    pool.reserve(hw > 1 ? hw - 1 : 0);
    for (unsigned t = 1; t < hw; ++t) pool.emplace_back(fmt, t);
    fmt(0);
    for (std::thread& th : pool) th.join();

    // 3) 顺序大块写盘
    std::ofstream file(name, std::ios::binary | std::ios::trunc);
    for (unsigned t = 0; t < hw; ++t) {
        if (!chunks[t].empty()) {
            file.write(chunks[t].data(), (std::streamsize)chunks[t].size());
        }
    }
    if (!tail.empty()) {
        // tail 来自文本模式读取 (只有 \n), 这里补成 \r\n 以保持一致
        std::string t2;
        t2.reserve(tail.size() + 64);
        for (char c : tail) {
            if (c == '\n') t2 += '\r';
            t2 += c;
        }
        file.write(t2.data(), (std::streamsize)t2.size());
    }
    file.close();
}

void save_RhoStates_dev(int total_points, const std::string& name)
{
    std::vector<RhoState> rsv;
    rsv.resize(total_points);
    static std::vector<RhoPoint_dev> staging;
    staging.resize(total_points);

    CHECK_CUDA(cudaMemcpy(staging.data(), RhoStates_host, total_points * sizeof(RhoPoint_dev), cudaMemcpyDeviceToHost));

    for (int i = 0; i < total_points; i++) {
        staging[i].to(rsv[i]);
        rsv[i].times = 0;
    }

    save_RhoStates_dev_fast(rsv.data(), total_points, name);

    std::cout << get_time() << " : save_RhoStates_dev. " << std::endl;
}

// DP 测试样点 (供 init_RhoStates_test 的尾槽使用): 取自 D:\DistinguishablePoints.txt
// 第 1 条记录, 即 40 位判据下的一次真实运行写出的可区分点。已离线核验:
//   x = m*G + n*MVP
//     = d0670ffb7d97f164bcb5e73ec8da8f5575ace1a94bf211911028d30000000000
// 低 40 位 (byte0..4) 全 0, 故构成 DP; 且 x 的 bit 40..103 恰好等于文件里记录的
// 索引, 即 RHO_DP_TEST_IDX。该点同时覆盖了 limb[2] (bit 64..95) 非 0 的情形,
// 这是纯构造值 (x≈2^40 / x≈2^104) 测不到的索引拼接分支。
#define RHO_DP_TEST_M   "18094cbd5ecb190d6ed18af0d31ccdb4c86d748c074d56c3ac111ea7d1e9631f"
#define RHO_DP_TEST_N   "f4ed2be3b6d43ec1c60c0bb1c62dfe9be31698293a68408337d3627bf716ccb5"
#define RHO_DP_TEST_IDX 12199110172925241555ULL

extern secp256k1_context* ctx;
void init_RhoStates_test(int total_points)
{
    // 分配设备内存并复制初始状态
    CHECK_CUDA(cudaMalloc(&RhoStates_host, total_points * sizeof(RhoPoint_dev)));
    CHECK_CUDA(cudaMemcpyToSymbol(RhoStates_dev, &RhoStates_host, sizeof(RhoPoint_dev*)));
    RhoState r;
    set_int256(r.m, "569103012ff8d20291a62809f4ac5f6c8f88a13d4208a6a674cec68f1307254e");
    set_int256(r.n, "92ce814fc881620c4461460d5144b54780edbae642905b0b847eb34ea5688bd3");
    create(ctx, &r.x, r.m, r.n);
    RhoPoint_dev t;
    for (int i = 0; i < total_points - 1; i++) {
        t.from(r);
        CHECK_CUDA(cudaMemcpy(RhoStates_host + i, &t, sizeof(RhoPoint_dev), cudaMemcpyHostToDevice));
        rho_F(ctx, r);
    }
    // 尾槽 (total_points-1) 是独立填充点, 不接在链上, 专门作 DP 判据的被测样点。
    // m/n 取自 D:\DistinguishablePoints.txt 的记录 (见 RHO_DP_TEST_*), 所以这个
    // 点在新判据下确实是可区分点, 其索引必须等于 RHO_DP_TEST_IDX。
    set_int256(r.m, RHO_DP_TEST_M);
    set_int256(r.n, RHO_DP_TEST_N);
    create(ctx, &r.x, r.m, r.n);
    t.from(r);
    CHECK_CUDA(cudaMemcpy(RhoStates_host + total_points - 1, &t, sizeof(RhoPoint_dev), cudaMemcpyHostToDevice));
}

void rho_play() {
    enable_blocking_sync(); // 必须最先调用：避免 cudaDeviceSynchronize 自旋空转占满一个核
    // 创建 DP 管理器
    DpManager dp_manager(dp_buffer_size);
    int gridSize = 0;
    int blockSize = 0;
    get_optimal_block_size(gridSize, blockSize);
    // 每线程 W 个 walker, 状态总数 = 线程数 * W
    constexpr int W = RHO_GPU_WALKERS;
    const int threads = gridSize * blockSize;
    const int total_points = threads * W;
    init_RhoStates_dev(total_points, _RSFile2_name);
    init_adds_pub_dev();
    // 初始化break_flag
    init_break_flag();
    while (!gameover) {
        break_rho(false);
        init_RhoStates_rand();
        rho_w<W><<<gridSize, blockSize>>>();
        // 等待核函数完成
        CHECK_CUDA(cudaDeviceSynchronize());
        dp_manager.save_dps();
        save_RhoStates_dev(total_points, _RSFile2_name);
    }
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

// 验证内核: 沿 init_RhoStates_test 生成的确定性测试链, 取连续 W 个状态
// 做一次批量步进, 逐个与链上后继对拍。失败计入 g_validate_fail。
template <int W>
__global__ void validate_multi_w()
{
    int stride = blockDim.x * gridDim.x;
    // 上界 RHOSTATES_TEST_NUM-1: 链后继只到索引 RHOSTATES_TEST_NUM-1 -> RHOSTATES_TEST_NUM,
    // 最后一个槽位 (RHOSTATES_TEST_NUM) 是独立填的 DP 测试样点, 不是链后继, 不参与链对拍
    for (int base = blockDim.x * blockIdx.x + threadIdx.x; base + W <= RHOSTATES_TEST_NUM - 1; base += stride) {
        RhoPoint_dev s[W];
#pragma unroll
        for (int k = 0; k < W; ++k) s[k] = RhoStates_dev[base + k];
        fun_add_w<W>(s, adds_pub_dev);
#pragma unroll
        for (int k = 0; k < W; ++k) {
            if (!(s[k] == RhoStates_dev[base + k + 1])) {
                unsigned long long n = atomicAdd(&g_validate_fail, 1ULL);
                if (n < 4) {
                    printf("validate_multi_w<W=%d> MISMATCH at base=%d k=%d\n", W, base, k);
                    print_rho_point_dev(s[k]);
                }
            }
        }
    }
}

__global__ void validate_safegcd()
{
    // 测试 safegcd 模逆: 直接验证 a * a^-1 == 1 (mod p)
    uint256_t probe[4] = {
        {{0x5F8E52C7, 0xD3A21B04, 0x9C56B9AF, 0x6E1F3D82, 0x2A8C77D1, 0xB4E09F63, 0x1D5AC7E8, 0x7F3B29A0}},
        {{0x00000001, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000}},
        {{0xFFFFFC2E, 0xFFFFFFFE, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF}}, // p-1
        {{0x12345678, 0x9ABCDEF0, 0x0FEDCBA9, 0x87765432, 0x1A2B3C4D, 0x5E6F7081, 0x92A3B4C5, 0xD6E7F809}},
    };
    for (int i = 0; i < 4; ++i) {
        uint256_t m1 = mod_inv_p(probe[i]);
        uint256_t one = {1};
        uint256_t got = mul_mod(m1, probe[i]);
        DEV_ASSERT(u256_equal(got, one));
    }
}

// 多 walker 点加核心 (step_prepare / step_apply) 的三个分支 + DP 判据。
//
// 以前这里测的是单点函数 point_add; 那个函数和 fun_add_w 里的分支判定是两份
// 逐字重复的代码, 已删除。现在测的就是生产核跑的那一套核心: 三个分支的触发
// 条件由具体操作数决定 (倍点要 Px==Qx, 无穷远要有一只点在无穷远), 没法用
// 步进表的索引构造, 所以直接用 point_step 喂 (P, Q):
//     mode 3 = G + ∞          mode 2 = G + (-G)
//     mode 1 = G + G (倍点)   mode 0 = G + 2G
// 最后再用 fun_add_w<4> 对同一组起点做一次批量求逆, 与 point_step 逐位对拍。
__global__ void validate_point_add()
{
    // 测试1：G + ∞ = G
    AffinePoint inf;
    inf.x = {{0}};
    inf.y = {{0}};
    inf.infinity = true;

    AffinePoint res1G = point_step(G, inf);
    DEV_ASSERT(!res1G.infinity);
    for (int i = 0; i < 8; ++i) {
        DEV_ASSERT(res1G.x.limb[i] == G.x.limb[i]);
        DEV_ASSERT(res1G.y.limb[i] == G.y.limb[i]);
    }

    // 测试1.1: G+(-G)
    AffinePoint res_1G;
    uint256_t _y = mod_sub({0}, G.y);
    res_1G.x = G.x;
    res_1G.y = _y;
    res_1G.infinity = false;
    AffinePoint res0G = point_step(G, res_1G);
    DEV_ASSERT(res0G.infinity);
    DEV_ASSERT(is_zero(res0G.x));
    DEV_ASSERT(is_zero(res0G.y));

    // 测试2：G + G的有效性
    AffinePoint res2G = point_step(G, G);
    DEV_ASSERT(!res2G.infinity);
    DEV_ASSERT(res2G.x.limb[7] == 0xC6047F94); // 2G的x坐标高位
    DEV_ASSERT(res2G.y.limb[7] == 0x1ae168fe); // 2G的y坐标高位
        
    // 测试3：G + 2G的有效性
    AffinePoint res3G = point_step(G, res2G);
    DEV_ASSERT(!res3G.infinity);
    DEV_ASSERT(res3G.x.limb[7] == 0xf9308a01); // 3G的x坐标高位
    DEV_ASSERT(res3G.y.limb[7] == 0x388f7b0f); // 3G的y坐标高位

    // 测试4: 批量路径 vs 逐点路径逐位对拍。
    // 同一组起点, fun_add_w<4> 一次批量求逆的结果必须与 point_step 各自求
    // 一次逆的结果完全一样 (mod_inv_p 和批量回代都返回 p 内的标准代表,
    // 两边后续的域运算序列也逐字相同, 所以应当逐字节相等)。
    // validate_multi_w 是对测试链的端到端对拍, 这里是对退化的"批量 == 逐个"
    // 本身的直接验证 —— 批量求逆不改变结果, 不是只碰巧在链上成立。
    {
        constexpr int W = 4;
        RhoPoint_dev expect[W];
        RhoPoint_dev got[W];
        for (int k = 0; k < W; ++k) {
            // 取测试链上 4 个真实状态, 保证 4 个分母互不相同 (非退化)
            got[k] = RhoStates_dev[k * 977 + 13];
            expect[k] = got[k];
            const RhoPoint_dev& a = adds_pub_dev[(unsigned char)got[k].x.x.limb[0]];
            expect[k].x = point_step(got[k].x, a.x);
            expect[k].m = mod_add(got[k].m, a.m, N);
            expect[k].n = mod_add(got[k].n, a.n, N);
        }
        fun_add_w<W>(got, adds_pub_dev);
        for (int k = 0; k < W; ++k) DEV_ASSERT(got[k] == expect[k]);
        // 4 个起点必须互不相同, 否则上面的对拍退化成同一个分母重复 4 次
        for (int i = 0; i < W; ++i)
            for (int j = i + 1; j < W; ++j)
                DEV_ASSERT(!u256_equal(expect[i].x.x, expect[j].x.x));
    }

    //测试 distinguishable: 低 40 位全 0 才构成 DP, 索引取随后的 64 位 (bit 40..103)。
    // 构造值先卡住索引拼接的三段边界: bit 40..63 (limb[1]>>8),
    // bit 64..95 (limb[2]<<24), bit 96..103 ((limb[3]&0xFF)<<56)。
    {
        uint256_t v = {{0}};
        DEV_ASSERT(distinguishable(v) == 0);   // 索引 0 与"非 DP"同值
        v.limb[1] = 0x00000100u;               // x = 2^40 -> 低 40 位全 0
        DEV_ASSERT(distinguishable(v) == 1);   // 索引 = x 的 bit 40 = 1
        v.limb[3] = 0x000000ABu;               // x 的 bit 96..103
        DEV_ASSERT(distinguishable(v) == (1ULL | (0xABULL << 56)));
        v.limb[1] = 0x00000101u;               // x 的 bit 32 置位 -> 低 40 位非 0
        DEV_ASSERT(distinguishable(v) == 0);
        DEV_ASSERT(distinguishable(RhoStates_dev[0].x.x) == 0);
    }

    // 真实数据正例: 尾槽 (RHOSTATES_TEST_NUM) 是 init_RhoStates_test 按 40 位判据
    // 从 D:\DistinguishablePoints.txt 填入的可区分点, 索引应与文件记录逐位相符。
    // (limb[2] 非 0, 补上上面构造值没覆盖到的那段拼接)
    DEV_ASSERT(distinguishable(RhoStates_dev[RHOSTATES_TEST_NUM].x.x) == RHO_DP_TEST_IDX);

    DEV_ASSERT(*break_flag_dev == true);
}

__global__ void validate_multi()
{
    //测试 rho_f_dev
    for (int i = 0; i < RHOSTATES_TEST_NUM / (blockDim.x * gridDim.x); i++) {
        int index = i * blockDim.x * gridDim.x + blockDim.x * blockIdx.x + threadIdx.x;
        RhoPoint_dev rs = RhoStates_dev[index];
        // W=1 实例: 这一步就是生产核 fun_add_w<1> 对第 0 个 walker 做的事
        fun_add_w<1>(&rs, adds_pub_dev);
        DEV_ASSERT((rs == RhoStates_dev[index + 1]));
    }

    // DP 缓冲测试: 往缓冲区写 RHODP_TEST_NUM 条记录以验证溢出/break 路径。
    // 索引用尾点的真实索引 (RHO_DP_TEST_IDX), 与尾点自洽。
    // 必须传尾点的**局部副本**: add_dp_to_buffer 会把传入的点换成 RhoStates_rand,
    // 直接传 RhoStates_dev[RHOSTATES_TEST_NUM] 会把尾点改掉, 而 validate_point_add
    // 还要用尾点做 DP 判据检查 (本内核排在 validate_point_add 之前跑)。
    int idx = blockDim.x * blockIdx.x + threadIdx.x;
    if (idx < RHODP_TEST_NUM) {
        RhoPoint_dev tail = RhoStates_dev[RHOSTATES_TEST_NUM];
        add_dp_to_buffer(RHO_DP_TEST_IDX, tail, dp_device_buffer, RHODP_TEST_NUM);
    }
}

// 点加基准循环。与 rho.cpp 的 perf_test_rho_affine_walkers 同口径: 推 batches*W
// 个点, 数 DP 命中 (命中率 2^-40, 不影响指令构成)。
//
// **必须走 fun_add_w<W>** —— 生产核 rho_w<W> 跑的就是这条批量求逆路径。
// 如果这两个基准改用别的单点实现, 就成了拿两套不同的点加算法
// 在比效率, 数字没有意义。
template <int W>
__host__ __device__ uint64_t perf_fun_w(RhoPoint_dev* s, const RhoPoint_dev* adds,
                                        uint64_t batches, uint32_t* count_dp_out)
{
    uint32_t count_dp = 0;
    for (uint64_t i = 0; i < batches; ++i) {
        fun_add_w<W>(s, adds);
        for (int k = 0; k < W; ++k) {
            if (distinguishable(s[k].x.x) != 0) count_dp++;
        }
    }
    if (count_dp_out) *count_dp_out = count_dp;
    return batches * (uint64_t)W;
}

// CPU 基准: 在 CPU 上跑**与 GPU 生产核完全相同**的批量求逆算法 (fun_add_w<W>,
// W = RHO_GPU_WALKERS), 用来和 rho.cpp 的实现对照。
// 与 perf_test_rho_affine_walkers 同口径 (800000 点), 所以:
//   perf_test_rho_affine_walkers  -> rho.cpp 的批量求逆算法
//   perf_test_cpu                 -> cuda.cu 的批量求逆算法, 同样 800000 点
// 两者相比就是"同一副算法在不同实现上"的差。
void perf_test_cpu() {
    constexpr int W = RHO_GPU_WALKERS;
    RhoPoint_dev adds_pub_tmp[256];
    for (int i = 0; i < sizeof(adds_pub_tmp) / sizeof(RhoPoint_dev); i++) {
        adds_pub_tmp[i].from(adds_pub[0][i]);
    }
    // 起点与 rho.cpp 的 bench_rho_walkers 一致: 第 k 个 walker 取表项 k
    RhoPoint_dev s[W];
    for (int k = 0; k < W; ++k) s[k] = adds_pub_tmp[k];
    const uint64_t batches = 800000 / W;
    uint32_t count_dp = 0;
    const auto start = std::chrono::steady_clock::now();
    uint64_t count_rho = perf_fun_w<W>(s, adds_pub_tmp, batches, &count_dp);
    const auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now() - start);
    double sec = elapsed.count() / 1000.0;
    std::cout << "cpu test (W=" << W << ", 批量求逆, 同 GPU 生产核 fun_add_w) elapsed: "
              << elapsed.count() << " ms, with " << count_rho << " RhoPoint (" << count_dp
              << " dp), avg " << (uint64_t)(count_rho / sec) << " points/s." << std::endl;
}

// 单线程 GPU 基准内核: **1 block x 1 thread**, 1 个线程推进 W 个 walker, 走的
// 就是生产核的 fun_add_w<W>。
//
// 用途: 给出"该算法在 GPU 单线程上到底能跑多快"的参照值, 和生产并发时的
// **每线程**吞吐 (= 总吞吐 / 线程数) 对比。生产并发每线程吞吐不该比这个 1 线程
// 值低太多 —— 低太多说明是并发本身 (降频/带宽/调度) 把单线程拖慢了, 而不是
// 算法慢; 这时该调的是 grid/block, 不是算法。
//
// 步进表走 __device__ 全局数组 adds_pub_dev (读命中 L1), 与生产核 rho_w<W>
// 同一套访存路径, 参照值才有意义。历史上一度试过把表搬进 __shared__ (每 block
// 私拷一份 36 KB): 单变量 A/B 显示各档吞吐都没赢 —— LDS 并不比 L1 命中的 LDG
// 便宜, 还多付拷表带宽、每次 __syncthreads 和一次占用降档。结论: 生产路径
// 不碰共享内存。
template <int W>
__global__ void perf_test_gpu_kernel(int batches, unsigned long long* cycles_out,
                                     unsigned int* dp_out)
{
    RhoPoint_dev s[W];
    for (int k = 0; k < W; ++k) s[k] = adds_pub_dev[k];

    long long t0 = clock64();
    perf_fun_w<W>(s, adds_pub_dev, batches, dp_out);
    long long t1 = clock64();
    if (cycles_out) atomicAdd(cycles_out, (unsigned long long)(t1 - t0));
}

void perf_test_gpu()
{
    constexpr int W = RHO_GPU_WALKERS;
    const uint64_t batches = 800000 / W;
    const uint64_t kPoints = batches * (uint64_t)W;
    unsigned long long* d_cycles;
    unsigned int* d_dp;
    CHECK_CUDA(cudaMalloc(&d_cycles, sizeof(unsigned long long)));
    CHECK_CUDA(cudaMalloc(&d_dp, sizeof(unsigned int)));
    CHECK_CUDA(cudaMemset(d_cycles, 0, sizeof(unsigned long long)));
    CHECK_CUDA(cudaMemset(d_dp, 0, sizeof(unsigned int)));
    cudaEvent_t start;
    cudaEvent_t stop;
    CHECK_CUDA(cudaEventCreate(&start));
    CHECK_CUDA(cudaEventCreate(&stop));
    CHECK_CUDA(cudaEventRecord(start));
    perf_test_gpu_kernel<W><<<1, 1>>>(batches, d_cycles, d_dp);
    CHECK_CUDA(cudaEventRecord(stop));
    CHECK_CUDA(cudaEventSynchronize(stop));
    CHECK_CUDA(cudaDeviceSynchronize());
    unsigned long long cycles = 0;
    unsigned int dp = 0;
    CHECK_CUDA(cudaMemcpy(&cycles, d_cycles, sizeof(unsigned long long), cudaMemcpyDeviceToHost));
    CHECK_CUDA(cudaMemcpy(&dp, d_dp, sizeof(unsigned int), cudaMemcpyDeviceToHost));
    float elapsed_ms = 0.0f;
    CHECK_CUDA(cudaEventElapsedTime(&elapsed_ms, start, stop));
    CHECK_CUDA(cudaEventDestroy(start));
    CHECK_CUDA(cudaEventDestroy(stop));
    CHECK_CUDA(cudaFree(d_cycles));
    CHECK_CUDA(cudaFree(d_dp));
    double sec = elapsed_ms / 1000.0;
    std::cout << "gpu test (W=" << W << ", 1 block x 1 thread, 同生产核 fun_add_w, 全局步进表) elapsed: "
              << elapsed_ms << " ms, with " << kPoints << " RhoPoint, avg "
              << (uint64_t)(kPoints / sec) << " points/s, "
              << (uint64_t)((double)cycles / (double)kPoints) << " cycles/point."
              << std::endl;
}

// ================== 生产核真实吞吐 ==================
//
// 为什么必须单独测: 生产核 rho_w<W> 和基准核 perf_rho_w_kernel<W> 是两份独立编译,
// 资源画像完全不同 ——
//     基准核 perf_rho_w_kernel: 168 regs -> 3 block/SM -> grid 138 ->  12 warps/SM
//     生产核 rho_w           :  78 regs -> 6 block/SM -> grid 276 ->  24 warps/SM
// (已删的) RHO_CONC_CURVE 测出基准核在 12 warps/SM 时每点周期就压到 144 (≈ SM 发射上限
// 4 指令/周期), 也就是说 12 个 warp 已经把发射槽占满了。那生产核多出来的那 12 个
// warp/SM 到底换来了什么? 如果什么都没换来, 那就是白烧电 —— 在 -pl 受限的笔记本上
// 还可能触到功耗墙把频率压下去, 总吞吐反而更低。这个账从来没有测过, 现在测。
//
// 测法: 生产核是 while(true) 长跑, 但它在 (count_rho & 0x3FFFF) == 0 时轮询
// break_flag。所以预先置 break_flag = true, 内核跑满 2^18 批 (= 每线程 2^18 * W 点)
// 就返回。这一段就是纯生产循环的稳态时间 (不含补点, 不含落盘)。
//
// 口径 (只测两档, 单遍):
//   k=0        1 block x 1 thread —— 同一个内核、同一段 poll 掩码, 就是本进程内的
//              "单线程参照值"。生产档的每线程吞吐直接除以它, 不吃跨运行的机器态漂移。
//   k=k_pol    grid = SM*k_pol, block, 即每 SM 驻留 RHO_PROD_WARPS_PER_SM 个 warp,
//              与 get_optimal_block_size 给生产用的几何完全一致 (该行标 POLICY)。
//   报三个数: 总吞吐 / 每线程吞吐 (= 该并发下单个线程的速度) / 单轮秒数。
//
// (原 1..occ 全档扫描 + MEAN 均值表 + 交换比表已随 W=4 定案删除 —— 那张表是选
//  RHO_PROD_WARPS_PER_SM 的判据本身, 结论已固化进该常量, 不必每跑一次重算;
//  交错两遍 (原 RHO_PROD_REPS) 也一并去掉, 只跑一遍。)
static void perf_prod_rho_w_throughput(int block)
{
    constexpr int W = RHO_GPU_WALKERS;
    const int prod_batches = 1 << 18;   // rho_w 的 poll 掩码, 内核最少要跑这么多批
    cudaDeviceProp prop;
    CHECK_CUDA(cudaGetDeviceProperties(&prop, 0));
    const int sm = prop.multiProcessorCount;

    // k_pol = 生产几何每 SM 的 block 数, 与 get_optimal_block_size 同一算法
    // (每 SM 目标 RHO_PROD_WARPS_PER_SM 个 warp, 每 block 提供 block/32 个)。
    // 这里特意不查 occupancy: 生产几何本来就与内核寄存器数无关, occupancy
    // 只被 perf_test_rho_gpu_walkers 用来给状态数组留额度, 不是定档依据。
    const int wpb = std::max(1, block / 32);
    const int k_pol = std::max(1, (RHO_PROD_WARPS_PER_SM + wpb - 1) / wpb);

    // rho_w 在 DP 命中时会调 add_dp_to_buffer(..., dp_device_buffer, ...),
    // 生产路径靠 DpManager 把这个设备指针填进 __device__ 符号。基准路径从没走过
    // 这一步, 所以这里必须自己建一个, 否则 2^-40 的命中率撞上一次就是空指针解引用。
    DpManager dp_manager(dp_buffer_size);

    const bool own_flag = (break_flag_host == nullptr);
    if (own_flag) init_break_flag();
    break_rho(true);    // 内核跑完第一个 poll 段就返回

    printf("  [prod] W=%d block=%d SM=%d points/thread=%d\n",
           W, block, sm, prod_batches * W);

    // 跑一档并返回每线程吞吐。k=0 = 1 block x 1 thread (进程内单线程参照);
    // k>=1 = 每 SM 发 k 个 block, 即 k*block/32 个 warp/SM。
    auto run_one = [&](int k) {
        const bool ref = (k == 0);
        const int grid = ref ? 1 : sm * k;
        const int blk = ref ? 1 : block;
        const uint64_t threads = (uint64_t)grid * blk;
        const uint64_t points = threads * (uint64_t)W * prod_batches;
        cudaEvent_t start, stop;
        CHECK_CUDA(cudaEventCreate(&start));
        CHECK_CUDA(cudaEventCreate(&stop));
        CHECK_CUDA(cudaEventRecord(start));
        rho_w<W><<<grid, blk>>>();
        CHECK_CUDA(cudaEventRecord(stop));
        CHECK_CUDA(cudaEventSynchronize(stop));
        CHECK_CUDA(cudaDeviceSynchronize());
        float ms = 0;
        CHECK_CUDA(cudaEventElapsedTime(&ms, start, stop));
        cudaEventDestroy(start);
        cudaEventDestroy(stop);
        const double sec = ms / 1000.0;
        const double total = (double)points / sec;
        const double pt = total / (double)threads;
        printf("  [prod] k=%-2d grid=%-4d block=%-4d threads=%-6d warps/SM=%-2d: "
               "%11.0f pts/s total, %8.0f pts/s per-thread, %6.1f s/round%s\n",
               k, grid, blk, (int)threads, ref ? 1 : k * blk / 32,
               total, pt, sec,
               ref ? "" : "   <- POLICY (production geometry)");
        return pt;
    };

    const double pt_ref = run_one(0);
    const double pt_pol = run_one(k_pol);
    if (pt_ref > 0.0) {
        printf("  [prod] POLICY per-thread = %.1f%% of 1x1 reference (%.0f vs %.0f pts/s)\n",
               100.0 * pt_pol / pt_ref, pt_pol, pt_ref);
    }

    break_rho(false);
    if (own_flag) free_break_flag();
}

void perf_test_rho_gpu_walkers()
{
    enable_blocking_sync();
    init_adds_pub_dev();

    printf("  [layout] RhoPoint_dev=%zu B (align %zu) AffinePoint=%zu B uint256_t=%zu B\n",
           sizeof(RhoPoint_dev), alignof(RhoPoint_dev), sizeof(AffinePoint), sizeof(uint256_t));

    int gridSize = 0, blockSize = 0;
    get_optimal_block_size(gridSize, blockSize);
    const int block = blockSize;

    // 状态数组按生产核 rho_w<W> 的满驻留额度预留: 单位是 walker 状态不是线程,
    // 内核按 RhoStates_dev[idx*W + k] 寻址, 每线程占 W 条, 必须乘 W
    // (k=0 的 1x1 行只用更少。曾漏乘 W, k>=3 档越界读出非法地址)。
    int total_max = 0;
    {
        cudaDeviceProp prop;
        CHECK_CUDA(cudaGetDeviceProperties(&prop, 0));
        constexpr int W = RHO_GPU_WALKERS;
        int occ = 0;
        CHECK_CUDA(cudaOccupancyMaxActiveBlocksPerMultiprocessor(
            &occ, (const void*)rho_w<W>, block, 0));
        if (occ < 1) occ = 1;
        total_max = prop.multiProcessorCount * occ * block * W;
    }
    printf("  [res] bench block=%d total_states=%d\n", block, total_max);
    init_RhoStates_dev(total_max, _RSFile2_name);

    // 生产核真实吞吐 (只两行: k=0 单线程参照 + k_pol 生产几何 POLICY)。
    // W 扫描 (run_perf_rho_w / RHO_PERF_WS / RHO_PERF_GRID) 已随 W=4 定案删除,
    // 结论固化在 RHO_GPU_WALKERS 与 RHO_PROD_WARPS_PER_SM 里;
    // 资源表 (RHO_PROD_ATTRS) 与并发曲线 (RHO_CONC_CURVE) 仪器亦已删, 只剩本档。
    perf_prod_rho_w_throughput(block);

    CHECK_CUDA(cudaFree(RhoStates_host));
    RhoStates_host = nullptr;
}

void perf_test() {
    // 性能测试
    enable_blocking_sync();
    init_adds_pub_dev();
    perf_test_cpu();
    perf_test_libsecp256k1();
    perf_test_rho_affine_walkers();
    perf_test_gpu();
    perf_test_rho_gpu_walkers();
}

// 清零设备端验证失败计数 (每个验证阶段开跑前调用)
static void validate_reset()
{
    unsigned long long zero = 0;
    CHECK_CUDA(cudaMemcpyToSymbol(g_validate_fail, &zero, sizeof(zero)));
}

// 读回设备端失败计数; 有失败则打印阶段名并返回 false
static bool validate_ok(const char* stage)
{
    unsigned long long n = 0;
    CHECK_CUDA(cudaMemcpyFromSymbol(&n, g_validate_fail, sizeof(n)));
    if (n != 0) {
        printf("validate FAILED: %s  (%llu failed check(s))\n", stage, n);
        return false;
    }
    return true;
}

// ---------------------------------------------------------------------------
// [仅 validate 用] 归约 (reduce_product) 对拍
//
// 参考实现故意**不复用生产代码里的 fold256**, 而是独立写一遍教科书算法 (两边
// 同时错的概率极低)。512 位从高位到低位每步 r = 2r + bit, 与 p 比较后最多减
// 一次 p。慢 (512 次迭代) 但显然正确。注意比较必须是**三态**的 (见下面 cmp),
// 早期版本写成 "判到小于还继续往下比", 低位会把 ge 翻回 true, 于是多减一次 p
// 并让 r[8] 下溢 —— 那才是当时 A/B 报 1024 个 failed 的真凶 (生产代码没错)。
//
// 为什么需要构造用例: 随机 512 位乘积下折叠链的进位远达不到上界, 只有构造出的
// 极端输入才会把进位链推到最满 (a[9] != 0), 从而使折叠的边界逻辑真正被执行。
//
// 测试输入:
//   (a) 随机 512 位乘积             -> 常规路径
//   (b) prod[0..15] 全 0xFFFFFFFF   -> V 最大, 进位链最满, 解析解 M^2 - 1
//   (c) hi 全 1 / lo 全 0           -> V = 2^512 - 2^256, 解析解 M^2 - M
//   (d) hi 全 0 / lo 全 1           -> H == 0, 只有 lo 参与, 解析解 M - 1
//   (e) 全 0                        -> 0
// ---------------------------------------------------------------------------
__host__ __device__ static void ref_mod_p(const uint32_t* v, uint32_t* out)
{
    uint32_t r[9] = {0, 0, 0, 0, 0, 0, 0, 0, 0}; // 多留一个肢体给 carry
    for (int bit = 511; bit >= 0; --bit) {
        uint32_t carry = (v[bit >> 5] >> (bit & 31)) & 1u;
        for (int i = 0; i < 9; ++i) {
            uint32_t nc = r[i] >> 31;
            r[i] = (r[i] << 1) | carry;
            carry = nc;
        }
        // 不变式: 每步 r <= p-1 (r' = 2r + bit <= 2p-1, 至多减一次 p 即回到 < p),
        // 所以 r[8] 恒为 0; 这里三态比较必须"一旦判定小于就停", 否则低位会把
        // ge 又翻回 true 从而多减一次 p (早期版本就踩了这个坑)。
        bool ge;
        if (r[8] != 0) {
            ge = true;
        } else {
            int cmp = 0;
            for (int i = 7; i >= 0 && cmp == 0; --i) {
                if (r[i] > p.limb[i]) cmp = 1;
                else if (r[i] < p.limb[i]) cmp = -1;
            }
            ge = (cmp >= 0);
        }
        if (ge) {
            uint64_t borrow = 0;
            for (int i = 0; i < 8; ++i) {
                uint64_t cur = (uint64_t)r[i] - p.limb[i] - borrow;
                r[i] = (uint32_t)cur;
                borrow = (cur >> 32) ? 1 : 0;
            }
            r[8] = (uint32_t)((uint64_t)r[8] - borrow);
        }
    }
    for (int i = 0; i < 8; ++i) out[i] = r[i];
}

// 填第 k 类测试输入 (k <= 4 为构造用例, k >= 5 为随机)
__host__ __device__ static void make_test_product(uint32_t* prod, unsigned int k, unsigned int tid)
{
    if (k == 0) {
        for (int i = 0; i < 16; ++i) prod[i] = 0xFFFFFFFFu;
    } else if (k == 1) {
        for (int i = 0; i < 8; ++i) prod[i] = 0u;
        for (int i = 8; i < 16; ++i) prod[i] = 0xFFFFFFFFu;
    } else if (k == 2) {
        for (int i = 0; i < 8; ++i) prod[i] = 0xFFFFFFFFu;
        for (int i = 8; i < 16; ++i) prod[i] = 0u;
    } else if (k == 3) {
        for (int i = 0; i < 16; ++i) prod[i] = 0u;
    } else {
        unsigned long long s =
            0x9E3779B97F4A7C15ull ^ ((unsigned long long)tid * 0xD1B54A32D192ED03ull);
        for (int i = 0; i < 16; ++i) {
            s ^= s << 13;
            s ^= s >> 7;
            s ^= s << 17;
            prod[i] = (uint32_t)s;
        }
    }
}

__global__ void validate_reduce_product()
{
    const unsigned int tid = blockIdx.x * blockDim.x + threadIdx.x;
    uint32_t prod[16];
    // 奇数线程走随机输入 (常态路径), 偶数线程轮流走 4 个构造用例
    make_test_product(prod, (tid & 1u) ? 5u : ((tid >> 1) & 3u), tid);

    const uint256_t got = reduce_product(prod);
    uint32_t want[8];
    ref_mod_p(prod, want);

    // 逐肢体断言, 这样 DEV_ASSERT 打印出来的条件能直接指出是哪个肢体错了
    for (int i = 0; i < 8; ++i) DEV_ASSERT(got.limb[i] == want[i]);
    DEV_ASSERT(!is_ge(got, p)); // 归约结果必须 < p
}

// host 侧对拍 + 差异打印 (设备端 printf 会互相交错, 不适合诊断)
static bool host_check_reduce_product()
{
    bool all_ok = true;
    for (unsigned int k = 0; k < 6; ++k) {
        uint32_t prod[16];
        make_test_product(prod, k, 12345u + k);
        const uint256_t got = reduce_product(prod);
        uint32_t want[8];
        ref_mod_p(prod, want);
        bool ok = true;
        for (int i = 0; i < 8; ++i)
            if (got.limb[i] != want[i]) ok = false;
        if (is_ge(got, p)) ok = false;
        if (!ok) all_ok = false;

        printf("  [case %u]%s  prod=", k, ok ? " ok  " : " BAD ");
        for (int i = 15; i >= 0; --i) printf("%08x", prod[i]);
        printf("\n           new  =");
        for (int i = 7; i >= 0; --i) printf("%08x", got.limb[i]);
        printf("\n           want =");
        for (int i = 7; i >= 0; --i) printf("%08x", want[i]);
        printf("\n");
    }
    return all_ok;
}

void validate_test()
{
    enable_blocking_sync();
    init_RhoStates_test(RHOSTATES_TEST_NUM + 1);
    init_adds_pub_dev();
    init_break_flag();
    DpManager dp_manager(RHODP_TEST_NUM + 10);

    // 设备端失败计数清零。Release 下内核里的 assert 会被 NDEBUG 编译掉, 所以
    // 内核内统一用 DEV_ASSERT 累加 g_validate_fail, 每个阶段跑完在这里查一次。
    validate_reset();
    const auto stage_ok = [](const char* name) {
        if (!validate_ok(name)) exit(EXIT_FAILURE);
    };

    // 归约 (reduce_product) 与独立教科书参考对拍, 含 4 个构造极端输入。
    // host 侧先跑, 这样失败时能打印完整诊断 (设备端 printf 会交错)。
    if (!host_check_reduce_product()) {
        printf("validate FAILED: host_check_reduce_product\n");
        exit(EXIT_FAILURE);
    }
    validate_reduce_product<<<8, 256>>>();
    CHECK_CUDA(cudaDeviceSynchronize());
    stage_ok("validate_reduce_product");

    // 单 walker 步进 vs 链后继对拍 + DP 缓冲写入/溢出路径
    validate_multi<<<10, 256>>>();
    CHECK_CUDA(cudaDeviceSynchronize());
    stage_ok("validate_multi");

    // safegcd 模逆: a * a^-1 == 1 (mod p)
    validate_safegcd<<<1, 1>>>();
    CHECK_CUDA(cudaDeviceSynchronize());
    stage_ok("validate_safegcd");

    // 多 walker 点加核心 (三个分支: 一般加法 / 倍点 / 无穷远) + 批量求逆与逐点
    // 对拍 + distinguishable 判据 (含测试链尾槽那个真实 DP 样点的索引核对)
    validate_point_add<<<1, 1>>>();
    CHECK_CUDA(cudaDeviceSynchronize());
    stage_ok("validate_point_add");

    // 多 walker 批量求逆对拍: 沿同一测试链, 连续 W 个状态批量步进一步,
    // 逐个与单 walker 后继对拍
    validate_multi_w<2><<<10, 256>>>();
    CHECK_CUDA(cudaDeviceSynchronize());
    validate_multi_w<4><<<10, 256>>>();
    CHECK_CUDA(cudaDeviceSynchronize());
    validate_multi_w<8><<<10, 256>>>();
    CHECK_CUDA(cudaDeviceSynchronize());
    stage_ok("validate_multi_w (W=2/4/8)");

    // 仿射点加 (libsecp256k1 内部 5x52 域实现) 的正确性验证。
    // 它自己内部也把 assert 换成了显式判断 + exit, 见 rho.cpp。
    validate_rho_affine();

    // 转换逻辑往返测试: RhoPoint -> RhoPoint_dev -> DpBuffer -> RhoPoint
    for (int i = 0; i < 4096; i++) {
        RhoPoint r, r2;
        r.rand();
        // 诊断: rand() 造出来的 (x,m,n) 三元组是否自洽
        HOST_ASSERT(check(ctx, &r.x, r.m, r.n));
        RhoPoint_dev t;
        t.from(r);
        DpBuffer buffer;
        transfer(buffer.sp.m, (const unsigned char*)&t.m);
        transfer(buffer.sp.n, (const unsigned char*)&t.n);
        HOST_ASSERT(buffer.sp == r);
        t.to(r2);
        HOST_ASSERT(memcmp(&r, &r2, sizeof(r2)) == 0);
    }

    CHECK_CUDA(cudaFree(RhoStates_host));
    RhoStates_host = nullptr;

    // 测试 init_RhoStates_dev / save_RhoStates_dev / loadRhoState 的往返
    int points = 100 * 960;
    const std::string fn_ = "D:\\test_rs.txt";
    const std::string fn2_ = "D:\\test_rs2.txt";
    init_RhoStates_dev(points, fn_);
    save_RhoStates_dev(points, fn_);
    std::vector<RhoState> rsv, rsv2;
    rsv.resize(points);
    rsv2.resize(points);
    int n1 = loadRhoState(rsv.data(), points, fn_);
    HOST_ASSERT(n1 == points);
    CHECK_CUDA(cudaFree(RhoStates_host));
    RhoStates_host = nullptr;
    init_RhoStates_dev(points, fn_);
    save_RhoStates_dev(points, fn2_);
    int n2 = loadRhoState(rsv2.data(), points, fn2_);
    HOST_ASSERT(n2 == points);
    for (int i = 0; i < points; i++) {
        HOST_ASSERT(check(ctx, &rsv[i].x, rsv[i].m, rsv[i].n));
        HOST_ASSERT(memcmp(&rsv[i], &rsv2[i], sizeof(rsv[i])) == 0);
    }
    std::remove(fn_.c_str());
    std::remove(fn2_.c_str());

    CHECK_CUDA(cudaFree(RhoStates_host));
    RhoStates_host = nullptr;
    printf("validate_test passed!\n");
}
