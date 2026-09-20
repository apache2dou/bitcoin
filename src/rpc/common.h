#ifndef BITCOIN_RPC_COMMON_H
#define BITCOIN_RPC_COMMON_H
#include "../../secp256k1/include/secp256k1.h"

#include <string>

class SecPair
{
public:
    unsigned char m[32] = {0};
    unsigned char n[32] = {0};
    bool rand();
    bool operator==(const SecPair& other) const;
};

class RhoPoint : public SecPair
{
public:
    secp256k1_pubkey x;
    bool rand();
};

// 64字节对齐（一条缓存行），避免多线程下 rs[] 数组相邻元素的伪共享
class alignas(64) RhoState : public RhoPoint
{
public:
    uint64_t times;
};

// 运行模式（由 main 命令行参数设置）：
// 1 = 仅CPU单线程，不启动CUDA
// 2 = CUDA启动，每核心1线程(multiple=1)，CPU启动 1/4 核数线程
// 3 = CUDA启动，每核心2线程(multiple=2)，CPU启动 1/2 核数线程（默认）
// 4 = CUDA启动，blockSize 用 cudaOccupancyMaxPotentialBlockSize 结果，CPU启动 核数-2 线程
extern int g_run_mode;

bool rho_F(secp256k1_context* ctx, RhoState& s);
void set_int256(unsigned char* cn, const char* n);
void set_int(unsigned char* cn, int64_t n);
void create(const secp256k1_context* ctx, secp256k1_pubkey* pk, const unsigned char* m, const unsigned char* n);
int check(const secp256k1_context* ctx, const secp256k1_pubkey* pk, const unsigned char* m, const unsigned char* n);
std::string get_time();
void break_rho(bool value);
void rho_play();
void validate_test();
void perf_test();
// 定义在 rpc/cuda.cu (BUILD_BITCOIN_CUDA) 或 rpc/cuda_stub.cpp: GPU 多 walker
// 批量求逆的基准测试, 由 perf_test() 调用
void perf_test_rho_gpu_walkers();
// 定义在 rpc/cuda.cu (BUILD_BITCOIN_CUDA): 基础算子 (mul_mod / mod_inv_p /
// mod_add / mod_sub) 的串行依赖链微基准, 用于把 "每点成本 = E + M/W + L(W)"
// 拆成可分别归因的项
void perf_micro();
// 定义在 rpc/rho.cpp: libsecp256k1 版本的点加性能测试, 由 perf_test() 调用
void perf_test_libsecp256k1();
// 定义在 rpc/rho.cpp: 直接用 libsecp256k1 内部 5x52 域实现的仿射点加性能测试
void perf_test_rho_affine();
// 定义在 rpc/rho.cpp: 仿射点加的正确性验证 (与库公开 API 逐步对拍), 由 validate_test() 调用
void validate_rho_affine();
// 定义在 rpc/rho.cpp: 仿射点加 (libsecp256k1 内部 5x52 域) 的初始化,
// 必须在启动 worker 线程之前调用一次
void rho_affine_prepare();
// 定义在 rpc/rho.cpp: 仿射点加版 rho_F (语义与 rho_F 一致) 的单 walker 版。
// 现在只用作对照 / 基准, 生产路径走下面的 rho_affine_FW。
void rho_affine_F(RhoState& rs);

// ---------------------------------------------------------------------------
// 同线程多 walker
//
// 一个线程串行推进 W 个互相独立的随机游走。它的全部意义在于: 每个 walker 每步
// 都要做一次域模逆, 而同一线程内 W 个分母可以凑成一批只求一次逆 (Montgomery
// 批量求逆), 于是每点的模逆成本从 1 次降到 1/W 次。这一点跨线程做不到 ——
// 线程之间没法把分母凑到一起去。
//
// 代价是每点多了约 3 次域乘 (前缀积 + 回溯), 所以 W 越大摊得越薄, 但收益迅速
// 递减。具体取几由实测决定: perf_test_rho_affine_walkers() 在同一个进程里把
// 1/2/4/8/16/32 各跑一遍 80 万点, 首尾各跑一次 W=1 作漂移对照。
//
// 实测 (RTX3070Ti 笔记本, i7 16 线程, Release, 写回消除优化后):
//     W=1   713k pts/s   (漂移对照 705k, 误差 1.1%)
//     W=2  1210k (1.70x)      W=8  2712k (3.80x)
//     W=4  1882k (2.64x)      W=16 3653k (5.12x)      W=32 4124k (5.78x)
//
// 拟合 a + b/W 得 a≈169ms, b≈800ms, 即天花板约 4.7M pts/s。
//
// W 越大线程总吞吐越高, 但单条链的推进速度 = 线程吞吐 / W, W 越大越慢:
//     W=2  每链 ~605k 步/s (1210k / 2)
//     W=16 每链 ~228k 步/s (3653k / 16)
//     W=32 每链 ~129k 步/s (4124k / 32)
// 于是按线程分工, 两个常量各自可调 (可用值 1/2/4/8/16/32):
//   - 线程0 用 RHO_WALKERS0 = 2: 单链速度优先。模式1 (仅CPU单线程)
//     也只有线程0, 同样是这个宽度;
//   - 其余线程用 RHO_WALKERS = 16: 吞吐与资源的平衡点 —— W=32 只再快
//     13%, 单链速度却再砍半, 且 1024/16 = 64 线程上限已覆盖全部运行模式
//     (最多的模式4 也只要 hw-2 = 14)。
// ---------------------------------------------------------------------------

// 已显式实例化的最大宽度 (rho.cpp 实例化了 1/2/4/8/16/32, 取别的值会链接失败)
constexpr int RHO_WALKERS_MAX = 32;

// 线程0 的 walker 数 (单链速度优先, 见上)。
constexpr int RHO_WALKERS0 = 2;
// 其余线程的 walker 数 (总吞吐优先)。
constexpr int RHO_WALKERS = 16;
static_assert(RHO_WALKERS0 >= 1 && RHO_WALKERS0 <= RHO_WALKERS_MAX, "RHO_WALKERS0 超出范围");
static_assert(RHO_WALKERS >= 1 && RHO_WALKERS <= RHO_WALKERS_MAX, "RHO_WALKERS 超出范围");

// RhoState 槽位总数: play() 的 rs[] 数组与 initRhoState 生成器共用。
// 槽位按线程分段独占: 线程0 占 [0, RHO_WALKERS0), 线程 i>0 各占连续
// RHO_WALKERS 个; 线程数上限 = 1 + (RHO_STATE_SLOTS - RHO_WALKERS0)/RHO_WALKERS
// (play() 里的 n_tasks 已按此 clamp)。扩容不影响 D:\RhoState.txt 旧档的读取:
// play() 是部分加载, 条数不足时只把缺的槽补随机。
constexpr int RHO_STATE_SLOTS = 1024;

// 定义在 rpc/rho.cpp: 一次推进连续的 W 个 RhoState (同一线程独占的一段)。
// 每个 walker 走恰好一步, 语义与 rho_affine_F(RhoState&) 完全一致。
//
// 返回 dp_mask: 第 i 位为 1 表示第 i 个 walker 本步命中 DP 点, 此时 rs[i]
// 已被写回最新状态, 调用方可立即读取/存档; 未命中位对应的 rs[i] 是陈旧的
// (最新状态在 thread_local 缓存里), 读取前必须先 rho_affine_flush。
template <int W>
uint32_t rho_affine_FW(RhoState* rs);

// 定义在 rpc/rho.cpp: 把 thread_local 缓存里的最新状态整体写回 rs[0..W)。
// 存档 (saveRhoState / archive) 之前、线程退出之前必须调用; 否则存的是
// 陈旧数据 (DP 命中率 2^-40, 常规运行中 rs 几乎从不被写)。
template <int W>
void rho_affine_flush(RhoState* rs);

// 定义在 rpc/rho.cpp: 扫描 1/2/4/8 个 walker 的吞吐, 用来选 RHO_WALKERS
void perf_test_rho_affine_walkers();
#endif // BITCOIN_RPC_COMMON_H
