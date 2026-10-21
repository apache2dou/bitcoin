// cuda_lab.cu
//
// GPU 实验田: 带玩乐性质、想在设备端试的点子都先在这里落地 —— 与 rho_lab.cpp
// (纯主机侧试验) 并列, 分工是"这批试验要不要碰设备"。
//
// 与 cuda.cu 的关系:
//   - cuda.cu 是生产/自检用的设备代码 (域运算、步进表、批量求逆、起点漫游...),
//     动它要谨慎;
//   - 本文件放宽标准: 新内核、新表示、半成品都可以先扔进来, 跑得出数、看得出收益
//     再考虑往 cuda.cu 搬。
//
// 几条硬约束 (nvcc 的翻译单元规则, 不知道会白折腾半天):
//
//   1) 独立翻译单元看不到 cuda.cu 里的文件作用域设备符号 (adds_pub_dev、
//      RhoStates_reserve、fun_add_w ...)。要用就得在本文件里
//        extern __constant__ uint256_t adds_pub_dev[];
//      这种形式重新声明一遍 (类型与维度必须逐字对齐, 否则静默错位), 或者干脆
//      在本文件内自带一份 —— 试验阶段后者通常更省事, 也不会把生产符号拖下水。
//
//   2) 设备代码里不能用 std::ostringstream 那一套 (见 common.h 里 CPrintStream
//      的说明): 要打印走 cprintf, 它 nvcc 的 host/device 两遍都能编。
//
//   3) 本文件只进 BUILD_BITCOIN_CUDA 分支 (见 src/CMakeLists.txt); 非 CUDA 构建
//      根本不编它。所以**只要**有主机侧代码引用本文件导出的符号, 就必须在
//      rpc/cuda_stub.cpp 里补一个同名桩函数, 否则非 CUDA 构建链接失败。
//
//   4) layout 相关的东西照抄 cuda.cu 的忠告: uint256_t 的 alignas(16) 是性能关键
//      (128 位访存), 改布局前先看那边的 static_assert 与量化对账注释。
//
// 约定: 只读现有生产状态 (D:\*.bin / RhoState*.txt 等), 不动生产存档、不启动
//       play、不写设备端生产缓冲, 除非某个试验确实需要并单独说明。
#include <cuda_runtime.h>

#include <cstdint>

#include "common.h"

// ---------------------------------------------------------------------------
// 试验区
//
// 新点子往这下面加。一个试验大致长这样:
//   1) 本文件里写内核 + 驱动代码 (静态/匿名 namespace 收起来, 免得撞 cuda.cu);
//   2) 需要被主机侧调到时, 在 common.h 的 "实验田" 一节加声明;
//   3) 若非 CUDA 构建也要能链接, 在 cuda_stub.cpp 补一个抛异常的桩;
//   4) 挂到 perf_test() / validate_test() 或命令行分支上跑。
// ---------------------------------------------------------------------------

// ===========================================================================
// 试验 1: k40 —— 沿固定加数链路扫 40 位可分点 (GPU)
//
// 目标: 枚举 k = 1, 2, 3, ... 把 x(k·Q) 的 40 位可分点 (低 40 位全 0) 连同它的 k
// 记下来。只用 GPU; CPU 一个线程都不开 (与生产的 rho_play 完全不同 —— 那边是
// "CPU 半核 + GPU" 一起撞碰撞)。
//
// 基准点 Q: 由 k40_play 的形参 use_mvp 决定 (见 rpc/common.h), 主机侧选好后用
// cudaMemcpyToSymbol 填进 k40_base_q:
//   use_mvp = false -> Q = G   (扫 k·G)
//   use_mvp = true  -> Q = MVP (扫 k·MVP)
// 设备侧对这个区别完全无感 —— 它只负责"每步加 Q"与"每批加 stride_k·Q",
// 所以一条内核同时覆盖两条链 (改 Q 不用重编内核)。
//
// ==== 算法: 固定加数 + 等差子链 ====
//   生产 rho_w 每个 walker 每步加步进表里按当前点低位选出的**随机**点, 所以
//   walker 的轨迹是随机游走, 只能在撞上 DP 时把当时的状态存下来。
//   这里反过来: 每个 walker 每步固定加同一个点
//        S = stride_k·Q   (stride_k = 每批覆盖多少个 k = 全部 walker 数,
//                          主机侧算好塞进 k40_stride_q)
//   于是线程 t 的第 j 个 walker 沿着
//        k = (t·W + j + 1) + i·stride_k,   i = 0, 1, 2, ...
//   的等差数列走 —— 它**就是**一条已知 k 的链, 不需要 m/n 记账, 也不需要存档
//   状态: k 是 (t, j, i) 的纯函数。
//
// ==== 不重不漏 (这一条是整个设计的关键) ====
//   一轮开始时, 主机给游标 cursor (含义: k <= cursor 已经扫过了), 然后
//     - 起点: 线程 t 的 walker j 从 k = cursor + (t·W + j + 1) 起,
//       t 遍历 [0, threads), j 遍历 [0, W) => 起点恰好覆盖
//       [cursor+1, cursor+stride_k];
//     - 每步 +stride_k => 第 i 步覆盖 k = cursor + (t·W+j+1) + i·stride_k。
//   把 (t·W+j+1) 看作 1..stride_k 里的一个余数 (每个余数恰好一次), 于是走满 T 步
//   之后覆盖的就是**连续区间** (cursor, cursor + T·stride_k], 每个 k 恰好一次。没有随机性,
//   没有 birthday 重叠, 也不会漏。
//
//   因为余数是 "t·W+j+1" 这种按线程连续编号的, 行/段 (block) 与余数区间的关系是
//   死的: 第 b 行的 W·blockDim 个 walker 正好对应
//   m ∈ [b·walkers_per_row+1, (b+1)·walkers_per_row]。
//   所以**段首点**只需要 rows = grid 个: 主机用 libsecp256k1 算
//   base[b] = P0 + (cursor + b·walkers_per_row + 1)·Q, 行内剩下
//   walkers_per_row-1 个点由设备侧一个线程串行 +Q 推出来 (k40_init_states)。
//   这一段串行建链是 (walkers_per_row-1) 次单线程点加, 相对整轮 (~2^20 批) 可以忽略。
//
// ==== 断点续算 ====
//   状态**只有游标 k 一个整数**: 每轮结束后 cursor += (本轮各线程实际走完的
//   最少批数)·stride_k, 覆盖写进 D:\<prefix><起点>.state (prefix 按 Q 分:
//   Kg40_ / Kmvp40_, 两档互不覆盖)。walker 的点不存档 —— 下一轮
//   重新由游标推出段首点建链即可。所以 Ctrl+C 之后重跑就是接着算, 不需要
//   RhoState 那种大存档。
//   Ctrl+C 落在轮中间时, 各线程走完的批数可能不一样 (差一个轮询间隔): 走到前面的
//   那些线程多算的那一小段 (最多 K40_POLL_MASK 批) 下轮会重算一遍。取最小值推进游标
//   是**保守**的, 不会漏 k; 但那些多算的 k 上如果命中了 DP, 当场写进文件、下轮重扫
//   再写一次就成了重复行 (k 唯一确定点, 重复只能来自重扫)。收拾办法在主机侧收账
//   那一步: **只落 k <= 本轮游标上界** 的记录 (见 k40_play 的 new_cursor), 超出的
//   那几条丢掉等下轮重扫时再记 —— 一行不多, 一行不少。
//
// ==== W 的选择 ====
//   生产核选 W 要同时保"单链速度"和"总吞吐" (见 cuda.cu 的 warps/SM 定档那几节),
//   本试验**只有一个指标: 总吞吐** (walker 走得慢无所谓, 反正 k 是算出来的,
//   不靠随机游走收敛)。所以取 W=32 —— cuda.cu 的 W 扫描里总吞吐的峰值
//   (基准核 803.5M pts/s, W=64 回落)。grid/block 仍按生产档
//   get_optimal_block_size() (每 SM 8 个 warp) 取, 与生产几何一致。
//
// 落盘格式 (与生产 DP 文件不同, 见任务说明): 每行 "<k> <索引>", 十进制文本。
// ===========================================================================

// 每线程 walker 数: 总吞吐优先, 取实测峰值 (见上)
constexpr int K40_W = 32;
// 单轮 DP 回读上限。2^-40 密度下, 一轮 ~2^20 批 x stride_k 个点期望命中不到 1 条,
// 256 条是纯保险 (计数到上限就置 break_flag, 本轮提前收尾)。
constexpr unsigned int K40_DP_MAX = 256;
// 设备缓冲容量 = 回读上限 + 20 档余量。口径与生产 add_dp_to_buffer 完全一致 (见
// cuda.cu 的 edge_pool_size 那段): "计数到上限置起 break_flag" 到 "各线程走到下一个
// 轮询点看到它" 之间还有一段窗口, 窗口里冒出来的命中照样会写缓冲 —— 这 20 档就是
// 留给它们的, 少一档就是越界写。生产取 20 是按 32 位判据定的 (窗口期望 ~3 条命中,
// Poisson(3) 冒到第 21 条的概率 ~1e-11); 本试验用 40 位判据, 密度是它的 1/256,
// 同一窗口只期望 0.01 条, 照抄 20 档只会更宽。主机只回读前 K40_DP_MAX 条。
constexpr unsigned int K40_DP_SLOTS = K40_DP_MAX + 20;
// 每轮批数: 2^20 批 x stride_k ≈ 3.95e11 个 k (按 ~6e8 pts/s 估计约 11 分钟), 也就是
// 落盘节奏 (~11 分钟一次)。想改只管改这个数, 别的都不用动。
constexpr unsigned long long K40_BATCHES = 1ULL << 20;
// 中断轮询间隔: 每 2^14 批查一次 break_flag。轮询越密, Ctrl+C 后要重算的尾巴越短。
constexpr unsigned long long K40_POLL_MASK = 0x3FFFULL;

// 基准点 Q (每步加什么): G 或 MVP, 由主机侧按 k40_play 的形参 use_mvp 填。
// 放 __constant__: 每步读的都是同一个地址 (同一线程 W 个 walker 读同一个 Q, 一整个
// warp 也读同一个 Q), 常量内存就是为这种 uniform 访存设计的。
__constant__ AffinePoint k40_base_q;
// 步长点 S = stride_k·Q (本轮固定加数)。主机侧用 cudaMemcpyToSymbol 填。
// 同样放 __constant__: 走的每一步读的都是同一个地址, 内联后 x/y 是 immediate 常量
// 操作数 (占一个 c[0][..] 槽位), 不像全局加载那样要吃寄存器 + 走 L1/L2。
__constant__ AffinePoint k40_stride_q;
// 本轮各线程走完的批数的最小值 (原子取小, 主机侧复位成 ULLONG_MAX)
__device__ unsigned long long k40_min_done;
// 本轮 DP 记录 (前 K40_DP_MAX 条有效, 再往后是窗口余量)
__device__ unsigned int k40_dp_count;
__device__ unsigned long long k40_dp_k[K40_DP_SLOTS];
__device__ unsigned long long k40_dp_idx[K40_DP_SLOTS];

// K40Start (65 字节非压缩, 大端) -> 设备端 AffinePoint。与 RhoPoint_dev::from
// 的 x 部分完全一样: pubkey 字节 memcpy 进 uint256_t, limb[0] 自然落到低位字。
static AffinePoint k40_to_affine(const K40Start& s)
{
    AffinePoint p;
    memset(&p, 0, sizeof(p));
    if (!s.infinity) {
        memcpy(&p.x, s.ser + 1, 32);
        memcpy(&p.y, s.ser + 33, 32);
    }
    p.infinity = s.infinity;
    return p;
}

// 单点加: P += Q (每步一次 mod_inv_p)。建链用, 一次一个点。
__device__ static void k40_add_affine(AffinePoint& P, const AffinePoint& Q)
{
    uint256_t den;
    const int mode = step_prepare(P, Q, &den);
    step_apply(P, (mode == 0 || mode == 1) ? mod_inv_p(den) : den, mode, Q);
}

// DP 记录: 填进本轮缓冲。
// 与生产 add_dp_to_buffer 同构 —— 原子取位置后**无条件写**, 不做边界判断:
// 越界由 "计数到 K40_DP_MAX 就置 break_flag" + K40_DP_SLOTS 的 20 档余量一起兜住,
// 和那边 "max_size + 20 档余量" 是同一套安排。
__device__ static void k40_dp_record(unsigned long long k, unsigned long long idx)
{
    const unsigned int slot = atomicAdd(&k40_dp_count, 1u);
    k40_dp_k[slot] = k;
    k40_dp_idx[slot] = idx;
    if (slot + 1 >= K40_DP_MAX) {
        *break_flag_dev = true;
    }
}

// 批量求逆: 同一线程 W 个 walker 同时加同一个点 Q。
// 与生产 fun_add_w<W> 的唯一区别是加数不查表 (整批同一个 Q), 求逆的摊薄手法
// 一模一样: 前向积 -> 一次 mod_inv_p -> 回代。
template <int W>
__host__ __device__ void k40_fun_add_q(AffinePoint* s, const AffinePoint& Q)
{
    uint256_t den[W], prefix[W];
    int mode[W];
    for (int k = 0; k < W; ++k) {
        mode[k] = step_prepare(s[k], Q, &den[k]);
        prefix[k] = (k == 0) ? den[k] : mul_mod(prefix[k - 1], den[k]);
    }
    uint256_t u = mod_inv_p(prefix[W - 1]);
    for (int k = W - 1; k >= 0; --k) {
        const uint256_t inv_den = (k > 0) ? mul_mod(u, prefix[k - 1]) : u;
        step_apply(s[k], inv_den, mode[k], Q);
        if (k > 0) u = mul_mod(u, den[k]);
    }
}

// 建链: 每行 (段) 的 walkers_per_row 个起点 = 段首点 + j·Q, 串行推。
// 网格 <<<rows, 1>>>, 每行一个线程 (walkers_per_row 次单线程点加, 相对整轮可忽略)。
// Q 从 k40_base_q 取: 这是内核里唯一一处"知道基准点是 G 还是 MVP"的地方, 而且它
// 只是读常量内存, 没有任何分支。
__global__ void k40_init_states(const AffinePoint* bases, AffinePoint* states,
                                unsigned long long walkers_per_row)
{
    if (threadIdx.x != 0) return;
    const unsigned long long row = blockIdx.x;
    AffinePoint P = bases[row];
    AffinePoint* out = states + row * walkers_per_row;
    for (unsigned long long j = 0; j < walkers_per_row; ++j) {
        out[j] = P;
        k40_add_affine(P, k40_base_q);
    }
}

// 扫描: 线程 tid 的第 k 个 walker 从 k = cursor + tid·W + k + 1 起, 每步 +stride_k。
// 先查 DP 再步进, 走满 n_batches 步 => 覆盖 (cursor, cursor + n_batches·stride_k]。
// 一步就是一批: 全部 walker 各走一格, 合起来正好是连续 stride_k 个 k。
template <int W>
__global__ void k40_scan(AffinePoint* states, unsigned long long cursor,
                         unsigned long long n_batches, unsigned long long stride_k)
{
    const unsigned long long tid = (unsigned long long)blockIdx.x * blockDim.x + threadIdx.x;
    // 本线程 W 个 walker 在 [1, stride_k] 余数区间里占的那一段: m_first .. m_first+W-1
    const unsigned long long m_first = tid * W + 1;
    AffinePoint s[W];
#pragma unroll
    for (int k = 0; k < W; ++k) {
        s[k] = states[m_first - 1 + k];
    }

    unsigned long long done = 0;
    while (done < n_batches) {
#pragma unroll
        for (int k = 0; k < W; ++k) {
            const unsigned long long idx = distinguishable(s[k].x);
            if (idx != 0) {
                k40_dp_record(cursor + m_first + (unsigned long long)k + done * stride_k, idx);
            }
        }
        if (done != 0 && (done & K40_POLL_MASK) == 0 && *break_flag_dev) break;
        k40_fun_add_q<W>(s, k40_stride_q);
        ++done;
    }
    atomicMin(&k40_min_done, done);
}

// ===========================================================================
// 驱动
//
// 形参 use_mvp: false 扫 k·G, true 扫 k·MVP (只影响基准点 Q 与存盘文件名, 内核与几何
// 一律不变 —— 所以它是个普通形参, 不做模板参数: 函数体里只把它传给普通函数,
// 内核一个分支都不看它, 模板实例化带不来任何收益)。
// ===========================================================================
void k40_play(const std::string& spec, bool use_mvp)
{
    uint64_t a_mvp = 0, b_g = 0;
    if (!k40_parse_spec(spec, a_mvp, b_g)) {
        std::cout << "k40: bad start spec '" << spec
                  << "' (syntax: 0 / 1mvp / <a>mvp / <b>g / <a>mvp+<b>g)" << std::endl;
        return;
    }
    const std::string tag = k40_spec_tag(a_mvp, b_g);
    const std::string chain = k40_chain_tag(use_mvp);
    const std::string dp_file = k40_dp_file(use_mvp, a_mvp, b_g);
    const std::string st_file = k40_state_file(use_mvp, a_mvp, b_g);

    K40Start p0;
    if (!k40_make_start(a_mvp, b_g, p0)) {
        std::cout << "k40: cannot build start P0 = " << tag << " (coef out of order?)" << std::endl;
        return;
    }
    // 基准点 Q: use_mvp = false -> G, true -> MVP。
    // 下面所有"每步加什么""每批加什么""第 m 个点是什么"都只看这一个点, 所以换
    // 链只影响这里 + 文件名前缀, 内核一行不改。
    K40Start base_q;
    if (!k40_base_point(use_mvp, base_q)) {
        std::cout << "k40: cannot build base point Q = " << chain << std::endl;
        return;
    }
    uint64_t cursor = k40_load_cursor(st_file);

    enable_blocking_sync();
    int grid_size = 0, block_size = 0;
    get_optimal_block_size(grid_size, block_size);

    // 三个几何量 (名字按它们在算法里的角色取, 不按公式里的字母):
    //   rows            行数 = 段数 = CUDA 的 block 数 (每行一个 block)
    //   walkers_per_row 每行 (每段) 的 walker 数 = block_size · W
    //   stride_k        每批覆盖多少个 k = 全部 walker 数 = rows · walkers_per_row,
    //                   也正是固定加数那个点 stride_k·Q 的倍数
    // 一次"批" = 全部 walker 各走一格 = 覆盖连续 stride_k 个 k。
    constexpr int W = K40_W;
    const int rows = grid_size;
    const uint64_t walkers_per_row = (uint64_t)block_size * W;
    const uint64_t stride_k = (uint64_t)rows * walkers_per_row;
    HOST_ASSERT(stride_k == (uint64_t)grid_size * block_size * W);

    // 步长点 stride_k·Q (直接拿基准点做标量乘, 两条链共用同一个算式)
    K40Start stride_start;
    if (!k40_mul(base_q, stride_k, stride_start)) {
        std::cout << "k40: cannot build stride point " << stride_k << "*Q (Q=" << chain << ")"
                  << std::endl;
        return;
    }
    const AffinePoint base_dev = k40_to_affine(base_q);
    const AffinePoint stride = k40_to_affine(stride_start);

    std::cout << get_time() << " : k40 start " << tag << " on Q=" << chain
              << (p0.infinity ? " (point at infinity)" : "") << ", cursor k=" << cursor << std::endl;
    std::cout << get_time() << " : k40 geometry: " << rows << " rows x " << walkers_per_row
              << " walkers/row, W=" << W << ", stride_k=" << stride_k << ", batches/round "
              << K40_BATCHES << " = " << (K40_BATCHES * stride_k)
              << " k's; dp -> " << dp_file << ", cursor -> " << st_file << std::endl;

    AffinePoint* bases_dev = nullptr;
    AffinePoint* states_dev = nullptr;
    CHECK_CUDA(cudaMalloc((void**)&bases_dev, (size_t)rows * sizeof(AffinePoint)));
    CHECK_CUDA(cudaMalloc((void**)&states_dev, (size_t)(stride_k * sizeof(AffinePoint))));
    CHECK_CUDA(cudaMemcpyToSymbol(k40_base_q, &base_dev, sizeof(AffinePoint)));
    CHECK_CUDA(cudaMemcpyToSymbol(k40_stride_q, &stride, sizeof(AffinePoint)));

    const bool own_flag = (break_flag_host == nullptr);
    if (own_flag) init_break_flag();
    break_rho(false);

    std::vector<AffinePoint> bases_host((size_t)rows);
    uint64_t round_no = 0;
    double total_pts = 0.0, total_secs = 0.0;
    uint64_t total_dps = 0;

    while (!gameover) {
        // 0) 清掉中断标志。每轮开头都清: 上一轮除了 Ctrl+C, 也可能因为 DP 缓冲写满
        //    而提前收尾, 那个标志没人清的话这一轮会刚起步就退出。
        //    清完再看一次 gameover: 中断正好落在上一轮收尾的间隙时, 别再开新的一轮。
        break_rho(false);
        if (gameover) break;

        // 1) 段首点 (依赖游标), 上传
        std::vector<K40Start> bases;
        if (!k40_build_bases(p0, base_q, cursor, walkers_per_row, rows, bases)) {
            std::cout << "k40: cannot build row bases (cursor k=" << cursor << "), stop" << std::endl;
            break;
        }
        for (int row = 0; row < rows; ++row) {
            bases_host[(size_t)row] = k40_to_affine(bases[(size_t)row]);
        }
        CHECK_CUDA(cudaMemcpy(bases_dev, bases_host.data(), (size_t)rows * sizeof(AffinePoint),
                              cudaMemcpyHostToDevice));

        // 2) 复位本轮计数
        const unsigned long long ull_max = ~0ULL;
        const unsigned int zero = 0;
        CHECK_CUDA(cudaMemcpyToSymbol(k40_min_done, &ull_max, sizeof(ull_max)));
        CHECK_CUDA(cudaMemcpyToSymbol(k40_dp_count, &zero, sizeof(zero)));

        // 3) 建链 + 扫描
        const std::chrono::steady_clock::time_point t0 = std::chrono::steady_clock::now();
        k40_init_states<<<rows, 1>>>(bases_dev, states_dev, walkers_per_row);
        CHECK_CUDA(cudaGetLastError());
        k40_scan<W><<<rows, block_size>>>(states_dev, cursor, K40_BATCHES, stride_k);
        CHECK_CUDA(cudaGetLastError());
        CHECK_CUDA(cudaDeviceSynchronize());
        const double secs =
            std::chrono::duration<double>(std::chrono::steady_clock::now() - t0).count();

        // 4) 收账: 最少批数 -> 游标; DP -> 文件
        unsigned long long min_done = 0;
        unsigned int ndp = 0;
        CHECK_CUDA(cudaMemcpyFromSymbol(&min_done, k40_min_done, sizeof(min_done)));
        CHECK_CUDA(cudaMemcpyFromSymbol(&ndp, k40_dp_count, sizeof(ndp)));
        // 计数可能略超上限: 值得落进 K40_DP_SLOTS 余量的那几条, 必然是"计数到 K40_DP_MAX
        // 已置起 break_flag"之后写的 (slot >= K40_DP_MAX 只可能发生在第 257 次递增),
        // 也就是本轮已经决定收尾的窗口里冒出来的 —— 不回读, 只取前 K40_DP_MAX 条。
        if (ndp > K40_DP_MAX) ndp = K40_DP_MAX;

        if (min_done == 0) {
            std::cout << "k40: no batch finished this round (interrupted), stop" << std::endl;
            break;
        }
        // 本轮覆盖的区间是 (cursor, cursor + min_done·stride_k], 游标正好推进到这个上界。
        // 各线程停在各自己的轮询点上, min_done 是其中最小的那个, 所以这个上界一定
        // 被某个线程真的扫过 (不会漏 k)。
        const uint64_t new_cursor = cursor + (uint64_t)min_done * stride_k;

        unsigned int kept = 0;
        if (ndp > 0) {
            std::vector<unsigned long long> ks((size_t)ndp), idxs((size_t)ndp);
            CHECK_CUDA(cudaMemcpyFromSymbol(ks.data(), k40_dp_k,
                                            (size_t)ndp * sizeof(unsigned long long)));
            CHECK_CUDA(cudaMemcpyFromSymbol(idxs.data(), k40_dp_idx,
                                            (size_t)ndp * sizeof(unsigned long long)));
            std::vector<uint64_t> kk;
            std::vector<uint64_t> ii;
            kk.reserve((size_t)ndp);
            ii.reserve((size_t)ndp);
            for (unsigned int i = 0; i < ndp; ++i) {
                // 只落 k <= new_cursor 的记录。超出的那几条来自"跑到前面的线程多走的
                // 那一小段" (中断时各线程停在各自的轮询点上, 最深的多走不到 K40_POLL_MASK
                // 批), 那一段下一轮会重扫、会重新记一遍 —— 现在写下去就是重复行
                // (k 唯一确定点, 重复只可能来自重扫)。丢掉这几条不丢数据: 一条不差地
                // 会从重扫里回来, 只是那一小段计算白跑 (2^14/2^20 ≈ 1.6% 的尾巴)。
                if ((uint64_t)ks[i] <= new_cursor) {
                    kk.push_back((uint64_t)ks[i]);
                    ii.push_back((uint64_t)idxs[i]);
                }
            }
            if (!kk.empty() && !k40_append_dps(dp_file, use_mvp, a_mvp, b_g, kk, ii)) {
                // 落盘失败就**不推进游标**地收工: 游标是唯一的断点状态, 划过去这一段 k
                // 就再也没机会重扫, 本轮这几条 DP 就永久丢了 (下轮顶多白跑 11 分钟)。
                std::cout << "k40: append to " << dp_file
                          << " failed, stop without advancing the cursor" << std::endl;
                break;
            }
            kept = (unsigned int)kk.size();
        }

        const double pts = (double)min_done * (double)stride_k;
        total_pts += pts;
        total_secs += secs;
        total_dps += kept;
        ++round_no;
        cursor = new_cursor;
        if (!k40_save_cursor(st_file, cursor, use_mvp)) {
            std::cout << "k40: cannot write cursor " << st_file << std::endl;
        }
        std::cout << get_time() << " : k40[" << tag << "/Q=" << chain << "] round " << round_no
                  << " batches " << min_done << "/" << K40_BATCHES << " cursor " << cursor
                  << " new dp " << kept;
        if (ndp > kept) {
            std::cout << " (" << (ndp - kept) << " ahead of cursor, left for next round)";
        }
        std::cout << " elapsed " << (unsigned long long)secs << " s ("
                  << (secs > 0.0 ? pts / 1e6 / secs : 0.0) << " M pts/s)" << std::endl;
    }

    std::cout << get_time() << " : k40[" << tag << "/Q=" << chain << "] exit: " << round_no
              << " rounds, " << (unsigned long long)total_pts << " pts, " << total_dps
              << " dp, cursor k="
              << cursor << ", avg "
              << (total_secs > 0.0 ? total_pts / total_secs / 1e6 : 0.0) << " M pts/s"
              << std::endl;

    if (own_flag) free_break_flag();
    CHECK_CUDA(cudaFree(states_dev));
    CHECK_CUDA(cudaFree(bases_dev));
}
// ---------------------------------------------------------------------------

// 占位: 目前还没有试验。留着这个空的翻译单元, 好让 CMake 的源列表先接上。
