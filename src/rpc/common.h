#ifndef BITCOIN_RPC_COMMON_H
#define BITCOIN_RPC_COMMON_H
#include "../../secp256k1/include/secp256k1.h"

#include <cstdint>
#include <sstream>
#include <string>
#include <unordered_map>
#include <vector>

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
// 4 = CUDA启动，CPU启动 核数-2 线程（blockSize 与运行模式无关, 见 cuda.cu 的
//     get_optimal_block_size）
extern int g_run_mode;

bool rho_F(secp256k1_context* ctx, RhoState& s);
void set_int256(unsigned char* cn, const char* n);
void set_int(unsigned char* cn, int64_t n);
void create(const secp256k1_context* ctx, secp256k1_pubkey* pk, const unsigned char* m, const unsigned char* n);
int check(const secp256k1_context* ctx, const secp256k1_pubkey* pk, const unsigned char* m, const unsigned char* n);
std::string get_time();

// ---------------------------------------------------------------------------
// 控制台输出 (UTF-8 安全)
//
// 源码里的字符串是 UTF-8 (MSVC 带 /utf-8), 而中文 Windows 的控制台活动代码页是
// 936(GBK): 把 UTF-8 字节直接丢出去, 屏幕上就是 "婧愬簱" 这种乱码。PowerShell 抓子
// 进程输出时也一样花 —— 它按启动时抓下的 [Console]::OutputEncoding (就是 OEM 代码页)
// 解码, 所以 pipe 里也照样乱。凡是**给人看**的中文控制台输出都走下面这两个入口, 由
// 它们按出口转码 (控制台走 WriteConsoleW, 管道按 OEM 代码页转码); 反过来, 写进日志
// 文件的文本一直是 UTF-8, 不要用这两个入口。
//   cprint()  << "中文 " << n << std::endl;    // 流式
//   cprintf("中文 %d\n", n);                   // printf 式
// 定义在 rpc/blockchain.cpp。
void cprint_write(const std::string& utf8);
void cprintf(const char* fmt, ...);

// cprint(): 一行拼完再一次性写出 (逐段转码会把一行拆得七零八落)。临时对象在整条
// 表达式结束时析构, 所以不用自己 flush; 拷贝/移动都删掉, 免得一条话印两遍。
//
// nvcc 不编这一层 (__CUDACC__ 在 nvcc 的 host/device 两遍里都有): cuda.cu 里用
// cprintf 就行, 免得 std::ostringstream 这种纯主机东西进了设备编译。
#ifndef __CUDACC__
class CPrintStream
{
public:
    CPrintStream() = default;
    CPrintStream(const CPrintStream&) = delete;
    CPrintStream(CPrintStream&&) = delete;
    template <typename T> CPrintStream& operator<<(const T& v)
    {
        m_ss << v;
        return *this;
    }
    // std::endl / std::flush 是函数模板, 上面那个按类型推导的重载收不了 (T 推不出来),
    // 单独给这种"吃流吐流"的操纵符开一个重载。真正写盘/写屏幕在析构里, 这里的 flush
    // 只作用于内部缓冲, 无所谓。
    CPrintStream& operator<<(std::ostream& (*manip)(std::ostream&))
    {
        manip(m_ss);
        return *this;
    }
    ~CPrintStream() { cprint_write(m_ss.str()); }

private:
    std::ostringstream m_ss;
};
inline CPrintStream cprint() { return CPrintStream(); }
#endif

void break_rho(bool value);
void rho_play();
// 定义在 rpc/cuda.cu (BUILD_BITCOIN_CUDA) 或 rpc/cuda_stub.cpp:
// 32 位 DP 起点漫游。与 rho_play 跑同一个核 rho_w<W,EDGE>、同一份 fun_add_w /
// add_dp_to_buffer, 区别只有编译期那一档: 判据换成 32 位, 命中后换的是"下一个
// 起点"(取自 DpSource32all.bin) 而不是预备队, 每条边走出来的 (起点索引, 终点
// 索引, m, n) 追加到 D:\Dp32Edge.txt, 状态落 D:\Dp32EdgeState.txt (文本)。
void dp32_edge_play();
void validate_test();
void perf_test();
// 定义在 rpc/cuda.cu (BUILD_BITCOIN_CUDA) 或 rpc/cuda_stub.cpp: GPU 多 walker
// 批量求逆的基准测试, 由 perf_test() 调用
void perf_test_rho_gpu_walkers();
// 定义在 rpc/rho.cpp: libsecp256k1 版本的点加性能测试, 由 perf_test() 调用
void perf_test_libsecp256k1();
// 定义在 rpc/rho.cpp: 仿射点加的正确性验证 (与库公开 API 逐步对拍), 由 validate_test() 调用
void validate_rho_affine();
// 定义在 rpc/rho.cpp: 仿射点加 (libsecp256k1 内部 5x52 域) 的初始化,
// 必须在启动 worker 线程之前调用一次
void rho_affine_prepare();

// ---------------------------------------------------------------------------
// 预备队 (RhoStates_reserve) 的来源与账本
//
// 池子的唯一用途: 某个 walker 命中可区分点时, 用池里对应槽位的一份独立点把它的
// (x, m, n) 整体顶替掉 (见 cuda.cu 的 add_dp_to_buffer), 让它从这份新起点继续走。
// 换起点跟"进环"无关 —— rho 的目标本来就是让轨迹走进环 (确定性步进 + 状态有限,
// 轨迹迟早进环), 这里只是给这个 walker 另配一份起点。
//
// 逻辑全在 rpc/rho.cpp (纯主机侧, 一行 CUDA 代码都不需要)。设备端只保留那份
// RhoStates_reserve 常量内存, 装载走 upload_RhoStates_reserve。
// ---------------------------------------------------------------------------

// 点的来源:
//   Random  现行做法: 每轮整池换新随机点, 没有账本 (也就是改造前的行为)
//   Special 特殊点: 先吃步进表 adds_pub[0][*] 的 256 条, 吃完再按需现算 1G, 2G, 3G, ...
//                   (阶梯无上限, 所以这一类取不完)
//   Dp      可区分点: 从 32 位 DP 源库 DpSource32.bin 里按槽位游标取 (库里 88.7 万条,
//           取到哪一条由 D:\RhoReserve.txt 里的 cursor 记着; 被征召销账立了墓碑的点不
//           会再发出去)
// 一个槽位可以用不同来源, 目前的生产配置是全池统一 (见 rho.cpp 的 g_reserve_source)。
//
// "点用过即退役"靠库存游标保证, 而游标是**跨进程**的生产状态: rho.cpp 每轮把它连同
// 账本写到 D:\RhoReserve.txt (格式见 rho.cpp 的"进程级状态落盘"一节)。不落盘的话,
// 重启就是游标归零 + 留用队员全丢, 头几批点跟上一次 run 逐字节重复 —— 起点相同、(m,n)
// 相同的轨迹产出的 DP 记录也完全相同, 而碰撞要的是"同一个 x 配不同的 (m,n)", 这种
// 记录一条都排不上用场。
enum class ReserveSource {
    Random,
    Special,
    Dp,
};

// 当前配置的来源 (定义在 rho.cpp)。名字给日志用。
ReserveSource reserve_configured_source();
const char*   reserve_source_name(ReserveSource s);

// 建账本。slots = DP 缓冲区的槽位数 (cuda.cu 的 dp_buffer_size, 由 rho_play 传进来),
// 每轮循环开始前调一次; 轮号与履历都必须跨轮存活, 所以只建一次。
// persistent = true 时启动即回读 D:\RhoReserve.txt (生产路径 rho_play 用; validate
// 一律不碰盘, 免得自检把生产存档盖掉或吃进半份旧状态)。
void init_reserve_pool(size_t slots, bool persistent = false);
// 每轮开跑前调一次: 账本补员 (纯主机侧) + 把槽位上的点整块传进设备常量内存。
void init_RhoStates_reserve();
// 账本记账: 这一轮设备写出去 dp_count 条 DP 记录。记录下标 = 被征调的槽位
// (add_dp_to_buffer 里 r = RhoStates_reserve[index], index 就是记录下标)。
void note_reserve_dps(unsigned int dp_count);
// 把货源游标与账本落盘 (游标丢了 = 重启后重复用点, 所以每轮结束后都要落一次)。
// 只在 init_reserve_pool(.., true) 之后有作用。
void save_reserve_state();
// 载入存档后的对账 (定义在 rho.cpp, 由 rho_play 在库载入之后调一次): 把"游标已经
// 推过、池子里又没有队员占着"的那几条源库记录销账 (立墓碑 + 追加进已征召库)。幂等。
// 注: "有没有队员占着"按**点**判 (队员的 x 复算索引回源库查槽位), 不能按池子槽位号
// 当源库槽位号用 —— 两套编号早早就会错开, 见 rho.cpp 里的说明。
void reserve_retire_consumed();
// 生产日志 (D:\iLog.txt) 追加一行 —— 日志文件里的文本一律 UTF-8, 所以不走 cprint/
// cprintf 那一层。rport 那些会改变两个 .bin 条数的事件 (预备点被征召销账) 走这里。
// 定义在 blockchain.cpp; 日志没开 (g_log == nullptr) 时静默。
void ilog_line(const std::string& utf8);
// 定义在 cuda.cu: 把主机侧的槽位点整块拷进设备常量内存 RhoStates_reserve。
void upload_RhoStates_reserve(const RhoPoint* points, size_t count);

// 验证用 (都定义在 rho.cpp):
void validate_reserve_pool_state();   // 账本状态机自测 (合成供应器 + 合成记录条数)
void validate_reserve_supplies();     // 真货源装载 + 抽样的点自洽
void validate_reserve_state_file();   // 状态存档往返自测 (写临时路径, 不碰生产存档)
bool reserve_slot_tracked(size_t slot);   // 槽位当前有没有队员 (随机点占位 = 没有)
// 定义在 cuda.cu: 按**当前配置**把生产启动那一步 (建池 -> 取满 -> 上传) 走一遍并逐槽
// 核对 —— 换货源之后想知道"这套配置真能跑生产了吗"就调它, 不必跑全量 validate。
void validate_reserve_prod_config();

// 定义在 cuda.cu: 被征召的预备点"重走"探针 (入口 testmvp 120 892)。
//
// 一个预备点被征召时, 命中那条 walker 的 (x, m, n) 被整体换成这份点, 它从新起点接着
// 走, 轮末由 save_RhoStates_dev 落盘。所以这份点的轨迹上**必有** RhoState2.txt 里的
// 一条记录 (只要这条 walker 之后再没被换过)。这个探针拿已征召库尾部那几条点的原始
// (m, n) 当起点, 用生产核同一套步进 (fun_add_w, W=4 批量求逆) 往前走, 每步拿 (m, n)
// 去 RhoState2.txt 的 (m, n) 集合里查, 把"走了多少步 / 落在第几条"报出来。
//
// 只读: 不动设备内存, 不写任何文件, 不启动 play；不消耗/不修改两个 .bin 和账本。
void rho_rewalk_probe();

// ---------------------------------------------------------------------------
// 32 位可区分点 (DP) 的源库 / 已征召库 / 全量库
//
// 判据: "n 位可区分点" = x 的低 n 位全 0 (x.data 按字节小端存坐标, 见 cuda.cu):
//   * 32 位判据: x 低 32 位全 0, 索引 = x 的 bit 32..95
//   * 40 位判据: x 低 40 位全 0, 索引 = x 的 bit 40..103 (= distinguishable() 的返回值)
// 源库 DpSource32.bin 是从 data 目录下的 DistinguishablePoints*.txt 语料合并来的
// (那批语料是 32 位 DP), 合并由离线脚本完成 —— 与全量库 DpSource32all.bin 同一个,
// 应用内已经没有重建入口。一个点被征召之后在源库**原地立墓碑** (m/n 清零, 槽位不
// 回收, 文件长度不变) + 追加到已征召库 DpDrafted32.bin。墓碑不动位置 ⇒ 源库**永远
// 保持按索引升序**, 磁盘二分一直有效。三个文件同构: 24 字节头 + 定长 72 字节记录。
//
// 两个库记的是**同一批点**: 源库里被立墓碑的那条, 就是已征召库里追加的那条。什么
// 时候销这笔账: 拿这个点当起点的那份预备队员**被征召** (它那一记漫步走到 DL 端点,
// 由 add_dp_to_buffer 换掉) 的时候 —— 见 rho.cpp 的 retire_dp_member。所以 3 类货源
// 每被用掉一个, 源库就少一条活的、已征召库多一条, 两库之和不变。
// 建库那一轮 (离线) 还写过一次已征召库: 语料里本身也是 40 位 DP 的那批不进源库,
// 直接计入已征召库。运行期的写作口只剩预备点被征召销账这一个。
// 漫步当场走出来的 40 位 DP 不归这两个库管 —— 它只写文本归档 _DPFile_name (见
// cuda.cu 的 save_dps), 那是采集结果的账。
//
// 全量库 DpSource32all.bin 跟上面两个不是一套账: 它是语料的**只读快照** —— 语料里
// 全部去重后的 32 位 DP (含本身就是 40 位 DP 的那 3,323 条) 按索引升序装在一个库里,
// 没有墓碑也没有征召销账, 运行期只用来跟语料对账。三个库同一套记录格式, 魔数同源。
// ---------------------------------------------------------------------------
constexpr const char* DP32_SOURCE_FILE   = "D:\\DpSource32.bin";
constexpr const char* DP32_DRAFTED_FILE  = "D:\\DpDrafted32.bin";
constexpr const char* DP32_ALL_FILE      = "D:\\DpSource32all.bin";
constexpr const char* DP32_SOURCE_MAGIC  = "DP32SRC1";
constexpr const char* DP32_DRAFTED_MAGIC = "DP32DRF1";
constexpr uint32_t    DP32_VERSION       = 1;

// 32 位 DP 起点漫游 (dp32_edge_play) 的两个文本落盘口 —— 故意用 txt 而不用 .bin,
// 方便直接翻看/核对:
//   Dp32Edge.txt      一行一条边, 空格分隔: "起点索引 终点索引 终点m 终点n"
//                     (起点索引 = 这条边是从哪个 32 位 DP 出发的, 用于跟踪)。
//                     一行 = 一次库派发, 所以行数可以拿来跟游标互校。
//   Dp32EdgeState.txt 每槽 4 行: x / m / n / 起点索引, 与 RhoState 文本格式逐字一致
//                     (第 4 行的 times 字段在这里被借用来存起点索引: 起点漫游不数
//                     步数, 所以 times 空着, 直接拿来放索引, 就能白嫖
//                     loadRhoState / saveRhoState 这一对读写函数)。
//                     库游标就藏在这一列里: 库位置是按游标递增发的, 派出去的最大那个
//                     索引值还握在某个活槽手上, 所以"把它换算成库位置再 + 1"就是游标,
//                     不必另存一份。注意索引值 (x 的 bit 32..95) 能到 9e17, **不能**直接
//                     当位置用 —— 换算靠库内二分 (库按索引升序), 见 cuda.cu 的
//                     dp32_edge_session。
// 起点索引的哨兵值 EDGE_SRC_NONE 见 cuda.cu。
constexpr const char* DP32_EDGE_FILE       = "D:\\Dp32Edge.txt";
constexpr const char* DP32_EDGE_STATE_FILE = "D:\\Dp32EdgeState.txt";

// 头里的 records 既是条数也是完整性凭据: 跟文件长度对不上就说明被截断/写坏了。
#pragma pack(push, 1)
struct Dp32Header {
    char magic[8];
    uint32_t version;
    uint32_t record_size;
    uint64_t records;
};
struct Dp32Record {
    uint64_t index;          // 32 位判据下该点的索引
    unsigned char m[32];     // 大端原样
    unsigned char n[32];
};
#pragma pack(pop)
static_assert(sizeof(Dp32Header) == 24, "Dp32Header 必须是 24 字节");
static_assert(sizeof(Dp32Record) == 72, "Dp32Record 必须是 72 字节");

// 墓碑 (假删除): m 与 n 全 0 表示这条已被征召 —— 记录槽位留在原地, 文件长度不变,
// 读取方必须主动跳过。合法记录不可能是全 0 (create() 对 m=n=0 得到的是无效点,
// 语料里也没有这种记录), 所以全 0 是安全的哨兵值; index 保留不动, 方便定位。
// 注意: 头里的 records **仍然包含**墓碑条目, 否则与文件长度的对账会失败。
inline bool dp32_is_tombstone(const Dp32Record& r)
{
    for (int i = 0; i < 32; ++i) {
        if (r.m[i] != 0 || r.n[i] != 0) return false;
    }
    return true;
}

// ---------------------------------------------------------------------------
// 32 位 DP 库的运行时查询 (瘦索引)
//
// 两个库都是 "24 字节头 + 定长 72 字节记录"。运行时**不把记录留在内存**, 只把每条
// 记录的 index 字段抽出来建索引 (源库 886,948 条约 7.1 MB, 另加 111 KB 墓碑位图),
// 记录本体仍在盘上, 命中之后才按槽位读那 72 字节。**查找全程不碰磁盘二分。**
//   * 源库按索引升序且索引唯一 ⇒ index -> 槽位就是有序数组的下标 (内存里二分);
//     墓碑位图里标过的槽位, 连那 72 字节都不用读。
//   * 已征召库按征召顺序追加, **同一个 index 可能有多条** (不同 x) ⇒ index -> 槽位列表。
// 判等一律比 x 全值: index 只是 x 的 bit 32..95, 同一个 index 不一定是同一个点。
// ---------------------------------------------------------------------------
enum class Dp32File { Source, Drafted };

// 源库按索引查的结果: 不在库里 / 还在 (活的) / 已立墓碑
enum class Dp32Hit { Absent, Live, Tombstone };

class Dp32Store
{
public:
    // 载入两个库的索引。任一库读不了 (缺失 / 魔数 / 版本 / 记录长度 / 条数与文件长度
    // 对不上 / 源库不再升序) ⇒ 整体失败, 并把已建的索引清掉 —— 不做"尽力恢复"。
    // drf_path 传 nullptr (或空串) ⇒ 只载前一个库: 全量库 DpSource32all.bin 就是这么
    // 载的 —— 它一个库装完语料里全部去重后的 32 位 DP, 既没有已征召库也没有墓碑。
    bool load(const char* src_path = DP32_SOURCE_FILE,
              const char* drf_path = DP32_DRAFTED_FILE);
    void unload();
    bool loaded() const { return m_loaded; }

    uint64_t src_count() const { return (uint64_t)m_src_keys.size(); }
    uint64_t drf_count() const { return m_drf_count; }
    uint64_t src_dead_count() const { return m_src_dead_n; }

    // 源库槽位的索引表 (升序去重, 槽位 = 下标)。漫步热路径不用它 —— 对账自测要把整张
    // 索引表跟语料去重后的索引集合逐条比 (条数相同但少了 A 多了 B, 光看条数看不出来)。
    const std::vector<uint64_t>& src_keys() const { return m_src_keys; }

    // 源库: 按索引取槽位 (索引唯一)。命中的槽位即使已墓碑也照样回填 slot。
    Dp32Hit src_find(uint64_t index, uint32_t& slot) const;
    // 源库槽位是不是墓碑 (纯内存位图, 零 I/O); 下标越界当作已墓碑
    bool src_dead(uint32_t slot) const;
    // 已征召库: 取同一索引下的全部槽位 (可能 0 条), 没有则返回 nullptr
    const std::vector<uint32_t>* drf_slots(uint64_t index) const;
    // 按槽位读一条记录 (命中之后才调; 一次 72 字节随机读, 不常开文件句柄)
    bool read(Dp32File which, uint32_t slot, Dp32Record& r) const;

    // ---- 生产侧的落盘写口 ----
    // 应用内只有这一个写口: 预备点被征召销账 (rho.cpp 的 retire_dp_member)。那是
    // "这一条已经用过了": 先 drf_append 再 src_tombstone, 两笔账一起记。(离线建库脚本
    // 另算, 不在应用内 —— 应用内没有重建入口, 见下面 validate_dp32_corpus。)
    //
    // 源库立墓碑: 内存位图标死 + 文件里那条的 (m, n) 原地清零。**槽位与 index 都
    // 不动**, 所以源库依然按索引升序 (槽位 = 下标这条捷径不破)。已经是墓碑的槽位
    // 直接返回 false, 不重写文件。
    bool src_tombstone(uint32_t slot);
    // 追加到已征召库: 文件尾写一条 + 头里的 records 同步更新 + 索引入桶。
    // 同一个 index 可以有多条 (不同点), 桶里就是一个列表。
    bool drf_append(uint64_t index, const unsigned char* m, const unsigned char* n);
    // 3 类货源的按槽位取点: 从 cursor (源库槽位号) 起找下一条活记录, 墓碑跳过, 读到
    // r 并把 cursor 推到该槽位之后。取完 (或库没载入) 返回 false。
    // 槽位只增不减、墓碑不移位, 所以同一个持久游标在任何时刻都指同一条记录。
    bool src_next(uint32_t& cursor, Dp32Record& r) const;

    const std::string& src_path() const { return m_src_path; }
    const std::string& drf_path() const { return m_drf_path; }

private:
    bool load_impl();

    std::vector<uint64_t> m_src_keys;   // 升序, 槽位 = 下标
    std::vector<uint64_t> m_src_dead;   // 墓碑位图: 每 64 条一个 uint64_t
    std::unordered_map<uint64_t, std::vector<uint32_t>> m_drf;
    uint64_t m_src_dead_n = 0;
    uint64_t m_drf_count = 0;
    std::string m_src_path;
    std::string m_drf_path;
    bool m_loaded = false;
};

// 全局唯一实例, 以及幂等载入。漫步热路径用它查。
//
// 载入结果只说给控制台听 (走 cprint, 见上): 每次启动都有的例行一行, 留在生产日志
// D:\iLog.txt 里没有价值 (库里有几条, 看那两个 .bin 的大小即可)。
// 载入**失败**是异常, 除控制台外还会记进生产日志。载入是幂等的, 最多印一次。
Dp32Store& dp32_store();
bool dp32_store_init();

// 32 位判据: x 低 32 位全 0 时回填 index = x 的 bit 32..95 并返回 true (定义在
// blockchain.cpp)。3 类货源从源库取出记录后用它复核"这条记录确实是 32 位 DP"。
bool dp32_test(const secp256k1_pubkey& pk, uint64_t& index);

// 自测: 合成库的载入/查找/墓碑/同索引多桶 + 6 个坏库用例 + 真库抽样复算。
// 定义在 blockchain.cpp (要对 x 全值复算, 需要 create)。由 validate_test() 调。
void validate_dp32_store();

// 自测: 库与 data 语料对账。语料侧的读法/抽样/报告两种口径完全一样, 只有"库侧怎么
// 查"不同 —— 所以下面这个目标只是库侧口径的开关:
//   TwoLib: 源库 + 已征召库。条数口径 (源库活记录) + (已征召库条数) == 语料去重后的
//           条目数; 语料里的 40 位点必定在已征召库, 其余点 = 源库一条活记录, 或者
//           已被征召销账立了墓碑 (那时已征召库里必有同一条)。
//   AllLib: 全量库 DpSource32all.bin。一个库装完语料里全部去重后的 32 位 DP (含 40 位
//           那批, 无墓碑) ⇒ 条数口径就是 库条数 == 语料去重后的条目数。
// 两种口径都每个语料文件均分抽 8 条现算 x 定位 (索引 + m/n 逐字节对), 并额外从 40 位
// 索引里挑 8 个靶子单独扫一遍, 保证"40 位那批"这条路径一定被走过。定义在 blockchain.cpp,
// 由 validate_test() 调 (默认 TwoLib), 也可用 testmvp 120 889 (TwoLib) /
// testmvp 120 888 (AllLib) 单独触发。
enum class Dp32CorpusTarget { TwoLib, AllLib };
void validate_dp32_corpus(Dp32CorpusTarget target = Dp32CorpusTarget::TwoLib);

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
// 每个 walker 走恰好一步, 语义与 blockchain.cpp 的 rho_F 一致。
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
