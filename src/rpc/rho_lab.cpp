// rho_lab.cpp
//
// 实验田: 带玩乐性质、用来"试试看能不能更快"的碰撞加速点子都先在这里落地。
//
// 与 rho.cpp 的分工:
//   - rho.cpp  是生产/自检代码 (仿射点加、批量求逆、预备队账本...), 动它要谨慎;
//   - 本文件放宽标准: 玩法、试验、半成品都可以先扔进来, 跑得通、看得出收益再考虑
//     往生产路径 (rho.cpp / cuda.cu / blockchain.cpp) 搬。
//
// 约定:
//   - 一律只读现有状态, 不改生产存档 (D:\Rho*.bin / RhoReserve.txt 等), 不启动
//     play、不动设备内存, 除非某个试验确实需要并单独说明。
//   - 对外入口在 rpc/common.h 里声明, 由 perf_test() / validate_test() 或命令行
//     分支调用。
//   - 借用 libsecp256k1 内部 5x52 域实现的手法与 rho.cpp 完全一致 (见那边的长注释);
//     需要时直接从 rho.cpp 复制那段包含顺序处理, 不要另起炉灶。
#include "common.h"

#include <cctype>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <fstream>
#include <iostream>
#include <string>
#include <vector>

// ---------------------------------------------------------------------------
// 试验区
//
// 新点子往这下面加。一个试验大致长这样:
//   1) 在本文件里写实现 (static / 匿名 namespace 收起来, 免得撞别的翻译单元);
//   2) 需要被外面调到时, 在 common.h 的 "实验田 (rho_lab.cpp)" 一节加声明;
//   3) 挂到 perf_test() / validate_test() 或命令行分支上跑。
// ---------------------------------------------------------------------------

// ===========================================================================
// 试验 1: kg40 —— 沿 k·G 固定加数链路扫 40 位可分点 (主机侧)
//
// 目标: 枚举 k = 1, 2, 3, ... , 把 x(k·G) 低 40 位全 0 的"可分点"连同它的 k
// 记下来 (DP 定义与生产一致, 即 cuda.cu 的 distinguishable: 低 40 位为 0, 索引
// = 第 40..103 位)。设备侧在 rpc/cuda_lab.cu 的 kg40_play(): 每个 walker 走的
// 是一条等差子链 (固定加数 = 步长点), 合起来不重不漏地覆盖一段连续的 k。
//
// 本文件只管四件纯主机的事, 不碰设备:
//   1) 起点描述串的解析与 P0 = a·MVP + b·G 的构造;
//   2) 起点 -> 文件名 的映射 (不同起点落不同文件);
//   3) 段首点 (每个 block 一段) 的构造, 给设备侧的串行建链当种子;
//   4) 断点游标 (k) 的读写 + DP 记录 ("<k> <索引>" 每行一条) 的追加落盘。
//
// 起点写法 ("起点"决定从哪个点开始数, 记下来的 k 始终是"从起点往后数了几个 G"):
//   0            P0 = 无穷远点 (= 0·G), 等价于从 1·G 开始
//   1mvp         P0 = 1·MVP
//   <a>mvp       P0 = a·MVP          (a 可省略 = 1)
//   <b>g         P0 = b·G
//   <a>mvp+<b>g  P0 = a·MVP + b·G    (b 后面的 g 可省略)
// 大小写不敏感。第 m 个点 (m >= 1) 是 P0 + m·G, 记下来的 k 就是 m。
// 于是: "0" 的第一个被检点是 1·G (k=1); "7g" 的 P0 = 7·G, 第一个被检点是 8·G,
// k 记 8 —— k 一律是"从 P0 起又加了几个 G", 不含起点本身的偏移。
// ===========================================================================

// pk_mvp 定义在 rpc/blockchain.cpp (生产里原本是 static, 为让实验田能拿 MVP 的
// 倍数点已去掉 static)。这里只读。
extern secp256k1_pubkey pk_mvp;
// 全局上下文 (blockchain.cpp 的 INIT 里创建), 点运算都要用它。
extern secp256k1_context* ctx;

namespace {

// uint64 写进 32 字节大端 (libsecp256k1 的标量入参格式)
void be32(unsigned char out[32], uint64_t v)
{
    std::memset(out, 0, 32);
    for (int i = 0; i < 8; ++i) {
        out[31 - i] = (unsigned char)((v >> (8 * i)) & 0xFFu);
    }
}

// 十进制无符号解析: 整串必须都是数字, 溢出算失败
bool parse_dec(const std::string& s, uint64_t& v)
{
    if (s.empty() || s.size() > 20) return false;
    uint64_t r = 0;
    for (const char c : s) {
        if (c < '0' || c > '9') return false;
        const uint64_t d = (uint64_t)(c - '0');
        if (r > (UINT64_MAX - d) / 10u) return false;
        r = r * 10u + d;
    }
    v = r;
    return true;
}

std::string lower(std::string s)
{
    for (char& c : s) c = (char)std::tolower((unsigned char)c);
    return s;
}

// 系数: 空串 = 1 ("mvp" 就是 "1mvp")
bool parse_coef(const std::string& s, uint64_t& v)
{
    if (s.empty()) {
        v = 1;
        return true;
    }
    return parse_dec(s, v);
}

// secp256k1_pubkey -> 65 字节非压缩编码。注意 libsecp256k1 的 pubkey.data 本来就是
// x||y 的大端 64 字节 (bc 的 create/check 直接 memcmp 前 32 字节比 x 就是这个原因),
// 所以不用走 secp256k1_ec_pubkey_serialize。
void start_from_pub(const secp256k1_pubkey& pk, Kg40Start& out)
{
    out.ser[0] = 0x04;
    std::memcpy(out.ser + 1, pk.data, 32);
    std::memcpy(out.ser + 33, pk.data + 32, 32);
    out.infinity = false;
}

// 起点 -> 文件名里能用的短标签 ("+" 换成 "_")
std::string file_tag(uint64_t a_mvp, uint64_t b_g)
{
    std::string t = kg40_spec_tag(a_mvp, b_g);
    for (char& c : t) {
        if (c == '+') c = '_';
    }
    return t;
}

} // namespace

bool kg40_parse_spec(const std::string& spec, uint64_t& a_mvp, uint64_t& b_g)
{
    a_mvp = 0;
    b_g = 0;
    const std::string s = lower(spec);
    if (s.empty() || s == "0") return true;

    const size_t plus = s.find('+');
    if (plus != std::string::npos && s.find('+', plus + 1) != std::string::npos) return false;
    std::string left = (plus == std::string::npos) ? s : s.substr(0, plus);
    std::string right = (plus == std::string::npos) ? std::string() : s.substr(plus + 1);

    // 右半: 有 '+' 就必须是 <b>g
    if (plus != std::string::npos) {
        if (right.empty() || right.back() != 'g') return false;
        right.pop_back();
        uint64_t v = 0;
        if (!parse_coef(right, v)) return false;
        b_g = v;
    }

    // 左半: <a>mvp / <b>g / 空 (= 0)
    if (left.empty()) return true;
    if (left.size() >= 3 && left.compare(left.size() - 3, 3, "mvp") == 0) {
        left.resize(left.size() - 3);
        uint64_t v = 0;
        if (!parse_coef(left, v)) return false;
        a_mvp = v;
        return true;
    }
    if (left.back() == 'g') {
        if (plus != std::string::npos) return false; // "1g+2g" 说不清
        left.pop_back();
        uint64_t v = 0;
        if (!parse_coef(left, v)) return false;
        b_g = v;
        return true;
    }
    return false; // 光秃秃的数字 (除 "0" 外) 说不清是 mvp 还是 g
}

std::string kg40_spec_tag(uint64_t a_mvp, uint64_t b_g)
{
    if (a_mvp == 0 && b_g == 0) return "0";
    std::string t;
    if (a_mvp != 0) t = std::to_string(a_mvp) + "mvp";
    if (b_g != 0) {
        if (!t.empty()) t += "+";
        t += std::to_string(b_g) + "g";
    }
    return t;
}

std::string kg40_dp_file(uint64_t a_mvp, uint64_t b_g)
{
    return "D:\\Kg40_" + file_tag(a_mvp, b_g) + ".txt";
}

std::string kg40_state_file(uint64_t a_mvp, uint64_t b_g)
{
    return "D:\\Kg40_" + file_tag(a_mvp, b_g) + ".state";
}

bool kg40_make_start(uint64_t a_mvp, uint64_t b_g, Kg40Start& out)
{
    out = Kg40Start();
    if (a_mvp == 0 && b_g == 0) {
        out.infinity = true; // 0·G = 无穷远点: 设备侧从 1·G 开始数的语义靠 m>=1 保证
        return true;
    }
    secp256k1_pubkey pk;
    if (a_mvp == 0) {
        // P0 = b·G。用标量 b 直接生成: 注意**不能**先拿 G 再 tweak_add(b),
        // 那是 1·G + b·G = (b+1)·G, 会把 k 整体错开一位。
        unsigned char s[32];
        be32(s, b_g);
        if (!secp256k1_ec_pubkey_create(ctx, &pk, s)) return false;
    } else {
        pk = pk_mvp;
        if (a_mvp != 1) {
            unsigned char s[32];
            be32(s, a_mvp);
            if (!secp256k1_ec_pubkey_tweak_mul(ctx, &pk, s)) return false; // a 倍 (a 超出群阶会失败)
        }
        if (b_g != 0) {
            unsigned char s[32];
            be32(s, b_g);
            if (!secp256k1_ec_pubkey_tweak_add(ctx, &pk, s)) return false; // + b·G
        }
    }
    start_from_pub(pk, out);
    return true;
}

bool kg40_build_bases(const Kg40Start& p0, uint64_t cursor, uint64_t walkers_per_row,
                      int rows, std::vector<Kg40Start>& out)
{
    if (rows <= 0 || walkers_per_row == 0) return false;
    if (cursor >= (1ULL << 62)) return false; // 免得下面加法绕回

    out.assign((size_t)rows, Kg40Start());
    for (int row = 0; row < rows; ++row) {
        // 第 row 行的第 0 个 walker 对应 m = cursor + row·walkers_per_row + 1 (m>=1 恒成立)
        const uint64_t m = cursor + (uint64_t)row * walkers_per_row + 1;
        unsigned char s[32];
        be32(s, m);
        secp256k1_pubkey pk;
        if (p0.infinity) {
            // P0 = ∞, P0 + m·G = m·G
            if (!secp256k1_ec_pubkey_create(ctx, &pk, s)) return false;
        } else {
            if (!secp256k1_ec_pubkey_parse(ctx, &pk, p0.ser, sizeof(p0.ser))) return false;
            if (!secp256k1_ec_pubkey_tweak_add(ctx, &pk, s)) return false;
        }
        start_from_pub(pk, out[(size_t)row]);
    }
    return true;
}

uint64_t kg40_load_cursor(const std::string& file)
{
    std::ifstream ifs(file);
    if (!ifs) return 0;
    std::string line;
    while (std::getline(ifs, line)) {
        if (line.empty()) continue;
        size_t b = 0;
        while (b < line.size() && std::isspace((unsigned char)line[b])) ++b;
        if (b >= line.size() || line[b] == '#') continue;
        size_t e = b;
        while (e < line.size() && !std::isspace((unsigned char)line[e])) ++e;
        uint64_t v = 0;
        if (parse_dec(line.substr(b, e - b), v)) return v;
        return 0; // 有行不是注释又不是数字: 当成没读过
    }
    return 0;
}

bool kg40_save_cursor(const std::string& file, uint64_t cursor)
{
    std::ofstream ofs(file, std::ios::trunc);
    if (!ofs) return false;
    ofs << "# kg40 断点: 已覆盖的 k 上界 (下一轮从 cursor+1·G 起)\n" << cursor << "\n";
    ofs.flush();
    return (bool)ofs;
}

bool kg40_append_dps(const std::string& file, uint64_t a_mvp, uint64_t b_g,
                     const std::vector<uint64_t>& ks, const std::vector<uint64_t>& idxs)
{
    if (ks.empty()) return true;
    if (ks.size() != idxs.size()) return false;

    bool need_header = true;
    {
        std::ifstream probe(file, std::ios::ate);
        if (probe) need_header = (probe.tellg() <= 0);
    }
    std::ofstream ofs(file, std::ios::app);
    if (!ofs) return false;
    if (need_header) {
        ofs << "# kg40 起点 P0 = " << kg40_spec_tag(a_mvp, b_g) << " (0 = 无穷远)\n"
            << "# 每行: <k> <索引>  => x(P0 + k*G) 低 40 位为 0, 索引 = 第 40..103 位\n";
    }
    for (size_t i = 0; i < ks.size(); ++i) {
        ofs << ks[i] << ' ' << idxs[i] << '\n';
    }
    ofs.flush();
    return (bool)ofs;
}
