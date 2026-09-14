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
// 定义在 rpc/rho.cpp: libsecp256k1 版本的点加性能测试, 由 perf_test() 调用
void perf_test_libsecp256k1();
// 定义在 rpc/rho.cpp: 直接用 libsecp256k1 内部 5x52 域实现的仿射点加性能测试
void perf_test_rho_affine();
// 定义在 rpc/rho.cpp: 仿射点加的正确性验证 (与库公开 API 逐步对拍), 由 validate_test() 调用
void validate_rho_affine();
// 定义在 rpc/rho.cpp: 仿射点加 (libsecp256k1 内部 5x52 域) 的初始化,
// 必须在启动 worker 线程之前调用一次
void rho_affine_prepare();
// 定义在 rpc/rho.cpp: 仿射点加版 rho_F (语义与 rho_F 一致), 供 class Rho 使用
void rho_affine_F(RhoState& rs);
#endif // BITCOIN_RPC_COMMON_H
