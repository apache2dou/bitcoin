#include "common.h"

#include <stdexcept>

void break_rho(bool)
{
}

void rho_play()
{
}

void validate_test()
{
    throw std::runtime_error("CUDA support is not enabled in this build.");
}

void perf_test()
{
    throw std::runtime_error("CUDA support is not enabled in this build.");
}

void perf_test_rho_gpu_walkers()
{
    throw std::runtime_error("CUDA support is not enabled in this build.");
}

// 预备队的上传端. 这条路径只由 rho_play 走到, 而非 CUDA 构建里 rho_play 是空函数,
// 所以这里只求"能链接上" (rho.cpp 无条件编译并引用它)。
void upload_RhoStates_reserve(const RhoPoint*, size_t)
{
    throw std::runtime_error("CUDA support is not enabled in this build.");
}

// 被征召点重走探针 (testmvp 120 892). 它要用设备侧的步进表 adds_pub_dev 与
// fun_add_w, 非 CUDA 构建里没有, 所以直接报错。
void rho_rewalk_probe()
{
    throw std::runtime_error("CUDA support is not enabled in this build.");
}
