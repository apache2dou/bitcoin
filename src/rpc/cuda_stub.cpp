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
