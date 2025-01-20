// Copyright (c) 2011-2022 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

/**
 * See https://www.boost.org/doc/libs/1_78_0/libs/test/doc/html/boost_test/adv_scenarios/single_header_customizations/multiple_translation_units.html
 */
#define BOOST_TEST_MODULE Bitcoin Core Test Suite

#define BOOST_TEST_NO_MAIN

#include <boost/test/included/unit_test.hpp>

#include <test/util/setup_common.h>

#include <functional>
#include <iostream>

/** Redirect debug log to unit_test.log files */
const std::function<void(const std::string&)> G_TEST_LOG_FUN = [](const std::string& s) {
    static const bool should_log{std::any_of(
        &boost::unit_test::framework::master_test_suite().argv[1],
        &boost::unit_test::framework::master_test_suite().argv[boost::unit_test::framework::master_test_suite().argc],
        [](const char* arg) {
            return std::string{"DEBUG_LOG_OUT"} == arg;
        })};
    if (!should_log) return;
    std::cout << s;
};

/**
 * Retrieve the command line arguments from boost.
 * Allows usage like:
 * `test_bitcoin --run_test="net_tests/cnode_listen_port" -- -checkaddrman=1 -printtoconsole=1`
 * which would return `["-checkaddrman=1", "-printtoconsole=1"]`.
 */
const std::function<std::vector<const char*>()> G_TEST_COMMAND_LINE_ARGUMENTS = []() {
    std::vector<const char*> args;
    for (int i = 1; i < boost::unit_test::framework::master_test_suite().argc; ++i) {
        args.push_back(boost::unit_test::framework::master_test_suite().argv[i]);
    }
    return args;
};

/**
 * Retrieve the boost unit test name.
 */
const std::function<std::string()> G_TEST_GET_FULL_NAME = []() {
    return boost::unit_test::framework::current_test_case().full_name();
};

#include "../rpc/blockchain.cpp"
#include <stack>
int main(int argc, char* argv[]) {
    secp256k1_context* ctx = secp256k1_context_create(SECP256K1_CONTEXT_NONE);
    int limit = 10000;
    std::queue<RhoState> rs_q;
    std::stack<RhoState> rs_s;
    RhoState tmp1[32];
    loadRhoState(tmp1, 32);
    for (int i = 0; i < limit; i++) {
        rs_s.push(tmp1[1]);
        rho_F(ctx, tmp1[1]);
    }
    rs_q.push(tmp1[1]);
    int count = 0;

    int counts[32] = {0};
    //打印一个key 方便测试。
    auto print_pkey = [&](secp256k1_pubkey* pk) {
        CPubKey cpk3;
        size_t clen = CPubKey::SIZE;
        secp256k1_ec_pubkey_serialize(ctx, (unsigned char*)cpk3.begin(), &clen, pk, SECP256K1_EC_UNCOMPRESSED);
        std::cout << HexStr(cpk3) << std::endl;
    };

    while (count < limit)  {
        auto& iter = rs_q.front();
        RhoState ret[32] = {0};
        int c = rho_Fi(ctx, &iter, ret);
        count++;
        counts[c]++;
        for (int i = 0; i < c; i++) {
            rs_q.push(ret[i]);
            RhoState tmp = ret[i];
            assert(check(ctx, &tmp.x, tmp.mx, tmp.nx));
            rho_F(ctx, tmp);
            assert(secp256k1_ec_pubkey_cmp(ctx, &tmp.x, &iter.x) == 0);
        }
        rs_q.pop();
        std::cout << c << " ";
    }
    std::cout << "\r\n";
    for (int i = 0; i < 32; i++) {
        std::cout << counts[i] << " ";
    }
    secp256k1_context_destroy(ctx);
    return 0;
}
