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

void test()
{
    int limit = 10000;
    std::queue<RhoState> rs_q;

    RhoState tmp_origin;
    tmp_origin.rand();
    rho_F(ctx, tmp_origin);

    int count = 0;

    int counts[32] = {0};
    // 打印一个key 方便测试。
    auto print_pkey = [&](secp256k1_pubkey* pk) {
        CPubKey cpk3;
        size_t clen = CPubKey::SIZE;
        secp256k1_ec_pubkey_serialize(ctx, (unsigned char*)cpk3.begin(), &clen, pk, SECP256K1_EC_UNCOMPRESSED);
        std::cout << HexStr(cpk3) << std::endl;
    };

    while (count < limit) {
        tmp_origin.rand();
        // rho_F(ctx, tmp_origin);
        RhoState ret[32] = {0};
        int c = rho_Fi(ctx, &tmp_origin, ret);
        count++;
        counts[c]++;
        for (int i = 0; i < c; i++) {
            RhoState tmp = ret[i];
            assert(check(ctx, &tmp.x, tmp.m, tmp.n));
            rho_F(ctx, tmp);
            assert(secp256k1_ec_pubkey_cmp(ctx, &tmp.x, &tmp_origin.x) == 0);
        }
        std::cout << c << " ";
    }
    std::cout << "\r\n";
    for (int i = 0; i < 32; i++) {
        std::cout << counts[i] << " ";
    }
}

#include <csignal>
// 信号处理函数
void signalHandler(int signum)
{
    std::cout << "Interrupt signal (" << signum << ") received." << std::endl;
    // 在这里可以添加程序退出前的清理代码
    // 例如关闭文件、释放资源等
    gameover = true;
}
void work() {
    // 注册信号处理函数，捕获 SIGINT 信号
    signal(SIGINT, signalHandler);
    std::cout << "game starting..." << std::endl;
    play<Rho>();
}


//=======>>>>>>>>>>>>>
#pragma comment(lib, "..\\..\\..\\build\\vcpkg_installed\\x64-windows\\lib\\libcrypto.lib")
#pragma comment(lib, "..\\..\\..\\build\\vcpkg_installed\\x64-windows\\lib\\libssl.lib")

#include <openssl/ec.h>
#include <openssl/obj_mac.h>
#include <openssl/bn.h>
#include <vector>

// 算法参数配置
constexpr int r = 16;
constexpr char STEP_FILE[] = "precomputed_steps.bin";
constexpr char SAVE_FILE[] = "rho_distinguishpoints.bin";
constexpr char KEY_FILE[] = "ec_keypair.txt";
constexpr char LOG_FILE[] = "pollard_rho.log";

class Logger
{
public:
    static void init()
    {
        log_file.open(LOG_FILE, std::ios::app);
        if (!log_file.is_open()) {
            std::cerr << "Failed to open log file\n";
        }
        log("========== New Session ==========");
    }

    static void log(const std::string& message)
    {
        const auto now = std::time(nullptr);
        char timestamp[64];
        std::strftime(timestamp, sizeof(timestamp), "[%Y-%m-%d %H:%M:%S] ", std::localtime(&now));

        const std::string log_entry = timestamp + message + "\n";

        // 输出到控制台
        std::cout << log_entry;

        // 写入日志文件
        if (log_file.is_open()) {
            log_file << log_entry;
            //log_file.flush();
        }
    }

    static void cleanup()
    {
        if (log_file.is_open()) {
            log_file.close();
        }
    }

private:
    static std::ofstream log_file;
};
std::ofstream Logger::log_file;

// 椭圆曲线上下文管理
struct CurveContext {
    EC_GROUP* group;
    BIGNUM* order;
    BN_CTX* bn_ctx;
    const EC_POINT* Q; // 目标公钥

    CurveContext(int nid = NID_secp112r1) : order(BN_new()),
                                            bn_ctx(BN_CTX_new()),
                                            Q(nullptr)
    {
        if (nid != 0) {
            group = EC_GROUP_new_by_curve_name(nid);
            EC_GROUP_get_order(group, order, bn_ctx);                                            
        } else {
            const char* p_hex = "800000000000001d";
            const char* a_hex = "1";
            const char* b_hex = "23";
            const char* n_hex = "80000000b60d4577";
            const char* gx_hex = "30d739f3e0467dd";
            const char* gy_hex = "6993cc78c1d6fa3";
            const char* h_hex = "1";

            EC_POINT* G = NULL;
            BIGNUM *p = BN_new(), *a = BN_new(), *b = BN_new();
            BIGNUM *n = BN_new(), *h = BN_new(), *gx = BN_new(), *gy = BN_new();

            // 设置示例参数（16 进制）
            BN_hex2bn(&p, p_hex);
            BN_hex2bn(&a, a_hex);
            BN_hex2bn(&b, b_hex);
            BN_hex2bn(&n, n_hex);
            BN_hex2bn(&h, h_hex);
            BN_hex2bn(&gx, gx_hex);
            BN_hex2bn(&gy, gy_hex);
            // 创建椭圆曲线群
            group = EC_GROUP_new_curve_GFp(p, a, b, NULL);
            if (!group) goto err;
            // 创建生成点 G
            G = EC_POINT_new(group);
            EC_POINT_set_affine_coordinates(group, G, gx, gy, NULL);
            // 设置群的生成点、阶数和余因子
            EC_GROUP_set_generator(group, G, n, h);

            EC_GROUP_get_order(group, order, bn_ctx);    
        err:
            BN_free(p);
            BN_free(a);
            BN_free(b);
            BN_free(n);
            BN_free(h);
            BN_free(gx);
            BN_free(gy);
            if (G != NULL) EC_POINT_free(G);
        }
    }

    ~CurveContext()
    {
        EC_GROUP_free(group);
        BN_free(order);
        BN_CTX_free(bn_ctx);
        if (Q) EC_POINT_free(const_cast<EC_POINT*>(Q));
    }

    void set_target(const EC_POINT* target)
    {
        Q = EC_POINT_dup(target, group);
    }
    // 新增密钥管理方法
    bool load_keypair(BIGNUM** priv_key, EC_POINT** pub_key)
    {
        std::ifstream file(KEY_FILE);
        if (!file.is_open()) return false;

        std::string line;

        try {
            // 解析私钥
            std::getline(file, line);
            BN_hex2bn(priv_key, line.c_str());

            // 解析公钥坐标
            BIGNUM* x = BN_new();
            BIGNUM* y = BN_new();
            std::getline(file, line);
            BN_hex2bn(&x, line.c_str());
            std::getline(file, line);
            BN_hex2bn(&y, line.c_str());

            // 创建公钥点
            *pub_key = EC_POINT_new(group);
            EC_POINT_set_affine_coordinates(group, *pub_key, x, y, bn_ctx);

            // 验证点是否在曲线上
            if (!EC_POINT_is_on_curve(group, *pub_key, bn_ctx)) {
                EC_POINT_free(*pub_key);
                BN_free(x);
                BN_free(y);
                return false;
            }

            BN_free(x);
            BN_free(y);
            return true;
        } catch (...) {
            return false;
        }
    }

    void generate_and_save_keypair(BIGNUM** priv_key, EC_POINT** pub_key)
    {
        // 生成新密钥对
        *priv_key = BN_new();
        BN_rand_range(*priv_key, order);

        *pub_key = EC_POINT_new(group);
        EC_POINT_mul(group, *pub_key, *priv_key, nullptr, nullptr, bn_ctx);

        // 保存到文件
        std::ofstream file(KEY_FILE);
        if (file.is_open()) {
            // 写入私钥
            char* priv_hex = BN_bn2hex(*priv_key);
            file << priv_hex << "\n";
            OPENSSL_free(priv_hex);

            // 写入公钥坐标
            BIGNUM *x = BN_new(), *y = BN_new();
            EC_POINT_get_affine_coordinates(group, *pub_key, x, y, bn_ctx);

            char* x_hex = BN_bn2hex(x);
            char* y_hex = BN_bn2hex(y);
            file << x_hex << "\n";
            file << y_hex << "\n";

            OPENSSL_free(x_hex);
            OPENSSL_free(y_hex);
            BN_free(x);
            BN_free(y);

            std::cout << "New keypair generated and saved to " << KEY_FILE << "\n";
        } else {
            std::cerr << "Warning: Failed to save keypair to file\n";
        }
    }
};

// 预计算步长结构
struct PrecomputedStep {
    EC_POINT* point;
    BIGNUM* s;
    BIGNUM* t;

    PrecomputedStep(const CurveContext& ctx) : point(EC_POINT_new(ctx.group)),
                                               s(BN_new()),
                                               t(BN_new())
    {
        BN_rand_range(s, ctx.order);
        BN_rand_range(t, ctx.order);
        EC_POINT_mul(ctx.group, point, s, ctx.Q, t, ctx.bn_ctx);
    }

    ~PrecomputedStep()
    {
        EC_POINT_free(point);
        BN_free(s);
        BN_free(t);
    }

    PrecomputedStep(PrecomputedStep&& other) noexcept : point(other.point),
                                                        s(other.s),
                                                        t(other.t)
    {
        other.point = nullptr;
        other.s = nullptr;
        other.t = nullptr;
    }
    // 从文件加载构造
    PrecomputedStep(const CurveContext& ctx, std::istream& is) : point(EC_POINT_new(ctx.group)),
                                                                 s(BN_new()),
                                                                 t(BN_new())
    {
        // 读取s值
        size_t s_len;
        is.read(reinterpret_cast<char*>(&s_len), sizeof(s_len));
        std::vector<unsigned char> s_buf(s_len);
        is.read(reinterpret_cast<char*>(s_buf.data()), s_len);
        BN_bin2bn(s_buf.data(), s_len, s);

        // 读取t值
        size_t t_len;
        is.read(reinterpret_cast<char*>(&t_len), sizeof(t_len));
        std::vector<unsigned char> t_buf(t_len);
        is.read(reinterpret_cast<char*>(t_buf.data()), t_len);
        BN_bin2bn(t_buf.data(), t_len, t);

        // 读取点数据
        size_t point_len;
        is.read(reinterpret_cast<char*>(&point_len), sizeof(point_len));
        std::vector<unsigned char> point_buf(point_len);
        is.read(reinterpret_cast<char*>(point_buf.data()), point_len);
        EC_POINT_oct2point(ctx.group, point, point_buf.data(), point_len, ctx.bn_ctx);
    }

    void save(const CurveContext& ctx, std::ostream& os) const
    {
        // 保存s值
        const size_t s_len = BN_num_bytes(s);
        std::vector<unsigned char> s_buf(s_len);
        BN_bn2bin(s, s_buf.data());
        os.write(reinterpret_cast<const char*>(&s_len), sizeof(s_len));
        os.write(reinterpret_cast<const char*>(s_buf.data()), s_len);

        // 保存t值
        const size_t t_len = BN_num_bytes(t);
        std::vector<unsigned char> t_buf(t_len);
        BN_bn2bin(t, t_buf.data());
        os.write(reinterpret_cast<const char*>(&t_len), sizeof(t_len));
        os.write(reinterpret_cast<const char*>(t_buf.data()), t_len);

        // 保存点数据
        const size_t point_len = EC_POINT_point2oct(ctx.group, point,
                                                    POINT_CONVERSION_COMPRESSED, nullptr, 0, ctx.bn_ctx);
        std::vector<unsigned char> point_buf(point_len);
        EC_POINT_point2oct(ctx.group, point, POINT_CONVERSION_COMPRESSED,
                           point_buf.data(), point_len, ctx.bn_ctx);
        os.write(reinterpret_cast<const char*>(&point_len), sizeof(point_len));
        os.write(reinterpret_cast<const char*>(point_buf.data()), point_len);
    }
};
// 可区分点管理
struct DistinguishedPoint {
    BIGNUM* a;
    BIGNUM* b;
    uint64_t step;

    DistinguishedPoint(BIGNUM* a_val, BIGNUM* b_val, uint64_t s) : a(BN_dup(a_val)),
                                                                   b(BN_dup(b_val)),
                                                                   step(s) {}

    DistinguishedPoint(DistinguishedPoint&& other) noexcept : a(other.a),
                                                              b(other.b),
                                                              step(other.step)
    {
        other.a = nullptr;
        other.b = nullptr;
    }

    ~DistinguishedPoint()
    {
        if (a) BN_free(a);
        if (b) BN_free(b);
    }
};

class PollardSolver
{
public:
    PollardSolver(std::shared_ptr<CurveContext> ctx) : ctx_(ctx),
                                                       current_(EC_POINT_new(ctx_->group)),
                                                       a_(BN_new()),
                                                       b_(BN_new()),
                                                       step_count_(0)
    {
        // 初始化随机起点
        BN_rand_range(a_, ctx_->order);
        BN_rand_range(b_, ctx_->order);
        EC_POINT_mul(ctx_->group, current_, a_, ctx_->Q, b_, ctx_->bn_ctx);

        // 尝试加载预计算步长
        if (!load_precomputed_steps()) {
            generate_precomputed_steps();
            save_precomputed_steps();
        }
    }

    BIGNUM* solve()
    {
        BIGNUM* ret = nullptr;
        while (ret == nullptr) {
            ++step_count_;
            ret = process_distinguished_point();
            walk_step();
        }
        save_progress();
        return ret;
    }

    // 设置起始点函数
    void set_initial(const BIGNUM* a, const BIGNUM* b)
    {
        // 复制并规范化输入参数
        BN_mod(a_, a, ctx_->order, ctx_->bn_ctx);
        BN_mod(b_, b, ctx_->order, ctx_->bn_ctx);

        // 重新计算当前点
        EC_POINT_mul(ctx_->group, current_, a_, ctx_->Q, b_, ctx_->bn_ctx);

        // 重置步数计数器
        step_count_ = 0;

        // 记录日志
        std::stringstream ss;
        char* a_hex = BN_bn2hex(a_);
        char* b_hex = BN_bn2hex(b_);
        ss << "Set initial point - a: 0x" << a_hex << ", b: 0x" << b_hex;
        Logger::log(ss.str());

        // 打印初始点坐标
        BIGNUM *x = BN_new(), *y = BN_new();
        EC_POINT_get_affine_coordinates(ctx_->group, current_, x, y, ctx_->bn_ctx);
        char* x_hex = BN_bn2hex(x);
        char* y_hex = BN_bn2hex(y);
        Logger::log("Initial point coordinates (x, y):\n"
                    "X: 0x" +
                    std::string(x_hex) + "\n" +
                    "Y: 0x" + std::string(y_hex));

        OPENSSL_free(a_hex);
        OPENSSL_free(b_hex);
        OPENSSL_free(x_hex);
        OPENSSL_free(y_hex);
        BN_free(x);
        BN_free(y);
    }
    //private:
    bool load_precomputed_steps()
    {
        if (!fs::exists(STEP_FILE)) return false;

        try {
            std::ifstream file(STEP_FILE, std::ios::binary);
            if (!file) return false;

            // 验证文件头
            int file_r;
            file.read(reinterpret_cast<char*>(&file_r), sizeof(file_r));
            if (file_r != r) {
                std::cerr << "Invalid step file configuration\n";
                return false;
            }

            steps_.reserve(r);
            for (int i = 0; i < r; ++i) {
                steps_.emplace_back(*ctx_, file);
            }

            std::cout << "Loaded " << r << " precomputed steps from file\n";
            return true;
        } catch (...) {
            std::cerr << "Error loading precomputed steps\n";
            steps_.clear();
            return false;
        }
    }

    void generate_precomputed_steps()
    {
        steps_.clear();
        steps_.reserve(r);
        for (int i = 0; i < r; ++i) {
            steps_.emplace_back(*ctx_);
        }
        std::cout << "Generated new precomputed steps\n";
    }

    void save_precomputed_steps() const
    {
        std::ofstream file(STEP_FILE, std::ios::binary);
        if (!file) {
            std::cerr << "Failed to save precomputed steps\n";
            return;
        }

        // 写入文件头
        file.write(reinterpret_cast<const char*>(&r), sizeof(r));

        // 写入每个步长
        for (const auto& step : steps_) {
            step.save(*ctx_, file);
        }

        std::cout << "Saved " << r << " precomputed steps to file\n";
    }
    BIGNUM* process_distinguished_point()
    {
        BIGNUM* ret = nullptr;
        const auto key = calculate_key(); 
        if (key != INVALID_KEY) {
            if (auto it = points_.find(key); it != points_.end()) {
                ret = handle_collision(it->second);
                assert(ret);
            } else {
                store_point(key);
                if ((key & 0xffffff0000000000) == 0)
                    std::cout << step_count_ << " ";
            }
        }
        return ret;
    }

    uint64_t calculate_key() const
    {
        BIGNUM* x = BN_new();
        EC_POINT_get_affine_coordinates(ctx_->group, current_, x, nullptr, ctx_->bn_ctx);

        unsigned char bin[32];
        const size_t len = BN_bn2bin(x, bin);
        BN_free(x);

        // 检查后2个字节是否为0
        if (len < 4 || *reinterpret_cast<uint16_t*>(bin + 6) != 0) {
            return INVALID_KEY;
        }

        // 提取8字节作为键
        uint64_t key = *reinterpret_cast<uint64_t*>(bin);
        return key;
    }

    BIGNUM* handle_collision(const DistinguishedPoint& dp)
    {
        const uint64_t tail_length = dp.step;
        const uint64_t cycle_length = step_count_ - dp.step;

        std::stringstream ss;
        ss << "\n=== Cycle Detected ===\n"
           << "Tail length:  " << tail_length << "\n"
           << "Cycle length: " << cycle_length << "\n"
           << "Total steps:  " << step_count_ << "\n"
           << "Storage size: " << points_.size() << "\n"
           << "========================\n";
        Logger::log(ss.str());

        BIGNUM* denominator = BN_new();
        BN_mod_sub(denominator, b_, dp.b, ctx_->order, ctx_->bn_ctx);

        if (!BN_is_zero(denominator)) {
            BIGNUM* d = calculate_private_key(dp, denominator);
            if (validate_key(d)) {
                BN_free(denominator);
                return d; 
            }
            BN_free(d);
        }
        Logger::log("short circulation!");
        BN_free(denominator);
        return nullptr;
    }

    BIGNUM* calculate_private_key(const DistinguishedPoint& dp, BIGNUM* denominator) const
    {
        BIGNUM* numerator = BN_new();
        BN_mod_sub(numerator, dp.a, a_, ctx_->order, ctx_->bn_ctx);

        BIGNUM* inv = BN_new();
        BN_mod_inverse(inv, denominator, ctx_->order, ctx_->bn_ctx);

        BIGNUM* d = BN_new();
        BN_mod_mul(d, numerator, inv, ctx_->order, ctx_->bn_ctx);

        BN_free(numerator);
        BN_free(inv);
        return d;
    }

    bool validate_key(BIGNUM* d) const
    {
        EC_POINT* test = EC_POINT_new(ctx_->group);
        EC_POINT_mul(ctx_->group, test, d, nullptr, nullptr, ctx_->bn_ctx);
        const bool valid = (EC_POINT_cmp(ctx_->group, test, ctx_->Q, ctx_->bn_ctx) == 0);
        EC_POINT_free(test);
        return valid;
    }

    void store_point(uint64_t key)
    {
        points_.emplace(key, DistinguishedPoint(a_, b_, step_count_));
    }

    void walk_step()
    {
        const size_t idx = get_step_index();
        const auto& step = steps_[idx];

        EC_POINT_add(ctx_->group, current_, current_, step.point, ctx_->bn_ctx);
        BN_mod_add(a_, a_, step.s, ctx_->order, ctx_->bn_ctx);
        BN_mod_add(b_, b_, step.t, ctx_->order, ctx_->bn_ctx);
    }

    size_t get_step_index() const
    {
        BIGNUM* x = BN_new();
        EC_POINT_get_affine_coordinates(ctx_->group, current_, x, nullptr, ctx_->bn_ctx);

        unsigned char bin[32];
        BN_bn2bin(x, bin);
        BN_free(x);

        const size_t offset = (BN_num_bytes(x) > 2) ? BN_num_bytes(x) - 2 : 0;
        return *reinterpret_cast<uint16_t*>(bin + offset) % r;
    }

    void save_progress() const
    {
        std::ofstream file(SAVE_FILE, std::ios::binary);
        const uint64_t count = points_.size();

        // 写入记录数量
        file.write(reinterpret_cast<const char*>(&count), sizeof(count));

        // 写入每个记录
        for (const auto& [key, dp] : points_) {
            file.write(reinterpret_cast<const char*>(&key), sizeof(key));
            write_bignum(file, dp.a);
            write_bignum(file, dp.b);
            file.write(reinterpret_cast<const char*>(&dp.step), sizeof(dp.step));
        }

        std::cout << "Progress saved: " << count << " points\n";
    }

    void load_progress()
    {
        std::ifstream file(SAVE_FILE, std::ios::binary);
        if (!file) return;

        uint64_t count;
        file.read(reinterpret_cast<char*>(&count), sizeof(count));

        for (uint64_t i = 0; i < count; ++i) {
            uint64_t key;
            file.read(reinterpret_cast<char*>(&key), sizeof(key));

            BIGNUM* a = read_bignum(file);
            BIGNUM* b = read_bignum(file);

            uint64_t step;
            file.read(reinterpret_cast<char*>(&step), sizeof(step));

            points_.emplace(key, DistinguishedPoint(a, b, step));
            BN_free(a);
            BN_free(b);
        }

        std::cout << "Loaded " << count << " points from disk\n";
    }

    auto lastPoint() {
        auto maxIt = points_.begin();
        auto maxValue = maxIt->second.step;
        for (auto it = std::next(points_.begin()); it != points_.end(); ++it) {
            if (it->second.step > maxValue) {
                maxValue = it->second.step;
                maxIt = it;
            }
        }
        return maxIt;
    }

    static void write_bignum(std::ostream& os, const BIGNUM* num)
    {
        const size_t len = BN_num_bytes(num);
        std::vector<unsigned char> buf(len);
        BN_bn2bin(num, buf.data());

        os.write(reinterpret_cast<const char*>(&len), sizeof(len));
        os.write(reinterpret_cast<const char*>(buf.data()), len);
    }

    static BIGNUM* read_bignum(std::istream& is)
    {
        size_t len;
        is.read(reinterpret_cast<char*>(&len), sizeof(len));

        std::vector<unsigned char> buf(len);
        is.read(reinterpret_cast<char*>(buf.data()), len);

        BIGNUM* num = BN_new();
        BN_bin2bn(buf.data(), len, num);
        return num;
    }

    static constexpr uint64_t INVALID_KEY = UINT64_MAX;

    std::shared_ptr<CurveContext> ctx_;
    std::vector<PrecomputedStep> steps_;
    std::map<uint64_t, DistinguishedPoint> points_;
    EC_POINT* current_;
    BIGNUM* a_;
    BIGNUM* b_;
    uint64_t step_count_;
};



void test_112() {
    try {
        auto ctx = std::make_shared<CurveContext>(0);

        // 生成测试密钥对
        BIGNUM* priv = nullptr;
        EC_POINT* pub = nullptr;
        // 尝试加载现有密钥对
        if (!ctx->load_keypair(&priv, &pub)) {
            // 生成并保存新密钥对
            ctx->generate_and_save_keypair(&priv, &pub);
        }
        ctx->set_target(pub);

        PollardSolver solver(ctx);
        BIGNUM* found = solver.solve();

        // 验证结果
        if (BN_cmp(found, priv) == 0) {
            char* hex = BN_bn2hex(found);
            Logger::log("\nSuccess! Private key: " + std::string(hex));
            OPENSSL_free(hex);
        }

        BN_free(priv);
        EC_POINT_free(pub);
        BN_free(found);
    } catch (...) {
        std::cout << "\nException handling!!!\n";
    }
}

void test_112_helper() {
    auto ctx = std::make_shared<CurveContext>(0);
    PollardSolver solver(ctx);
    solver.load_progress();
    auto last = solver.lastPoint();
    std::cout << last->second.step << std::endl;
}

//========<<<<<<<<<<<<<<
#include <conio.h>
int main(int argc, char* argv[])
{
    /* INIT _init;
    work();*/

    Logger::init();
    test_112();
    Logger::cleanup();

    std::wcout << L"请按任意键结束..." << std::endl;
    _getch(); // 等待用户按下任意键
    return 0;
}
