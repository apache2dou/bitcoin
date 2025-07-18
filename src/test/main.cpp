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
    stop_game();
}
void work() {
    std::cout << "game starting..." << std::endl;
    play<Rho>();
    //play<BabyGiant>();
}

#if 0
//=======>>>>>>>>>>>>>
#pragma comment(lib, "..\\..\\..\\build\\vcpkg_installed\\x64-windows\\lib\\libcrypto.lib")
#pragma comment(lib, "..\\..\\..\\build\\vcpkg_installed\\x64-windows\\lib\\libssl.lib")

#include <openssl/ec.h>
#include <openssl/obj_mac.h>
#include <openssl/bn.h>
#include <vector>

// 算法参数配置
#define FILE_DIR ""
constexpr int r = 32;
constexpr char STEP_FILE[] = FILE_DIR "precomputed_steps.bin";
constexpr char SAVE_FILE[] = FILE_DIR "rho_distinguishpoints_%04d.bin";
constexpr char KEY_FILE[] = FILE_DIR "ec_keypair.txt";
constexpr char LOG_FILE[] = FILE_DIR "pollard_rho.log";
constexpr char ID_FILE[] = FILE_DIR "rho.id";

// ID管理类
enum class IDState { RUNNING,
                     PAUSED,
                     COMPLETED };

class IDManager
{
private:
    std::map<int, IDState> id_states;
    int max_id = 0;
    const std::string filename = ID_FILE;
    mutable std::mutex mtx;

    void update_max_id()
    {
        if (!id_states.empty()) {
            max_id = std::max_element(id_states.begin(), id_states.end(),
                                      [](const auto& a, const auto& b) { return a.first < b.first; })
                         ->first;
        }
    }

public:
    IDManager()
    {
        load_from_file();
    }

    ~IDManager()
    {
        save_to_file();
    }

    // 请求可用ID（优先返回暂停状态的ID）
    virtual int request_id()
    {
        std::lock_guard<std::mutex> lock(mtx);

        // 优先查找暂停状态的ID
        auto paused_it = std::find_if(id_states.begin(), id_states.end(),
                                      [](const auto& p) { return p.second == IDState::PAUSED; });

        if (paused_it != id_states.end()) {
            paused_it->second = IDState::RUNNING;
            return paused_it->first;
        }

        // 生成新ID
        int new_id = ++max_id;
        id_states[new_id] = IDState::RUNNING;
        return new_id;
    }

    // 暂停指定ID的工作
    bool pause_id(int id)
    {
        std::lock_guard<std::mutex> lock(mtx);
        auto it = id_states.find(id);
        if (it != id_states.end() && it->second == IDState::RUNNING) {
            it->second = IDState::PAUSED;
            return true;
        }
        return false;
    }

    // 标记ID为完成状态
    bool complete_id(int id)
    {
        std::lock_guard<std::mutex> lock(mtx);
        auto it = id_states.find(id);
        if (it != id_states.end()) {
            id_states.erase(it);
            return true;
        }
        return false;
    }

    // 获取ID状态
    IDState get_state(int id) const
    {
        std::lock_guard<std::mutex> lock(mtx);
        auto it = id_states.find(id);
        return (it != id_states.end()) ? it->second : IDState::COMPLETED;
    }

private:
    // 持久化到文件
    void save_to_file() const
    {
        std::lock_guard<std::mutex> lock(mtx);
        std::ofstream file(filename);
        if (!file.is_open()) return;

        for (const auto& [id, state] : id_states) {
            file << id << "," << static_cast<int>(state) << "\n";
        }
    }

    // 从文件加载状态
    void load_from_file()
    {
        std::lock_guard<std::mutex> lock(mtx);
        std::ifstream file(filename);
        if (!file.is_open()) return;

        id_states.clear();
        std::string line;
        while (std::getline(file, line)) {
            std::istringstream iss(line);
            std::string id_str, state_str;

            if (std::getline(iss, id_str, ',') &&
                std::getline(iss, state_str)) {
                try {
                    int id = std::stoi(id_str);
                    IDState state = static_cast<IDState>(std::stoi(state_str));

                    if (state != IDState::COMPLETED) {
                        id_states[id] = state;
                        max_id = std::max(max_id, id);
                    }
                } catch (...) {
                    // 忽略格式错误行
                }
            }
        }
    }

    // 获取所有未完成ID列表
    std::vector<int> get_active_ids() const
    {
        std::lock_guard<std::mutex> lock(mtx);
        std::vector<int> ids;
        for (const auto& [id, state] : id_states) {
            ids.push_back(id);
        }
        return ids;
    }
};

class DummyIDManager : public IDManager
{
public:
    int request_id() { return 66; }
    bool pause_id(int id)
    {
        return true;
    }
    bool complete_id(int id) { return true; }

};

class Logger
{
public:
    static void init()
    {
        log_file.open(LOG_FILE, std::ios::app);
        if (!log_file.is_open()) {
            std::cerr << "Failed to open log file\n";
        }
        enable(true);
    }

    static void log(const std::string& message, bool flush = false)
    {
        const auto now = std::time(nullptr);
        char timestamp[64];
        std::strftime(timestamp, sizeof(timestamp), "[%Y-%m-%d %H:%M:%S] ", std::localtime(&now));

        const std::string log_entry = timestamp + message + "\n";

        // 输出到控制台
        std::cout << log_entry;

        // 写入日志文件
        if (log_file.is_open() && enable_) {
            log_file << log_entry;
            if (flush)
                log_file.flush();
        }
    }

    static void cleanup()
    {
        if (log_file.is_open()) {
            log_file.close();
        }
    }
    static void enable(bool e) {
        enable_ = e;
    }

private:
    static bool enable_;
    static std::ofstream log_file;
};
bool Logger::enable_;
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
    EC_POINT* inverse_point; // 逆步长点

    PrecomputedStep(const CurveContext& ctx) : point(EC_POINT_new(ctx.group)),
                                               inverse_point(EC_POINT_new(ctx.group)),
                                               s(BN_new()),
                                               t(BN_new())
    {
        BN_rand_range(s, ctx.order);
        BN_rand_range(t, ctx.order);
        EC_POINT_mul(ctx.group, point, s, ctx.Q, t, ctx.bn_ctx);
        EC_POINT_copy(inverse_point, point);
        EC_POINT_invert(ctx.group, inverse_point, ctx.bn_ctx);
    }

    ~PrecomputedStep()
    {
        if (point) EC_POINT_free(point);
        if (inverse_point) EC_POINT_free(inverse_point);
        if (s) BN_free(s);
        if (t) BN_free(t);
    }

    PrecomputedStep(PrecomputedStep&& other) noexcept : point(other.point),
                                                        inverse_point(other.inverse_point),
                                                        s(other.s),
                                                        t(other.t)
    {
        other.point = nullptr;
        other.inverse_point = nullptr;
        other.s = nullptr;
        other.t = nullptr;
    }

    PrecomputedStep& operator=(PrecomputedStep&& other) noexcept
    {
        if (this != &other) {
            // 1. 清理现有资源
            if (point) EC_POINT_free(point);
            if (inverse_point) EC_POINT_free(inverse_point);
            if (s) BN_free(s);
            if (t) BN_free(t);

            // 2. 转移资源所有权
            point = other.point;
            inverse_point = other.inverse_point;
            s = other.s;
            t = other.t;

            // 3. 置空源对象指针
            other.point = nullptr;
            other.inverse_point = nullptr;
            other.s = nullptr;
            other.t = nullptr;
        }
        return *this;
    }

    // 从文件加载构造
    PrecomputedStep(const CurveContext& ctx, std::istream& is) : point(EC_POINT_new(ctx.group)),
                                                                 inverse_point(EC_POINT_new(ctx.group)),
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

        EC_POINT_copy(inverse_point, point);
        EC_POINT_invert(ctx.group, inverse_point, ctx.bn_ctx);
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
    PollardSolver(std::shared_ptr<CurveContext> ctx, IDManager& manager) : ctx_(ctx),
                                                                           step_count_(0),
                                                                           id_manager(manager),
                                                                           run_id_(id_manager.request_id())
    {
        static RecursiveMutex steps_mutex;
        {
            LOCK(steps_mutex);
            // 尝试加载预计算步长
            if (!load_precomputed_steps(STEP_FILE, steps_)) {
                generate_precomputed_steps();
                save_precomputed_steps();
            }
        }
        // 初始化随机起点
        StartPointResult sp;
        if (run_id_ != 66) {
            sp = generate_start_point_with_min_predecessors(6, 1000000);
        }
        if (!sp.success) {
            Logger::log("generate_start_point_with_min_predecessors failed");
            current_ = EC_POINT_new(ctx_->group);
            a_ = BN_new();
            b_ = BN_new();
            BN_rand_range(a_, ctx_->order);
            BN_rand_range(b_, ctx_->order);
            EC_POINT_mul(ctx_->group, current_, a_, ctx_->Q, b_, ctx_->bn_ctx);
        } else {
            a_ = sp.a;
            b_ = sp.b;
            current_ = sp.point;
        }
    }

    BIGNUM* solve()
    {
        bool loaded = load_progress(run_id_);
        if (loaded) {
            auto last = lastPoint();
            assert(last != points_.end());
            set_initial(last->second.a, last->second.b, last->second.step);
        }
        if (!loaded)
            printPoint(a_, b_, current_);
        BIGNUM* ret = nullptr;
        while (ret == nullptr) {
            if (gameover) {
                id_manager.pause_id(run_id_);
                break;
            }
            ++step_count_;
            walk_step();
            ret = process_distinguished_point();
        }
        save_progress();
        return ret;
    }

    // 设置起始点函数
    void set_initial(const BIGNUM* a, const BIGNUM* b, uint64_t step_count)
    {
        // 复制并规范化输入参数
        BN_mod(a_, a, ctx_->order, ctx_->bn_ctx);
        BN_mod(b_, b, ctx_->order, ctx_->bn_ctx);

        // 重新计算当前点
        EC_POINT_mul(ctx_->group, current_, a_, ctx_->Q, b_, ctx_->bn_ctx);

        // 重置步数计数器
        step_count_ = step_count;

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
    bool load_precomputed_steps(const char* filename, std::vector<PrecomputedStep>& step_vec)
    {
        if (!fs::exists(filename)) return false;

        try {
            std::ifstream file(filename, std::ios::binary);
            if (!file) return false;

            // 验证文件头
            int file_r;
            file.read(reinterpret_cast<char*>(&file_r), sizeof(file_r));
            if (file_r != r) {
                std::cerr << "Invalid step file configuration\n";
                return false;
            }

            step_vec.clear();
            step_vec.reserve(r);
            for (int i = 0; i < r; ++i) {
                step_vec.emplace_back(*ctx_, file);
            }

            std::cout << "Loaded " << r << " precomputed steps from file\n";
            return true;
        } catch (...) {
            std::cerr << "Error loading precomputed steps\n";
            step_vec.clear();
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

    // 在加载/生成预计算步长后调用此函数
    void adjust_last_step()
    {
        if (steps_.size() < 2) {
            Logger::log("Not enough steps to adjust, need at least 2 elements");
            return;
        }

        // 初始化累加器
        EC_POINT* sum_point = EC_POINT_new(ctx_->group);
        BIGNUM* sum_s = BN_new();
        BIGNUM* sum_t = BN_new();
        BN_zero(sum_s);
        BN_zero(sum_t);

        // 遍历前N-1个元素进行累加
        const size_t last_index = steps_.size() - 1;
        for (size_t i = 0; i < last_index; ++i) {
            const auto& step = steps_[i];

            // 累加点坐标
            EC_POINT_add(ctx_->group, sum_point, sum_point, step.point, ctx_->bn_ctx);

            // 累加标量值（模运算）
            BN_mod_add(sum_s, sum_s, step.s, ctx_->order, ctx_->bn_ctx);
            BN_mod_add(sum_t, sum_t, step.t, ctx_->order, ctx_->bn_ctx);
        }

        // 创建新的最后一步
        PrecomputedStep new_last_step(*ctx_);
        EC_POINT_copy(new_last_step.point, sum_point);
        BN_copy(new_last_step.s, sum_s);
        BN_copy(new_last_step.t, sum_t);

        // 验证新步长的有效性
        if (!validate_step(new_last_step)) {
            Logger::log("Failed to validate adjusted last step");
            EC_POINT_free(sum_point);
            BN_free(sum_s);
            BN_free(sum_t);
            return;
        }

        // 替换最后一步（带资源清理）
        steps_.back() = std::move(new_last_step);

        // 释放临时资源
        EC_POINT_free(sum_point);
        BN_free(sum_s);
        BN_free(sum_t);

        Logger::log("Successfully adjusted last step to sum of previous steps");
    }

    // 验证步长有效性
    bool validate_step(const PrecomputedStep& step) const
    {
        EC_POINT* calc_point = EC_POINT_new(ctx_->group);
        bool valid = false;

        // 验证sG + tQ = point
        EC_POINT_mul(ctx_->group, calc_point, step.s, ctx_->Q, step.t, ctx_->bn_ctx);
        valid = (EC_POINT_cmp(ctx_->group, calc_point, step.point, ctx_->bn_ctx) == 0);

        EC_POINT_free(calc_point);
        return valid;
    }

        // 斐波那契模式预计算步长生成
    void generate_fibonacci_steps(int num_steps)
    {
        if (num_steps < 2) {
            Logger::log("Fibonacci steps require at least 2 steps");
            return;
        }

        // 清理现有步长
        steps_.clear();
        steps_.reserve(num_steps);

        // 初始化前两个步长
        BIGNUM* s[2] = {BN_new(), BN_new()};
        BIGNUM* t[2] = {BN_new(), BN_new()};

        // 生成初始随机值（可改为固定种子）
        BN_rand_range(s[0], ctx_->order);
        BN_rand_range(t[0], ctx_->order);
        BN_rand_range(s[1], ctx_->order);
        BN_rand_range(t[1], ctx_->order);

        // 添加前两步
        add_fib_step(s[0], t[0]);
        add_fib_step(s[1], t[1]);

        // 生成后续步长
        for (int i = 2; i < num_steps; ++i) {
            BIGNUM* new_s = BN_new();
            BIGNUM* new_t = BN_new();

            // s_i = (s_{i-1} + s_{i-2}) mod n
            BN_mod_add(new_s, s[1], s[0], ctx_->order, ctx_->bn_ctx);
            // t_i = (t_{i-1} + t_{i-2}) mod n
            BN_mod_add(new_t, t[1], t[0], ctx_->order, ctx_->bn_ctx);

            // 验证并添加新步长
            if (!add_fib_step(new_s, new_t)) break;

            // 滚动更新缓存
            BN_free(s[0]);
            BN_free(t[0]);
            s[0] = s[1];
            t[0] = t[1];
            s[1] = new_s;
            t[1] = new_t;
        }

        // 清理剩余资源
        BN_free(s[0]);
        BN_free(t[0]);
        BN_free(s[1]);
        BN_free(t[1]);
    }

    bool add_fib_step(BIGNUM* s, BIGNUM* t)
    {
        PrecomputedStep new_step(*ctx_);

        // 计算点坐标
        if (!EC_POINT_mul(ctx_->group, new_step.point, s, ctx_->Q, t, ctx_->bn_ctx)) {
            Logger::log("Failed to compute step point");
            return false;
        }

        // 验证点有效性
        if (!EC_POINT_is_on_curve(ctx_->group, new_step.point, ctx_->bn_ctx)) {
            Logger::log("Generated point is not on curve");
            return false;
        }

        // 复制标量值
        BN_copy(new_step.s, s);
        BN_copy(new_step.t, t);

        steps_.push_back(std::move(new_step));
        return true;
    }


    BIGNUM* process_distinguished_point()
    {
        BIGNUM* ret = nullptr;
        const auto key = calculate_key(); 
        if (key != INVALID_KEY) {
            if (auto it = points_.find(key); it != points_.end()) {
                ret = handle_collision(it->second);
                id_manager.complete_id(run_id_);
                assert(ret);
            } else {
                store_point(key);
                if ((key & 0xfffffff000000000) == 0)
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
        // 返回一个非空值，方便退出循环。
        BIGNUM* result = BN_new();
        EC_POINT* stored_point = EC_POINT_new(ctx_->group);

        EC_POINT_mul(ctx_->group, stored_point, dp.a, ctx_->Q, dp.b, ctx_->bn_ctx);

        int collision_type = -1;
        if (EC_POINT_cmp(ctx_->group, current_, stored_point, ctx_->bn_ctx) == 0) {
            collision_type = 0;
        } else {
            BIGNUM* current_x = BN_new();
            BIGNUM* current_y = BN_new();
            BIGNUM* stored_x = BN_new();
            BIGNUM* stored_y = BN_new();
            EC_POINT_get_affine_coordinates(ctx_->group, current_,
                                            current_x, current_y,
                                            ctx_->bn_ctx);
            EC_POINT_get_affine_coordinates(ctx_->group, stored_point,
                                            stored_x, stored_y,
                                            ctx_->bn_ctx);
            if (BN_cmp(current_x, stored_x) == 0) {
                BIGNUM* sum_y = BN_new();
                BN_mod_add(sum_y, current_y, stored_y, ctx_->order, ctx_->bn_ctx);
                if (BN_is_zero(sum_y)) {
                    collision_type = 1;
                }
                BN_free(sum_y);
            }
            BN_free(current_x);
            BN_free(current_y);
            BN_free(stored_x);
            BN_free(stored_y);
        }
        if (collision_type != -1) {
            const uint64_t tail_length = dp.step;
            const uint64_t cycle_length = step_count_ - dp.step;

            std::stringstream ss;
            ss << "\n=== Cycle Detected ===\n"
               << "run_id_: " << run_id_ << "\n"
               << "collision_type: " << collision_type << "\n"
               << "Tail length:  " << tail_length << "\n"
               << "Cycle length: " << cycle_length << "\n"
               << "Total steps:  " << step_count_ << "\n"
               << "Storage size: " << points_.size() << "\n"
               << "========================";
            Logger::log(ss.str());

            BIGNUM* result_tmp = process_collision_case(dp, collision_type);
            if (result_tmp != nullptr) {
                BN_free(result);
                result = result_tmp;
            }
        }

        return result;
    }

    BIGNUM* process_collision_case(const DistinguishedPoint& dp, int case_type)
    {
        BIGNUM* denominator = BN_new();
        BIGNUM* numerator = BN_new();
        BIGNUM* inv_denominator = BN_new();
        BIGNUM* d = BN_new();
        BIGNUM* result = nullptr;

        do {
            if (case_type == 0) { // 常规碰撞
                if (!BN_mod_sub(numerator, dp.a, a_, ctx_->order, ctx_->bn_ctx)) break;
                if (!BN_mod_sub(denominator, b_, dp.b, ctx_->order, ctx_->bn_ctx)) break;
            } else { // x相同y相反的情况
                if (!BN_mod_add(numerator, dp.a, a_, ctx_->order, ctx_->bn_ctx)) break;
                if (!BN_mod_add(denominator, dp.b, b_, ctx_->order, ctx_->bn_ctx)) break;
                if (!BN_mod_sub(numerator, ctx_->order, numerator, ctx_->order, ctx_->bn_ctx)) break;
            }

            if (BN_is_zero(denominator)) {
                Logger::log("Zero denominator encountered");
                break;
            }

            if (!BN_mod_inverse(inv_denominator, denominator, ctx_->order, ctx_->bn_ctx)) {
                Logger::log("Failed to compute modular inverse");
                break;
            }

            if (!BN_mod_mul(d, numerator, inv_denominator, ctx_->order, ctx_->bn_ctx)) {
                Logger::log("Failed to compute private key candidate");
                break;
            }

            // 规范化为非负表示
            if (BN_is_negative(d)) {
                BN_add(d, d, ctx_->order);
            }

            if (validate_key(d)) {
                result = BN_dup(d); // 转移所有权给调用者
                Logger::log("Valid private key found");
            }
        } while (false);

        BN_free(denominator);
        BN_free(numerator);
        BN_free(inv_denominator);
        BN_free(d);
        return result;
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
        const size_t idx = get_step_index_for_point(current_);
        const auto& step = steps_[idx];

        EC_POINT_add(ctx_->group, current_, current_, step.point, ctx_->bn_ctx);
        BN_mod_add(a_, a_, step.s, ctx_->order, ctx_->bn_ctx);
        BN_mod_add(b_, b_, step.t, ctx_->order, ctx_->bn_ctx);
    }
    /**
     * 逆向步进函数
     * @param current_point 当前点
     * @param a 当前a标量
     * @param b 当前b标量
     * @return 包含所有可能前驱点及其参数的列表，格式为：
     *         vector<tuple<前驱点EC_POINT*, 前驱a BIGNUM*, 前驱b BIGNUM*>>
     */
    std::vector<std::tuple<EC_POINT*, BIGNUM*, BIGNUM*>>
    reverse_walk_step(const EC_POINT* current_point,
                      const BIGNUM* a,
                      const BIGNUM* b)
    {
        std::vector<std::tuple<EC_POINT*, BIGNUM*, BIGNUM*>> predecessors;

        // 遍历所有预计算步长
        for (size_t i = 0; i < steps_.size(); ++i) {
            const auto& step = steps_[i];

            // 计算候选前驱点：candidate = current - step_i
            EC_POINT* candidate = EC_POINT_new(ctx_->group);
            EC_POINT_copy(candidate, current_point);

            // 执行点减法：current + (-step_i)
            EC_POINT_add(ctx_->group, candidate, candidate, step.inverse_point, ctx_->bn_ctx);

            // 验证候选点有效性
            /* if (!EC_POINT_is_on_curve(ctx_->group, candidate, ctx_->bn_ctx)) {
                EC_POINT_free(candidate);
                continue;
            }*/

            // 验证候选点的下一步是否指向当前点
            size_t candidate_idx = get_step_index_for_point(candidate);
            if (candidate_idx != i) {
                EC_POINT_free(candidate);
                continue;
            }

            // 计算对应的前驱标量
            BIGNUM* prev_a = BN_dup(a);
            BIGNUM* prev_b = BN_dup(b);
            BN_mod_sub(prev_a, prev_a, step.s, ctx_->order, ctx_->bn_ctx);
            BN_mod_sub(prev_b, prev_b, step.t, ctx_->order, ctx_->bn_ctx);

            // 添加到结果列表
            predecessors.emplace_back(candidate, prev_a, prev_b);
        }

        return predecessors;
    }
    size_t get_step_index_for_point(const EC_POINT* point) const
    {
        BIGNUM* x = BN_new();
        EC_POINT_get_affine_coordinates(ctx_->group, point, x, nullptr, ctx_->bn_ctx);

        unsigned char bin[32];
        BN_bn2bin(x, bin);
        const size_t offset = (BN_num_bytes(x) > 2) ? BN_num_bytes(x) - 2 : 0;
        BN_free(x);
        static size_t mask = r - 1;
        return *reinterpret_cast<uint16_t*>(bin + offset) & mask;
    }
    // 返回结构封装结果和状态
    struct StartPointResult {
        EC_POINT* point = nullptr;
        BIGNUM* a = nullptr;
        BIGNUM* b = nullptr;
        bool success = false;
    };
    // 生成起始点函数返回结构
    StartPointResult generate_start_point_with_min_predecessors(
        int min_predecessors,
        int max_attempts = 10000)
    {
        StartPointResult result;

        // 创建新资源
        EC_POINT* current_point = EC_POINT_new(ctx_->group);
        BIGNUM* current_a = BN_new();
        BIGNUM* current_b = BN_new();
        if (!current_point || !current_a || !current_b) {
            if (current_point) EC_POINT_free(current_point);
            if (current_a) BN_free(current_a);
            if (current_b) BN_free(current_b);
            return result;
        }
        for (int attempt = 0; attempt < max_attempts; ++attempt) {
            // 生成随机参数
            BN_rand_range(current_a, ctx_->order);
            BN_rand_range(current_b, ctx_->order);
            EC_POINT_mul(ctx_->group, current_point, current_a, ctx_->Q, current_b, ctx_->bn_ctx);

            // 检查前置点数量
            auto predecessors = reverse_walk_step(current_point, current_a, current_b);
            const bool valid = predecessors.size() >= min_predecessors;

            // 清理前置点资源
            for (auto& [p, a, b] : predecessors) {
                EC_POINT_free(p);
                BN_free(a);
                BN_free(b);
            }

            if (valid) {
                // 转移资源所有权
                result.point = current_point;
                result.a = current_a;
                result.b = current_b;
                result.success = true;
                return result;
            }
        }
        // 释放尝试资源
        EC_POINT_free(current_point);
        BN_free(current_a);
        BN_free(current_b);

        return result;
    }

    void save_progress() const
    {
        std::ofstream file(format_filename(SAVE_FILE, run_id_), std::ios::binary);
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

    std::string format_filename(const std::string& pattern, int id) const
    {
        char buf[256];
        snprintf(buf, sizeof(buf), pattern.c_str(), id);
        return buf;
    }

    bool load_progress(int id)
    {
        std::ifstream file(format_filename(SAVE_FILE, id), std::ios::binary);
        if (!file) return false;

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
        return true;
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

    void printPoint(BIGNUM* a, BIGNUM* b, EC_POINT* _point) const
    {
        // 记录详细的初始点信息
        std::stringstream log_ss;
        log_ss << "Initial Point Configuration [Run ID: " << run_id_ << "]\n";

        // 记录标量参数
        char* a_hex = BN_bn2hex(a);
        char* b_hex = BN_bn2hex(b);
        log_ss << "  Scalar a: 0x" << a_hex << "\n";
        log_ss << "  Scalar b: 0x" << b_hex << "\n";
        OPENSSL_free(a_hex);
        OPENSSL_free(b_hex);

        // 获取并记录点坐标
        BIGNUM *x = BN_new(), *y = BN_new();
        if (EC_POINT_get_affine_coordinates(ctx_->group, _point, x, y, ctx_->bn_ctx)) {
            char* x_hex = BN_bn2hex(x);
            char* y_hex = BN_bn2hex(y);

            log_ss << "  Point Coordinates:\n"
                   << "    X: 0x" << x_hex << "\n"
                   << "    Y: 0x" << y_hex << "\n";

            OPENSSL_free(x_hex);
            OPENSSL_free(y_hex);
            Logger::log(log_ss.str());
        } else {
            Logger::log("Error: Failed to get initial point coordinates");
        }

        BN_free(x);
        BN_free(y);
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
    /**
     * 从文件加载私钥
     * @param filename 私钥文件路径
     * @return 成功返回BIGNUM指针，失败返回nullptr
     */
    BIGNUM* load_private_key(const std::string& filename)
    {
        std::ifstream file(filename);
        if (!file.is_open()) {
            Logger::log("Failed to open private key file: " + filename);
            return nullptr;
        }

        std::string line;
        std::getline(file, line); // 读取私钥HEX字符串

        BIGNUM* d = BN_new();
        if (BN_hex2bn(&d, line.c_str()) == 0) {
            Logger::log("Invalid private key format in file: " + filename);
            BN_free(d);
            return nullptr;
        }

        // 验证私钥范围 [1, order-1]
        if (BN_cmp(d, BN_value_one()) < 0 || BN_cmp(d, ctx_->order) >= 0) {
            Logger::log("Private key out of valid range");
            BN_free(d);
            return nullptr;
        }

        return d;
    }

        /**
     * 计算并打印步长标量（需要先加载私钥）
     * @param d 私钥
     */
    void calculate_and_print_scalars(BIGNUM* d)
    {
        if (!d || !ctx_ || !ctx_->group) {
            Logger::log("Invalid parameters for scalar calculation");
            return;
        }

        BIGNUM* n = ctx_->order;
        BIGNUM* scalar = BN_new();
        BIGNUM* temp = BN_new();

        std::stringstream ss;
        ss << "\n=== Step Scalar Calculation (d: 0x" << BN_bn2hex(d) << ") ===";
        Logger::log(ss.str());

        for (size_t i = 0; i < steps_.size(); ++i) {
            const auto& step = steps_[i];

            // 计算标量：s_i + t_i*d mod n
            BN_mod_mul(temp, step.t, d, n, ctx_->bn_ctx);      // t_i*d
            BN_mod_add(scalar, step.s, temp, n, ctx_->bn_ctx); // s_i + t_i*d

            // 构建输出信息
            ss.str("");
            ss << "  s + t*d: 0x" << BN_bn2hex(scalar) << "\n"
               << "  Verify: " << (verify_scalar(scalar, step.point) ? "Valid" : "Invalid");
            Logger::log(ss.str());

        }

        BN_free(scalar);
        BN_free(temp);
        Logger::log("=== End of Scalar Calculation ===");
    }

    /**
     * 验证标量计算结果是否正确
     * @param scalar 计算的标量值
     * @param point 对应的步长点
     * @return 验证结果
     */
    bool verify_scalar(BIGNUM* scalar, EC_POINT* point)
    {
        EC_POINT* calc_point = EC_POINT_new(ctx_->group);
        EC_POINT_mul(ctx_->group, calc_point, scalar, nullptr, nullptr, ctx_->bn_ctx);

        const int cmp = EC_POINT_cmp(ctx_->group, calc_point, point, ctx_->bn_ctx);
        EC_POINT_free(calc_point);

        return cmp == 0;
    }


    static constexpr uint64_t INVALID_KEY = UINT64_MAX;

    std::shared_ptr<CurveContext> ctx_;
    std::vector<PrecomputedStep> steps_;
    std::map<uint64_t, DistinguishedPoint> points_;
    EC_POINT* current_;
    BIGNUM* a_;
    BIGNUM* b_;
    uint64_t step_count_;
    IDManager& id_manager;
    const int run_id_;
};

// 获取系统核心数
unsigned get_core_count()
{
    unsigned cores = std::thread::hardware_concurrency();
    return (cores > 2) ? (cores - 2) : 1;
}

void test_112()
{
    const unsigned num_solvers = get_core_count();
    std::vector<std::thread> threads;
    IDManager id_mgr;
    auto _run = [&id_mgr]() {
        try {
            PollardSolver* solver = nullptr;
            // 生成测试密钥对
            BIGNUM* priv = nullptr;
            EC_POINT* pub = nullptr;
            static RecursiveMutex keypair_mutex;
            auto ctx = std::make_shared<CurveContext>(0);

            {
                LOCK(keypair_mutex);
                // 尝试加载现有密钥对
                if (!ctx->load_keypair(&priv, &pub)) {
                    // 生成并保存新密钥对
                    ctx->generate_and_save_keypair(&priv, &pub);
                }
            }
            ctx->set_target(pub);

            solver = new PollardSolver(ctx, id_mgr);
            BIGNUM* found = solver->solve(); // 验证结果
            if (found != nullptr) {
                if (BN_cmp(found, priv) == 0) {
                    char* hex = BN_bn2hex(found);
                    Logger::log("Success! Private key: " + std::string(hex), true);
                    OPENSSL_free(hex);
                } else {
                    Logger::log("Failed!!!", true);
                }
                BN_free(found);
            }
            BN_free(priv);
            EC_POINT_free(pub);
            if (solver) delete solver;
        } catch (...) {
            std::cout << "\nException handling!!!\n";
        }
    };
    // 创建并启动线程
    for (unsigned i = 0; i < num_solvers; ++i) {
        threads.emplace_back(_run);
    }
    // 等待所有线程完成
    for (auto& t : threads) {
        if (t.joinable()) t.join();
    }
}

void test_112_helper() {
    Logger::enable(false);
    BIGNUM* priv = nullptr;
    EC_POINT* pub = nullptr;
    auto ctx = std::make_shared<CurveContext>(0);
    ctx->load_keypair(&priv, &pub);
    ctx->set_target(pub);
    BN_free(priv);
    EC_POINT_free(pub);
    DummyIDManager id_mgr;
    PollardSolver solver(ctx, id_mgr);

    //研究规律
    /*
    auto sec = solver.load_private_key("ec_keypair.txt");
    solver.calculate_and_print_scalars(sec);
    BN_free(sec);*/

    /*
    solver.load_progress(1);
    auto last = solver.lastPoint();
    assert(last != solver.points_.end());
    solver.set_initial(last->second.a, last->second.b, last->second.step);
    uint32_t stat[64] = {0};
    do {
        solver.walk_step();
        auto predecessors = solver.reverse_walk_step(solver.current_, solver.a_, solver.b_);
        std::cout << predecessors.size() << " ";
        stat[predecessors.size()]++;

        // 清理前置点资源
        for (auto& [p, a, b] : predecessors) {
            EC_POINT_free(p);
            BN_free(a);
            BN_free(b);
        }
    } while (solver.a_ != last->second.a && stat[1] < 10000);
    std::cout << std::endl;
    for (auto s: stat)
        std::cout << s << " ";*/

    //测试斐波那契 step
     solver.generate_fibonacci_steps(r);
    solver.save_precomputed_steps();

    //将最后一个step 改为之前step之和
    /*std::vector<PrecomputedStep> steps2;
    solver.load_precomputed_steps(STEP_FILE, steps2);
    solver.adjust_last_step();
    solver.save_precomputed_steps();
    solver.load_precomputed_steps(STEP_FILE, solver.steps_);
    int i = 0;
    for (; i < steps2.size() - 1; i++) {
        assert(EC_POINT_cmp(ctx->group, solver.steps_[i].point, steps2[i].point, ctx->bn_ctx) == 0);
    }
    assert(EC_POINT_cmp(ctx->group, solver.steps_[i].point, steps2[i].point, ctx->bn_ctx) != 0);*/

    //测试generate_start_point_with_min_predecessors 效果
    /* auto sp = solver.generate_start_point_with_min_predecessors(6, 1000000);
    if (!sp.success) {
        std::cout << "generate_start_point_with_min_predecessors failed\n";
        return;
    }
    for (int i = 1; i < 11; i++) {
        solver.load_progress(i);
    }
    solver.set_initial(sp.a, sp.b, 0);
    BIGNUM* found = solver.solve();
    if (found != nullptr) {
        BN_free(found);
    }*/
}

//========<<<<<<<<<<<<<<
#endif  //64位曲线

#include <csignal>

void validate_test();
void perf_test();
int main(int argc, char* argv[])
{
    // 注册信号处理函数，捕获 SIGINT 信号
    std::signal(SIGINT, signalHandler);

    INIT _init;
    work();

    //validate_test();
    //perf_test();

    //test();

    /* Logger::init();
    test_112_helper();
    Logger::cleanup();*/

    std::cout << "Finish. Press Enter..." << std::endl;
    std::cin.get(); // 等待用户按下任意键
    return 0;
}
