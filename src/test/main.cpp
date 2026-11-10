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
#include <cstdlib>

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

#include <algorithm>
#include <csignal>
#include <cctype>
#include <future>
#include <string>
#include <thread>
#include <vector>

// ---------------------------------------------------------------------------
// 进程单例: 同一时刻只允许一个 test_bitcoin 进程
//
// 为什么要这个: 本程序的生产状态全在**exe 同目录**的那几个固定文件里 (iLog.txt /
// RhoState2.txt / RhoReserve.txt / Dp32Edge.txt / Dp32EdgeState.txt ...), 而且是
// **每轮整份重写**。两个实例同时跑, 后启动的那个会拿自己的状态覆盖前一个的落盘,
// 边表还会互相穿插, 结果两边的进度一起作废 —— 而文件本身看不出是谁写坏的。
//
// 实现用操作系统内核对象的独占, 不用"锁文件 + 手工删":
//   Windows: 命名互斥体。进程消失 (正常退出 / Ctrl+C / 被 TerminateProcess) 时
//            内核自动关闭句柄、释放占有, **不存在残留锁**, 收工后可以立刻重启。
//   POSIX:   在 /tmp 的锁文件上加 flock(LOCK_EX | LOCK_NB), fd 随进程关闭一起释放。
//
// 名字固定 (不带 PID / 时间戳 / 构建类型): Debug 与 Release 若指向同一个 exe 目录,
// 写的就是**同一批**文件 (把 exe 拷过去跑、或用同一个输出目录时都会发生), 所以一律
// 互斥。Local\ 前缀 = 按登录会话隔离, 同一台机器上另一个用户再跑一份互不影响。
//
// 覆盖范围是整个进程: 生产 (play), 以及 perf / rhoperf / validate 三个常驻入口都算 ——
// 后两个虽然没有生产副作用, 但它们也要读 RhoState2.txt 等文件, 让它们和正在跑的
// 生产实例并存没有意义, 还容易让人误读"两边同时跑"的结果。
// ---------------------------------------------------------------------------
#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#else
#include <fcntl.h>
#include <sys/file.h>
#include <unistd.h>
#endif

namespace {

class ProcessSingleton
{
public:
    ProcessSingleton(const ProcessSingleton&) = delete;
    ProcessSingleton& operator=(const ProcessSingleton&) = delete;

    ProcessSingleton()
    {
#ifdef _WIN32
        // 返回 nullptr 时把错误码取出来 (GetLastError 会被随后的调用冲掉)
        m_handle = (void*)::CreateMutexW(nullptr, TRUE, kMutexName);
        const unsigned long err = m_handle == nullptr ? (unsigned long)::GetLastError() : 0;
        if (m_handle == nullptr) {
            // 建不出来 (权限 / 句柄耗尽) 不当作"已有实例": 宁可放开, 也不无故拒绝启动。
            cprint() << "单例: 创建互斥体失败 (GetLastError=" << err
                     << "), 不做单例限制, 继续启动" << std::endl;
            m_acquired = true;
            return;
        }
        if (::GetLastError() == ERROR_ALREADY_EXISTS) {
            // 别人先建的: 我们只是又开了一个句柄, 关掉它 (不释放别人的占有)
            ::CloseHandle((HANDLE)m_handle);
            m_handle = nullptr;
            m_acquired = false;
            return;
        }
        // 我们建的 => 同时已经持有它 (bInitialOwner = TRUE), 一直持有到进程结束
        m_acquired = true;
#else
        m_fd = ::open(kLockPath, O_CREAT | O_RDWR | O_CLOEXEC, 0600);
        if (m_fd < 0) {
            m_acquired = true; // 打不开锁文件就不设限, 同 Windows 那一支的口径
            return;
        }
        if (::flock(m_fd, LOCK_EX | LOCK_NB) != 0) {
            ::close(m_fd);
            m_fd = -1;
            m_acquired = false;
            return;
        }
        m_acquired = true;
#endif
    }

    ~ProcessSingleton()
    {
#ifdef _WIN32
        if (m_handle != nullptr) ::CloseHandle((HANDLE)m_handle);
#else
        // 不 unlink 锁文件: 留着这个 inode 给下一个实例加锁, 避免
        // "删文件 + 别人刚好打开" 的经典竞态。文件本身是空的, 留在 /tmp 无害。
        if (m_fd >= 0) ::close(m_fd);
#endif
    }

    // true = 本进程是当前唯一的实例 (或无法判定, 见上); false = 已有实例在跑
    bool acquired() const { return m_acquired; }

private:
#ifdef _WIN32
    static constexpr const wchar_t* kMutexName = L"Local\\bitcoin-rho-test-singleton";
    void* m_handle = nullptr; // HANDLE (用 void* 收着, 免得这个类型名散到别处)
#else
    static constexpr const char* kLockPath = "/tmp/bitcoin-rho-test-singleton.lock";
    int m_fd = -1;
#endif
    bool m_acquired = false;
};

// ---------------------------------------------------------------------------
// 控制台窗口显示/隐藏热键 (Windows 专用; 其他平台是不做事的桩)
//
// 为什么要: 这程序一跑就是几小时到几天, 控制台一直占着半块屏幕。想让它整个退到后台
// 继续算 (连任务栏按钮一起去掉), 又随时能按一下就调出来看进度。
//
// 为什么必须单开一条线程: 全局热键按**线程**投递 (RegisterHotKey 传 NULL 窗口时,
// WM_HOTKEY 只发给注册它的那个线程), 而主线程正卡在 play()/perf_test() 里 join 工作
// 线程, 没有消息泵可跑。所以这里起一条专职线程: 注册热键 -> MsgWaitForMultipleObjects
// 等消息 -> 收到 WM_HOTKEY 就 ShowWindow。
//
// ==== 键位 ====
// 固定 Ctrl+Alt+/，不做配置。选它的理由：带两个修饰键，不会把单个 Ctrl+X 从整个
// 系统里抢走；而 / 又不是常用组合（不像 Ctrl+Alt+A 撞 QQ 截图、Ctrl+Alt+Z 撞 QQ
// 消息盒子、Ctrl+Alt+B 撞 VS 断点窗口）。
// VK_OEM_2 是美式键盘上 /? 那个键；中文输入法下的键位映射由系统给，实测可用。
//
// **注册失败就直接报失败**，不换键、不降级：热键被别的程序占了是本程序控制不了的
// 事，静默换一个别的键反而让人以为按的键没生效。
//
// ==== 任务栏图标 ====
// SW_HIDE 是连任务栏按钮一起隐藏的 (console 窗口是普通顶层窗口)，恢复时 SW_SHOW 会把
// 按钮一起带回来 —— 这两条在经典 conhost 下都成立，不需要额外的 ITaskbarList 调用。
// 唯一做不到的是 Windows Terminal: 它把控制台托管在自己的窗口里，GetConsoleWindow()
// 给到的是个"影子窗口"，SW_HIDE 对它无效，任务栏上留下的是 WT 自己的标签按钮。
// 那种情况下退一步最小化，并提示一次。
//
// 用 .bat 启动的情况 (启动出来的就是经典 conhost，所以能真隐藏):
//   双击 .bat -> 系统新建一个 conhost 窗口给 cmd.exe -> test_bitcoin 继承它，
//   GetConsoleWindow() 拿到的就是这个窗口，SW_HIDE 能把它连任务栏按钮一起藏掉。
//   两种不成立的情形: (a) 已经是 Windows Terminal 里的标签页 (影子窗口问题同上);
//   (b) 在**已经打开的** cmd 窗口里跑 .bat —— 那是用户自己的会话，隐藏会把这个
//   cmd 窗口 (以及同一控制台里其它程序) 一起藏掉，再按一次才回来。所以想看干净的
//   "无窗口"效果，用 .bat 里的 start "" test_bitcoin.exe 单开一个，或直接双击 exe。
// ---------------------------------------------------------------------------
#ifdef _WIN32

// 固定组合: Ctrl+Alt+/
static constexpr UINT kHotkeyMods = MOD_CONTROL | MOD_ALT;
static constexpr UINT kHotkeyVk = VK_OEM_2;   // '/?' 键

// ==== 空闲检测的参数 (只在窗口隐藏期间生效) ====
// 规则只有一条: **有人在用就停算**。
//   有人在用 = 最近 kIdlePauseMs 内有过键鼠输入  -> 停算;
//   人走了   = 连续 kIdleResumeMs 都没有任何输入 -> 才恢复。
// 恢复之后**没有**任何"至少算满多久"的承诺: 只要有输入, 下一个采样节拍 (1 秒)
// 就会立刻再停。人回来就停, 不管刚恢复多久。
//
// 刚隐藏的 kIdleStartDelayMs 内**不做任何检测**: 隐藏这个动作本身就是按热键干的,
// 之后往往还要开关别的窗口、敲几下键盘 —— 那些操作跟"有人在用这台机器算不算打扰"
// 无关, 却会把检测立刻判成"有人在用"从而又停一次。所以先让计算跑满这 5 分钟,
// 过了才开始看键鼠。
//
// 为什么恢复阈值比暂停阈值大这么多 (1 分钟 vs 2 小时): 每停一次, GPU 内核都要走到
// 下一个 poll 检查点才收尾 (RHO_POLL_BATCHES = 2^12 批, 约 2.4 s) 并整份落盘
// (~1~2 s), CPU 侧还要走一次 barrier 存档。若"停 30 秒算 30 秒"地来回切, 总产出
// 反而比一刻不停地跑更低。宽死区纯粹是为了避开这种抖动, 不代表算多久。
static constexpr ULONGLONG kIdlePauseMs = 60ULL * 1000;          // 最近 1 分钟有输入 => 有人在用 => 停
static constexpr ULONGLONG kIdleResumeMs = 7200ULL * 1000;       // 连续 2 小时无输入 => 人走了 => 恢复
static constexpr ULONGLONG kIdleStartDelayMs = 300ULL * 1000;    // 隐藏后先放跑 5 分钟再开检测
// 采样节拍就是泵线程的等待超时 (1 秒), 见 pump()。

// 距最近一次键鼠输入过去了多少毫秒; 拿不到时返回 0 (= 当作"刚动过", 保守停算)。
static ULONGLONG input_idle_ms()
{
    LASTINPUTINFO li{};
    li.cbSize = sizeof(li);
    if (!::GetLastInputInfo(&li)) return 0;
    // dwTime 与 GetTickCount 同一个时基 (毫秒); 无符号相减扛得住 49.7 天的回绕
    return (ULONGLONG)(::GetTickCount() - li.dwTime);
}

class ConsoleToggleHotkey
{
public:
    ConsoleToggleHotkey(const ConsoleToggleHotkey&) = delete;
    ConsoleToggleHotkey& operator=(const ConsoleToggleHotkey&) = delete;
    ConsoleToggleHotkey() = default;
    ~ConsoleToggleHotkey() { stop(); }

    // 注册热键并起消息泵线程。没有控制台窗口或注册失败时返回 false，由调用方报错。
    bool start()
    {
        m_hwnd = ::GetConsoleWindow();
        if (m_hwnd == nullptr) {
            cprint() << "[hotkey] 没有控制台窗口 (输出被重定向或当服务跑), 隐藏/显示热键不可用"
                     << std::endl;
            return false;
        }

        // 记下"窗口此刻究竟可不可见"。这条决定了隐藏能不能验证:
        //   经典 conhost  -> GetConsoleWindow() 是屏幕上那个窗口, WS_VISIBLE 置着, true;
        //   ConPTY/WT     -> 拿到的是 PseudoConsoleWindow 影子窗口。
        // ⚠ 影子窗口的 WS_VISIBLE **也是置着的**, 而且 ShowWindow(SW_HIDE) 会把它清掉,
        //   于是"复核不可见"判成功 —— 但屏幕上的终端窗口属于 WindowsTerminal.exe,
        //   一点变化都没有。实测 (2026-11-09, WT pid 32496):
        //     test_bitcoin.exe  pid=32836  class=PseudoConsoleWindow           title=''
        //     WindowsTerminal.exe pid=32496 class=CASCADIA_HOSTING_WINDOW_CLASS title='D:\test_EC\test_bitcoin.exe'
        //   所以必须**先按类名认出这是 ConPTY**, 再去别的进程里找真正露着的那个窗口。
        m_win_was_visible = is_window_visible(m_hwnd);
        m_console_class = window_class_wide(m_hwnd);
        m_console_is_pty = (_wcsicmp(m_console_class.c_str(), L"PseudoConsoleWindow") == 0);

        // 匹配宿主窗口用的两个候选标题: 控制台标题 / exe 全路径 (WT 的标签标题就是后者)
        {
            wchar_t buf[1024] = {0};
            if (::GetConsoleTitleW(buf, (DWORD)(sizeof(buf) / sizeof(buf[0]))) > 0) m_console_title = buf;
            wchar_t exe[1024] = {0};
            const DWORD n = ::GetModuleFileNameW(nullptr, exe, (DWORD)(sizeof(exe) / sizeof(exe[0])));
            if (n > 0 && n < (DWORD)(sizeof(exe) / sizeof(exe[0]))) m_exe_path.assign(exe, n);
        }

        m_stop_event = ::CreateEventW(nullptr, TRUE, FALSE, nullptr);
        if (m_stop_event == nullptr) {
            cprint() << "[hotkey] 建停止事件失败, 隐藏/显示热键不可用" << std::endl;
            return false;
        }

        // ⚠ 热键必须在**泵线程**里注册。hWnd == NULL 时 WM_HOTKEY 只投递到注册它的
        //   那个线程的消息队列; 在主线程注册、在别的线程 PeekMessage 是一个消息都收不到
        //   的 —— 主线程正卡在 play() 的 join() 里, 本来也没机会泵消息。
        //   用 promise 把注册结果同步回来, 让 start() 仍能立刻报成功/失败。
        std::promise<bool> ready;
        std::future<bool> ready_fut = ready.get_future();
        m_thread = std::thread([this, &ready] { pump(ready); });
        if (!ready_fut.get()) {
            ::SetEvent(m_stop_event);
            m_thread.join();
            ::CloseHandle(m_stop_event);
            m_stop_event = nullptr;
            cprint() << "[hotkey] Ctrl+Alt+/ 注册失败 (GetLastError=" << (unsigned long)m_register_error
                     << "), 已被别的程序占用; 隐藏/显示热键不可用" << std::endl;
            return false;
        }
        m_registered = true;
        return true;
    }

    void stop()
    {
        resume_compute();   // 退出前必须先放行, 否则 join 会卡在暂停的计算线程上
        if (m_stop_event != nullptr) ::SetEvent(m_stop_event);
        // 注销在泵线程里做 (与注册同线程才有意义), 这里只负责等它结束
        if (m_thread.joinable()) m_thread.join();
        m_registered = false;
        if (m_stop_event != nullptr) {
            ::CloseHandle(m_stop_event);
            m_stop_event = nullptr;
        }
    }

private:
    // 进程内唯一即可; 与别的程序不冲突 (GlobalAddAtom 的 id 是另一套, 这里够用)
    static constexpr int kHotkeyId = 0x4B34;

    void pump(std::promise<bool>& ready)
    {
        // 注册热键 —— 必须在这个线程里, 理由见 start()
        if (::RegisterHotKey(nullptr, kHotkeyId, kHotkeyMods, kHotkeyVk) == 0) {
            m_register_error = (unsigned long)::GetLastError();
            ready.set_value(false);
            return;
        }
        ready.set_value(true);

        MSG msg;
        for (;;) {
            // 1 秒超时 (原来是 INFINITE): 隐藏期间这一秒一次的空转同时充当空闲
            // 检测的节拍器, 见 idle_tick。没隐藏时它只是每秒醒一次, 代价可忽略。
            const DWORD r = ::MsgWaitForMultipleObjects(1, &m_stop_event, FALSE, 1000,
                                                        QS_ALLINPUT);
            if (r == WAIT_OBJECT_0 + 1) {
                while (::PeekMessageW(&msg, nullptr, 0, 0, PM_REMOVE)) {
                    if (msg.message == WM_HOTKEY && (int)msg.wParam == kHotkeyId) {
                        toggle();
                    }
                }
            } else if (r == WAIT_TIMEOUT) {
                idle_tick();
            } else {
                break; // 停止信号 (WAIT_OBJECT_0) 或出错
            }
        }
        ::UnregisterHotKey(nullptr, kHotkeyId);
    }

    // 隐藏期间的节拍器 (每秒一次): 看一次最近输入时间。
    //   隐藏后不足 kIdleStartDelayMs -> 什么都不做 (把这段时间留给用户自己操作)
    //   有人在用 (idle < kIdlePauseMs)     -> 停算;
    //   人走了   (idle >= kIdleResumeMs)   -> 恢复。
    // 两个条件互斥且各自独立成立, **不存在"恢复后要撑够多久才允许再停"**: 恢复之后
    // 只要有输入, 下一秒就再停。死区只影响"多久没人用才值得重新开算"。
    void idle_tick()
    {
        if (!m_hidden) return;
        if ((ULONGLONG)(::GetTickCount() - m_hidden_tick) < kIdleStartDelayMs) return;
        const ULONGLONG idle = input_idle_ms();
        if (!m_paused && idle < kIdlePauseMs) {
            m_paused = true;
            set_compute_pause(true);
        } else if (m_paused && idle >= kIdleResumeMs) {
            m_paused = false;
            set_compute_pause(false);
        }
    }

    // 无条件放行 (显示窗口 / 关闭检测 / 退出时调用)。幂等。
    void resume_compute()
    {
        if (!m_paused) return;
        m_paused = false;
        set_compute_pause(false);
    }

    void toggle()
    {
        if (m_hwnd == nullptr) return;
        if (m_hidden) show_window();
        else hide_window();
    }

    // ---- 窗口状态的两个小工具 ----

    // 窗口在屏幕上真的露着吗 (IsWindowVisible 只看 WS_VISIBLE 及其祖先, 最小化仍算可见)
    static bool is_window_visible(HWND h)
    {
        return h != nullptr && ::IsWindowVisible(h) != FALSE;
    }

    // 是不是已知的控制台宿主窗口类 (Windows Terminal 宿主 / 经典 conhost)
    static bool is_console_host_class(HWND h)
    {
        const std::wstring cls = window_class_wide(h);
        return _wcsicmp(cls.c_str(), L"CASCADIA_HOSTING_WINDOW_CLASS") == 0 ||
               _wcsicmp(cls.c_str(), L"ConsoleWindowClass") == 0;
    }

    // 宿主进程是不是控制台宿主 (排除碰巧同名的其它程序)
    static bool is_console_host_process(HWND h)
    {
        DWORD pid = 0;
        ::GetWindowThreadProcessId(h, &pid);
        const std::wstring proc = process_image_name(pid);
        return _wcsicmp(proc.c_str(), L"WindowsTerminal.exe") == 0 ||
               _wcsicmp(proc.c_str(), L"OpenConsole.exe") == 0 ||
               _wcsicmp(proc.c_str(), L"conhost.exe") == 0;
    }

    // 窗口类名 (宽字符; ConsoleWindowClass / PseudoConsoleWindow / CASCADIA_... )
    static std::wstring window_class_wide(HWND h)
    {
        wchar_t buf[256] = {0};
        if (h == nullptr) return std::wstring();
        const int n = ::GetClassNameW(h, buf, (int)(sizeof(buf) / sizeof(buf[0])));
        return n > 0 ? std::wstring(buf, (size_t)n) : std::wstring();
    }

    // 窗口类名 (纯 ASCII, 报错时打到控制台用)
    static std::string window_class_name(HWND h)
    {
        const std::wstring w = window_class_wide(h);
        if (w.empty()) return std::string("(unknown)");
        std::string out;
        out.reserve(w.size());
        for (const wchar_t c : w) out.push_back(c < 0x80 ? (char)c : '?');
        return out;
    }

    // 进程映像名 (不含目录)。取不到返回空串。
    static std::wstring process_image_name(DWORD pid)
    {
        HANDLE h = ::OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
        if (h == nullptr) return std::wstring();
        wchar_t buf[1024] = {0};
        DWORD n = (DWORD)(sizeof(buf) / sizeof(buf[0]));
        const BOOL ok = ::QueryFullProcessImageNameW(h, 0, buf, &n);
        ::CloseHandle(h);
        if (!ok || n == 0) return std::wstring();
        std::wstring p(buf, (size_t)n);
        const size_t cut = p.find_last_of(L"\\/");
        return cut == std::wstring::npos ? p : p.substr(cut + 1);
    }

    // 找 ConPTY 的宿主窗口 (真正露在屏幕上的那个)。
    //
    // 为什么非得跨进程找: Windows Terminal 把控制台渲染在自己的窗口里, 我们的
    // PseudoConsoleWindow 是个 0 尺寸的影子 —— 对它 ShowWindow 只改自己的 WS_VISIBLE,
    // 屏幕上纹丝不动。真正属于"用户看着的那个窗口"的类名是
    // CASCADIA_HOSTING_WINDOW_CLASS, 宿主进程是 WindowsTerminal.exe。
    //
    // 安全性: 只认两类窗口 (WT 宿主 / 经典 conhost), 且标题必须**完全等于**我们的
    // 控制台标题或 exe 全路径; 有多个同类同标题的窗口就放弃 (宁可报失败, 不误伤别人
    // 的终端)。
    struct HostSearch {
        const std::wstring* title = nullptr;
        const std::wstring* exe = nullptr;
        HWND found = nullptr;
        int matches = 0;
    };

    static BOOL CALLBACK find_host_cb(HWND h, LPARAM lp)
    {
        HostSearch* s = reinterpret_cast<HostSearch*>(lp);
        if (!::IsWindowVisible(h) || ::IsIconic(h)) return TRUE;      // 只要露着的
        if (::GetWindow(h, GW_OWNER) != nullptr) return TRUE;         // 只要顶层无主窗口
        if (!is_console_host_class(h)) return TRUE;
        wchar_t tt[1024] = {0};
        if (::GetWindowTextW(h, tt, (int)(sizeof(tt) / sizeof(tt[0]))) <= 0) return TRUE;
        const bool hit = (s->title != nullptr && !s->title->empty() && _wcsicmp(tt, s->title->c_str()) == 0) ||
                         (s->exe != nullptr && !s->exe->empty() && _wcsicmp(tt, s->exe->c_str()) == 0);
        if (!hit) return TRUE;
        s->found = h;
        ++s->matches;
        return TRUE;   // 继续数, 有歧义就放弃
    }

    // 按标题找宿主窗口 —— 这只是一条**兜底**路径, 见 hide_window_impl 开头的说明。
    // 标题匹配天生不可靠: WT 的主窗口标题是"当前活动标签页"的标题, 我们切到别的
    // 标签页、或 WT 自己改标题之后就匹配不上了 (这正是"有时候隐藏失败"的主因)。
    HWND find_terminal_host_window() const
    {
        HostSearch s;
        s.title = &m_console_title;
        s.exe = &m_exe_path;
        ::EnumWindows(&ConsoleToggleHotkey::find_host_cb, reinterpret_cast<LPARAM>(&s));
        if (s.matches != 1) {
            if (s.matches > 1) {
                cprint() << "[hotkey] 找到 " << s.matches
                         << " 个标题相同的终端窗口, 无法确定该藏哪一个, 放弃隐藏" << std::endl;
            }
            return nullptr;
        }
        if (!is_console_host_process(s.found)) return nullptr;
        return s.found;
    }

    // 藏掉一个窗口并复核。成功返回 true 并把 m_hide_target 记下 (恢复时用)。
    // 判据是"现在真的不可见了", 不是"ShowWindow 没报错"。
    bool try_hide_window(HWND h)
    {
        if (h == nullptr || !::IsWindow(h)) return false;
        ::ShowWindow(h, SW_HIDE);
        if (!is_window_visible(h)) {
            m_hide_target = h;
            return true;
        }
        // 藏不掉就回滚, 别把用户的窗口弄到半隐身状态
        ::ShowWindow(h, SW_SHOW);
        if (::IsIconic(h)) ::ShowWindow(h, SW_RESTORE);
        return false;
    }

    // 隐藏: 窗口**和它的任务栏按钮**一起消失, 进程照常跑。
    // 返回是否真的藏掉了 —— 判据不是"调用没报错", 而是"这个窗口现在不可见了"。
    bool hide_window_impl()
    {
        // (0) 首选: PseudoConsoleWindow 的 **owner 就是宿主窗口**。
        //     实测 (2026-11-09 与 11-10 两次抓):
        //       hwnd=6688204 pid=30548 OWNER=721838 ROOT=6688204 class=PseudoConsoleWindow
        //       hwnd=721838  pid=19820 OWNER=0      ROOT=721838  class=CASCADIA_HOSTING_WINDOW_CLASS
        //     我们自己的 0 尺寸影子窗口没被设过 parent, 所以 GA_ROOT 返回它自己 ——
        //     旧版步骤 (3) 因此永远走不到。而 owner 这条链是**确定性**的, 与标题无关。
        //     必须走这条: 标题匹配只在"我们的标签页正好是活动页"时才成立, 一旦切页
        //     或 WT 自己改了标题就匹配不上, 这就是"有时候隐藏失败"的主因。
        if (m_console_is_pty) {
            HWND host = ::GetWindow(m_hwnd, GW_OWNER);
            if (host != nullptr && is_console_host_class(host) && is_console_host_process(host)) {
                if (try_hide_window(host)) return true;
            }
        }

        // (1) 经典 conhost: 我们自己的窗口就是屏幕上那个, 直接藏。
        //     ⚠ PTY 下必须跳过这一步: 影子窗口的 WS_VISIBLE 会被 SW_HIDE 清掉,
        //     于是复核"不可见"成立、函数报成功, 但屏幕毫无变化。
        if (!m_console_is_pty && m_win_was_visible) {
            if (try_hide_window(m_hwnd)) return true;
        }

        // (2) 兜底: 按标题去 EnumWindows 里找 (owner 链拿不到时才会走到这儿)。
        if (m_console_is_pty) {
            if (try_hide_window(find_terminal_host_window())) return true;
        }

        // (3) 再兜底: 影子窗口万一挂在某个根窗口下面。
        //     必须先确认根窗口是"可见且没最小化"的, 否则可能把用户别的窗口弄没。
        {
            HWND root = ::GetAncestor(m_hwnd, GA_ROOT);
            if (root != nullptr && root != m_hwnd && is_window_visible(root) &&
                !::IsIconic(root) && is_console_host_class(root)) {
                if (try_hide_window(root)) return true;
            }
        }

        // (4) 都失败: 至少把桌面让出来, 但**如实报失败**, 不假装成功。
        if (m_win_was_visible) ::ShowWindow(m_hwnd, SW_MINIMIZE);
        return false;
    }

    void hide_window()
    {
        m_hidden = true;

        if (!hide_window_impl() && !m_warned) {
            m_warned = true;
            // 现在首选路径是 owner 链, 走到这里说明 owner 和标题这两条都没成。
            // 报出能直接定位问题的三件事: 我们自己是什么窗口、owner 指向谁、owner 的类名。
            HWND owner = ::GetWindow(m_hwnd, GW_OWNER);
            cprint() << "[hotkey] 隐藏失败: 本进程窗口类是 " << window_class_name(m_hwnd)
                     << ", GW_OWNER=" << (unsigned long long)(uintptr_t)owner;
            if (owner != nullptr) {
                cprint() << " (类名 " << window_class_name(owner) << ", 可见="
                         << (is_window_visible(owner) ? 1 : 0) << ")";
            } else {
                cprint() << " (无 owner)";
            }
            cprint() << "。\n"
                        "         owner 链、标题匹配、根窗口都失败, 已退一步最小化。\n"
                        "         把上面这一行发给开发者, 能直接看出宿主窗口挂在哪。"
                     << std::endl;
        }

        // 隐藏**不**停算: 刚按完热键, 必然算"有人在用", 但那只是隐藏窗口这个动作
        // 本身。检测在 kIdleStartDelayMs 之后才生效 (见 idle_tick), 期间照常算。
        // 用幂等的 resume_compute() 而不是直接写 m_paused = false —— 后者在"旗子还
        // 立着"的情况下会让 m_paused 与实际暂停状态脱节, 计算就永远恢复不了。
        resume_compute();
        m_hidden_tick = ::GetTickCount();
    }

    // 显示: 窗口和任务栏按钮一起回来, 并抢到前台。
    void show_window()
    {
        // 先放行计算, 再显示 —— 免得窗口已经出来了计算还停着, 让人以为进程卡死。
        resume_compute();

        // 隐藏时藏的是宿主窗口 (PTY 的 owner / 兜底找到的那个), 恢复也必须把它带回来。
        // 记下来再清空: 后面抢前台要用这个窗口, 而不是 0 尺寸的影子窗口。
        HWND shown = m_hide_target;
        if (m_hide_target != nullptr) {
            ::ShowWindow(m_hide_target, SW_SHOW);
            if (::IsIconic(m_hide_target)) ::ShowWindow(m_hide_target, SW_RESTORE);
            m_hide_target = nullptr;
        }
        ::ShowWindow(m_hwnd, SW_SHOW);
        if (::IsIconic(m_hwnd)) ::ShowWindow(m_hwnd, SW_RESTORE);
        bring_to_front(shown != nullptr ? shown : foreground_target());
        m_hidden = false;
    }

    // 屏幕上那个"用户看着的窗口": 优先用刚恢复的那一个; 其次 PTY 下取 owner;
    // 最后退回自己的窗口 (经典 conhost 就是它)。
    HWND foreground_target() const
    {
        if (m_console_is_pty) {
            HWND owner = ::GetWindow(m_hwnd, GW_OWNER);
            if (owner != nullptr) return owner;
        }
        return m_hwnd;
    }

    void bring_to_front(HWND h)
    {
        if (h == nullptr) return;
        if (::SetForegroundWindow(h)) return;
        // 前台锁 (另一程序正占着前台) 时 SetForegroundWindow 会失败。绕法: 短暂置顶再
        // 取消置顶 —— 这一步把窗口顶到 z 序最前, 之后 SetForegroundWindow 才成功。
        ::SetWindowPos(h, HWND_TOPMOST, 0, 0, 0, 0,
                       SWP_NOMOVE | SWP_NOSIZE | SWP_SHOWWINDOW);
        ::SetWindowPos(h, HWND_NOTOPMOST, 0, 0, 0, 0,
                       SWP_NOMOVE | SWP_NOSIZE | SWP_SHOWWINDOW);
        if (!::SetForegroundWindow(h)) {
            ::FlashWindow(h, TRUE);   // 最后退一步: 任务栏按钮闪一下提醒用户
        }
    }

    HWND m_hwnd = nullptr;
    HANDLE m_stop_event = nullptr;
    std::thread m_thread;
    bool m_registered = false;
    bool m_hidden = false;
    bool m_warned = false;
    bool m_paused = false;   // 是否已向计算侧下过 pause (与 m_hidden 不同: 后者是窗口状态)
    // 隐藏时刻 (GetTickCount 时基)。隐藏后的 kIdleStartDelayMs 内不做键鼠检测。
    ULONGLONG m_hidden_tick = 0;
    // 泵线程里 RegisterHotKey 失败时的 GetLastError, 供 start() 报错用
    unsigned long m_register_error = 0;
    // start() 时控制台窗口是否真的可见。区分"经典 conhost 窗口"与"ConPTY 影子窗口"
    // 的唯一依据 —— 影子窗口创建时就没有 WS_VISIBLE, 对它 SW_HIDE 是空操作。
    bool m_win_was_visible = false;
    // 真正被藏起来的窗口。通常就是 m_hwnd; 若走了宿主回退 (ConPTY 的 WT 窗口 /
    // GA_ROOT) 则指向那个窗口, 恢复时必须把它一起带回来。
    HWND m_hide_target = nullptr;
    // 控制台窗口类名 (宽字符), 以及"是不是 ConPTY 影子窗口"。
    // PTY 下必须跳过我方窗口的 SW_HIDE 复核 —— 影子窗口会"假装藏成功"。
    std::wstring m_console_class;
    bool m_console_is_pty = false;
    // 用来在宿主进程里认出"哪个窗口是我们的终端" (WT 标签标题 = exe 全路径)
    std::wstring m_console_title;
    std::wstring m_exe_path;
};

#else // !_WIN32

class ConsoleToggleHotkey
{
public:
    bool start() { return false; }
    void stop() {}
};

#endif // _WIN32

} // namespace

void validate_test();
void perf_test();
int main(int argc, char* argv[])
{
    // 单例必须在 INIT 之前: INIT 的构造函数就会打开 iLog.txt (exe 同目录, append),
    // 而下面三个常驻入口 (perf / rhoperf / validate) 也都要读那个目录下的状态文件。
    ProcessSingleton singleton;
    if (!singleton.acquired()) {
        cprint() << "已有一个 test_bitcoin 进程在运行 (单例标识 "
#ifdef _WIN32
                 "Local\\bitcoin-rho-test-singleton"
#else
                 "/tmp/bitcoin-rho-test-singleton.lock"
#endif
                 " 已被占用), 本实例退出。\n"
                 "同一时刻只允许一个实例: 两个进程同写一个数据目录会互相覆盖。\n"
                 "确认是不是上一份还没退干净 (Ctrl+C 之后它要先写完盘); 或者到任务管理器里\n"
                 "结束那个 test_bitcoin.exe 再启动。"
              << std::endl;
        return 1;
    }

    // 运行模式：1=仅CPU单线程(无CUDA) 2=multiple=1,CPU 1/4核(默认) 3=multiple=2,CPU 1/2核
    //           4=CPU 核数-2 线程(blockSize 与模式无关, 见 cuda.cu 的 get_optimal_block_size)
    // 用法: test_bitcoin 3  或  test_bitcoin.exe -m 4
    for (int i = 1; i < argc; ++i) {
        int m = 0;
        if (argv[i][0] == '-' || argv[i][0] == '/') {
            if ((argv[i][1] == 'm' || argv[i][1] == 'M') && argv[i][2] == '\0' && i + 1 < argc) {
                m = std::atoi(argv[++i]);     // -m 4
            } else {
                continue;
            }
        } else {
            m = std::atoi(argv[i]);           // 直接数字: 3
        }
        if (m >= 1 && m <= 4) g_run_mode = m;
    }
    std::cout << "run mode: " << g_run_mode << std::endl;

    // 基准/验证的常驻入口, 免去"改代码 -> 跑 -> 还原"的循环:
    //   test_bitcoin.exe perf       跑 perf_test()
    //   test_bitcoin.exe rhoperf    只跑 perf_test_rho_gpu_walkers() (迭代用, 快)
    //   test_bitcoin.exe validate   跑 validate_test()
    // 不带参数时行为与以前完全一致 (走 work())。
    bool run_perf = false, run_validate = false, run_rho_perf = false;

    // 热键开关 (默认开)。Ctrl+Alt+/ 是**整机全局**热键: RegisterHotKey 同一个键
    // 只能有一个进程注册成功, 先注册的那个独占。
    //   典型场景: 本机和远程机器各跑一个实例, 用 VNC 连远程。两边都注册的话, 本机
    //   那个会先把键抢走, 于是在 VNC 窗口里按键只有本机实例响应, 远程的收不到。
    //   给**本机**那个加 -nohotkey, 热键就留给远程实例 (反过来也一样)。
    // 用法: test_EC.exe 2 -nohotkey    或    test_EC.exe 2 /nohotkey
    // (前缀 - 与 / 都收; 大小写不敏感。)
    bool hotkey_enabled = true;

    // GPU 跑哪一路 (默认 rho_play = 40 位生产路)。两路互斥, 理由见 common.h 的说明。
    // 用法: test_EC.exe 2 -edge
    bool want_edge = false;

    for (int i = 1; i < argc; ++i) {
        std::string arg = argv[i];
        if (!arg.empty() && (arg[0] == '-' || arg[0] == '/')) arg.erase(0, 1);
        if (arg.empty()) continue;
        std::transform(arg.begin(), arg.end(), arg.begin(),
                       [](unsigned char c) { return (char)std::tolower(c); });
        if (arg == "perf") run_perf = true;
        else if (arg == "rhoperf") run_rho_perf = true;
        else if (arg == "validate") run_validate = true;
        else if (arg == "nohotkey") hotkey_enabled = false;
        else if (arg == "edge") want_edge = true;
    }
    g_use_edge_play = want_edge;
    if (run_perf && run_validate) {
        cprint() << "perf 与 validate 不能同时跑" << std::endl;
        return 1;
    }

    // 注册信号处理函数，捕获 SIGINT 信号
    std::signal(SIGINT, signalHandler);

    // 控制台窗口热键: Ctrl+Alt+/ 隐藏/显示本窗口 (连任务栏图标一起)。
    // 只有 Windows 真正生效; 其他平台或没有控制台窗口时静默跳过。
    // 热键被别的程序占着会直接报错, 不换键 (详见 ConsoleToggleHotkey 的注释)。
    // 生命周期绑在 main 上: 跑到末尾那句 cin.get() 等回车时热键仍然有效。
    // 启停过程不打印任何提示 —— 这几行提示已经删掉了, 需要时报错会走 cprint()。
    // -nohotkey 时整个对象都不启动: 不注册、不起泵线程, 于是"隐藏窗口 + 空闲停算"
    // 这一整套也一并关闭 (它们全靠这条线程驱动)。
    ConsoleToggleHotkey console_hotkey;
    if (hotkey_enabled) {
        console_hotkey.start();
    } else {
        cprint() << "热键未注册 (-nohotkey): 本实例不响应 Ctrl+Alt+/, 也不做窗口隐藏/空闲停算"
                 << std::endl;
    }

    INIT _init;
    if (run_perf) {
        perf_test();
    } else if (run_rho_perf) {
        perf_test_rho_gpu_walkers();
    } else if (run_validate) {
        validate_test();
    } else {
        // 到真正分派的这一层才打路径 —— 它只影响 work(), perf/validate 不看它。
        // 模式 1 不启动 CUDA, 所以不能报成 "rho_play"。
        if (g_run_mode == 1) {
            cprint() << "gpu path: 无 (run mode 1, 只跑 CPU)" << std::endl;
        } else {
            cprint() << "gpu path: "
                     << (g_use_edge_play ? "dp32_edge_play (32 位边表)"
                                         : "rho_play (40 位 DP)")
                     << std::endl;
        }
        work();
    }

    //test();

    /* Logger::init();
    test_112_helper();
    Logger::cleanup();*/

    std::cout << "Finish. Press Enter..." << std::endl;
    std::cin.get(); // 等待用户按下任意键
    return 0;
}
