// Copyright (c) 2010 Satoshi Nakamoto
// Copyright (c) 2009-2022 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <rpc/blockchain.h>

#include <blockfilter.h>
#include <chain.h>
#include <chainparams.h>
#include <chainparamsbase.h>
#include <clientversion.h>
#include <coins.h>
#include <common/args.h>
#include <consensus/amount.h>
#include <consensus/params.h>
#include <consensus/validation.h>
#include <core_io.h>
#include <deploymentinfo.h>
#include <deploymentstatus.h>
#include <flatfile.h>
#include <hash.h>
#include <index/blockfilterindex.h>
#include <index/coinstatsindex.h>
#include <interfaces/mining.h>
#include <kernel/coinstats.h>
#include <logging/timer.h>
#include <net.h>
#include <net_processing.h>
#include <node/blockstorage.h>
#include <node/context.h>
#include <node/transaction.h>
#include <node/utxo_snapshot.h>
#include <node/warnings.h>
#include <primitives/transaction.h>
#include <rpc/server.h>
#include <rpc/server_util.h>
#include <rpc/util.h>
#include <script/descriptor.h>
#include <serialize.h>
#include <streams.h>
#include <sync.h>
#include <txdb.h>
#include <txmempool.h>
#include <undo.h>
#include <univalue.h>
#include <util/check.h>
#include <util/fs.h>
#include <util/strencodings.h>
#include <util/translation.h>
#include <validation.h>
#include <validationinterface.h>
#include <versionbits.h>

#ifdef WIN32
#include <compat/compat.h> // 必须先于 windows.h 引入 winsock2.h
#include <windows.h>
#else
#include <sched.h>
#endif

#include <stdint.h>

#include <cstdarg>
#include <cstdio>

#include <condition_variable>
#include <memory>
#include <mutex>
#include <optional>
#include <barrier>

// ---------------------------------------------------------------------------
// 控制台输出 (UTF-8 安全)。为什么需要这一层、怎么用, 见 common.h 的说明。
// ---------------------------------------------------------------------------
void cprint_write(const std::string& utf8)
{
#ifdef WIN32
    // UTF-8 -> UTF-16。源串本来就是 UTF-8 (带 /utf-8 编出来的字面量), 这一步正常
    // 不会失败; 真失败了就落到下面原样写, 至少不比从前更糟。
    const int wlen = utf8.empty() ? 0 : MultiByteToWideChar(CP_UTF8, 0, utf8.data(),
                                                            (int)utf8.size(), nullptr, 0);
    if (wlen > 0) {
        std::wstring w((size_t)wlen, L'\0');
        MultiByteToWideChar(CP_UTF8, 0, utf8.data(), (int)utf8.size(), &w[0], wlen);

        // 出口一: stdout 挂在真正的控制台上。WriteConsoleW 收 UTF-16, 与代码页无关,
        // 中文/日文/emoji 都能出 (控制台代码页是 65001 也无所谓)。
        const HANDLE h = GetStdHandle(STD_OUTPUT_HANDLE);
        DWORD mode = 0;
        if (h != nullptr && h != INVALID_HANDLE_VALUE && GetConsoleMode(h, &mode)) {
            std::fflush(stdout);   // 先让 std::cout/printf 压着的字节出去, 免得插队
            DWORD written = 0;
            ::WriteConsoleW(h, w.data(), (DWORD)w.size(), &written, nullptr);
            return;
        }

        // 出口二: stdout 是管道或文件 (PowerShell 抓子进程输出就是这一种) —— 消费端
        // 按**系统 OEM 代码页**解 (PS 5.1 的 [Console]::OutputEncoding 就是启动时
        // 抓下的 OEM CP, 中文机 = 936)。所以这里按 OEM CP 转码再写, 中文就正常。
        const UINT oem = GetOEMCP();
        const int blen = WideCharToMultiByte(oem, 0, w.data(), (int)w.size(), nullptr, 0,
                                             "\x01", nullptr);
        if (blen > 0) {
            std::string out((size_t)blen, '\0');
            WideCharToMultiByte(oem, 0, w.data(), (int)w.size(), &out[0], blen, "\x01", nullptr);
            // 转不出来的字会变成哨兵 '\x01' —— 说明这台机器的 OEM 代码页根本装不下中文
            // (英文机的 437 之类)。那就别糟蹋, 原样写 UTF-8: 那种环境的消费端本来也是 UTF-8。
            if (out.find('\x01') == std::string::npos) {
                std::fwrite(out.data(), 1, out.size(), stdout);
                std::fflush(stdout);
                return;
            }
        }
    }
#endif
    // 非 Windows, 或上面两步都没走通: 原样写 UTF-8。
    std::fwrite(utf8.data(), 1, utf8.size(), stdout);
    std::fflush(stdout);
}

void cprintf(const char* fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    va_list ap2;
    va_copy(ap2, ap);
    const int n = std::vsnprintf(nullptr, 0, fmt, ap);
    va_end(ap);
    if (n > 0) {
        std::string buf((size_t)n + 1, '\0');
        std::vsnprintf(&buf[0], buf.size(), fmt, ap2);
        buf.resize((size_t)n);
        cprint_write(buf);
    }
    va_end(ap2);
}

using kernel::CCoinsStats;
using kernel::CoinStatsHashType;

using interfaces::Mining;
using node::BlockManager;
using node::NodeContext;
using node::SnapshotMetadata;
using util::MakeUnorderedList;

std::tuple<std::unique_ptr<CCoinsViewCursor>, CCoinsStats, const CBlockIndex*>
PrepareUTXOSnapshot(
    Chainstate& chainstate,
    const std::function<void()>& interruption_point = {})
    EXCLUSIVE_LOCKS_REQUIRED(::cs_main);

UniValue WriteUTXOSnapshot(
    Chainstate& chainstate,
    CCoinsViewCursor* pcursor,
    CCoinsStats* maybe_stats,
    const CBlockIndex* tip,
    AutoFile& afile,
    const fs::path& path,
    const fs::path& temppath,
    const std::function<void()>& interruption_point = {});

/* Calculate the difficulty for a given block index.
 */
double GetDifficulty(const CBlockIndex& blockindex)
{
    int nShift = (blockindex.nBits >> 24) & 0xff;
    double dDiff =
        (double)0x0000ffff / (double)(blockindex.nBits & 0x00ffffff);

    while (nShift < 29)
    {
        dDiff *= 256.0;
        nShift++;
    }
    while (nShift > 29)
    {
        dDiff /= 256.0;
        nShift--;
    }

    return dDiff;
}

static int ComputeNextBlockAndDepth(const CBlockIndex& tip, const CBlockIndex& blockindex, const CBlockIndex*& next)
{
    next = tip.GetAncestor(blockindex.nHeight + 1);
    if (next && next->pprev == &blockindex) {
        return tip.nHeight - blockindex.nHeight + 1;
    }
    next = nullptr;
    return &blockindex == &tip ? 1 : -1;
}

static const CBlockIndex* ParseHashOrHeight(const UniValue& param, ChainstateManager& chainman)
{
    LOCK(::cs_main);
    CChain& active_chain = chainman.ActiveChain();

    if (param.isNum()) {
        const int height{param.getInt<int>()};
        if (height < 0) {
            throw JSONRPCError(RPC_INVALID_PARAMETER, strprintf("Target block height %d is negative", height));
        }
        const int current_tip{active_chain.Height()};
        if (height > current_tip) {
            throw JSONRPCError(RPC_INVALID_PARAMETER, strprintf("Target block height %d after current tip %d", height, current_tip));
        }

        return active_chain[height];
    } else {
        const uint256 hash{ParseHashV(param, "hash_or_height")};
        const CBlockIndex* pindex = chainman.m_blockman.LookupBlockIndex(hash);

        if (!pindex) {
            throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Block not found");
        }

        return pindex;
    }
}

UniValue blockheaderToJSON(const CBlockIndex& tip, const CBlockIndex& blockindex)
{
    // Serialize passed information without accessing chain state of the active chain!
    AssertLockNotHeld(cs_main); // For performance reasons

    UniValue result(UniValue::VOBJ);
    result.pushKV("hash", blockindex.GetBlockHash().GetHex());
    const CBlockIndex* pnext;
    int confirmations = ComputeNextBlockAndDepth(tip, blockindex, pnext);
    result.pushKV("confirmations", confirmations);
    result.pushKV("height", blockindex.nHeight);
    result.pushKV("version", blockindex.nVersion);
    result.pushKV("versionHex", strprintf("%08x", blockindex.nVersion));
    result.pushKV("merkleroot", blockindex.hashMerkleRoot.GetHex());
    result.pushKV("time", blockindex.nTime);
    result.pushKV("mediantime", blockindex.GetMedianTimePast());
    result.pushKV("nonce", blockindex.nNonce);
    result.pushKV("bits", strprintf("%08x", blockindex.nBits));
    result.pushKV("difficulty", GetDifficulty(blockindex));
    result.pushKV("chainwork", blockindex.nChainWork.GetHex());
    result.pushKV("nTx", blockindex.nTx);

    if (blockindex.pprev)
        result.pushKV("previousblockhash", blockindex.pprev->GetBlockHash().GetHex());
    if (pnext)
        result.pushKV("nextblockhash", pnext->GetBlockHash().GetHex());
    return result;
}

UniValue blockToJSON(BlockManager& blockman, const CBlock& block, const CBlockIndex& tip, const CBlockIndex& blockindex, TxVerbosity verbosity)
{
    UniValue result = blockheaderToJSON(tip, blockindex);

    result.pushKV("strippedsize", (int)::GetSerializeSize(TX_NO_WITNESS(block)));
    result.pushKV("size", (int)::GetSerializeSize(TX_WITH_WITNESS(block)));
    result.pushKV("weight", (int)::GetBlockWeight(block));
    UniValue txs(UniValue::VARR);

    switch (verbosity) {
        case TxVerbosity::SHOW_TXID:
            for (const CTransactionRef& tx : block.vtx) {
                txs.push_back(tx->GetHash().GetHex());
            }
            break;

        case TxVerbosity::SHOW_DETAILS:
        case TxVerbosity::SHOW_DETAILS_AND_PREVOUT:
            CBlockUndo blockUndo;
            const bool is_not_pruned{WITH_LOCK(::cs_main, return !blockman.IsBlockPruned(blockindex))};
            bool have_undo{is_not_pruned && WITH_LOCK(::cs_main, return blockindex.nStatus & BLOCK_HAVE_UNDO)};
            if (have_undo && !blockman.UndoReadFromDisk(blockUndo, blockindex)) {
                throw JSONRPCError(RPC_INTERNAL_ERROR, "Undo data expected but can't be read. This could be due to disk corruption or a conflict with a pruning event.");
            }
            for (size_t i = 0; i < block.vtx.size(); ++i) {
                const CTransactionRef& tx = block.vtx.at(i);
                // coinbase transaction (i.e. i == 0) doesn't have undo data
                const CTxUndo* txundo = (have_undo && i > 0) ? &blockUndo.vtxundo.at(i - 1) : nullptr;
                UniValue objTx(UniValue::VOBJ);
                TxToUniv(*tx, /*block_hash=*/uint256(), /*entry=*/objTx, /*include_hex=*/true, txundo, verbosity);
                txs.push_back(std::move(objTx));
            }
            break;
    }

    result.pushKV("tx", std::move(txs));

    return result;
}

static RPCHelpMan getblockcount()
{
    return RPCHelpMan{"getblockcount",
                "\nReturns the height of the most-work fully-validated chain.\n"
                "The genesis block has height 0.\n",
                {},
                RPCResult{
                    RPCResult::Type::NUM, "", "The current block count"},
                RPCExamples{
                    HelpExampleCli("getblockcount", "")
            + HelpExampleRpc("getblockcount", "")
                },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    ChainstateManager& chainman = EnsureAnyChainman(request.context);
    LOCK(cs_main);
    return chainman.ActiveChain().Height();
},
    };
}

static RPCHelpMan getbestblockhash()
{
    return RPCHelpMan{"getbestblockhash",
                "\nReturns the hash of the best (tip) block in the most-work fully-validated chain.\n",
                {},
                RPCResult{
                    RPCResult::Type::STR_HEX, "", "the block hash, hex-encoded"},
                RPCExamples{
                    HelpExampleCli("getbestblockhash", "")
            + HelpExampleRpc("getbestblockhash", "")
                },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    ChainstateManager& chainman = EnsureAnyChainman(request.context);
    LOCK(cs_main);
    return chainman.ActiveChain().Tip()->GetBlockHash().GetHex();
},
    };
}

static RPCHelpMan waitfornewblock()
{
    return RPCHelpMan{"waitfornewblock",
                "\nWaits for any new block and returns useful info about it.\n"
                "\nReturns the current block on timeout or exit.\n"
                "\nMake sure to use no RPC timeout (bitcoin-cli -rpcclienttimeout=0)",
                {
                    {"timeout", RPCArg::Type::NUM, RPCArg::Default{0}, "Time in milliseconds to wait for a response. 0 indicates no timeout."},
                },
                RPCResult{
                    RPCResult::Type::OBJ, "", "",
                    {
                        {RPCResult::Type::STR_HEX, "hash", "The blockhash"},
                        {RPCResult::Type::NUM, "height", "Block height"},
                    }},
                RPCExamples{
                    HelpExampleCli("waitfornewblock", "1000")
            + HelpExampleRpc("waitfornewblock", "1000")
                },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    int timeout = 0;
    if (!request.params[0].isNull())
        timeout = request.params[0].getInt<int>();
    if (timeout < 0) throw JSONRPCError(RPC_MISC_ERROR, "Negative timeout");

    NodeContext& node = EnsureAnyNodeContext(request.context);
    Mining& miner = EnsureMining(node);

    auto block{CHECK_NONFATAL(miner.getTip()).value()};
    if (IsRPCRunning()) {
        block = timeout ? miner.waitTipChanged(block.hash, std::chrono::milliseconds(timeout)) : miner.waitTipChanged(block.hash);
    }

    UniValue ret(UniValue::VOBJ);
    ret.pushKV("hash", block.hash.GetHex());
    ret.pushKV("height", block.height);
    return ret;
},
    };
}

static RPCHelpMan waitforblock()
{
    return RPCHelpMan{"waitforblock",
                "\nWaits for a specific new block and returns useful info about it.\n"
                "\nReturns the current block on timeout or exit.\n"
                "\nMake sure to use no RPC timeout (bitcoin-cli -rpcclienttimeout=0)",
                {
                    {"blockhash", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "Block hash to wait for."},
                    {"timeout", RPCArg::Type::NUM, RPCArg::Default{0}, "Time in milliseconds to wait for a response. 0 indicates no timeout."},
                },
                RPCResult{
                    RPCResult::Type::OBJ, "", "",
                    {
                        {RPCResult::Type::STR_HEX, "hash", "The blockhash"},
                        {RPCResult::Type::NUM, "height", "Block height"},
                    }},
                RPCExamples{
                    HelpExampleCli("waitforblock", "\"0000000000079f8ef3d2c688c244eb7a4570b24c9ed7b4a8c619eb02596f8862\" 1000")
            + HelpExampleRpc("waitforblock", "\"0000000000079f8ef3d2c688c244eb7a4570b24c9ed7b4a8c619eb02596f8862\", 1000")
                },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    int timeout = 0;

    uint256 hash(ParseHashV(request.params[0], "blockhash"));

    if (!request.params[1].isNull())
        timeout = request.params[1].getInt<int>();
    if (timeout < 0) throw JSONRPCError(RPC_MISC_ERROR, "Negative timeout");

    NodeContext& node = EnsureAnyNodeContext(request.context);
    Mining& miner = EnsureMining(node);

    auto block{CHECK_NONFATAL(miner.getTip()).value()};
    const auto deadline{std::chrono::steady_clock::now() + 1ms * timeout};
    while (IsRPCRunning() && block.hash != hash) {
        if (timeout) {
            auto now{std::chrono::steady_clock::now()};
            if (now >= deadline) break;
            const MillisecondsDouble remaining{deadline - now};
            block = miner.waitTipChanged(block.hash, remaining);
        } else {
            block = miner.waitTipChanged(block.hash);
        }
    }

    UniValue ret(UniValue::VOBJ);
    ret.pushKV("hash", block.hash.GetHex());
    ret.pushKV("height", block.height);
    return ret;
},
    };
}

static RPCHelpMan waitforblockheight()
{
    return RPCHelpMan{"waitforblockheight",
                "\nWaits for (at least) block height and returns the height and hash\n"
                "of the current tip.\n"
                "\nReturns the current block on timeout or exit.\n"
                "\nMake sure to use no RPC timeout (bitcoin-cli -rpcclienttimeout=0)",
                {
                    {"height", RPCArg::Type::NUM, RPCArg::Optional::NO, "Block height to wait for."},
                    {"timeout", RPCArg::Type::NUM, RPCArg::Default{0}, "Time in milliseconds to wait for a response. 0 indicates no timeout."},
                },
                RPCResult{
                    RPCResult::Type::OBJ, "", "",
                    {
                        {RPCResult::Type::STR_HEX, "hash", "The blockhash"},
                        {RPCResult::Type::NUM, "height", "Block height"},
                    }},
                RPCExamples{
                    HelpExampleCli("waitforblockheight", "100 1000")
            + HelpExampleRpc("waitforblockheight", "100, 1000")
                },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    int timeout = 0;

    int height = request.params[0].getInt<int>();

    if (!request.params[1].isNull())
        timeout = request.params[1].getInt<int>();
    if (timeout < 0) throw JSONRPCError(RPC_MISC_ERROR, "Negative timeout");

    NodeContext& node = EnsureAnyNodeContext(request.context);
    Mining& miner = EnsureMining(node);

    auto block{CHECK_NONFATAL(miner.getTip()).value()};
    const auto deadline{std::chrono::steady_clock::now() + 1ms * timeout};

    while (IsRPCRunning() && block.height < height) {
        if (timeout) {
            auto now{std::chrono::steady_clock::now()};
            if (now >= deadline) break;
            const MillisecondsDouble remaining{deadline - now};
            block = miner.waitTipChanged(block.hash, remaining);
        } else {
            block = miner.waitTipChanged(block.hash);
        }
    }

    UniValue ret(UniValue::VOBJ);
    ret.pushKV("hash", block.hash.GetHex());
    ret.pushKV("height", block.height);
    return ret;
},
    };
}

static RPCHelpMan syncwithvalidationinterfacequeue()
{
    return RPCHelpMan{"syncwithvalidationinterfacequeue",
                "\nWaits for the validation interface queue to catch up on everything that was there when we entered this function.\n",
                {},
                RPCResult{RPCResult::Type::NONE, "", ""},
                RPCExamples{
                    HelpExampleCli("syncwithvalidationinterfacequeue","")
            + HelpExampleRpc("syncwithvalidationinterfacequeue","")
                },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    NodeContext& node = EnsureAnyNodeContext(request.context);
    CHECK_NONFATAL(node.validation_signals)->SyncWithValidationInterfaceQueue();
    return UniValue::VNULL;
},
    };
}

static RPCHelpMan getdifficulty()
{
    return RPCHelpMan{"getdifficulty",
                "\nReturns the proof-of-work difficulty as a multiple of the minimum difficulty.\n",
                {},
                RPCResult{
                    RPCResult::Type::NUM, "", "the proof-of-work difficulty as a multiple of the minimum difficulty."},
                RPCExamples{
                    HelpExampleCli("getdifficulty", "")
            + HelpExampleRpc("getdifficulty", "")
                },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    ChainstateManager& chainman = EnsureAnyChainman(request.context);
    LOCK(cs_main);
    return GetDifficulty(*CHECK_NONFATAL(chainman.ActiveChain().Tip()));
},
    };
}

static RPCHelpMan getblockfrompeer()
{
    return RPCHelpMan{
        "getblockfrompeer",
        "Attempt to fetch block from a given peer.\n\n"
        "We must have the header for this block, e.g. using submitheader.\n"
        "The block will not have any undo data which can limit the usage of the block data in a context where the undo data is needed.\n"
        "Subsequent calls for the same block may cause the response from the previous peer to be ignored.\n"
        "Peers generally ignore requests for a stale block that they never fully verified, or one that is more than a month old.\n"
        "When a peer does not respond with a block, we will disconnect.\n"
        "Note: The block could be re-pruned as soon as it is received.\n\n"
        "Returns an empty JSON object if the request was successfully scheduled.",
        {
            {"blockhash", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "The block hash to try to fetch"},
            {"peer_id", RPCArg::Type::NUM, RPCArg::Optional::NO, "The peer to fetch it from (see getpeerinfo for peer IDs)"},
        },
        RPCResult{RPCResult::Type::OBJ, "", /*optional=*/false, "", {}},
        RPCExamples{
            HelpExampleCli("getblockfrompeer", "\"00000000c937983704a73af28acdec37b049d214adbda81d7e2a3dd146f6ed09\" 0")
            + HelpExampleRpc("getblockfrompeer", "\"00000000c937983704a73af28acdec37b049d214adbda81d7e2a3dd146f6ed09\" 0")
        },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    const NodeContext& node = EnsureAnyNodeContext(request.context);
    ChainstateManager& chainman = EnsureChainman(node);
    PeerManager& peerman = EnsurePeerman(node);

    const uint256& block_hash{ParseHashV(request.params[0], "blockhash")};
    const NodeId peer_id{request.params[1].getInt<int64_t>()};

    const CBlockIndex* const index = WITH_LOCK(cs_main, return chainman.m_blockman.LookupBlockIndex(block_hash););

    if (!index) {
        throw JSONRPCError(RPC_MISC_ERROR, "Block header missing");
    }

    // Fetching blocks before the node has syncing past their height can prevent block files from
    // being pruned, so we avoid it if the node is in prune mode.
    if (chainman.m_blockman.IsPruneMode() && index->nHeight > WITH_LOCK(chainman.GetMutex(), return chainman.ActiveTip()->nHeight)) {
        throw JSONRPCError(RPC_MISC_ERROR, "In prune mode, only blocks that the node has already synced previously can be fetched from a peer");
    }

    const bool block_has_data = WITH_LOCK(::cs_main, return index->nStatus & BLOCK_HAVE_DATA);
    if (block_has_data) {
        throw JSONRPCError(RPC_MISC_ERROR, "Block already downloaded");
    }

    if (const auto err{peerman.FetchBlock(peer_id, *index)}) {
        throw JSONRPCError(RPC_MISC_ERROR, err.value());
    }
    return UniValue::VOBJ;
},
    };
}

static RPCHelpMan getblockhash()
{
    return RPCHelpMan{"getblockhash",
                "\nReturns hash of block in best-block-chain at height provided.\n",
                {
                    {"height", RPCArg::Type::NUM, RPCArg::Optional::NO, "The height index"},
                },
                RPCResult{
                    RPCResult::Type::STR_HEX, "", "The block hash"},
                RPCExamples{
                    HelpExampleCli("getblockhash", "1000")
            + HelpExampleRpc("getblockhash", "1000")
                },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    ChainstateManager& chainman = EnsureAnyChainman(request.context);
    LOCK(cs_main);
    const CChain& active_chain = chainman.ActiveChain();

    int nHeight = request.params[0].getInt<int>();
    if (nHeight < 0 || nHeight > active_chain.Height())
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Block height out of range");

    const CBlockIndex* pblockindex = active_chain[nHeight];
    return pblockindex->GetBlockHash().GetHex();
},
    };
}

static RPCHelpMan getblockheader()
{
    return RPCHelpMan{"getblockheader",
                "\nIf verbose is false, returns a string that is serialized, hex-encoded data for blockheader 'hash'.\n"
                "If verbose is true, returns an Object with information about blockheader <hash>.\n",
                {
                    {"blockhash", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "The block hash"},
                    {"verbose", RPCArg::Type::BOOL, RPCArg::Default{true}, "true for a json object, false for the hex-encoded data"},
                },
                {
                    RPCResult{"for verbose = true",
                        RPCResult::Type::OBJ, "", "",
                        {
                            {RPCResult::Type::STR_HEX, "hash", "the block hash (same as provided)"},
                            {RPCResult::Type::NUM, "confirmations", "The number of confirmations, or -1 if the block is not on the main chain"},
                            {RPCResult::Type::NUM, "height", "The block height or index"},
                            {RPCResult::Type::NUM, "version", "The block version"},
                            {RPCResult::Type::STR_HEX, "versionHex", "The block version formatted in hexadecimal"},
                            {RPCResult::Type::STR_HEX, "merkleroot", "The merkle root"},
                            {RPCResult::Type::NUM_TIME, "time", "The block time expressed in " + UNIX_EPOCH_TIME},
                            {RPCResult::Type::NUM_TIME, "mediantime", "The median block time expressed in " + UNIX_EPOCH_TIME},
                            {RPCResult::Type::NUM, "nonce", "The nonce"},
                            {RPCResult::Type::STR_HEX, "bits", "The bits"},
                            {RPCResult::Type::NUM, "difficulty", "The difficulty"},
                            {RPCResult::Type::STR_HEX, "chainwork", "Expected number of hashes required to produce the current chain"},
                            {RPCResult::Type::NUM, "nTx", "The number of transactions in the block"},
                            {RPCResult::Type::STR_HEX, "previousblockhash", /*optional=*/true, "The hash of the previous block (if available)"},
                            {RPCResult::Type::STR_HEX, "nextblockhash", /*optional=*/true, "The hash of the next block (if available)"},
                        }},
                    RPCResult{"for verbose=false",
                        RPCResult::Type::STR_HEX, "", "A string that is serialized, hex-encoded data for block 'hash'"},
                },
                RPCExamples{
                    HelpExampleCli("getblockheader", "\"00000000c937983704a73af28acdec37b049d214adbda81d7e2a3dd146f6ed09\"")
            + HelpExampleRpc("getblockheader", "\"00000000c937983704a73af28acdec37b049d214adbda81d7e2a3dd146f6ed09\"")
                },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    uint256 hash(ParseHashV(request.params[0], "hash"));

    bool fVerbose = true;
    if (!request.params[1].isNull())
        fVerbose = request.params[1].get_bool();

    const CBlockIndex* pblockindex;
    const CBlockIndex* tip;
    {
        ChainstateManager& chainman = EnsureAnyChainman(request.context);
        LOCK(cs_main);
        pblockindex = chainman.m_blockman.LookupBlockIndex(hash);
        tip = chainman.ActiveChain().Tip();
    }

    if (!pblockindex) {
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Block not found");
    }

    if (!fVerbose)
    {
        DataStream ssBlock{};
        ssBlock << pblockindex->GetBlockHeader();
        std::string strHex = HexStr(ssBlock);
        return strHex;
    }

    return blockheaderToJSON(*tip, *pblockindex);
},
    };
}

void CheckBlockDataAvailability(BlockManager& blockman, const CBlockIndex& blockindex, bool check_for_undo)
{
    AssertLockHeld(cs_main);
    uint32_t flag = check_for_undo ? BLOCK_HAVE_UNDO : BLOCK_HAVE_DATA;
    if (!(blockindex.nStatus & flag)) {
        if (blockman.IsBlockPruned(blockindex)) {
            throw JSONRPCError(RPC_MISC_ERROR, strprintf("%s not available (pruned data)", check_for_undo ? "Undo data" : "Block"));
        }
        if (check_for_undo) {
            throw JSONRPCError(RPC_MISC_ERROR, "Undo data not available");
        }
        throw JSONRPCError(RPC_MISC_ERROR, "Block not available (not fully downloaded)");
    }
}

static CBlock GetBlockChecked(BlockManager& blockman, const CBlockIndex& blockindex)
{
    CBlock block;
    {
        LOCK(cs_main);
        CheckBlockDataAvailability(blockman, blockindex, /*check_for_undo=*/false);
    }

    if (!blockman.ReadBlockFromDisk(block, blockindex)) {
        // Block not found on disk. This shouldn't normally happen unless the block was
        // pruned right after we released the lock above.
        throw JSONRPCError(RPC_MISC_ERROR, "Block not found on disk");
    }

    return block;
}

static std::vector<uint8_t> GetRawBlockChecked(BlockManager& blockman, const CBlockIndex& blockindex)
{
    std::vector<uint8_t> data{};
    FlatFilePos pos{};
    {
        LOCK(cs_main);
        CheckBlockDataAvailability(blockman, blockindex, /*check_for_undo=*/false);
        pos = blockindex.GetBlockPos();
    }

    if (!blockman.ReadRawBlockFromDisk(data, pos)) {
        // Block not found on disk. This shouldn't normally happen unless the block was
        // pruned right after we released the lock above.
        throw JSONRPCError(RPC_MISC_ERROR, "Block not found on disk");
    }

    return data;
}

static CBlockUndo GetUndoChecked(BlockManager& blockman, const CBlockIndex& blockindex)
{
    CBlockUndo blockUndo;

    // The Genesis block does not have undo data
    if (blockindex.nHeight == 0) return blockUndo;

    {
        LOCK(cs_main);
        CheckBlockDataAvailability(blockman, blockindex, /*check_for_undo=*/true);
    }

    if (!blockman.UndoReadFromDisk(blockUndo, blockindex)) {
        throw JSONRPCError(RPC_MISC_ERROR, "Can't read undo data from disk");
    }

    return blockUndo;
}

const RPCResult getblock_vin{
    RPCResult::Type::ARR, "vin", "",
    {
        {RPCResult::Type::OBJ, "", "",
        {
            {RPCResult::Type::ELISION, "", "The same output as verbosity = 2"},
            {RPCResult::Type::OBJ, "prevout", "(Only if undo information is available)",
            {
                {RPCResult::Type::BOOL, "generated", "Coinbase or not"},
                {RPCResult::Type::NUM, "height", "The height of the prevout"},
                {RPCResult::Type::STR_AMOUNT, "value", "The value in " + CURRENCY_UNIT},
                {RPCResult::Type::OBJ, "scriptPubKey", "",
                {
                    {RPCResult::Type::STR, "asm", "Disassembly of the output script"},
                    {RPCResult::Type::STR, "desc", "Inferred descriptor for the output"},
                    {RPCResult::Type::STR_HEX, "hex", "The raw output script bytes, hex-encoded"},
                    {RPCResult::Type::STR, "address", /*optional=*/true, "The Bitcoin address (only if a well-defined address exists)"},
                    {RPCResult::Type::STR, "type", "The type (one of: " + GetAllOutputTypes() + ")"},
                }},
            }},
        }},
    }
};

static RPCHelpMan getblock()
{
    return RPCHelpMan{"getblock",
                "\nIf verbosity is 0, returns a string that is serialized, hex-encoded data for block 'hash'.\n"
                "If verbosity is 1, returns an Object with information about block <hash>.\n"
                "If verbosity is 2, returns an Object with information about block <hash> and information about each transaction.\n"
                "If verbosity is 3, returns an Object with information about block <hash> and information about each transaction, including prevout information for inputs (only for unpruned blocks in the current best chain).\n",
                {
                    {"blockhash", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "The block hash"},
                    {"verbosity|verbose", RPCArg::Type::NUM, RPCArg::Default{1}, "0 for hex-encoded data, 1 for a JSON object, 2 for JSON object with transaction data, and 3 for JSON object with transaction data including prevout information for inputs",
                     RPCArgOptions{.skip_type_check = true}},
                },
                {
                    RPCResult{"for verbosity = 0",
                RPCResult::Type::STR_HEX, "", "A string that is serialized, hex-encoded data for block 'hash'"},
                    RPCResult{"for verbosity = 1",
                RPCResult::Type::OBJ, "", "",
                {
                    {RPCResult::Type::STR_HEX, "hash", "the block hash (same as provided)"},
                    {RPCResult::Type::NUM, "confirmations", "The number of confirmations, or -1 if the block is not on the main chain"},
                    {RPCResult::Type::NUM, "size", "The block size"},
                    {RPCResult::Type::NUM, "strippedsize", "The block size excluding witness data"},
                    {RPCResult::Type::NUM, "weight", "The block weight as defined in BIP 141"},
                    {RPCResult::Type::NUM, "height", "The block height or index"},
                    {RPCResult::Type::NUM, "version", "The block version"},
                    {RPCResult::Type::STR_HEX, "versionHex", "The block version formatted in hexadecimal"},
                    {RPCResult::Type::STR_HEX, "merkleroot", "The merkle root"},
                    {RPCResult::Type::ARR, "tx", "The transaction ids",
                        {{RPCResult::Type::STR_HEX, "", "The transaction id"}}},
                    {RPCResult::Type::NUM_TIME, "time",       "The block time expressed in " + UNIX_EPOCH_TIME},
                    {RPCResult::Type::NUM_TIME, "mediantime", "The median block time expressed in " + UNIX_EPOCH_TIME},
                    {RPCResult::Type::NUM, "nonce", "The nonce"},
                    {RPCResult::Type::STR_HEX, "bits", "The bits"},
                    {RPCResult::Type::NUM, "difficulty", "The difficulty"},
                    {RPCResult::Type::STR_HEX, "chainwork", "Expected number of hashes required to produce the chain up to this block (in hex)"},
                    {RPCResult::Type::NUM, "nTx", "The number of transactions in the block"},
                    {RPCResult::Type::STR_HEX, "previousblockhash", /*optional=*/true, "The hash of the previous block (if available)"},
                    {RPCResult::Type::STR_HEX, "nextblockhash", /*optional=*/true, "The hash of the next block (if available)"},
                }},
                    RPCResult{"for verbosity = 2",
                RPCResult::Type::OBJ, "", "",
                {
                    {RPCResult::Type::ELISION, "", "Same output as verbosity = 1"},
                    {RPCResult::Type::ARR, "tx", "",
                    {
                        {RPCResult::Type::OBJ, "", "",
                        {
                            {RPCResult::Type::ELISION, "", "The transactions in the format of the getrawtransaction RPC. Different from verbosity = 1 \"tx\" result"},
                            {RPCResult::Type::NUM, "fee", "The transaction fee in " + CURRENCY_UNIT + ", omitted if block undo data is not available"},
                        }},
                    }},
                }},
                    RPCResult{"for verbosity = 3",
                RPCResult::Type::OBJ, "", "",
                {
                    {RPCResult::Type::ELISION, "", "Same output as verbosity = 2"},
                    {RPCResult::Type::ARR, "tx", "",
                    {
                        {RPCResult::Type::OBJ, "", "",
                        {
                            getblock_vin,
                        }},
                    }},
                }},
        },
                RPCExamples{
                    HelpExampleCli("getblock", "\"00000000c937983704a73af28acdec37b049d214adbda81d7e2a3dd146f6ed09\"")
            + HelpExampleRpc("getblock", "\"00000000c937983704a73af28acdec37b049d214adbda81d7e2a3dd146f6ed09\"")
                },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    uint256 hash(ParseHashV(request.params[0], "blockhash"));

    int verbosity{ParseVerbosity(request.params[1], /*default_verbosity=*/1)};

    const CBlockIndex* pblockindex;
    const CBlockIndex* tip;
    ChainstateManager& chainman = EnsureAnyChainman(request.context);
    {
        LOCK(cs_main);
        pblockindex = chainman.m_blockman.LookupBlockIndex(hash);
        tip = chainman.ActiveChain().Tip();

        if (!pblockindex) {
            throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Block not found");
        }
    }

    const std::vector<uint8_t> block_data{GetRawBlockChecked(chainman.m_blockman, *pblockindex)};

    if (verbosity <= 0) {
        return HexStr(block_data);
    }

    DataStream block_stream{block_data};
    CBlock block{};
    block_stream >> TX_WITH_WITNESS(block);

    TxVerbosity tx_verbosity;
    if (verbosity == 1) {
        tx_verbosity = TxVerbosity::SHOW_TXID;
    } else if (verbosity == 2) {
        tx_verbosity = TxVerbosity::SHOW_DETAILS;
    } else {
        tx_verbosity = TxVerbosity::SHOW_DETAILS_AND_PREVOUT;
    }

    return blockToJSON(chainman.m_blockman, block, *tip, *pblockindex, tx_verbosity);
},
    };
}

//! Return height of highest block that has been pruned, or std::nullopt if no blocks have been pruned
std::optional<int> GetPruneHeight(const BlockManager& blockman, const CChain& chain) {
    AssertLockHeld(::cs_main);

    // Search for the last block missing block data or undo data. Don't let the
    // search consider the genesis block, because the genesis block does not
    // have undo data, but should not be considered pruned.
    const CBlockIndex* first_block{chain[1]};
    const CBlockIndex* chain_tip{chain.Tip()};

    // If there are no blocks after the genesis block, or no blocks at all, nothing is pruned.
    if (!first_block || !chain_tip) return std::nullopt;

    // If the chain tip is pruned, everything is pruned.
    if (!((chain_tip->nStatus & BLOCK_HAVE_MASK) == BLOCK_HAVE_MASK)) return chain_tip->nHeight;

    const auto& first_unpruned{*CHECK_NONFATAL(blockman.GetFirstBlock(*chain_tip, /*status_mask=*/BLOCK_HAVE_MASK, first_block))};
    if (&first_unpruned == first_block) {
        // All blocks between first_block and chain_tip have data, so nothing is pruned.
        return std::nullopt;
    }

    // Block before the first unpruned block is the last pruned block.
    return CHECK_NONFATAL(first_unpruned.pprev)->nHeight;
}

static RPCHelpMan pruneblockchain()
{
    return RPCHelpMan{"pruneblockchain", "",
                {
                    {"height", RPCArg::Type::NUM, RPCArg::Optional::NO, "The block height to prune up to. May be set to a discrete height, or to a " + UNIX_EPOCH_TIME + "\n"
            "                  to prune blocks whose block time is at least 2 hours older than the provided timestamp."},
                },
                RPCResult{
                    RPCResult::Type::NUM, "", "Height of the last block pruned"},
                RPCExamples{
                    HelpExampleCli("pruneblockchain", "1000")
            + HelpExampleRpc("pruneblockchain", "1000")
                },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    ChainstateManager& chainman = EnsureAnyChainman(request.context);
    if (!chainman.m_blockman.IsPruneMode()) {
        throw JSONRPCError(RPC_MISC_ERROR, "Cannot prune blocks because node is not in prune mode.");
    }

    LOCK(cs_main);
    Chainstate& active_chainstate = chainman.ActiveChainstate();
    CChain& active_chain = active_chainstate.m_chain;

    int heightParam = request.params[0].getInt<int>();
    if (heightParam < 0) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Negative block height.");
    }

    // Height value more than a billion is too high to be a block height, and
    // too low to be a block time (corresponds to timestamp from Sep 2001).
    if (heightParam > 1000000000) {
        // Add a 2 hour buffer to include blocks which might have had old timestamps
        const CBlockIndex* pindex = active_chain.FindEarliestAtLeast(heightParam - TIMESTAMP_WINDOW, 0);
        if (!pindex) {
            throw JSONRPCError(RPC_INVALID_PARAMETER, "Could not find block with at least the specified timestamp.");
        }
        heightParam = pindex->nHeight;
    }

    unsigned int height = (unsigned int) heightParam;
    unsigned int chainHeight = (unsigned int) active_chain.Height();
    if (chainHeight < chainman.GetParams().PruneAfterHeight()) {
        throw JSONRPCError(RPC_MISC_ERROR, "Blockchain is too short for pruning.");
    } else if (height > chainHeight) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Blockchain is shorter than the attempted prune height.");
    } else if (height > chainHeight - MIN_BLOCKS_TO_KEEP) {
        LogDebug(BCLog::RPC, "Attempt to prune blocks close to the tip.  Retaining the minimum number of blocks.\n");
        height = chainHeight - MIN_BLOCKS_TO_KEEP;
    }

    PruneBlockFilesManual(active_chainstate, height);
    return GetPruneHeight(chainman.m_blockman, active_chain).value_or(-1);
},
    };
}

CoinStatsHashType ParseHashType(const std::string& hash_type_input)
{
    if (hash_type_input == "hash_serialized_3") {
        return CoinStatsHashType::HASH_SERIALIZED;
    } else if (hash_type_input == "muhash") {
        return CoinStatsHashType::MUHASH;
    } else if (hash_type_input == "none") {
        return CoinStatsHashType::NONE;
    } else {
        throw JSONRPCError(RPC_INVALID_PARAMETER, strprintf("'%s' is not a valid hash_type", hash_type_input));
    }
}

/**
 * Calculate statistics about the unspent transaction output set
 *
 * @param[in] index_requested Signals if the coinstatsindex should be used (when available).
 */
static std::optional<kernel::CCoinsStats> GetUTXOStats(CCoinsView* view, node::BlockManager& blockman,
                                                       kernel::CoinStatsHashType hash_type,
                                                       const std::function<void()>& interruption_point = {},
                                                       const CBlockIndex* pindex = nullptr,
                                                       bool index_requested = true)
{
    // Use CoinStatsIndex if it is requested and available and a hash_type of Muhash or None was requested
    if ((hash_type == kernel::CoinStatsHashType::MUHASH || hash_type == kernel::CoinStatsHashType::NONE) && g_coin_stats_index && index_requested) {
        if (pindex) {
            return g_coin_stats_index->LookUpStats(*pindex);
        } else {
            CBlockIndex& block_index = *CHECK_NONFATAL(WITH_LOCK(::cs_main, return blockman.LookupBlockIndex(view->GetBestBlock())));
            return g_coin_stats_index->LookUpStats(block_index);
        }
    }

    // If the coinstats index isn't requested or is otherwise not usable, the
    // pindex should either be null or equal to the view's best block. This is
    // because without the coinstats index we can only get coinstats about the
    // best block.
    CHECK_NONFATAL(!pindex || pindex->GetBlockHash() == view->GetBestBlock());

    return kernel::ComputeUTXOStats(hash_type, view, blockman, interruption_point);
}

static RPCHelpMan gettxoutsetinfo()
{
    return RPCHelpMan{"gettxoutsetinfo",
                "\nReturns statistics about the unspent transaction output set.\n"
                "Note this call may take some time if you are not using coinstatsindex.\n",
                {
                    {"hash_type", RPCArg::Type::STR, RPCArg::Default{"hash_serialized_3"}, "Which UTXO set hash should be calculated. Options: 'hash_serialized_3' (the legacy algorithm), 'muhash', 'none'."},
                    {"hash_or_height", RPCArg::Type::NUM, RPCArg::DefaultHint{"the current best block"}, "The block hash or height of the target height (only available with coinstatsindex).",
                     RPCArgOptions{
                         .skip_type_check = true,
                         .type_str = {"", "string or numeric"},
                     }},
                    {"use_index", RPCArg::Type::BOOL, RPCArg::Default{true}, "Use coinstatsindex, if available."},
                },
                RPCResult{
                    RPCResult::Type::OBJ, "", "",
                    {
                        {RPCResult::Type::NUM, "height", "The block height (index) of the returned statistics"},
                        {RPCResult::Type::STR_HEX, "bestblock", "The hash of the block at which these statistics are calculated"},
                        {RPCResult::Type::NUM, "txouts", "The number of unspent transaction outputs"},
                        {RPCResult::Type::NUM, "bogosize", "Database-independent, meaningless metric indicating the UTXO set size"},
                        {RPCResult::Type::STR_HEX, "hash_serialized_3", /*optional=*/true, "The serialized hash (only present if 'hash_serialized_3' hash_type is chosen)"},
                        {RPCResult::Type::STR_HEX, "muhash", /*optional=*/true, "The serialized hash (only present if 'muhash' hash_type is chosen)"},
                        {RPCResult::Type::NUM, "transactions", /*optional=*/true, "The number of transactions with unspent outputs (not available when coinstatsindex is used)"},
                        {RPCResult::Type::NUM, "disk_size", /*optional=*/true, "The estimated size of the chainstate on disk (not available when coinstatsindex is used)"},
                        {RPCResult::Type::STR_AMOUNT, "total_amount", "The total amount of coins in the UTXO set"},
                        {RPCResult::Type::STR_AMOUNT, "total_unspendable_amount", /*optional=*/true, "The total amount of coins permanently excluded from the UTXO set (only available if coinstatsindex is used)"},
                        {RPCResult::Type::OBJ, "block_info", /*optional=*/true, "Info on amounts in the block at this block height (only available if coinstatsindex is used)",
                        {
                            {RPCResult::Type::STR_AMOUNT, "prevout_spent", "Total amount of all prevouts spent in this block"},
                            {RPCResult::Type::STR_AMOUNT, "coinbase", "Coinbase subsidy amount of this block"},
                            {RPCResult::Type::STR_AMOUNT, "new_outputs_ex_coinbase", "Total amount of new outputs created by this block"},
                            {RPCResult::Type::STR_AMOUNT, "unspendable", "Total amount of unspendable outputs created in this block"},
                            {RPCResult::Type::OBJ, "unspendables", "Detailed view of the unspendable categories",
                            {
                                {RPCResult::Type::STR_AMOUNT, "genesis_block", "The unspendable amount of the Genesis block subsidy"},
                                {RPCResult::Type::STR_AMOUNT, "bip30", "Transactions overridden by duplicates (no longer possible with BIP30)"},
                                {RPCResult::Type::STR_AMOUNT, "scripts", "Amounts sent to scripts that are unspendable (for example OP_RETURN outputs)"},
                                {RPCResult::Type::STR_AMOUNT, "unclaimed_rewards", "Fee rewards that miners did not claim in their coinbase transaction"},
                            }}
                        }},
                    }},
                RPCExamples{
                    HelpExampleCli("gettxoutsetinfo", "") +
                    HelpExampleCli("gettxoutsetinfo", R"("none")") +
                    HelpExampleCli("gettxoutsetinfo", R"("none" 1000)") +
                    HelpExampleCli("gettxoutsetinfo", R"("none" '"00000000c937983704a73af28acdec37b049d214adbda81d7e2a3dd146f6ed09"')") +
                    HelpExampleCli("-named gettxoutsetinfo", R"(hash_type='muhash' use_index='false')") +
                    HelpExampleRpc("gettxoutsetinfo", "") +
                    HelpExampleRpc("gettxoutsetinfo", R"("none")") +
                    HelpExampleRpc("gettxoutsetinfo", R"("none", 1000)") +
                    HelpExampleRpc("gettxoutsetinfo", R"("none", "00000000c937983704a73af28acdec37b049d214adbda81d7e2a3dd146f6ed09")")
                },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    UniValue ret(UniValue::VOBJ);

    const CBlockIndex* pindex{nullptr};
    const CoinStatsHashType hash_type{request.params[0].isNull() ? CoinStatsHashType::HASH_SERIALIZED : ParseHashType(request.params[0].get_str())};
    bool index_requested = request.params[2].isNull() || request.params[2].get_bool();

    NodeContext& node = EnsureAnyNodeContext(request.context);
    ChainstateManager& chainman = EnsureChainman(node);
    Chainstate& active_chainstate = chainman.ActiveChainstate();
    active_chainstate.ForceFlushStateToDisk();

    CCoinsView* coins_view;
    BlockManager* blockman;
    {
        LOCK(::cs_main);
        coins_view = &active_chainstate.CoinsDB();
        blockman = &active_chainstate.m_blockman;
        pindex = blockman->LookupBlockIndex(coins_view->GetBestBlock());
    }

    if (!request.params[1].isNull()) {
        if (!g_coin_stats_index) {
            throw JSONRPCError(RPC_INVALID_PARAMETER, "Querying specific block heights requires coinstatsindex");
        }

        if (hash_type == CoinStatsHashType::HASH_SERIALIZED) {
            throw JSONRPCError(RPC_INVALID_PARAMETER, "hash_serialized_3 hash type cannot be queried for a specific block");
        }

        if (!index_requested) {
            throw JSONRPCError(RPC_INVALID_PARAMETER, "Cannot set use_index to false when querying for a specific block");
        }
        pindex = ParseHashOrHeight(request.params[1], chainman);
    }

    if (index_requested && g_coin_stats_index) {
        if (!g_coin_stats_index->BlockUntilSyncedToCurrentChain()) {
            const IndexSummary summary{g_coin_stats_index->GetSummary()};

            // If a specific block was requested and the index has already synced past that height, we can return the
            // data already even though the index is not fully synced yet.
            if (pindex->nHeight > summary.best_block_height) {
                throw JSONRPCError(RPC_INTERNAL_ERROR, strprintf("Unable to get data because coinstatsindex is still syncing. Current height: %d", summary.best_block_height));
            }
        }
    }

    const std::optional<CCoinsStats> maybe_stats = GetUTXOStats(coins_view, *blockman, hash_type, node.rpc_interruption_point, pindex, index_requested);
    if (maybe_stats.has_value()) {
        const CCoinsStats& stats = maybe_stats.value();
        ret.pushKV("height", (int64_t)stats.nHeight);
        ret.pushKV("bestblock", stats.hashBlock.GetHex());
        ret.pushKV("txouts", (int64_t)stats.nTransactionOutputs);
        ret.pushKV("bogosize", (int64_t)stats.nBogoSize);
        if (hash_type == CoinStatsHashType::HASH_SERIALIZED) {
            ret.pushKV("hash_serialized_3", stats.hashSerialized.GetHex());
        }
        if (hash_type == CoinStatsHashType::MUHASH) {
            ret.pushKV("muhash", stats.hashSerialized.GetHex());
        }
        CHECK_NONFATAL(stats.total_amount.has_value());
        ret.pushKV("total_amount", ValueFromAmount(stats.total_amount.value()));
        if (!stats.index_used) {
            ret.pushKV("transactions", static_cast<int64_t>(stats.nTransactions));
            ret.pushKV("disk_size", stats.nDiskSize);
        } else {
            ret.pushKV("total_unspendable_amount", ValueFromAmount(stats.total_unspendable_amount));

            CCoinsStats prev_stats{};
            if (pindex->nHeight > 0) {
                const std::optional<CCoinsStats> maybe_prev_stats = GetUTXOStats(coins_view, *blockman, hash_type, node.rpc_interruption_point, pindex->pprev, index_requested);
                if (!maybe_prev_stats) {
                    throw JSONRPCError(RPC_INTERNAL_ERROR, "Unable to read UTXO set");
                }
                prev_stats = maybe_prev_stats.value();
            }

            UniValue block_info(UniValue::VOBJ);
            block_info.pushKV("prevout_spent", ValueFromAmount(stats.total_prevout_spent_amount - prev_stats.total_prevout_spent_amount));
            block_info.pushKV("coinbase", ValueFromAmount(stats.total_coinbase_amount - prev_stats.total_coinbase_amount));
            block_info.pushKV("new_outputs_ex_coinbase", ValueFromAmount(stats.total_new_outputs_ex_coinbase_amount - prev_stats.total_new_outputs_ex_coinbase_amount));
            block_info.pushKV("unspendable", ValueFromAmount(stats.total_unspendable_amount - prev_stats.total_unspendable_amount));

            UniValue unspendables(UniValue::VOBJ);
            unspendables.pushKV("genesis_block", ValueFromAmount(stats.total_unspendables_genesis_block - prev_stats.total_unspendables_genesis_block));
            unspendables.pushKV("bip30", ValueFromAmount(stats.total_unspendables_bip30 - prev_stats.total_unspendables_bip30));
            unspendables.pushKV("scripts", ValueFromAmount(stats.total_unspendables_scripts - prev_stats.total_unspendables_scripts));
            unspendables.pushKV("unclaimed_rewards", ValueFromAmount(stats.total_unspendables_unclaimed_rewards - prev_stats.total_unspendables_unclaimed_rewards));
            block_info.pushKV("unspendables", std::move(unspendables));

            ret.pushKV("block_info", std::move(block_info));
        }
    } else {
        throw JSONRPCError(RPC_INTERNAL_ERROR, "Unable to read UTXO set");
    }
    return ret;
},
    };
}

static RPCHelpMan gettxout()
{
    return RPCHelpMan{"gettxout",
        "\nReturns details about an unspent transaction output.\n",
        {
            {"txid", RPCArg::Type::STR, RPCArg::Optional::NO, "The transaction id"},
            {"n", RPCArg::Type::NUM, RPCArg::Optional::NO, "vout number"},
            {"include_mempool", RPCArg::Type::BOOL, RPCArg::Default{true}, "Whether to include the mempool. Note that an unspent output that is spent in the mempool won't appear."},
        },
        {
            RPCResult{"If the UTXO was not found", RPCResult::Type::NONE, "", ""},
            RPCResult{"Otherwise", RPCResult::Type::OBJ, "", "", {
                {RPCResult::Type::STR_HEX, "bestblock", "The hash of the block at the tip of the chain"},
                {RPCResult::Type::NUM, "confirmations", "The number of confirmations"},
                {RPCResult::Type::STR_AMOUNT, "value", "The transaction value in " + CURRENCY_UNIT},
                {RPCResult::Type::OBJ, "scriptPubKey", "", {
                    {RPCResult::Type::STR, "asm", "Disassembly of the output script"},
                    {RPCResult::Type::STR, "desc", "Inferred descriptor for the output"},
                    {RPCResult::Type::STR_HEX, "hex", "The raw output script bytes, hex-encoded"},
                    {RPCResult::Type::STR, "type", "The type, eg pubkeyhash"},
                    {RPCResult::Type::STR, "address", /*optional=*/true, "The Bitcoin address (only if a well-defined address exists)"},
                }},
                {RPCResult::Type::BOOL, "coinbase", "Coinbase or not"},
            }},
        },
        RPCExamples{
            "\nGet unspent transactions\n"
            + HelpExampleCli("listunspent", "") +
            "\nView the details\n"
            + HelpExampleCli("gettxout", "\"txid\" 1") +
            "\nAs a JSON-RPC call\n"
            + HelpExampleRpc("gettxout", "\"txid\", 1")
                },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    NodeContext& node = EnsureAnyNodeContext(request.context);
    ChainstateManager& chainman = EnsureChainman(node);
    LOCK(cs_main);

    UniValue ret(UniValue::VOBJ);

    auto hash{Txid::FromUint256(ParseHashV(request.params[0], "txid"))};
    COutPoint out{hash, request.params[1].getInt<uint32_t>()};
    bool fMempool = true;
    if (!request.params[2].isNull())
        fMempool = request.params[2].get_bool();

    Coin coin;
    Chainstate& active_chainstate = chainman.ActiveChainstate();
    CCoinsViewCache* coins_view = &active_chainstate.CoinsTip();

    if (fMempool) {
        const CTxMemPool& mempool = EnsureMemPool(node);
        LOCK(mempool.cs);
        CCoinsViewMemPool view(coins_view, mempool);
        if (!view.GetCoin(out, coin) || mempool.isSpent(out)) {
            return UniValue::VNULL;
        }
    } else {
        if (!coins_view->GetCoin(out, coin)) {
            return UniValue::VNULL;
        }
    }

    const CBlockIndex* pindex = active_chainstate.m_blockman.LookupBlockIndex(coins_view->GetBestBlock());
    ret.pushKV("bestblock", pindex->GetBlockHash().GetHex());
    if (coin.nHeight == MEMPOOL_HEIGHT) {
        ret.pushKV("confirmations", 0);
    } else {
        ret.pushKV("confirmations", (int64_t)(pindex->nHeight - coin.nHeight + 1));
    }
    ret.pushKV("value", ValueFromAmount(coin.out.nValue));
    UniValue o(UniValue::VOBJ);
    ScriptToUniv(coin.out.scriptPubKey, /*out=*/o, /*include_hex=*/true, /*include_address=*/true);
    ret.pushKV("scriptPubKey", std::move(o));
    ret.pushKV("coinbase", (bool)coin.fCoinBase);

    return ret;
},
    };
}

static RPCHelpMan verifychain()
{
    return RPCHelpMan{"verifychain",
                "\nVerifies blockchain database.\n",
                {
                    {"checklevel", RPCArg::Type::NUM, RPCArg::DefaultHint{strprintf("%d, range=0-4", DEFAULT_CHECKLEVEL)},
                        strprintf("How thorough the block verification is:\n%s", MakeUnorderedList(CHECKLEVEL_DOC))},
                    {"nblocks", RPCArg::Type::NUM, RPCArg::DefaultHint{strprintf("%d, 0=all", DEFAULT_CHECKBLOCKS)}, "The number of blocks to check."},
                },
                RPCResult{
                    RPCResult::Type::BOOL, "", "Verification finished successfully. If false, check debug.log for reason."},
                RPCExamples{
                    HelpExampleCli("verifychain", "")
            + HelpExampleRpc("verifychain", "")
                },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    const int check_level{request.params[0].isNull() ? DEFAULT_CHECKLEVEL : request.params[0].getInt<int>()};
    const int check_depth{request.params[1].isNull() ? DEFAULT_CHECKBLOCKS : request.params[1].getInt<int>()};

    ChainstateManager& chainman = EnsureAnyChainman(request.context);
    LOCK(cs_main);

    Chainstate& active_chainstate = chainman.ActiveChainstate();
    return CVerifyDB(chainman.GetNotifications()).VerifyDB(
               active_chainstate, chainman.GetParams().GetConsensus(), active_chainstate.CoinsTip(), check_level, check_depth) == VerifyDBResult::SUCCESS;
},
    };
}

static void SoftForkDescPushBack(const CBlockIndex* blockindex, UniValue& softforks, const ChainstateManager& chainman, Consensus::BuriedDeployment dep)
{
    // For buried deployments.

    if (!DeploymentEnabled(chainman, dep)) return;

    UniValue rv(UniValue::VOBJ);
    rv.pushKV("type", "buried");
    // getdeploymentinfo reports the softfork as active from when the chain height is
    // one below the activation height
    rv.pushKV("active", DeploymentActiveAfter(blockindex, chainman, dep));
    rv.pushKV("height", chainman.GetConsensus().DeploymentHeight(dep));
    softforks.pushKV(DeploymentName(dep), std::move(rv));
}

static void SoftForkDescPushBack(const CBlockIndex* blockindex, UniValue& softforks, const ChainstateManager& chainman, Consensus::DeploymentPos id)
{
    // For BIP9 deployments.

    if (!DeploymentEnabled(chainman, id)) return;
    if (blockindex == nullptr) return;

    auto get_state_name = [](const ThresholdState state) -> std::string {
        switch (state) {
        case ThresholdState::DEFINED: return "defined";
        case ThresholdState::STARTED: return "started";
        case ThresholdState::LOCKED_IN: return "locked_in";
        case ThresholdState::ACTIVE: return "active";
        case ThresholdState::FAILED: return "failed";
        }
        return "invalid";
    };

    UniValue bip9(UniValue::VOBJ);

    const ThresholdState next_state = chainman.m_versionbitscache.State(blockindex, chainman.GetConsensus(), id);
    const ThresholdState current_state = chainman.m_versionbitscache.State(blockindex->pprev, chainman.GetConsensus(), id);

    const bool has_signal = (ThresholdState::STARTED == current_state || ThresholdState::LOCKED_IN == current_state);

    // BIP9 parameters
    if (has_signal) {
        bip9.pushKV("bit", chainman.GetConsensus().vDeployments[id].bit);
    }
    bip9.pushKV("start_time", chainman.GetConsensus().vDeployments[id].nStartTime);
    bip9.pushKV("timeout", chainman.GetConsensus().vDeployments[id].nTimeout);
    bip9.pushKV("min_activation_height", chainman.GetConsensus().vDeployments[id].min_activation_height);

    // BIP9 status
    bip9.pushKV("status", get_state_name(current_state));
    bip9.pushKV("since", chainman.m_versionbitscache.StateSinceHeight(blockindex->pprev, chainman.GetConsensus(), id));
    bip9.pushKV("status_next", get_state_name(next_state));

    // BIP9 signalling status, if applicable
    if (has_signal) {
        UniValue statsUV(UniValue::VOBJ);
        std::vector<bool> signals;
        BIP9Stats statsStruct = chainman.m_versionbitscache.Statistics(blockindex, chainman.GetConsensus(), id, &signals);
        statsUV.pushKV("period", statsStruct.period);
        statsUV.pushKV("elapsed", statsStruct.elapsed);
        statsUV.pushKV("count", statsStruct.count);
        if (ThresholdState::LOCKED_IN != current_state) {
            statsUV.pushKV("threshold", statsStruct.threshold);
            statsUV.pushKV("possible", statsStruct.possible);
        }
        bip9.pushKV("statistics", std::move(statsUV));

        std::string sig;
        sig.reserve(signals.size());
        for (const bool s : signals) {
            sig.push_back(s ? '#' : '-');
        }
        bip9.pushKV("signalling", sig);
    }

    UniValue rv(UniValue::VOBJ);
    rv.pushKV("type", "bip9");
    if (ThresholdState::ACTIVE == next_state) {
        rv.pushKV("height", chainman.m_versionbitscache.StateSinceHeight(blockindex, chainman.GetConsensus(), id));
    }
    rv.pushKV("active", ThresholdState::ACTIVE == next_state);
    rv.pushKV("bip9", std::move(bip9));

    softforks.pushKV(DeploymentName(id), std::move(rv));
}

// used by rest.cpp:rest_chaininfo, so cannot be static
RPCHelpMan getblockchaininfo()
{
    return RPCHelpMan{"getblockchaininfo",
        "Returns an object containing various state info regarding blockchain processing.\n",
        {},
        RPCResult{
            RPCResult::Type::OBJ, "", "",
            {
                {RPCResult::Type::STR, "chain", "current network name (" LIST_CHAIN_NAMES ")"},
                {RPCResult::Type::NUM, "blocks", "the height of the most-work fully-validated chain. The genesis block has height 0"},
                {RPCResult::Type::NUM, "headers", "the current number of headers we have validated"},
                {RPCResult::Type::STR, "bestblockhash", "the hash of the currently best block"},
                {RPCResult::Type::NUM, "difficulty", "the current difficulty"},
                {RPCResult::Type::NUM_TIME, "time", "The block time expressed in " + UNIX_EPOCH_TIME},
                {RPCResult::Type::NUM_TIME, "mediantime", "The median block time expressed in " + UNIX_EPOCH_TIME},
                {RPCResult::Type::NUM, "verificationprogress", "estimate of verification progress [0..1]"},
                {RPCResult::Type::BOOL, "initialblockdownload", "(debug information) estimate of whether this node is in Initial Block Download mode"},
                {RPCResult::Type::STR_HEX, "chainwork", "total amount of work in active chain, in hexadecimal"},
                {RPCResult::Type::NUM, "size_on_disk", "the estimated size of the block and undo files on disk"},
                {RPCResult::Type::BOOL, "pruned", "if the blocks are subject to pruning"},
                {RPCResult::Type::NUM, "pruneheight", /*optional=*/true, "height of the last block pruned, plus one (only present if pruning is enabled)"},
                {RPCResult::Type::BOOL, "automatic_pruning", /*optional=*/true, "whether automatic pruning is enabled (only present if pruning is enabled)"},
                {RPCResult::Type::NUM, "prune_target_size", /*optional=*/true, "the target size used by pruning (only present if automatic pruning is enabled)"},
                (IsDeprecatedRPCEnabled("warnings") ?
                    RPCResult{RPCResult::Type::STR, "warnings", "any network and blockchain warnings (DEPRECATED)"} :
                    RPCResult{RPCResult::Type::ARR, "warnings", "any network and blockchain warnings (run with `-deprecatedrpc=warnings` to return the latest warning as a single string)",
                    {
                        {RPCResult::Type::STR, "", "warning"},
                    }
                    }
                ),
            }},
        RPCExamples{
            HelpExampleCli("getblockchaininfo", "")
            + HelpExampleRpc("getblockchaininfo", "")
        },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    ChainstateManager& chainman = EnsureAnyChainman(request.context);
    LOCK(cs_main);
    Chainstate& active_chainstate = chainman.ActiveChainstate();

    const CBlockIndex& tip{*CHECK_NONFATAL(active_chainstate.m_chain.Tip())};
    const int height{tip.nHeight};
    UniValue obj(UniValue::VOBJ);
    obj.pushKV("chain", chainman.GetParams().GetChainTypeString());
    obj.pushKV("blocks", height);
    obj.pushKV("headers", chainman.m_best_header ? chainman.m_best_header->nHeight : -1);
    obj.pushKV("bestblockhash", tip.GetBlockHash().GetHex());
    obj.pushKV("difficulty", GetDifficulty(tip));
    obj.pushKV("time", tip.GetBlockTime());
    obj.pushKV("mediantime", tip.GetMedianTimePast());
    obj.pushKV("verificationprogress", GuessVerificationProgress(chainman.GetParams().TxData(), &tip));
    obj.pushKV("initialblockdownload", chainman.IsInitialBlockDownload());
    obj.pushKV("chainwork", tip.nChainWork.GetHex());
    obj.pushKV("size_on_disk", chainman.m_blockman.CalculateCurrentUsage());
    obj.pushKV("pruned", chainman.m_blockman.IsPruneMode());
    if (chainman.m_blockman.IsPruneMode()) {
        const auto prune_height{GetPruneHeight(chainman.m_blockman, active_chainstate.m_chain)};
        obj.pushKV("pruneheight", prune_height ? prune_height.value() + 1 : 0);

        const bool automatic_pruning{chainman.m_blockman.GetPruneTarget() != BlockManager::PRUNE_TARGET_MANUAL};
        obj.pushKV("automatic_pruning",  automatic_pruning);
        if (automatic_pruning) {
            obj.pushKV("prune_target_size", chainman.m_blockman.GetPruneTarget());
        }
    }

    NodeContext& node = EnsureAnyNodeContext(request.context);
    obj.pushKV("warnings", node::GetWarningsForRpc(*CHECK_NONFATAL(node.warnings), IsDeprecatedRPCEnabled("warnings")));
    return obj;
},
    };
}

namespace {
const std::vector<RPCResult> RPCHelpForDeployment{
    {RPCResult::Type::STR, "type", "one of \"buried\", \"bip9\""},
    {RPCResult::Type::NUM, "height", /*optional=*/true, "height of the first block which the rules are or will be enforced (only for \"buried\" type, or \"bip9\" type with \"active\" status)"},
    {RPCResult::Type::BOOL, "active", "true if the rules are enforced for the mempool and the next block"},
    {RPCResult::Type::OBJ, "bip9", /*optional=*/true, "status of bip9 softforks (only for \"bip9\" type)",
    {
        {RPCResult::Type::NUM, "bit", /*optional=*/true, "the bit (0-28) in the block version field used to signal this softfork (only for \"started\" and \"locked_in\" status)"},
        {RPCResult::Type::NUM_TIME, "start_time", "the minimum median time past of a block at which the bit gains its meaning"},
        {RPCResult::Type::NUM_TIME, "timeout", "the median time past of a block at which the deployment is considered failed if not yet locked in"},
        {RPCResult::Type::NUM, "min_activation_height", "minimum height of blocks for which the rules may be enforced"},
        {RPCResult::Type::STR, "status", "status of deployment at specified block (one of \"defined\", \"started\", \"locked_in\", \"active\", \"failed\")"},
        {RPCResult::Type::NUM, "since", "height of the first block to which the status applies"},
        {RPCResult::Type::STR, "status_next", "status of deployment at the next block"},
        {RPCResult::Type::OBJ, "statistics", /*optional=*/true, "numeric statistics about signalling for a softfork (only for \"started\" and \"locked_in\" status)",
        {
            {RPCResult::Type::NUM, "period", "the length in blocks of the signalling period"},
            {RPCResult::Type::NUM, "threshold", /*optional=*/true, "the number of blocks with the version bit set required to activate the feature (only for \"started\" status)"},
            {RPCResult::Type::NUM, "elapsed", "the number of blocks elapsed since the beginning of the current period"},
            {RPCResult::Type::NUM, "count", "the number of blocks with the version bit set in the current period"},
            {RPCResult::Type::BOOL, "possible", /*optional=*/true, "returns false if there are not enough blocks left in this period to pass activation threshold (only for \"started\" status)"},
        }},
        {RPCResult::Type::STR, "signalling", /*optional=*/true, "indicates blocks that signalled with a # and blocks that did not with a -"},
    }},
};

UniValue DeploymentInfo(const CBlockIndex* blockindex, const ChainstateManager& chainman)
{
    UniValue softforks(UniValue::VOBJ);
    SoftForkDescPushBack(blockindex, softforks, chainman, Consensus::DEPLOYMENT_HEIGHTINCB);
    SoftForkDescPushBack(blockindex, softforks, chainman, Consensus::DEPLOYMENT_DERSIG);
    SoftForkDescPushBack(blockindex, softforks, chainman, Consensus::DEPLOYMENT_CLTV);
    SoftForkDescPushBack(blockindex, softforks, chainman, Consensus::DEPLOYMENT_CSV);
    SoftForkDescPushBack(blockindex, softforks, chainman, Consensus::DEPLOYMENT_SEGWIT);
    SoftForkDescPushBack(blockindex, softforks, chainman, Consensus::DEPLOYMENT_TESTDUMMY);
    SoftForkDescPushBack(blockindex, softforks, chainman, Consensus::DEPLOYMENT_TAPROOT);
    return softforks;
}
} // anon namespace

RPCHelpMan getdeploymentinfo()
{
    return RPCHelpMan{"getdeploymentinfo",
        "Returns an object containing various state info regarding deployments of consensus changes.",
        {
            {"blockhash", RPCArg::Type::STR_HEX, RPCArg::Default{"hash of current chain tip"}, "The block hash at which to query deployment state"},
        },
        RPCResult{
            RPCResult::Type::OBJ, "", "", {
                {RPCResult::Type::STR, "hash", "requested block hash (or tip)"},
                {RPCResult::Type::NUM, "height", "requested block height (or tip)"},
                {RPCResult::Type::OBJ_DYN, "deployments", "", {
                    {RPCResult::Type::OBJ, "xxxx", "name of the deployment", RPCHelpForDeployment}
                }},
            }
        },
        RPCExamples{ HelpExampleCli("getdeploymentinfo", "") + HelpExampleRpc("getdeploymentinfo", "") },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
        {
            const ChainstateManager& chainman = EnsureAnyChainman(request.context);
            LOCK(cs_main);
            const Chainstate& active_chainstate = chainman.ActiveChainstate();

            const CBlockIndex* blockindex;
            if (request.params[0].isNull()) {
                blockindex = CHECK_NONFATAL(active_chainstate.m_chain.Tip());
            } else {
                const uint256 hash(ParseHashV(request.params[0], "blockhash"));
                blockindex = chainman.m_blockman.LookupBlockIndex(hash);
                if (!blockindex) {
                    throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Block not found");
                }
            }

            UniValue deploymentinfo(UniValue::VOBJ);
            deploymentinfo.pushKV("hash", blockindex->GetBlockHash().ToString());
            deploymentinfo.pushKV("height", blockindex->nHeight);
            deploymentinfo.pushKV("deployments", DeploymentInfo(blockindex, chainman));
            return deploymentinfo;
        },
    };
}

/** Comparison function for sorting the getchaintips heads.  */
struct CompareBlocksByHeight
{
    bool operator()(const CBlockIndex* a, const CBlockIndex* b) const
    {
        /* Make sure that unequal blocks with the same height do not compare
           equal. Use the pointers themselves to make a distinction. */

        if (a->nHeight != b->nHeight)
          return (a->nHeight > b->nHeight);

        return a < b;
    }
};

static RPCHelpMan getchaintips()
{
    return RPCHelpMan{"getchaintips",
                "Return information about all known tips in the block tree,"
                " including the main chain as well as orphaned branches.\n",
                {},
                RPCResult{
                    RPCResult::Type::ARR, "", "",
                    {{RPCResult::Type::OBJ, "", "",
                        {
                            {RPCResult::Type::NUM, "height", "height of the chain tip"},
                            {RPCResult::Type::STR_HEX, "hash", "block hash of the tip"},
                            {RPCResult::Type::NUM, "branchlen", "zero for main chain, otherwise length of branch connecting the tip to the main chain"},
                            {RPCResult::Type::STR, "status", "status of the chain, \"active\" for the main chain\n"
            "Possible values for status:\n"
            "1.  \"invalid\"               This branch contains at least one invalid block\n"
            "2.  \"headers-only\"          Not all blocks for this branch are available, but the headers are valid\n"
            "3.  \"valid-headers\"         All blocks are available for this branch, but they were never fully validated\n"
            "4.  \"valid-fork\"            This branch is not part of the active chain, but is fully validated\n"
            "5.  \"active\"                This is the tip of the active main chain, which is certainly valid"},
                        }}}},
                RPCExamples{
                    HelpExampleCli("getchaintips", "")
            + HelpExampleRpc("getchaintips", "")
                },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    ChainstateManager& chainman = EnsureAnyChainman(request.context);
    LOCK(cs_main);
    CChain& active_chain = chainman.ActiveChain();

    /*
     * Idea: The set of chain tips is the active chain tip, plus orphan blocks which do not have another orphan building off of them.
     * Algorithm:
     *  - Make one pass through BlockIndex(), picking out the orphan blocks, and also storing a set of the orphan block's pprev pointers.
     *  - Iterate through the orphan blocks. If the block isn't pointed to by another orphan, it is a chain tip.
     *  - Add the active chain tip
     */
    std::set<const CBlockIndex*, CompareBlocksByHeight> setTips;
    std::set<const CBlockIndex*> setOrphans;
    std::set<const CBlockIndex*> setPrevs;

    for (const auto& [_, block_index] : chainman.BlockIndex()) {
        if (!active_chain.Contains(&block_index)) {
            setOrphans.insert(&block_index);
            setPrevs.insert(block_index.pprev);
        }
    }

    for (std::set<const CBlockIndex*>::iterator it = setOrphans.begin(); it != setOrphans.end(); ++it) {
        if (setPrevs.erase(*it) == 0) {
            setTips.insert(*it);
        }
    }

    // Always report the currently active tip.
    setTips.insert(active_chain.Tip());

    /* Construct the output array.  */
    UniValue res(UniValue::VARR);
    for (const CBlockIndex* block : setTips) {
        UniValue obj(UniValue::VOBJ);
        obj.pushKV("height", block->nHeight);
        obj.pushKV("hash", block->phashBlock->GetHex());

        const int branchLen = block->nHeight - active_chain.FindFork(block)->nHeight;
        obj.pushKV("branchlen", branchLen);

        std::string status;
        if (active_chain.Contains(block)) {
            // This block is part of the currently active chain.
            status = "active";
        } else if (block->nStatus & BLOCK_FAILED_MASK) {
            // This block or one of its ancestors is invalid.
            status = "invalid";
        } else if (!block->HaveNumChainTxs()) {
            // This block cannot be connected because full block data for it or one of its parents is missing.
            status = "headers-only";
        } else if (block->IsValid(BLOCK_VALID_SCRIPTS)) {
            // This block is fully validated, but no longer part of the active chain. It was probably the active block once, but was reorganized.
            status = "valid-fork";
        } else if (block->IsValid(BLOCK_VALID_TREE)) {
            // The headers for this block are valid, but it has not been validated. It was probably never part of the most-work chain.
            status = "valid-headers";
        } else {
            // No clue.
            status = "unknown";
        }
        obj.pushKV("status", status);

        res.push_back(std::move(obj));
    }

    return res;
},
    };
}

static RPCHelpMan preciousblock()
{
    return RPCHelpMan{"preciousblock",
                "\nTreats a block as if it were received before others with the same work.\n"
                "\nA later preciousblock call can override the effect of an earlier one.\n"
                "\nThe effects of preciousblock are not retained across restarts.\n",
                {
                    {"blockhash", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "the hash of the block to mark as precious"},
                },
                RPCResult{RPCResult::Type::NONE, "", ""},
                RPCExamples{
                    HelpExampleCli("preciousblock", "\"blockhash\"")
            + HelpExampleRpc("preciousblock", "\"blockhash\"")
                },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    uint256 hash(ParseHashV(request.params[0], "blockhash"));
    CBlockIndex* pblockindex;

    ChainstateManager& chainman = EnsureAnyChainman(request.context);
    {
        LOCK(cs_main);
        pblockindex = chainman.m_blockman.LookupBlockIndex(hash);
        if (!pblockindex) {
            throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Block not found");
        }
    }

    BlockValidationState state;
    chainman.ActiveChainstate().PreciousBlock(state, pblockindex);

    if (!state.IsValid()) {
        throw JSONRPCError(RPC_DATABASE_ERROR, state.ToString());
    }

    return UniValue::VNULL;
},
    };
}

void InvalidateBlock(ChainstateManager& chainman, const uint256 block_hash) {
    BlockValidationState state;
    CBlockIndex* pblockindex;
    {
        LOCK(chainman.GetMutex());
        pblockindex = chainman.m_blockman.LookupBlockIndex(block_hash);
        if (!pblockindex) {
            throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Block not found");
        }
    }
    chainman.ActiveChainstate().InvalidateBlock(state, pblockindex);

    if (state.IsValid()) {
        chainman.ActiveChainstate().ActivateBestChain(state);
    }

    if (!state.IsValid()) {
        throw JSONRPCError(RPC_DATABASE_ERROR, state.ToString());
    }
}

static RPCHelpMan invalidateblock()
{
    return RPCHelpMan{"invalidateblock",
                "\nPermanently marks a block as invalid, as if it violated a consensus rule.\n",
                {
                    {"blockhash", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "the hash of the block to mark as invalid"},
                },
                RPCResult{RPCResult::Type::NONE, "", ""},
                RPCExamples{
                    HelpExampleCli("invalidateblock", "\"blockhash\"")
            + HelpExampleRpc("invalidateblock", "\"blockhash\"")
                },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    ChainstateManager& chainman = EnsureAnyChainman(request.context);
    uint256 hash(ParseHashV(request.params[0], "blockhash"));

    InvalidateBlock(chainman, hash);

    return UniValue::VNULL;
},
    };
}

void ReconsiderBlock(ChainstateManager& chainman, uint256 block_hash) {
    {
        LOCK(chainman.GetMutex());
        CBlockIndex* pblockindex = chainman.m_blockman.LookupBlockIndex(block_hash);
        if (!pblockindex) {
            throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Block not found");
        }

        chainman.ActiveChainstate().ResetBlockFailureFlags(pblockindex);
    }

    BlockValidationState state;
    chainman.ActiveChainstate().ActivateBestChain(state);

    if (!state.IsValid()) {
        throw JSONRPCError(RPC_DATABASE_ERROR, state.ToString());
    }
}

static RPCHelpMan reconsiderblock()
{
    return RPCHelpMan{"reconsiderblock",
                "\nRemoves invalidity status of a block, its ancestors and its descendants, reconsider them for activation.\n"
                "This can be used to undo the effects of invalidateblock.\n",
                {
                    {"blockhash", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "the hash of the block to reconsider"},
                },
                RPCResult{RPCResult::Type::NONE, "", ""},
                RPCExamples{
                    HelpExampleCli("reconsiderblock", "\"blockhash\"")
            + HelpExampleRpc("reconsiderblock", "\"blockhash\"")
                },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    ChainstateManager& chainman = EnsureAnyChainman(request.context);
    uint256 hash(ParseHashV(request.params[0], "blockhash"));

    ReconsiderBlock(chainman, hash);

    return UniValue::VNULL;
},
    };
}

static RPCHelpMan getchaintxstats()
{
    return RPCHelpMan{"getchaintxstats",
                "\nCompute statistics about the total number and rate of transactions in the chain.\n",
                {
                    {"nblocks", RPCArg::Type::NUM, RPCArg::DefaultHint{"one month"}, "Size of the window in number of blocks"},
                    {"blockhash", RPCArg::Type::STR_HEX, RPCArg::DefaultHint{"chain tip"}, "The hash of the block that ends the window."},
                },
                RPCResult{
                    RPCResult::Type::OBJ, "", "",
                    {
                        {RPCResult::Type::NUM_TIME, "time", "The timestamp for the final block in the window, expressed in " + UNIX_EPOCH_TIME},
                        {RPCResult::Type::NUM, "txcount", /*optional=*/true,
                         "The total number of transactions in the chain up to that point, if known. "
                         "It may be unknown when using assumeutxo."},
                        {RPCResult::Type::STR_HEX, "window_final_block_hash", "The hash of the final block in the window"},
                        {RPCResult::Type::NUM, "window_final_block_height", "The height of the final block in the window."},
                        {RPCResult::Type::NUM, "window_block_count", "Size of the window in number of blocks"},
                        {RPCResult::Type::NUM, "window_interval", /*optional=*/true, "The elapsed time in the window in seconds. Only returned if \"window_block_count\" is > 0"},
                        {RPCResult::Type::NUM, "window_tx_count", /*optional=*/true,
                         "The number of transactions in the window. "
                         "Only returned if \"window_block_count\" is > 0 and if txcount exists for the start and end of the window."},
                        {RPCResult::Type::NUM, "txrate", /*optional=*/true,
                         "The average rate of transactions per second in the window. "
                         "Only returned if \"window_interval\" is > 0 and if window_tx_count exists."},
                    }},
                RPCExamples{
                    HelpExampleCli("getchaintxstats", "")
            + HelpExampleRpc("getchaintxstats", "2016")
                },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    ChainstateManager& chainman = EnsureAnyChainman(request.context);
    const CBlockIndex* pindex;
    int blockcount = 30 * 24 * 60 * 60 / chainman.GetParams().GetConsensus().nPowTargetSpacing; // By default: 1 month

    if (request.params[1].isNull()) {
        LOCK(cs_main);
        pindex = chainman.ActiveChain().Tip();
    } else {
        uint256 hash(ParseHashV(request.params[1], "blockhash"));
        LOCK(cs_main);
        pindex = chainman.m_blockman.LookupBlockIndex(hash);
        if (!pindex) {
            throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Block not found");
        }
        if (!chainman.ActiveChain().Contains(pindex)) {
            throw JSONRPCError(RPC_INVALID_PARAMETER, "Block is not in main chain");
        }
    }

    CHECK_NONFATAL(pindex != nullptr);

    if (request.params[0].isNull()) {
        blockcount = std::max(0, std::min(blockcount, pindex->nHeight - 1));
    } else {
        blockcount = request.params[0].getInt<int>();

        if (blockcount < 0 || (blockcount > 0 && blockcount >= pindex->nHeight)) {
            throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid block count: should be between 0 and the block's height - 1");
        }
    }

    const CBlockIndex& past_block{*CHECK_NONFATAL(pindex->GetAncestor(pindex->nHeight - blockcount))};
    const int64_t nTimeDiff{pindex->GetMedianTimePast() - past_block.GetMedianTimePast()};

    UniValue ret(UniValue::VOBJ);
    ret.pushKV("time", (int64_t)pindex->nTime);
    if (pindex->m_chain_tx_count) {
        ret.pushKV("txcount", pindex->m_chain_tx_count);
    }
    ret.pushKV("window_final_block_hash", pindex->GetBlockHash().GetHex());
    ret.pushKV("window_final_block_height", pindex->nHeight);
    ret.pushKV("window_block_count", blockcount);
    if (blockcount > 0) {
        ret.pushKV("window_interval", nTimeDiff);
        if (pindex->m_chain_tx_count != 0 && past_block.m_chain_tx_count != 0) {
            const auto window_tx_count = pindex->m_chain_tx_count - past_block.m_chain_tx_count;
            ret.pushKV("window_tx_count", window_tx_count);
            if (nTimeDiff > 0) {
                ret.pushKV("txrate", double(window_tx_count) / nTimeDiff);
            }
        }
    }

    return ret;
},
    };
}

template<typename T>
static T CalculateTruncatedMedian(std::vector<T>& scores)
{
    size_t size = scores.size();
    if (size == 0) {
        return 0;
    }

    std::sort(scores.begin(), scores.end());
    if (size % 2 == 0) {
        return (scores[size / 2 - 1] + scores[size / 2]) / 2;
    } else {
        return scores[size / 2];
    }
}

void CalculatePercentilesByWeight(CAmount result[NUM_GETBLOCKSTATS_PERCENTILES], std::vector<std::pair<CAmount, int64_t>>& scores, int64_t total_weight)
{
    if (scores.empty()) {
        return;
    }

    std::sort(scores.begin(), scores.end());

    // 10th, 25th, 50th, 75th, and 90th percentile weight units.
    const double weights[NUM_GETBLOCKSTATS_PERCENTILES] = {
        total_weight / 10.0, total_weight / 4.0, total_weight / 2.0, (total_weight * 3.0) / 4.0, (total_weight * 9.0) / 10.0
    };

    int64_t next_percentile_index = 0;
    int64_t cumulative_weight = 0;
    for (const auto& element : scores) {
        cumulative_weight += element.second;
        while (next_percentile_index < NUM_GETBLOCKSTATS_PERCENTILES && cumulative_weight >= weights[next_percentile_index]) {
            result[next_percentile_index] = element.first;
            ++next_percentile_index;
        }
    }

    // Fill any remaining percentiles with the last value.
    for (int64_t i = next_percentile_index; i < NUM_GETBLOCKSTATS_PERCENTILES; i++) {
        result[i] = scores.back().first;
    }
}

template<typename T>
static inline bool SetHasKeys(const std::set<T>& set) {return false;}
template<typename T, typename Tk, typename... Args>
static inline bool SetHasKeys(const std::set<T>& set, const Tk& key, const Args&... args)
{
    return (set.count(key) != 0) || SetHasKeys(set, args...);
}

// outpoint (needed for the utxo index) + nHeight + fCoinBase
static constexpr size_t PER_UTXO_OVERHEAD = sizeof(COutPoint) + sizeof(uint32_t) + sizeof(bool);

static RPCHelpMan getblockstats()
{
    return RPCHelpMan{"getblockstats",
                "\nCompute per block statistics for a given window. All amounts are in satoshis.\n"
                "It won't work for some heights with pruning.\n",
                {
                    {"hash_or_height", RPCArg::Type::NUM, RPCArg::Optional::NO, "The block hash or height of the target block",
                     RPCArgOptions{
                         .skip_type_check = true,
                         .type_str = {"", "string or numeric"},
                     }},
                    {"stats", RPCArg::Type::ARR, RPCArg::DefaultHint{"all values"}, "Values to plot (see result below)",
                        {
                            {"height", RPCArg::Type::STR, RPCArg::Optional::OMITTED, "Selected statistic"},
                            {"time", RPCArg::Type::STR, RPCArg::Optional::OMITTED, "Selected statistic"},
                        },
                        RPCArgOptions{.oneline_description="stats"}},
                },
                RPCResult{
            RPCResult::Type::OBJ, "", "",
            {
                {RPCResult::Type::NUM, "avgfee", /*optional=*/true, "Average fee in the block"},
                {RPCResult::Type::NUM, "avgfeerate", /*optional=*/true, "Average feerate (in satoshis per virtual byte)"},
                {RPCResult::Type::NUM, "avgtxsize", /*optional=*/true, "Average transaction size"},
                {RPCResult::Type::STR_HEX, "blockhash", /*optional=*/true, "The block hash (to check for potential reorgs)"},
                {RPCResult::Type::ARR_FIXED, "feerate_percentiles", /*optional=*/true, "Feerates at the 10th, 25th, 50th, 75th, and 90th percentile weight unit (in satoshis per virtual byte)",
                {
                    {RPCResult::Type::NUM, "10th_percentile_feerate", "The 10th percentile feerate"},
                    {RPCResult::Type::NUM, "25th_percentile_feerate", "The 25th percentile feerate"},
                    {RPCResult::Type::NUM, "50th_percentile_feerate", "The 50th percentile feerate"},
                    {RPCResult::Type::NUM, "75th_percentile_feerate", "The 75th percentile feerate"},
                    {RPCResult::Type::NUM, "90th_percentile_feerate", "The 90th percentile feerate"},
                }},
                {RPCResult::Type::NUM, "height", /*optional=*/true, "The height of the block"},
                {RPCResult::Type::NUM, "ins", /*optional=*/true, "The number of inputs (excluding coinbase)"},
                {RPCResult::Type::NUM, "maxfee", /*optional=*/true, "Maximum fee in the block"},
                {RPCResult::Type::NUM, "maxfeerate", /*optional=*/true, "Maximum feerate (in satoshis per virtual byte)"},
                {RPCResult::Type::NUM, "maxtxsize", /*optional=*/true, "Maximum transaction size"},
                {RPCResult::Type::NUM, "medianfee", /*optional=*/true, "Truncated median fee in the block"},
                {RPCResult::Type::NUM, "mediantime", /*optional=*/true, "The block median time past"},
                {RPCResult::Type::NUM, "mediantxsize", /*optional=*/true, "Truncated median transaction size"},
                {RPCResult::Type::NUM, "minfee", /*optional=*/true, "Minimum fee in the block"},
                {RPCResult::Type::NUM, "minfeerate", /*optional=*/true, "Minimum feerate (in satoshis per virtual byte)"},
                {RPCResult::Type::NUM, "mintxsize", /*optional=*/true, "Minimum transaction size"},
                {RPCResult::Type::NUM, "outs", /*optional=*/true, "The number of outputs"},
                {RPCResult::Type::NUM, "subsidy", /*optional=*/true, "The block subsidy"},
                {RPCResult::Type::NUM, "swtotal_size", /*optional=*/true, "Total size of all segwit transactions"},
                {RPCResult::Type::NUM, "swtotal_weight", /*optional=*/true, "Total weight of all segwit transactions"},
                {RPCResult::Type::NUM, "swtxs", /*optional=*/true, "The number of segwit transactions"},
                {RPCResult::Type::NUM, "time", /*optional=*/true, "The block time"},
                {RPCResult::Type::NUM, "total_out", /*optional=*/true, "Total amount in all outputs (excluding coinbase and thus reward [ie subsidy + totalfee])"},
                {RPCResult::Type::NUM, "total_size", /*optional=*/true, "Total size of all non-coinbase transactions"},
                {RPCResult::Type::NUM, "total_weight", /*optional=*/true, "Total weight of all non-coinbase transactions"},
                {RPCResult::Type::NUM, "totalfee", /*optional=*/true, "The fee total"},
                {RPCResult::Type::NUM, "txs", /*optional=*/true, "The number of transactions (including coinbase)"},
                {RPCResult::Type::NUM, "utxo_increase", /*optional=*/true, "The increase/decrease in the number of unspent outputs (not discounting op_return and similar)"},
                {RPCResult::Type::NUM, "utxo_size_inc", /*optional=*/true, "The increase/decrease in size for the utxo index (not discounting op_return and similar)"},
                {RPCResult::Type::NUM, "utxo_increase_actual", /*optional=*/true, "The increase/decrease in the number of unspent outputs, not counting unspendables"},
                {RPCResult::Type::NUM, "utxo_size_inc_actual", /*optional=*/true, "The increase/decrease in size for the utxo index, not counting unspendables"},
            }},
                RPCExamples{
                    HelpExampleCli("getblockstats", R"('"00000000c937983704a73af28acdec37b049d214adbda81d7e2a3dd146f6ed09"' '["minfeerate","avgfeerate"]')") +
                    HelpExampleCli("getblockstats", R"(1000 '["minfeerate","avgfeerate"]')") +
                    HelpExampleRpc("getblockstats", R"("00000000c937983704a73af28acdec37b049d214adbda81d7e2a3dd146f6ed09", ["minfeerate","avgfeerate"])") +
                    HelpExampleRpc("getblockstats", R"(1000, ["minfeerate","avgfeerate"])")
                },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    ChainstateManager& chainman = EnsureAnyChainman(request.context);
    const CBlockIndex& pindex{*CHECK_NONFATAL(ParseHashOrHeight(request.params[0], chainman))};

    std::set<std::string> stats;
    if (!request.params[1].isNull()) {
        const UniValue stats_univalue = request.params[1].get_array();
        for (unsigned int i = 0; i < stats_univalue.size(); i++) {
            const std::string stat = stats_univalue[i].get_str();
            stats.insert(stat);
        }
    }

    const CBlock& block = GetBlockChecked(chainman.m_blockman, pindex);
    const CBlockUndo& blockUndo = GetUndoChecked(chainman.m_blockman, pindex);

    const bool do_all = stats.size() == 0; // Calculate everything if nothing selected (default)
    const bool do_mediantxsize = do_all || stats.count("mediantxsize") != 0;
    const bool do_medianfee = do_all || stats.count("medianfee") != 0;
    const bool do_feerate_percentiles = do_all || stats.count("feerate_percentiles") != 0;
    const bool loop_inputs = do_all || do_medianfee || do_feerate_percentiles ||
        SetHasKeys(stats, "utxo_increase", "utxo_increase_actual", "utxo_size_inc", "utxo_size_inc_actual", "totalfee", "avgfee", "avgfeerate", "minfee", "maxfee", "minfeerate", "maxfeerate");
    const bool loop_outputs = do_all || loop_inputs || stats.count("total_out");
    const bool do_calculate_size = do_mediantxsize ||
        SetHasKeys(stats, "total_size", "avgtxsize", "mintxsize", "maxtxsize", "swtotal_size");
    const bool do_calculate_weight = do_all || SetHasKeys(stats, "total_weight", "avgfeerate", "swtotal_weight", "avgfeerate", "feerate_percentiles", "minfeerate", "maxfeerate");
    const bool do_calculate_sw = do_all || SetHasKeys(stats, "swtxs", "swtotal_size", "swtotal_weight");

    CAmount maxfee = 0;
    CAmount maxfeerate = 0;
    CAmount minfee = MAX_MONEY;
    CAmount minfeerate = MAX_MONEY;
    CAmount total_out = 0;
    CAmount totalfee = 0;
    int64_t inputs = 0;
    int64_t maxtxsize = 0;
    int64_t mintxsize = MAX_BLOCK_SERIALIZED_SIZE;
    int64_t outputs = 0;
    int64_t swtotal_size = 0;
    int64_t swtotal_weight = 0;
    int64_t swtxs = 0;
    int64_t total_size = 0;
    int64_t total_weight = 0;
    int64_t utxos = 0;
    int64_t utxo_size_inc = 0;
    int64_t utxo_size_inc_actual = 0;
    std::vector<CAmount> fee_array;
    std::vector<std::pair<CAmount, int64_t>> feerate_array;
    std::vector<int64_t> txsize_array;

    for (size_t i = 0; i < block.vtx.size(); ++i) {
        const auto& tx = block.vtx.at(i);
        outputs += tx->vout.size();

        CAmount tx_total_out = 0;
        if (loop_outputs) {
            for (const CTxOut& out : tx->vout) {
                tx_total_out += out.nValue;

                size_t out_size = GetSerializeSize(out) + PER_UTXO_OVERHEAD;
                utxo_size_inc += out_size;

                // The Genesis block and the repeated BIP30 block coinbases don't change the UTXO
                // set counts, so they have to be excluded from the statistics
                if (pindex.nHeight == 0 || (IsBIP30Repeat(pindex) && tx->IsCoinBase())) continue;
                // Skip unspendable outputs since they are not included in the UTXO set
                if (out.scriptPubKey.IsUnspendable()) continue;

                ++utxos;
                utxo_size_inc_actual += out_size;
            }
        }

        if (tx->IsCoinBase()) {
            continue;
        }

        inputs += tx->vin.size(); // Don't count coinbase's fake input
        total_out += tx_total_out; // Don't count coinbase reward

        int64_t tx_size = 0;
        if (do_calculate_size) {

            tx_size = tx->GetTotalSize();
            if (do_mediantxsize) {
                txsize_array.push_back(tx_size);
            }
            maxtxsize = std::max(maxtxsize, tx_size);
            mintxsize = std::min(mintxsize, tx_size);
            total_size += tx_size;
        }

        int64_t weight = 0;
        if (do_calculate_weight) {
            weight = GetTransactionWeight(*tx);
            total_weight += weight;
        }

        if (do_calculate_sw && tx->HasWitness()) {
            ++swtxs;
            swtotal_size += tx_size;
            swtotal_weight += weight;
        }

        if (loop_inputs) {
            CAmount tx_total_in = 0;
            const auto& txundo = blockUndo.vtxundo.at(i - 1);
            for (const Coin& coin: txundo.vprevout) {
                const CTxOut& prevoutput = coin.out;

                tx_total_in += prevoutput.nValue;
                size_t prevout_size = GetSerializeSize(prevoutput) + PER_UTXO_OVERHEAD;
                utxo_size_inc -= prevout_size;
                utxo_size_inc_actual -= prevout_size;
            }

            CAmount txfee = tx_total_in - tx_total_out;
            CHECK_NONFATAL(MoneyRange(txfee));
            if (do_medianfee) {
                fee_array.push_back(txfee);
            }
            maxfee = std::max(maxfee, txfee);
            minfee = std::min(minfee, txfee);
            totalfee += txfee;

            // New feerate uses satoshis per virtual byte instead of per serialized byte
            CAmount feerate = weight ? (txfee * WITNESS_SCALE_FACTOR) / weight : 0;
            if (do_feerate_percentiles) {
                feerate_array.emplace_back(feerate, weight);
            }
            maxfeerate = std::max(maxfeerate, feerate);
            minfeerate = std::min(minfeerate, feerate);
        }
    }

    CAmount feerate_percentiles[NUM_GETBLOCKSTATS_PERCENTILES] = { 0 };
    CalculatePercentilesByWeight(feerate_percentiles, feerate_array, total_weight);

    UniValue feerates_res(UniValue::VARR);
    for (int64_t i = 0; i < NUM_GETBLOCKSTATS_PERCENTILES; i++) {
        feerates_res.push_back(feerate_percentiles[i]);
    }

    UniValue ret_all(UniValue::VOBJ);
    ret_all.pushKV("avgfee", (block.vtx.size() > 1) ? totalfee / (block.vtx.size() - 1) : 0);
    ret_all.pushKV("avgfeerate", total_weight ? (totalfee * WITNESS_SCALE_FACTOR) / total_weight : 0); // Unit: sat/vbyte
    ret_all.pushKV("avgtxsize", (block.vtx.size() > 1) ? total_size / (block.vtx.size() - 1) : 0);
    ret_all.pushKV("blockhash", pindex.GetBlockHash().GetHex());
    ret_all.pushKV("feerate_percentiles", std::move(feerates_res));
    ret_all.pushKV("height", (int64_t)pindex.nHeight);
    ret_all.pushKV("ins", inputs);
    ret_all.pushKV("maxfee", maxfee);
    ret_all.pushKV("maxfeerate", maxfeerate);
    ret_all.pushKV("maxtxsize", maxtxsize);
    ret_all.pushKV("medianfee", CalculateTruncatedMedian(fee_array));
    ret_all.pushKV("mediantime", pindex.GetMedianTimePast());
    ret_all.pushKV("mediantxsize", CalculateTruncatedMedian(txsize_array));
    ret_all.pushKV("minfee", (minfee == MAX_MONEY) ? 0 : minfee);
    ret_all.pushKV("minfeerate", (minfeerate == MAX_MONEY) ? 0 : minfeerate);
    ret_all.pushKV("mintxsize", mintxsize == MAX_BLOCK_SERIALIZED_SIZE ? 0 : mintxsize);
    ret_all.pushKV("outs", outputs);
    ret_all.pushKV("subsidy", GetBlockSubsidy(pindex.nHeight, chainman.GetParams().GetConsensus()));
    ret_all.pushKV("swtotal_size", swtotal_size);
    ret_all.pushKV("swtotal_weight", swtotal_weight);
    ret_all.pushKV("swtxs", swtxs);
    ret_all.pushKV("time", pindex.GetBlockTime());
    ret_all.pushKV("total_out", total_out);
    ret_all.pushKV("total_size", total_size);
    ret_all.pushKV("total_weight", total_weight);
    ret_all.pushKV("totalfee", totalfee);
    ret_all.pushKV("txs", (int64_t)block.vtx.size());
    ret_all.pushKV("utxo_increase", outputs - inputs);
    ret_all.pushKV("utxo_size_inc", utxo_size_inc);
    ret_all.pushKV("utxo_increase_actual", utxos - inputs);
    ret_all.pushKV("utxo_size_inc_actual", utxo_size_inc_actual);

    if (do_all) {
        return ret_all;
    }

    UniValue ret(UniValue::VOBJ);
    for (const std::string& stat : stats) {
        const UniValue& value = ret_all[stat];
        if (value.isNull()) {
            throw JSONRPCError(RPC_INVALID_PARAMETER, strprintf("Invalid selected statistic '%s'", stat));
        }
        ret.pushKV(stat, value);
    }
    return ret;
},
    };
}

namespace {
//! Search for a given set of pubkey scripts
bool FindScriptPubKey(std::atomic<int>& scan_progress, const std::atomic<bool>& should_abort, int64_t& count, CCoinsViewCursor* cursor, const std::set<CScript>& needles, std::map<COutPoint, Coin>& out_results, std::function<void()>& interruption_point)
{
    scan_progress = 0;
    count = 0;
    while (cursor->Valid()) {
        COutPoint key;
        Coin coin;
        if (!cursor->GetKey(key) || !cursor->GetValue(coin)) return false;
        if (++count % 8192 == 0) {
            interruption_point();
            if (should_abort) {
                // allow to abort the scan via the abort reference
                return false;
            }
        }
        if (count % 256 == 0) {
            // update progress reference every 256 item
            uint32_t high = 0x100 * *UCharCast(key.hash.begin()) + *(UCharCast(key.hash.begin()) + 1);
            scan_progress = (int)(high * 100.0 / 65536.0 + 0.5);
        }
        if (needles.count(coin.out.scriptPubKey)) {
            out_results.emplace(key, coin);
        }
        cursor->Next();
    }
    scan_progress = 100;
    return true;
}
} // namespace

/** RAII object to prevent concurrency issue when scanning the txout set */
static std::atomic<int> g_scan_progress;
static std::atomic<bool> g_scan_in_progress;
static std::atomic<bool> g_should_abort_scan;
class CoinsViewScanReserver
{
private:
    bool m_could_reserve{false};
public:
    explicit CoinsViewScanReserver() = default;

    bool reserve() {
        CHECK_NONFATAL(!m_could_reserve);
        if (g_scan_in_progress.exchange(true)) {
            return false;
        }
        CHECK_NONFATAL(g_scan_progress == 0);
        m_could_reserve = true;
        return true;
    }

    ~CoinsViewScanReserver() {
        if (m_could_reserve) {
            g_scan_in_progress = false;
            g_scan_progress = 0;
        }
    }
};

static const auto scan_action_arg_desc = RPCArg{
    "action", RPCArg::Type::STR, RPCArg::Optional::NO, "The action to execute\n"
        "\"start\" for starting a scan\n"
        "\"abort\" for aborting the current scan (returns true when abort was successful)\n"
        "\"status\" for progress report (in %) of the current scan"
};

static const auto scan_objects_arg_desc = RPCArg{
    "scanobjects", RPCArg::Type::ARR, RPCArg::Optional::OMITTED, "Array of scan objects. Required for \"start\" action\n"
        "Every scan object is either a string descriptor or an object:",
    {
        {"descriptor", RPCArg::Type::STR, RPCArg::Optional::OMITTED, "An output descriptor"},
        {"", RPCArg::Type::OBJ, RPCArg::Optional::OMITTED, "An object with output descriptor and metadata",
            {
                {"desc", RPCArg::Type::STR, RPCArg::Optional::NO, "An output descriptor"},
                {"range", RPCArg::Type::RANGE, RPCArg::Default{1000}, "The range of HD chain indexes to explore (either end or [begin,end])"},
            }},
    },
    RPCArgOptions{.oneline_description="[scanobjects,...]"},
};

static const auto scan_result_abort = RPCResult{
    "when action=='abort'", RPCResult::Type::BOOL, "success",
    "True if scan will be aborted (not necessarily before this RPC returns), or false if there is no scan to abort"
};
static const auto scan_result_status_none = RPCResult{
    "when action=='status' and no scan is in progress - possibly already completed", RPCResult::Type::NONE, "", ""
};
static const auto scan_result_status_some = RPCResult{
    "when action=='status' and a scan is currently in progress", RPCResult::Type::OBJ, "", "",
    {{RPCResult::Type::NUM, "progress", "Approximate percent complete"},}
};


static RPCHelpMan scantxoutset()
{
    // raw() descriptor corresponding to mainnet address 12cbQLTFMXRnSzktFkuoG3eHoMeFtpTu3S
    const std::string EXAMPLE_DESCRIPTOR_RAW = "raw(76a91411b366edfc0a8b66feebae5c2e25a7b6a5d1cf3188ac)#fm24fxxy";

    return RPCHelpMan{"scantxoutset",
        "\nScans the unspent transaction output set for entries that match certain output descriptors.\n"
        "Examples of output descriptors are:\n"
        "    addr(<address>)                      Outputs whose output script corresponds to the specified address (does not include P2PK)\n"
        "    raw(<hex script>)                    Outputs whose output script equals the specified hex-encoded bytes\n"
        "    combo(<pubkey>)                      P2PK, P2PKH, P2WPKH, and P2SH-P2WPKH outputs for the given pubkey\n"
        "    pkh(<pubkey>)                        P2PKH outputs for the given pubkey\n"
        "    sh(multi(<n>,<pubkey>,<pubkey>,...)) P2SH-multisig outputs for the given threshold and pubkeys\n"
        "    tr(<pubkey>)                         P2TR\n"
        "    tr(<pubkey>,{pk(<pubkey>)})          P2TR with single fallback pubkey in tapscript\n"
        "    rawtr(<pubkey>)                      P2TR with the specified key as output key rather than inner\n"
        "    wsh(and_v(v:pk(<pubkey>),after(2)))  P2WSH miniscript with mandatory pubkey and a timelock\n"
        "\nIn the above, <pubkey> either refers to a fixed public key in hexadecimal notation, or to an xpub/xprv optionally followed by one\n"
        "or more path elements separated by \"/\", and optionally ending in \"/*\" (unhardened), or \"/*'\" or \"/*h\" (hardened) to specify all\n"
        "unhardened or hardened child keys.\n"
        "In the latter case, a range needs to be specified by below if different from 1000.\n"
        "For more information on output descriptors, see the documentation in the doc/descriptors.md file.\n",
        {
            scan_action_arg_desc,
            scan_objects_arg_desc,
        },
        {
            RPCResult{"when action=='start'; only returns after scan completes", RPCResult::Type::OBJ, "", "", {
                {RPCResult::Type::BOOL, "success", "Whether the scan was completed"},
                {RPCResult::Type::NUM, "txouts", "The number of unspent transaction outputs scanned"},
                {RPCResult::Type::NUM, "height", "The block height at which the scan was done"},
                {RPCResult::Type::STR_HEX, "bestblock", "The hash of the block at the tip of the chain"},
                {RPCResult::Type::ARR, "unspents", "",
                {
                    {RPCResult::Type::OBJ, "", "",
                    {
                        {RPCResult::Type::STR_HEX, "txid", "The transaction id"},
                        {RPCResult::Type::NUM, "vout", "The vout value"},
                        {RPCResult::Type::STR_HEX, "scriptPubKey", "The output script"},
                        {RPCResult::Type::STR, "desc", "A specialized descriptor for the matched output script"},
                        {RPCResult::Type::STR_AMOUNT, "amount", "The total amount in " + CURRENCY_UNIT + " of the unspent output"},
                        {RPCResult::Type::BOOL, "coinbase", "Whether this is a coinbase output"},
                        {RPCResult::Type::NUM, "height", "Height of the unspent transaction output"},
                        {RPCResult::Type::STR_HEX, "blockhash", "Blockhash of the unspent transaction output"},
                        {RPCResult::Type::NUM, "confirmations", "Number of confirmations of the unspent transaction output when the scan was done"},
                    }},
                }},
                {RPCResult::Type::STR_AMOUNT, "total_amount", "The total amount of all found unspent outputs in " + CURRENCY_UNIT},
            }},
            scan_result_abort,
            scan_result_status_some,
            scan_result_status_none,
        },
        RPCExamples{
            HelpExampleCli("scantxoutset", "start \'[\"" + EXAMPLE_DESCRIPTOR_RAW + "\"]\'") +
            HelpExampleCli("scantxoutset", "status") +
            HelpExampleCli("scantxoutset", "abort") +
            HelpExampleRpc("scantxoutset", "\"start\", [\"" + EXAMPLE_DESCRIPTOR_RAW + "\"]") +
            HelpExampleRpc("scantxoutset", "\"status\"") +
            HelpExampleRpc("scantxoutset", "\"abort\"")
        },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    UniValue result(UniValue::VOBJ);
    const auto action{self.Arg<std::string>("action")};
    if (action == "status") {
        CoinsViewScanReserver reserver;
        if (reserver.reserve()) {
            // no scan in progress
            return UniValue::VNULL;
        }
        result.pushKV("progress", g_scan_progress.load());
        return result;
    } else if (action == "abort") {
        CoinsViewScanReserver reserver;
        if (reserver.reserve()) {
            // reserve was possible which means no scan was running
            return false;
        }
        // set the abort flag
        g_should_abort_scan = true;
        return true;
    } else if (action == "start") {
        CoinsViewScanReserver reserver;
        if (!reserver.reserve()) {
            throw JSONRPCError(RPC_INVALID_PARAMETER, "Scan already in progress, use action \"abort\" or \"status\"");
        }

        if (request.params.size() < 2) {
            throw JSONRPCError(RPC_MISC_ERROR, "scanobjects argument is required for the start action");
        }

        std::set<CScript> needles;
        std::map<CScript, std::string> descriptors;
        CAmount total_in = 0;

        // loop through the scan objects
        for (const UniValue& scanobject : request.params[1].get_array().getValues()) {
            FlatSigningProvider provider;
            auto scripts = EvalDescriptorStringOrObject(scanobject, provider);
            for (CScript& script : scripts) {
                std::string inferred = InferDescriptor(script, provider)->ToString();
                needles.emplace(script);
                descriptors.emplace(std::move(script), std::move(inferred));
            }
        }

        // Scan the unspent transaction output set for inputs
        UniValue unspents(UniValue::VARR);
        std::vector<CTxOut> input_txos;
        std::map<COutPoint, Coin> coins;
        g_should_abort_scan = false;
        int64_t count = 0;
        std::unique_ptr<CCoinsViewCursor> pcursor;
        const CBlockIndex* tip;
        NodeContext& node = EnsureAnyNodeContext(request.context);
        {
            ChainstateManager& chainman = EnsureChainman(node);
            LOCK(cs_main);
            Chainstate& active_chainstate = chainman.ActiveChainstate();
            active_chainstate.ForceFlushStateToDisk();
            pcursor = CHECK_NONFATAL(active_chainstate.CoinsDB().Cursor());
            tip = CHECK_NONFATAL(active_chainstate.m_chain.Tip());
        }
        bool res = FindScriptPubKey(g_scan_progress, g_should_abort_scan, count, pcursor.get(), needles, coins, node.rpc_interruption_point);
        result.pushKV("success", res);
        result.pushKV("txouts", count);
        result.pushKV("height", tip->nHeight);
        result.pushKV("bestblock", tip->GetBlockHash().GetHex());

        for (const auto& it : coins) {
            const COutPoint& outpoint = it.first;
            const Coin& coin = it.second;
            const CTxOut& txo = coin.out;
            const CBlockIndex& coinb_block{*CHECK_NONFATAL(tip->GetAncestor(coin.nHeight))};
            input_txos.push_back(txo);
            total_in += txo.nValue;

            UniValue unspent(UniValue::VOBJ);
            unspent.pushKV("txid", outpoint.hash.GetHex());
            unspent.pushKV("vout", outpoint.n);
            unspent.pushKV("scriptPubKey", HexStr(txo.scriptPubKey));
            unspent.pushKV("desc", descriptors[txo.scriptPubKey]);
            unspent.pushKV("amount", ValueFromAmount(txo.nValue));
            unspent.pushKV("coinbase", coin.IsCoinBase());
            unspent.pushKV("height", coin.nHeight);
            unspent.pushKV("blockhash", coinb_block.GetBlockHash().GetHex());
            unspent.pushKV("confirmations", tip->nHeight - coin.nHeight + 1);

            unspents.push_back(std::move(unspent));
        }
        result.pushKV("unspents", std::move(unspents));
        result.pushKV("total_amount", ValueFromAmount(total_in));
    } else {
        throw JSONRPCError(RPC_INVALID_PARAMETER, strprintf("Invalid action '%s'", action));
    }
    return result;
},
    };
}

/** RAII object to prevent concurrency issue when scanning blockfilters */
static std::atomic<int> g_scanfilter_progress;
static std::atomic<int> g_scanfilter_progress_height;
static std::atomic<bool> g_scanfilter_in_progress;
static std::atomic<bool> g_scanfilter_should_abort_scan;
class BlockFiltersScanReserver
{
private:
    bool m_could_reserve{false};
public:
    explicit BlockFiltersScanReserver() = default;

    bool reserve() {
        CHECK_NONFATAL(!m_could_reserve);
        if (g_scanfilter_in_progress.exchange(true)) {
            return false;
        }
        m_could_reserve = true;
        return true;
    }

    ~BlockFiltersScanReserver() {
        if (m_could_reserve) {
            g_scanfilter_in_progress = false;
        }
    }
};

static bool CheckBlockFilterMatches(BlockManager& blockman, const CBlockIndex& blockindex, const GCSFilter::ElementSet& needles)
{
    const CBlock block{GetBlockChecked(blockman, blockindex)};
    const CBlockUndo block_undo{GetUndoChecked(blockman, blockindex)};

    // Check if any of the outputs match the scriptPubKey
    for (const auto& tx : block.vtx) {
        if (std::any_of(tx->vout.cbegin(), tx->vout.cend(), [&](const auto& txout) {
                return needles.count(std::vector<unsigned char>(txout.scriptPubKey.begin(), txout.scriptPubKey.end())) != 0;
            })) {
            return true;
        }
    }
    // Check if any of the inputs match the scriptPubKey
    for (const auto& txundo : block_undo.vtxundo) {
        if (std::any_of(txundo.vprevout.cbegin(), txundo.vprevout.cend(), [&](const auto& coin) {
                return needles.count(std::vector<unsigned char>(coin.out.scriptPubKey.begin(), coin.out.scriptPubKey.end())) != 0;
            })) {
            return true;
        }
    }

    return false;
}

static RPCHelpMan scanblocks()
{
    return RPCHelpMan{"scanblocks",
        "\nReturn relevant blockhashes for given descriptors (requires blockfilterindex).\n"
        "This call may take several minutes. Make sure to use no RPC timeout (bitcoin-cli -rpcclienttimeout=0)",
        {
            scan_action_arg_desc,
            scan_objects_arg_desc,
            RPCArg{"start_height", RPCArg::Type::NUM, RPCArg::Default{0}, "Height to start to scan from"},
            RPCArg{"stop_height", RPCArg::Type::NUM, RPCArg::DefaultHint{"chain tip"}, "Height to stop to scan"},
            RPCArg{"filtertype", RPCArg::Type::STR, RPCArg::Default{BlockFilterTypeName(BlockFilterType::BASIC)}, "The type name of the filter"},
            RPCArg{"options", RPCArg::Type::OBJ_NAMED_PARAMS, RPCArg::Optional::OMITTED, "",
                {
                    {"filter_false_positives", RPCArg::Type::BOOL, RPCArg::Default{false}, "Filter false positives (slower and may fail on pruned nodes). Otherwise they may occur at a rate of 1/M"},
                },
                RPCArgOptions{.oneline_description="options"}},
        },
        {
            scan_result_status_none,
            RPCResult{"When action=='start'; only returns after scan completes", RPCResult::Type::OBJ, "", "", {
                {RPCResult::Type::NUM, "from_height", "The height we started the scan from"},
                {RPCResult::Type::NUM, "to_height", "The height we ended the scan at"},
                {RPCResult::Type::ARR, "relevant_blocks", "Blocks that may have matched a scanobject.", {
                    {RPCResult::Type::STR_HEX, "blockhash", "A relevant blockhash"},
                }},
                {RPCResult::Type::BOOL, "completed", "true if the scan process was not aborted"}
            }},
            RPCResult{"when action=='status' and a scan is currently in progress", RPCResult::Type::OBJ, "", "", {
                    {RPCResult::Type::NUM, "progress", "Approximate percent complete"},
                    {RPCResult::Type::NUM, "current_height", "Height of the block currently being scanned"},
                },
            },
            scan_result_abort,
        },
        RPCExamples{
            HelpExampleCli("scanblocks", "start '[\"addr(bcrt1q4u4nsgk6ug0sqz7r3rj9tykjxrsl0yy4d0wwte)\"]' 300000") +
            HelpExampleCli("scanblocks", "start '[\"addr(bcrt1q4u4nsgk6ug0sqz7r3rj9tykjxrsl0yy4d0wwte)\"]' 100 150 basic") +
            HelpExampleCli("scanblocks", "status") +
            HelpExampleRpc("scanblocks", "\"start\", [\"addr(bcrt1q4u4nsgk6ug0sqz7r3rj9tykjxrsl0yy4d0wwte)\"], 300000") +
            HelpExampleRpc("scanblocks", "\"start\", [\"addr(bcrt1q4u4nsgk6ug0sqz7r3rj9tykjxrsl0yy4d0wwte)\"], 100, 150, \"basic\"") +
            HelpExampleRpc("scanblocks", "\"status\"")
        },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    UniValue ret(UniValue::VOBJ);
    if (request.params[0].get_str() == "status") {
        BlockFiltersScanReserver reserver;
        if (reserver.reserve()) {
            // no scan in progress
            return NullUniValue;
        }
        ret.pushKV("progress", g_scanfilter_progress.load());
        ret.pushKV("current_height", g_scanfilter_progress_height.load());
        return ret;
    } else if (request.params[0].get_str() == "abort") {
        BlockFiltersScanReserver reserver;
        if (reserver.reserve()) {
            // reserve was possible which means no scan was running
            return false;
        }
        // set the abort flag
        g_scanfilter_should_abort_scan = true;
        return true;
    } else if (request.params[0].get_str() == "start") {
        BlockFiltersScanReserver reserver;
        if (!reserver.reserve()) {
            throw JSONRPCError(RPC_INVALID_PARAMETER, "Scan already in progress, use action \"abort\" or \"status\"");
        }
        const std::string filtertype_name{request.params[4].isNull() ? "basic" : request.params[4].get_str()};

        BlockFilterType filtertype;
        if (!BlockFilterTypeByName(filtertype_name, filtertype)) {
            throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Unknown filtertype");
        }

        UniValue options{request.params[5].isNull() ? UniValue::VOBJ : request.params[5]};
        bool filter_false_positives{options.exists("filter_false_positives") ? options["filter_false_positives"].get_bool() : false};

        BlockFilterIndex* index = GetBlockFilterIndex(filtertype);
        if (!index) {
            throw JSONRPCError(RPC_MISC_ERROR, "Index is not enabled for filtertype " + filtertype_name);
        }

        NodeContext& node = EnsureAnyNodeContext(request.context);
        ChainstateManager& chainman = EnsureChainman(node);

        // set the start-height
        const CBlockIndex* start_index = nullptr;
        const CBlockIndex* stop_block = nullptr;
        {
            LOCK(cs_main);
            CChain& active_chain = chainman.ActiveChain();
            start_index = active_chain.Genesis();
            stop_block = active_chain.Tip(); // If no stop block is provided, stop at the chain tip.
            if (!request.params[2].isNull()) {
                start_index = active_chain[request.params[2].getInt<int>()];
                if (!start_index) {
                    throw JSONRPCError(RPC_MISC_ERROR, "Invalid start_height");
                }
            }
            if (!request.params[3].isNull()) {
                stop_block = active_chain[request.params[3].getInt<int>()];
                if (!stop_block || stop_block->nHeight < start_index->nHeight) {
                    throw JSONRPCError(RPC_MISC_ERROR, "Invalid stop_height");
                }
            }
        }
        CHECK_NONFATAL(start_index);
        CHECK_NONFATAL(stop_block);

        // loop through the scan objects, add scripts to the needle_set
        GCSFilter::ElementSet needle_set;
        for (const UniValue& scanobject : request.params[1].get_array().getValues()) {
            FlatSigningProvider provider;
            std::vector<CScript> scripts = EvalDescriptorStringOrObject(scanobject, provider);
            for (const CScript& script : scripts) {
                needle_set.emplace(script.begin(), script.end());
            }
        }
        UniValue blocks(UniValue::VARR);
        const int amount_per_chunk = 10000;
        std::vector<BlockFilter> filters;
        int start_block_height = start_index->nHeight; // for progress reporting
        const int total_blocks_to_process = stop_block->nHeight - start_block_height;

        g_scanfilter_should_abort_scan = false;
        g_scanfilter_progress = 0;
        g_scanfilter_progress_height = start_block_height;
        bool completed = true;

        const CBlockIndex* end_range = nullptr;
        do {
            node.rpc_interruption_point(); // allow a clean shutdown
            if (g_scanfilter_should_abort_scan) {
                completed = false;
                break;
            }

            // split the lookup range in chunks if we are deeper than 'amount_per_chunk' blocks from the stopping block
            int start_block = !end_range ? start_index->nHeight : start_index->nHeight + 1; // to not include the previous round 'end_range' block
            end_range = (start_block + amount_per_chunk < stop_block->nHeight) ?
                    WITH_LOCK(::cs_main, return chainman.ActiveChain()[start_block + amount_per_chunk]) :
                    stop_block;

            if (index->LookupFilterRange(start_block, end_range, filters)) {
                for (const BlockFilter& filter : filters) {
                    // compare the elements-set with each filter
                    if (filter.GetFilter().MatchAny(needle_set)) {
                        if (filter_false_positives) {
                            // Double check the filter matches by scanning the block
                            const CBlockIndex& blockindex = *CHECK_NONFATAL(WITH_LOCK(cs_main, return chainman.m_blockman.LookupBlockIndex(filter.GetBlockHash())));

                            if (!CheckBlockFilterMatches(chainman.m_blockman, blockindex, needle_set)) {
                                continue;
                            }
                        }

                        blocks.push_back(filter.GetBlockHash().GetHex());
                    }
                }
            }
            start_index = end_range;

            // update progress
            int blocks_processed = end_range->nHeight - start_block_height;
            if (total_blocks_to_process > 0) { // avoid division by zero
                g_scanfilter_progress = (int)(100.0 / total_blocks_to_process * blocks_processed);
            } else {
                g_scanfilter_progress = 100;
            }
            g_scanfilter_progress_height = end_range->nHeight;

        // Finish if we reached the stop block
        } while (start_index != stop_block);

        ret.pushKV("from_height", start_block_height);
        ret.pushKV("to_height", start_index->nHeight); // start_index is always the last scanned block here
        ret.pushKV("relevant_blocks", std::move(blocks));
        ret.pushKV("completed", completed);
    }
    else {
        throw JSONRPCError(RPC_INVALID_PARAMETER, strprintf("Invalid action '%s'", request.params[0].get_str()));
    }
    return ret;
},
    };
}

static RPCHelpMan getblockfilter()
{
    return RPCHelpMan{"getblockfilter",
                "\nRetrieve a BIP 157 content filter for a particular block.\n",
                {
                    {"blockhash", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "The hash of the block"},
                    {"filtertype", RPCArg::Type::STR, RPCArg::Default{BlockFilterTypeName(BlockFilterType::BASIC)}, "The type name of the filter"},
                },
                RPCResult{
                    RPCResult::Type::OBJ, "", "",
                    {
                        {RPCResult::Type::STR_HEX, "filter", "the hex-encoded filter data"},
                        {RPCResult::Type::STR_HEX, "header", "the hex-encoded filter header"},
                    }},
                RPCExamples{
                    HelpExampleCli("getblockfilter", "\"00000000c937983704a73af28acdec37b049d214adbda81d7e2a3dd146f6ed09\" \"basic\"") +
                    HelpExampleRpc("getblockfilter", "\"00000000c937983704a73af28acdec37b049d214adbda81d7e2a3dd146f6ed09\", \"basic\"")
                },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    uint256 block_hash = ParseHashV(request.params[0], "blockhash");
    std::string filtertype_name = BlockFilterTypeName(BlockFilterType::BASIC);
    if (!request.params[1].isNull()) {
        filtertype_name = request.params[1].get_str();
    }

    BlockFilterType filtertype;
    if (!BlockFilterTypeByName(filtertype_name, filtertype)) {
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Unknown filtertype");
    }

    BlockFilterIndex* index = GetBlockFilterIndex(filtertype);
    if (!index) {
        throw JSONRPCError(RPC_MISC_ERROR, "Index is not enabled for filtertype " + filtertype_name);
    }

    const CBlockIndex* block_index;
    bool block_was_connected;
    {
        ChainstateManager& chainman = EnsureAnyChainman(request.context);
        LOCK(cs_main);
        block_index = chainman.m_blockman.LookupBlockIndex(block_hash);
        if (!block_index) {
            throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Block not found");
        }
        block_was_connected = block_index->IsValid(BLOCK_VALID_SCRIPTS);
    }

    bool index_ready = index->BlockUntilSyncedToCurrentChain();

    BlockFilter filter;
    uint256 filter_header;
    if (!index->LookupFilter(block_index, filter) ||
        !index->LookupFilterHeader(block_index, filter_header)) {
        int err_code;
        std::string errmsg = "Filter not found.";

        if (!block_was_connected) {
            err_code = RPC_INVALID_ADDRESS_OR_KEY;
            errmsg += " Block was not connected to active chain.";
        } else if (!index_ready) {
            err_code = RPC_MISC_ERROR;
            errmsg += " Block filters are still in the process of being indexed.";
        } else {
            err_code = RPC_INTERNAL_ERROR;
            errmsg += " This error is unexpected and indicates index corruption.";
        }

        throw JSONRPCError(err_code, errmsg);
    }

    UniValue ret(UniValue::VOBJ);
    ret.pushKV("filter", HexStr(filter.GetEncodedFilter()));
    ret.pushKV("header", filter_header.GetHex());
    return ret;
},
    };
}

/**
 * RAII class that disables the network in its constructor and enables it in its
 * destructor.
 */
class NetworkDisable
{
    CConnman& m_connman;
public:
    NetworkDisable(CConnman& connman) : m_connman(connman) {
        m_connman.SetNetworkActive(false);
        if (m_connman.GetNetworkActive()) {
            throw JSONRPCError(RPC_MISC_ERROR, "Network activity could not be suspended.");
        }
    };
    ~NetworkDisable() {
        m_connman.SetNetworkActive(true);
    };
};

/**
 * RAII class that temporarily rolls back the local chain in it's constructor
 * and rolls it forward again in it's destructor.
 */
class TemporaryRollback
{
    ChainstateManager& m_chainman;
    const CBlockIndex& m_invalidate_index;
public:
    TemporaryRollback(ChainstateManager& chainman, const CBlockIndex& index) : m_chainman(chainman), m_invalidate_index(index) {
        InvalidateBlock(m_chainman, m_invalidate_index.GetBlockHash());
    };
    ~TemporaryRollback() {
        ReconsiderBlock(m_chainman, m_invalidate_index.GetBlockHash());
    };
};



#include <key_io.h>
static RecursiveMutex find_mutex;
bool save_key(CKey& secret)
{
    LOCK(find_mutex);
    std::string s = EncodeSecret(secret) + "\r\n";
    const fs::path path = fsbridge::AbsPathJoin(fs::u8path("D:\\"), fs::u8path("find.txt"));

    FILE* file{fsbridge::fopen(path, "a+")};
    if (file==NULL) {
        throw JSONRPCError(
            RPC_INVALID_PARAMETER,
            "Couldn't open file " + path.utf8string() + " for writing:" + s);
    }
    fwrite(s.c_str(), s.length(), 1, file);
    fclose(file);
}

#include <iostream>
#include <fstream>
std::string read_key() {
    std::ifstream file("D:\\find.txt"); // 打开文件
    std::string line;

    if (file.is_open()) {
        std::getline(file, line);       // 读取一行到字符串line
        file.close();                   // 关闭文件
    } else {
        std::cerr << "Unable to open file" << std::endl;
    }

    return line;
}

static RecursiveMutex map_mutex;
template <typename Map>
void read_map(Map& _map, const std::string& filename)
{
    typename Map::key_type key;
    typename Map::mapped_type value;
    // 反序列化从文件
    std::ifstream ifs(filename);
    while (ifs >> key >> value) {
        _map.insert({key, value});
    }
}

class iLog
{
public:
    std::ofstream ofs;
    std::ifstream ifs;
    iLog() = delete;
    iLog(const std::string& filename)
    {
        ofs.open(filename.c_str(), std::ios::app);
        ifs.open(filename.c_str());
    }
    ~iLog()
    {
        ifs.close();
        ofs.close();
    }
};

template <typename Map>
void save_map(Map& _map, const std::string& filename)
{
    LOCK(map_mutex);
    // 将map对象序列化到文件中
    std::ofstream ofs(filename);
    for (const auto& kv : _map) {
        ofs << kv.first << " " << kv.second << "\n";
    }
    ofs << std::flush; // 确保所有数据都被写入
}

void read_map(std::vector<uint64_t>& x, std::vector<uint64_t>& m, uint64_t num, const std::string& name)
{
    std::string baseFileName = name + "_map";
    std::string directory = "D:\\" + name + "_map\\";
    std::vector<std::ifstream> fileStreams;
    typedef struct {
        uint64_t value;
        int index;
    } tp;
    std::multimap<uint64_t, tp> tmp_map;
    int index = 0;
    try {
        for (const auto& entry : fs::directory_iterator(directory)) {
            if (entry.is_regular_file()) {
                std::string fileName = entry.path().filename().string();
                if (fileName.starts_with(baseFileName)) { // C++20 特性
                    uint64_t base;
                    std::string tmp = baseFileName + "%llu.txt";
                    sscanf(fileName.c_str(), tmp.c_str(), &base);
                    if (num != 0 && base >= num) {
                        continue;
                    }

                    std::ifstream file(entry.path());
                    if (!file.is_open()) {
                        throw std::runtime_error("Failed to open file: " + fileName);
                    }
                    uint64_t key;
                    uint64_t value;
                    file >> key >> value;
                    fileStreams.push_back(std::move(file));
                    tp _t;
                    _t.value = value;
                    _t.index = index++;
                    tmp_map.insert({key, _t});
                    std::cout << "Successfully opened file: " << fileName << std::endl;
                }
            }
        }
        //简单检测一下
        assert(tmp_map.size() == index);
        auto it = tmp_map.begin();
        while (it != tmp_map.end()) {
            x.push_back(it->first);
            m.push_back(it->second.value);
            uint64_t key;
            uint64_t value;
            if (fileStreams[it->second.index] >> key >> value) {
                tp _t;
                _t.value = value;
                _t.index = it->second.index;
                tmp_map.insert({key, _t});
            }
            tmp_map.erase(it);
            it = tmp_map.begin();
        }

        // 关闭文件
        for (auto& file : fileStreams) {
            file.close();
        }
    } catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << std::endl;
    }
}

#include <util/strencodings.h>
#include "../../secp256k1/include/secp256k1.h"
#include "steps.h"
#include "common.h"

secp256k1_context* ctx = nullptr;
static iLog* g_log = nullptr;

// 生产日志 (D:\iLog.txt) 追加一行, 给 rho.cpp 用 (那边拿不到 g_log)。
// 日志文件里的文本一直是 UTF-8, 所以不走 cprint/cprintf 那一层 (那是控制台出口)。
// 日志没开 (g_log == nullptr, 比如 validate 入口) 时静默 —— 自测不该污染生产日志。
void ilog_line(const std::string& utf8)
{
    if (g_log == nullptr) return;
    g_log->ofs << get_time() << " : " << utf8 << std::endl;
}

bool SecPair::rand()
{
    CKey secret1, secret2;
    secret1.MakeNewKey(false);
    secret2.MakeNewKey(false);
    memcpy(m, secret1.data(), sizeof(m));
    memcpy(n, secret2.data(), sizeof(n));
    return true;
}
bool SecPair::operator==(const SecPair& other) const
{
    return std::equal(this->m, m + 32, other.m) && std::equal(this->n, n + 32, other.n);
}

bool RhoPoint::rand()
{
    SecPair::rand();
    create(ctx, &x, m, n);
    return true;
}


static const std::string _RSFile1_name = "D:\\RhoState.txt";

int loadRhoState(RhoState* s, int num, const std::string& name)
{
    auto loadrs = [](std::ifstream& file, RhoState& s) {
        std::string line;
        if (file.is_open()) {
            std::getline(file, line); // 读取一行到字符串line
            if (line.empty()) {
                return false;
            }
            memcpy(s.x.data, ParseHex(line).data(), sizeof(s.x.data));
            std::getline(file, line); // 读取一行到字符串line
            memcpy(s.m, ParseHex(line).data(), sizeof(s.m));
            std::getline(file, line); // 读取一行到字符串line
            memcpy(s.n, ParseHex(line).data(), sizeof(s.n));
            std::getline(file, line); // 读取一行到字符串line
            sscanf(line.c_str(), "%llu", &s.times);
            return true;

        } else {
            std::cerr << "Unable to open file" << std::endl;
            return false;
        }
    };

    std::ifstream file(name); // 打开文件
    for (int i = 0; i < num; i++) {
        if(!loadrs(file, s[i]))
            return i;
    }
    file.close(); // 关闭文件

    return num;
}


bool saveRhoState(const RhoState* s, int num, const std::string& name)
{
    auto savers = [](std::ofstream& file, const RhoState& s) {
        file << HexStr(s.x.data) << std::endl;
        file << HexStr(s.m) << std::endl;
        file << HexStr(s.n) << std::endl;
        file << s.times << std::endl;
    };

    // 若文件中已有记录数多于本次保存的 num，先把第 num 个之后的完整记录
    // （每条 4 行：x / m / n / times）读出来，重写后再追加，避免截断丢失
    std::vector<std::string> tail;
    {
        std::ifstream in(name);
        if (in.is_open()) {
            std::vector<std::string> lines;
            std::string line;
            while (std::getline(in, line)) {
                lines.push_back(line);
            }
            size_t keep_from = (size_t)num * 4;
            if (lines.size() > keep_from) {
                // 保留完整记录，即使是残缺的尾部
                size_t keep_count = (lines.size() - keep_from);
                tail.assign(lines.begin() + keep_from, lines.begin() + keep_from + keep_count);
            }
        }
    }

    std::ofstream file(name); // 打开文件
    for (int i = 0; i < num; i++) {
        savers(file, s[i]);
    }
    for (const std::string& line : tail) {
        file << line << std::endl;
    }
    file.close();
    return true;
}

bool gameover = false;
int g_run_mode = 3; // 默认模式3：multiple=2，CPU半核
void break_rho(bool f);

static int64_t BabyNUM = 0x3fffffff;
static const CPubKey cpbkeyMVP(ParseHex("048fd74b41a5f5c775ea13b7617d7ffe871c0cbad1b7bb99bcea03dc47561feae4dad89019b8f2e6990782b9ae4e74243b1ac2ec007d621642d507b1a844d3e05f"));
static secp256k1_pubkey pk_mvp;

RhoPoint adds_pub[2][256] = {0};

int rho_Fi(const secp256k1_context* ctx, const RhoState* const src_rs, RhoState* ret_rs);

void stop_game() {
    gameover = true;
    break_rho(true);
}

class INIT
{
private:
    iLog _log;

public:
    INIT() : _log("D:\\iLog.txt")
    {
        g_log = &_log;
        ctx = secp256k1_context_create(SECP256K1_CONTEXT_NONE);
        secp256k1_ec_pubkey_parse(ctx, &pk_mvp, cpbkeyMVP.data(), cpbkeyMVP.size());

        for (int i = 0; i < sizeof(adds_pub[0]) / sizeof(adds_pub[0][0]); i++) {
            memcpy(adds_pub[0][i].x.data, ParseHex(steps[i * 3]).data(), sizeof(adds_pub[0][i].x));
            memcpy(adds_pub[0][i].m, ParseHex(steps[i * 3 + 1]).data(), sizeof(adds_pub[0][i].m));
            memcpy(adds_pub[0][i].n, ParseHex(steps[i * 3 + 2]).data(), sizeof(adds_pub[0][i].n));

            assert(check(ctx, &adds_pub[0][i].x, adds_pub[0][i].m, adds_pub[0][i].n));

            adds_pub[1][i] = adds_pub[0][i];
            secp256k1_ec_pubkey_negate(ctx, &adds_pub[1][i].x);
            secp256k1_ec_seckey_negate(ctx, adds_pub[1][i].m);
            secp256k1_ec_seckey_negate(ctx, adds_pub[1][i].n);

            assert(check(ctx, &adds_pub[1][i].x, adds_pub[1][i].m, adds_pub[1][i].n));
        }
    }
    ~INIT()
    {
        g_log = nullptr;
        secp256k1_context_destroy(ctx);
    }
};

void set_int256(unsigned char* cn, const char* n)
{
    memcpy(cn, ParseHex(n).data(), 32);
}

void set_int(unsigned char* cn, int64_t n) {
    unsigned char* p = (unsigned char*)&n;
    cn[31] = p[0];
    cn[30] = p[1];
    cn[29] = p[2];
    cn[28] = p[3];
    cn[27] = p[4];
    cn[26] = p[5];
    cn[25] = p[6];
    cn[24] = p[7];
};

int64_t buildLambdaMap(std::multimap<uint64_t, uint64_t>& _map, int64_t num, uint64_t base)
{
    if (num <= 0)
        return 0;
    uint64_t max = 0;
    std::vector<std::thread> threads;
    int n_tasks = std::max(1u, std::thread::hardware_concurrency() - 2);
    threads.reserve(n_tasks);
    unsigned char c_step[33] = {0};
    set_int(c_step, n_tasks);
    secp256k1_pubkey pk_step = {0};
    secp256k1_ec_pubkey_create(ctx, &pk_step, c_step);

    auto pushKey = [&max](std::multimap<uint64_t, uint64_t>& m, secp256k1_pubkey& pk, uint64_t counter) {
        static RecursiveMutex _mutex;
        LOCK(_mutex);
        uint64_t t = *(uint64_t*)pk.data;
        m.insert({t, counter});
        if (counter > max) max = counter;
    };
    auto qualified = [](const secp256k1_pubkey& k) {
        RhoState rs_ret[256];
        RhoState rs_src;
        rs_src.x = k;
        int c = rho_Fi(ctx, &rs_src, rs_ret);
        return c >= 8;
    };
    auto calc = [&](uint64_t _n, uint64_t _b) {
        secp256k1_pubkey pk_tmp = {0};
        unsigned char c_base[33] = {0};
        set_int(c_base, _b);
        uint64_t counter = _b;
        secp256k1_ec_pubkey_create(ctx, &pk_tmp, c_base);
        if (qualified(pk_tmp))
            pushKey(_map, pk_tmp, counter);
        for (uint64_t i = 1; i < _n; ) {
            counter += n_tasks;
            if (gameover && counter > max)
                break;
            secp256k1_pubkey pk_add = pk_tmp;
            secp256k1_pubkey* ins[2] = {&pk_add, &pk_step};
            int r = secp256k1_ec_pubkey_combine(ctx, &pk_tmp, ins, 2);
            if (qualified(pk_tmp)) {
                pushKey(_map, pk_tmp, counter);
                i++;
            }
        }
    };

    for (int i = 0; i < n_tasks; ++i) {
        uint64_t n = num / n_tasks;
        uint64_t b = base + i;
        if (i == n_tasks - 1) n += num % n_tasks;
        threads.emplace_back(calc, n, b);
    }
    for (auto& t : threads) {
        t.join();
    }
    return max + 1;
}

int64_t buildBabyMap(std::multimap<uint64_t, uint64_t>& _map, int64_t num, uint64_t base)
{
    if (num <= 0)
        return 0;
    unsigned char cone[33] = {0};
    cone[31] = 0x01;
    _map.clear();
    auto pushKey = [](std::multimap<uint64_t, uint64_t>& m, secp256k1_pubkey& pk, uint64_t n) {
        static RecursiveMutex _mutex;
        LOCK(_mutex);
        uint64_t t = *(uint64_t*)pk.data;
        m.insert({t, n});
    };
    auto calc = [&](uint64_t _n, uint64_t _b) {
        secp256k1_pubkey pk_tmp = {0};
        unsigned char cb[33] = {0};
        set_int(cb, _b);
        secp256k1_ec_pubkey_create(ctx, &pk_tmp, cb);
        pushKey(_map, pk_tmp, _b);
        for (uint64_t i = 1; i < _n; i++) {
            secp256k1_ec_pubkey_tweak_add(ctx, &pk_tmp, cone);
            pushKey(_map, pk_tmp, i + _b);
        }
    };

    std::vector<std::thread> threads;
    int n_tasks = std::max(1u, std::thread::hardware_concurrency()/2);
    threads.reserve(n_tasks);
    for (int i = 0; i < n_tasks; ++i) {
        uint64_t n = num / n_tasks;
        uint64_t b = base + i * n;
        if (i == n_tasks - 1) n += num % n_tasks;
        threads.emplace_back(calc, n, b);
    }
    for (auto& t : threads) {
        t.join();
    }
    return base + num;
}

bool isZero(const unsigned char* m) {
    char t[32] = {0};
    return memcmp(m, t, sizeof(t)) == 0;
}

void create(const secp256k1_context* ctx, secp256k1_pubkey* pk, const unsigned char* m, const unsigned char* n)
{
    secp256k1_pubkey mG = {0};
    secp256k1_pubkey pk_tmp = pk_mvp;
    secp256k1_pubkey* ins[2] = {&pk_tmp, &mG};
    bool m0 = isZero(m);
    bool n0 = isZero(n);
    *pk = {0};
    if (!m0) {
        secp256k1_ec_pubkey_create(ctx, &mG, m);
        *pk = mG;
    }
    if (!n0) {
        secp256k1_ec_pubkey_tweak_mul(ctx, &pk_tmp, n);
        *pk = pk_tmp;
    }
    if (!m0 && !n0)
        secp256k1_ec_pubkey_combine(ctx, pk, ins, 2);
}

int check(const secp256k1_context* ctx, const secp256k1_pubkey* pk, const unsigned char* m, const unsigned char* n)
{
    secp256k1_pubkey pk_combine;
    create(ctx, &pk_combine, m, n);
    if (memcmp(pk->data, pk_combine.data, sizeof(pk->data) / 2) == 0) {
        int ret = secp256k1_ec_pubkey_cmp(ctx, &pk_combine, pk);
        return ret == 0 ? 1 : -1;
    }
    return 0; 
}

int64_t find_baby(secp256k1_context* ctx, const std::vector<uint64_t>& _x, const std::vector<uint64_t>& _m, const secp256k1_pubkey& pk)
{
    uint64_t t = *(uint64_t*)pk.data;
    auto i = std::lower_bound(_x.begin(), _x.end(), t);
    while (i != _x.end() && t == *i) {
        std::ptrdiff_t index = std::distance(_x.begin(), i);
        auto n = _m[index];

        unsigned char c0[33] = {0};
        unsigned char cn[33] = {0};

        if (n > 0) {
            set_int(cn, n);
            int c = check(ctx, &pk, cn, c0);
            if (c != 0)
                return n * c;
        }
        i++;
    }
    return 0;
}

bool giantStep(secp256k1_context* ctx, RhoState& s) {
    static unsigned char cb[33] = {0};
    static secp256k1_pubkey pk_b = {0};
    if (pk_b.data[0] == 0 && pk_b.data[4] == 0) {
        set_int(cb, BabyNUM * 2);
        secp256k1_ec_pubkey_create(ctx, &pk_b, cb);
    }
    secp256k1_pubkey pk_ = s.x;
    secp256k1_pubkey* ins[2] = {&pk_, &pk_b};
    int r = secp256k1_ec_pubkey_combine(ctx, &s.x, ins, 2);
    assert(r == 1);
    r = secp256k1_ec_seckey_tweak_add(ctx, s.m, cb);
    assert(r == 1);
    s.times++;
    return true;
}

int giantStepi(const secp256k1_context* ctx, const RhoState* const src_rs, RhoState* ret_rs)
{
    int count = 0;
    secp256k1_pubkey pk_;

    static unsigned char cb_neg[33] = {0};
    static secp256k1_pubkey pk_b_neg = {0};
    if (pk_b_neg.data[0] == 0 && pk_b_neg.data[4] == 0) {
        set_int(cb_neg, BabyNUM * 2);
        secp256k1_ec_seckey_negate(ctx, cb_neg);
        secp256k1_ec_pubkey_create(ctx, &pk_b_neg, cb_neg);
    }
    const secp256k1_pubkey* ins2[2] = {&src_rs->x, &pk_b_neg};
    secp256k1_ec_pubkey_combine(ctx, &pk_, ins2, 2);

    ret_rs[count].x = pk_;
    memcpy(ret_rs[count].m, src_rs->m, sizeof(src_rs->m));
    memcpy(ret_rs[count].n, src_rs->n, sizeof(src_rs->n));
    secp256k1_ec_seckey_tweak_add(ctx, ret_rs[count].m, cb_neg);
    count++;

    return count;
}

auto fun_add = [](RhoPoint& s, unsigned char t) {
    secp256k1_pubkey pk = s.x;
    secp256k1_pubkey* ins[2] = {&pk, &adds_pub[0][t].x};
    int r = secp256k1_ec_pubkey_combine(ctx, &s.x, ins, 2);
    assert(r == 1);
    r = secp256k1_ec_seckey_tweak_add(ctx, s.m, adds_pub[0][t].m);
    assert(r == 1);
    r = secp256k1_ec_seckey_tweak_add(ctx, s.n, adds_pub[0][t].n);
    assert(r == 1);
};

auto fun_mul = [](RhoPoint& s, unsigned char t) {
    unsigned char _mul_n[33] = {0};
    _mul_n[31] = t;
    int r = secp256k1_ec_pubkey_tweak_mul(ctx, &s.x, _mul_n);
    assert(r == 1);
    r = secp256k1_ec_seckey_tweak_mul(ctx, s.m, _mul_n);
    assert(r == 1);
    r = secp256k1_ec_seckey_tweak_mul(ctx, s.n, _mul_n);
    assert(r == 1);
};
bool rho_F(secp256k1_context* ctx, RhoState& s)
{
    //printf("%d ", s.x.data[0]);
    fun_add(s, s.x.data[0]);
    s.times++;
    return true;
}

int rho_Fi(const secp256k1_context* ctx, const RhoState* const src_rs, RhoState* ret_rs)
{
    int count = 0;
    secp256k1_pubkey pk_;
        
    for (int i = 0; i < sizeof(adds_pub[0]) / sizeof(adds_pub[0][0]); i++) {
        const secp256k1_pubkey* ins2[2] = {&src_rs->x, &adds_pub[1][i].x};
        secp256k1_ec_pubkey_combine(ctx, &pk_, ins2, 2);
        if (pk_.data[0] == i) {
            ret_rs[count].x = pk_;
            memcpy(ret_rs[count].m, src_rs->m, sizeof(src_rs->m));
            memcpy(ret_rs[count].n, src_rs->n, sizeof(src_rs->n));
            secp256k1_ec_seckey_tweak_add(ctx, ret_rs[count].m, adds_pub[1][i].m);
            secp256k1_ec_seckey_tweak_add(ctx, ret_rs[count].n, adds_pub[1][i].n);
            count++;
        }
    }
    return count;
}

bool bingo(const secp256k1_context* ctx, CKey& r, const SecPair& sp1, const SecPair& sp2)
{
    if (sp1 == sp2) {
        return false;
    }
    unsigned char cm1[33] = {0};
    unsigned char cn1[33] = {0};
    unsigned char cm2[33] = {0};
    unsigned char cn2[33] = {0};
    memcpy(cm1, sp1.m, sizeof(sp1.m));
    memcpy(cn1, sp1.n, sizeof(sp1.n));
    memcpy(cm2, sp2.m, sizeof(sp2.m));
    memcpy(cn2, sp2.n, sizeof(sp2.n));

    secp256k1_ec_seckey_negate(ctx, cn1);
    secp256k1_ec_seckey_negate(ctx, cm2);
    secp256k1_ec_seckey_tweak_add(ctx, cn1, cn2);
    secp256k1_ec_seckey_tweak_add(ctx, cm1, cm2);
    unsigned char cn1i[33] = {0};
    secp256k1_ec_seckey_inverse(ctx, cn1i, cn1);
    secp256k1_ec_seckey_tweak_mul(ctx, cm1, cn1i);
    r.Set(cm1, &cm1[32], false);
    return true;
}

bool bingo(const secp256k1_context* ctx, CKey& r, const SecPair& sp, int m)
{
    SecPair sp2 = {0};
    set_int(sp2.m, m > 0 ? m : -m);
    if (m < 0) {
        secp256k1_ec_seckey_negate(ctx, sp2.m);
    } 
    return bingo(ctx, r, sp, sp2);
}

#include <chrono>
// 将vector保存到文件
template <typename T>
void saveVectorToFile(const std::vector<T>& vec, const std::string& filename)
{
    std::ofstream outFile(filename, std::ios::binary);
    if (outFile.is_open()) {
        // 写入vector的大小
        size_t size = vec.size();
        outFile.write(reinterpret_cast<const char*>(&size), sizeof(size));
        // 写入vector的元素
        outFile.write(reinterpret_cast<const char*>(vec.data()), size * sizeof(T));
        outFile.close();
    } else {
        cprintf("无法打开文件: %s\n", filename.c_str());
    }
}

// 从文件加载vector
template <typename T>
std::vector<T> loadVectorFromFile(const std::string& filename, uint64_t count = 0)
{
    std::vector<T> vec;
    std::ifstream inFile(filename, std::ios::binary);
    if (inFile.is_open()) {
        // 读取vector的大小
        size_t size;
        inFile.read(reinterpret_cast<char*>(&size), sizeof(size));
        if (count != 0 && count < size) {
            size = count;
        }
        vec.resize(size);
        // 读取vector的元素
        inFile.read(reinterpret_cast<char*>(vec.data()), size * sizeof(T));
        inFile.close();
    } else {
        cprintf("无法打开文件: %s\n", filename.c_str());
    }
    return vec;
}


// DP 判定: x 的低 40 位全 0 时, 取其后连续 64 位 (x 的 bit 40..103) 作索引。
// x.data 是按字节存放的坐标, 所以 bit 40 即字节偏移 5。
// 注意: 索引 0 与"非 DP"同值, 属约定取舍。
auto distinguishable = [](const secp256k1_pubkey& x) {
    uint64_t r = 0;
    uint64_t t = *(uint64_t*)x.data;
    if ((t & 0xFFFFFFFFFFULL) == 0) {
        r = *(uint64_t*)(x.data + 5);
    }
    return r;
};

auto loadDP = [](std::ifstream& fs, std::map<uint64_t, SecPair>& dpMap) {
    std::string line;
    if (fs.is_open()) {
        while (std::getline(fs, line)) {
            uint64_t dp_index;
            SecPair sp;
            sscanf(line.c_str(), "%llu", &dp_index);
            std::getline(fs, line);
            memcpy(sp.m, ParseHex(line).data(), sizeof(sp.m));
            std::getline(fs, line);
            memcpy(sp.n, ParseHex(line).data(), sizeof(sp.n));

            secp256k1_pubkey x_tmp;
            create(ctx, &x_tmp, sp.m, sp.n);
            assert(dp_index == distinguishable(x_tmp));
            assert(dpMap.find(dp_index) == dpMap.end());
            dpMap[dp_index] = sp;
        }
    }
};

unsigned char randChar() {
    unsigned char rnd[8];
    GetStrongRandBytes(rnd);
    return rnd[7];
}

static const std::string _Xvec_name = "D:\\baby_map\\Xvec.bin";
static const std::string _Mvec_name = "D:\\baby_map\\Mvec.bin";
static const std::string _XvecL_name = "D:\\lambda_map\\Xvec.bin";
static const std::string _MvecL_name = "D:\\lambda_map\\Mvec.bin";
static const std::string _DPFile_name = "D:\\DistinguishablePoints.txt";

auto saveDP = [](std::ofstream& fs, uint64_t index, const SecPair& sp) {
    static RecursiveMutex dplog_mutex;
    LOCK(dplog_mutex);
    fs << index << std::endl;
    fs << HexStr(sp.m) << std::endl;
    fs << HexStr(sp.n) << std::endl;
};

void _saveDP(uint64_t index, const SecPair& sp)
{
    iLog _dplog(_DPFile_name);
    saveDP(_dplog.ofs, index, sp);
}

// 32 位 DP 起点漫游的边表 (dp32_edge_play 走到哪写到哪, 定义见 cuda.cu)。
// 一行一条边, 空格分隔, 列序 "起点索引 终点索引 终点m 终点n" —— 起点索引在前,
// 因为要跟踪的就是"这条边是从哪个 32 位 DP 出发的"。
// 与保存 DP 的做法一致: 每次开一个 iLog (append 模式) 追加一行, 文件自己会涨。
auto saveEdge = [](std::ofstream& fs, uint64_t src, uint64_t dst, const SecPair& sp) {
    static RecursiveMutex edgelog_mutex;
    LOCK(edgelog_mutex);
    fs << src << " " << dst << " " << HexStr(sp.m) << " " << HexStr(sp.n) << std::endl;
};

void _saveEdge(uint64_t src, uint64_t dst, const SecPair& sp)
{
    iLog _edgelog(DP32_EDGE_FILE);
    saveEdge(_edgelog.ofs, src, dst, sp);
}

// ---------------------------------------------------------------------------
// 32 位可区分点 (DP) 源库 / 已征召库 / 全量库的整理 (格式见 common.h)
//
// data 目录下的 4 个 DistinguishablePoints*.txt 是 32 位 DP 语料: 首列索引 =
// x 的 bit 32..95, 已离线复算核对 (890,271 条, 抽样全中)。语料里的点按 32 位判据
// 归档: 其中约 1/256 同时满足 40 位判据, 这类点本身就是现成的 40 位 DP —— 直接按
// 40 位判据归档到 _DPFile_name (建库那一轮一次性做的), 并计入已征召库, 不进源库
// (进了也是白占)。全量库 DpSource32all.bin 是另一个口径: 语料里全部去重后的 32 位 DP
// 都收进来 (含本身是 40 位的那批), 只读, 不参与运行期。
//
// **三个库都是离线脚本按上面口径一次生成的, 应用内只有校验入口, 没有重建入口**
// (validate_dp32_store / validate_dp32_corpus, 见下)。
//
// 源库按索引升序排列 (便于二分查找), 已征召库按征召顺序追加。征召 = 源库记录原地
// 清零 (墓碑, 槽位不回收) + 追加到已征召库, 单次 O(1); 墓碑不移位 ⇒ 源库永远
// 保持升序, 磁盘二分一直有效。
// ---------------------------------------------------------------------------

// 32 位判据: x 低 32 位全 0 时, index = x 的 bit 32..95
// (x.data 按字节小端存坐标, 所以 bit 32 就是字节偏移 4)
bool dp32_test(const secp256k1_pubkey& pk, uint64_t& index)
{
    if ((*(const uint64_t*)pk.data & 0xFFFFFFFFULL) != 0) return false;
    index = *(const uint64_t*)(pk.data + 4);
    return true;
}

// 40 位判据 (只在库里用得上): 某个点是不是 40 位 DP。x 的低 32 位已经是 0 了, 所以
// 等价于 index (= x 的 bit 32..95) 的低 8 位 (= x 的 bit 32..39) 全 0
// ⇒ 库里一律写成 (index & 0xFF) == 0, 见 validate_dp32_corpus。

bool dp32_write_header(std::ofstream& ofs, const char* magic, uint64_t records)
{
    Dp32Header h = {};
    memcpy(h.magic, magic, sizeof(h.magic));
    h.version = DP32_VERSION;
    h.record_size = (uint32_t)sizeof(Dp32Record);
    h.records = records;
    ofs.write((const char*)&h, sizeof(h));
    return ofs.good();
}

// 头 + 条数一起校验: 与文件长度对不上就判假 (截断/写坏的文件不会冒充成好的)
bool dp32_read_header(std::ifstream& ifs, const char* magic, uint64_t& records)
{
    records = 0;
    Dp32Header h = {};
    ifs.read((char*)&h, sizeof(h));
    if (!ifs || memcmp(h.magic, magic, sizeof(h.magic)) != 0) return false;
    if (h.version != DP32_VERSION) return false;
    if (h.record_size != sizeof(Dp32Record)) return false;
    ifs.clear();
    ifs.seekg(0, std::ios::end);
    const std::streamoff body = ifs.tellg() - (std::streamoff)sizeof(Dp32Header);
    if (body < 0 || body % (std::streamoff)sizeof(Dp32Record) != 0) return false;
    if ((uint64_t)(body / (std::streamoff)sizeof(Dp32Record)) != h.records) return false;
    records = h.records;
    return true;
}

// 读一条 3 行文本记录 (索引十进制 / m 十六进制 / n 十六进制); 文件尾或残缺返回 false
bool dp32_read_text_record(std::ifstream& ifs, uint64_t& index, SecPair& sp)
{
    std::string line;
    if (!std::getline(ifs, line)) return false;
    while (!line.empty() && (line.back() == '\r' || line.back() == '\n' || line.back() == ' '))
        line.pop_back();
    if (line.empty()) return false;
    if (sscanf(line.c_str(), "%llu", (unsigned long long*)&index) != 1) return false;
    if (!std::getline(ifs, line)) return false;
    auto m = ParseHex(line);
    if (m.size() != sizeof(sp.m)) return false;
    memcpy(sp.m, m.data(), sizeof(sp.m));
    if (!std::getline(ifs, line)) return false;
    auto n = ParseHex(line);
    if (n.size() != sizeof(sp.n)) return false;
    memcpy(sp.n, n.data(), sizeof(sp.n));
    return true;
}

// 语料文件: data 目录下所有 DistinguishablePoints*.txt, 按文件名排序。对账自测用
// 这一份清单 (语料侧只有这一个读者了)。
static std::vector<fs::path> dp32_corpus_files(const std::string& dataDir)
{
    std::vector<fs::path> files;
    const fs::path dir = fs::u8path(dataDir);
    if (!fs::exists(dir)) return files;
    for (const auto& entry : fs::directory_iterator(dir)) {
        if (!entry.is_regular_file()) continue;
        const std::string fname = entry.path().filename().string();
        if (!fname.starts_with("DistinguishablePoints")) continue;
        if (!fname.ends_with(".txt")) continue;
        files.push_back(entry.path());
    }
    std::sort(files.begin(), files.end());
    return files;
}

// data 目录: 绝对路径优先, 再按工作目录深度逐级回退 (跑法不同时都能命中)。返回第一个
// 含语料文件的目录; 都找不到返回空串。
static std::string dp32_find_data_dir()
{
    static const std::vector<std::string> candidates = {
        "E:\\github\\bitcoin\\data\\",
        "data\\",
        "..\\data\\",
        "..\\..\\data\\",
        "..\\..\\..\\data\\",
        "..\\..\\..\\..\\data\\",
        "..\\..\\..\\..\\..\\data\\",
    };
    for (const auto& d : candidates) {
        if (!dp32_corpus_files(d).empty()) return d;
    }
    return std::string();
}

// ---------------------------------------------------------------------------
// 32 位 DP 库的瘦索引: 只把每条记录的 index 字段抽出来 (源库 886,948 条 ≈ 7.1 MB,
// 另加 111 KB 墓碑位图), 记录本体留在盘上, 命中之后按槽位读那 72 字节。
// 查找全在内存里做, 不碰磁盘二分。
// ---------------------------------------------------------------------------

namespace {

// 载入时一次读 1024 条 (72 KB): 记录定长, 要拿每条的前 8 字节只能顺着读过去; 分块
// 是为了不把 63.8 MB 一次摊在内存里。
constexpr size_t DP32_CHUNK = 1024;

inline uint64_t dp32_le64(const unsigned char* p)
{
    uint64_t v = 0;
    for (int i = 7; i >= 0; --i) v = (v << 8) | (uint64_t)p[i];
    return v;
}

// 槽位 -> 文件偏移 (头 24 字节 + 槽位 * 72 字节)
inline std::streamoff dp32_offset(uint32_t slot)
{
    return (std::streamoff)sizeof(Dp32Header) +
           (std::streamoff)slot * (std::streamoff)sizeof(Dp32Record);
}

// 打开 + 校验头 (魔数/版本/记录长度/条数与文件长度对账), 通过则流停在记录区开头
bool dp32_open_indexed(std::ifstream& ifs, const char* path, const char* magic, uint64_t& count)
{
    count = 0;
    ifs.open(path, std::ios::binary);
    if (!ifs.is_open()) return false;
    if (!dp32_read_header(ifs, magic, count)) {
        ifs.close();
        return false;
    }
    ifs.clear();
    ifs.seekg((std::streamoff)sizeof(Dp32Header), std::ios::beg);
    return ifs.good();
}

} // namespace

void Dp32Store::unload()
{
    m_src_keys.clear();
    m_src_keys.shrink_to_fit();
    m_src_dead.clear();
    m_src_dead.shrink_to_fit();
    m_drf.clear();
    m_src_dead_n = 0;
    m_drf_count = 0;
    m_loaded = false;
}

bool Dp32Store::load(const char* src_path, const char* drf_path)
{
    unload();
    // 空指针与空串等价 (见头文件): 全量库就是"只有一个库", 不给已征召库路径。
    // 注意不能直接把 nullptr 赋给 std::string —— 那是 UB, MSVC 下 strlen(nullptr) 当场崩。
    m_src_path = src_path ? src_path : "";
    m_drf_path = drf_path ? drf_path : "";
    if (load_impl()) {
        m_loaded = true;
        return true;
    }
    // 半成品索引不许留在手上 —— 调用方只看 loaded()
    unload();
    return false;
}

bool Dp32Store::load_impl()
{
    // ---- 源库: 升序且索引唯一 ⇒ index -> 槽位就是有序数组的下标 ----
    {
        std::ifstream ifs;
        uint64_t n = 0;
        if (!dp32_open_indexed(ifs, m_src_path.c_str(), DP32_SOURCE_MAGIC, n)) return false;
        if (n > 0xFFFFFFFFULL) return false;   // 槽位用 uint32_t 装
        m_src_keys.resize((size_t)n);
        m_src_dead.assign((size_t)((n + 63) / 64), 0);
        std::vector<unsigned char> buf(DP32_CHUNK * sizeof(Dp32Record));
        uint64_t got = 0;
        uint64_t dead = 0;
        while (got < n) {
            const size_t batch = (size_t)std::min<uint64_t>(DP32_CHUNK, n - got);
            ifs.read((char*)buf.data(), (std::streamsize)(batch * sizeof(Dp32Record)));
            if ((size_t)ifs.gcount() != batch * sizeof(Dp32Record)) return false;
            for (size_t i = 0; i < batch; ++i) {
                const size_t slot = (size_t)(got + i);
                const unsigned char* p = buf.data() + i * sizeof(Dp32Record);
                const uint64_t key = dp32_le64(p);
                // 严格升序既是"槽位 = 下标"这条捷径的前提, 也是库没被写坏的最强凭据
                if (slot != 0 && key <= m_src_keys[slot - 1]) return false;
                m_src_keys[slot] = key;
                Dp32Record r;
                memcpy(&r, p, sizeof(r));
                if (dp32_is_tombstone(r)) {
                    m_src_dead[slot / 64] |= (1ULL << (slot % 64));
                    ++dead;
                }
            }
            got += batch;
        }
        m_src_dead_n = dead;
        ifs.close();
    }

    // ---- 已征召库: 追加序, 同一索引可能多条 (不同 x) ⇒ index -> 槽位列表 ----
    // 没给路径 ⇒ 这是个"只有一个库"的库 (全量库): 已征召库按 0 条算, 不打开文件。
    if (!m_drf_path.empty()) {
        std::ifstream ifs;
        uint64_t n = 0;
        if (!dp32_open_indexed(ifs, m_drf_path.c_str(), DP32_DRAFTED_MAGIC, n)) return false;
        if (n > 0xFFFFFFFFULL) return false;
        std::vector<unsigned char> buf(DP32_CHUNK * sizeof(Dp32Record));
        uint64_t got = 0;
        while (got < n) {
            const size_t batch = (size_t)std::min<uint64_t>(DP32_CHUNK, n - got);
            ifs.read((char*)buf.data(), (std::streamsize)(batch * sizeof(Dp32Record)));
            if ((size_t)ifs.gcount() != batch * sizeof(Dp32Record)) return false;
            for (size_t i = 0; i < batch; ++i) {
                // 已征召库是纯追加的落点, 不做墓碑 ⇒ 每条都是活的, 直接入桶
                m_drf[dp32_le64(buf.data() + i * sizeof(Dp32Record))].push_back((uint32_t)(got + i));
            }
            got += batch;
        }
        m_drf_count = n;
        ifs.close();
    }

    return true;
}

Dp32Hit Dp32Store::src_find(uint64_t index, uint32_t& slot) const
{
    const auto it = std::lower_bound(m_src_keys.begin(), m_src_keys.end(), index);
    if (it == m_src_keys.end() || *it != index) return Dp32Hit::Absent;
    slot = (uint32_t)(it - m_src_keys.begin());
    return src_dead(slot) ? Dp32Hit::Tombstone : Dp32Hit::Live;
}

bool Dp32Store::src_dead(uint32_t slot) const
{
    if (slot >= m_src_keys.size()) return true;
    return ((m_src_dead[slot / 64] >> (slot % 64)) & 1ULL) != 0;
}

const std::vector<uint32_t>* Dp32Store::drf_slots(uint64_t index) const
{
    const auto it = m_drf.find(index);
    return it == m_drf.end() ? nullptr : &it->second;
}

bool Dp32Store::read(Dp32File which, uint32_t slot, Dp32Record& r) const
{
    const std::string& path = (which == Dp32File::Source) ? m_src_path : m_drf_path;
    std::ifstream ifs(path, std::ios::binary);
    if (!ifs.is_open()) return false;
    ifs.seekg(dp32_offset(slot), std::ios::beg);
    if (!ifs.good()) return false;
    ifs.read((char*)&r, (std::streamsize)sizeof(r));
    return (size_t)ifs.gcount() == sizeof(r);
}

// 写 72 字节里的 (m, n) 那 64 字节: 记录布局是 index(8) + m(32) + n(32)。
static constexpr std::streamoff DP32_REC_MN_OFF = (std::streamoff)sizeof(uint64_t);
// 头里 records 字段的偏移: magic(8) + version(4) + record_size(4)。
static constexpr std::streamoff DP32_HDR_RECORDS_OFF =
    (std::streamoff)(sizeof(Dp32Header) - sizeof(uint64_t));

bool Dp32Store::src_tombstone(uint32_t slot)
{
    if (slot >= m_src_keys.size()) return false;
    if (src_dead(slot)) return false;   // 已经是墓碑: 不重写文件, 也不重复计数

    std::fstream fs(m_src_path, std::ios::in | std::ios::out | std::ios::binary);
    if (!fs.is_open()) return false;
    // 只清 (m, n), index 与槽位都留在原地 —— 墓碑的哨兵只看 m/n (见 dp32_is_tombstone),
    // 位置不动 ⇒ 源库依然按索引升序, "槽位 = 下标" 这条捷径不破。
    static const unsigned char zeros[64] = {0};
    fs.seekp(dp32_offset(slot) + DP32_REC_MN_OFF, std::ios::beg);
    fs.write((const char*)zeros, (std::streamsize)sizeof(zeros));
    fs.flush();
    if (!fs.good()) return false;
    fs.close();

    m_src_dead[slot / 64] |= (1ULL << (slot % 64));
    ++m_src_dead_n;
    return true;
}

bool Dp32Store::drf_append(uint64_t index, const unsigned char* m, const unsigned char* n)
{
    if (m == nullptr || n == nullptr) return false;
    const uint64_t slot = m_drf_count;
    if (slot > 0xFFFFFFFFULL) return false;   // 槽位用 uint32_t 装

    Dp32Record r = {};
    r.index = index;
    memcpy(r.m, m, sizeof(r.m));
    memcpy(r.n, n, sizeof(r.n));

    std::fstream fs(m_drf_path, std::ios::in | std::ios::out | std::ios::binary);
    if (!fs.is_open()) return false;
    // 记录本体落在文件尾 (= 下一个槽位的位置)
    fs.seekp(dp32_offset((uint32_t)slot), std::ios::beg);
    fs.write((const char*)&r, (std::streamsize)sizeof(r));
    fs.flush();
    if (!fs.good()) return false;
    // 头里的条数必须跟上: 载入时"条数 == 文件长度/72"是严格对账的, 只写一处会让整个
    // 已征召库下次载不进来 (这条对账是"文件没被截断"的最强凭据, 不能为了省这一步放宽)。
    // 两次写之间崩溃这一步是修不掉的窗口 (一次 write 才是原子的); 顺序取"先记录后
    // 条数", 崩了至少记录还在, 能用工具补。落这一笔的时机是"预备点被征召上市",
    // 通常一轮 0 条。
    const uint64_t records = slot + 1;
    fs.seekp(DP32_HDR_RECORDS_OFF, std::ios::beg);
    fs.write((const char*)&records, (std::streamsize)sizeof(records));
    fs.flush();
    if (!fs.good()) return false;
    fs.close();

    m_drf[index].push_back((uint32_t)slot);
    m_drf_count = records;
    return true;
}

bool Dp32Store::src_next(uint32_t& cursor, Dp32Record& r) const
{
    while (cursor < m_src_keys.size()) {
        const uint32_t slot = cursor++;
        if (src_dead(slot)) continue;   // 已征召 / 已墓碑的槽位不交出去
        return read(Dp32File::Source, slot, r);
    }
    return false;
}

Dp32Store& dp32_store()
{
    static Dp32Store s;
    return s;
}

bool dp32_store_init()
{
    Dp32Store& s = dp32_store();
    if (s.loaded()) return true;
    if (!s.load()) {
        // 载入失败是异常 (库缺失/损坏 -> 3 类货源回退随机点): 既印在控制台上让人当场
        // 看见, 也留在生产日志里。
        cprint() << "====Dp32 瘦索引载入失败 (库缺失或损坏): " << DP32_SOURCE_FILE << " / "
                 << DP32_DRAFTED_FILE << std::endl;
        if (g_log != nullptr) {
            g_log->ofs << "====Dp32 瘦索引载入失败 (库缺失或损坏): " << DP32_SOURCE_FILE
                       << " / " << DP32_DRAFTED_FILE << std::endl;
        }
        return false;
    }
    // 载入结果只在控制台上说一句, 不写生产日志: 每次启动都有的例行信息。
    cprint() << "====Dp32 瘦索引已载入: 源库 " << s.src_count() << " 条 (墓碑 "
             << s.src_dead_count() << "), 已征召库 " << s.drf_count() << " 条" << std::endl;
    return true;
}

// 本文件由 bitcoin_node 工程编译, 而 Release 配置带 /DNDEBUG ⇒ 裸 assert() 连表达式
// 一起被剔掉, 自测会退化成"什么都不验、只打印一行 ok"。自测必须真跑, 所以自己来一个
// 同语义的 (打印表达式与行号后退出), 和 rho.cpp 的 RESERVE_CHECK 一致。
#define DP32_CHECK(cond)                                                     \
    do {                                                                     \
        if (!(cond)) {                                                       \
            std::printf("dp32 check FAILED: %s (line %d)\n", #cond, __LINE__); \
            std::fflush(stdout);                                             \
            std::abort();                                                    \
        }                                                                    \
    } while (0)

// 自测: 全部走合成文件 (不碰生产库); 最后若真库在, 再做一轮抽样复算。
void validate_dp32_store()
{
    const std::string psrc = std::string(DP32_SOURCE_FILE) + ".selftest";
    const std::string pdrf = std::string(DP32_DRAFTED_FILE) + ".selftest";
    const std::string pbad = psrc + ".bad";

    auto mk = [](uint64_t index, unsigned char tag) {
        Dp32Record r;
        memset(&r, 0, sizeof(r));
        r.index = index;
        memset(r.m, tag, sizeof(r.m));
        memset(r.n, (unsigned char)(tag + 1), sizeof(r.n));
        return r;
    };
    auto tomb = [](uint64_t index) {
        Dp32Record r;
        memset(&r, 0, sizeof(r));
        r.index = index;   // 墓碑只清 m/n, index 留在原地
        return r;
    };
    auto dump = [](const std::string& p, const char* magic, const std::vector<Dp32Record>& rs) {
        std::ofstream ofs(p, std::ios::binary | std::ios::trunc);
        if (!ofs.is_open()) return false;
        if (!dp32_write_header(ofs, magic, rs.size())) return false;
        if (!rs.empty()) {
            ofs.write((const char*)rs.data(), (std::streamsize)(rs.size() * sizeof(Dp32Record)));
        }
        ofs.flush();
        return ofs.good();
    };
    auto slurp = [](const std::string& p) {
        std::ifstream ifs(p, std::ios::binary);
        return std::vector<unsigned char>((std::istreambuf_iterator<char>(ifs)),
                                          std::istreambuf_iterator<char>());
    };
    auto sput = [](const std::string& p, const std::vector<unsigned char>& b) {
        std::ofstream ofs(p, std::ios::binary | std::ios::trunc);
        if (!ofs.is_open()) return false;
        if (!b.empty()) ofs.write((const char*)b.data(), (std::streamsize)b.size());
        ofs.flush();
        return ofs.good();
    };

    // 合成库: 源库 3 条 (槽位 1 是墓碑, 索引留在原地); 已征召库 3 条, 其中索引 20 有两条
    const std::vector<Dp32Record> src = {mk(10, 0x11), tomb(20), mk(30, 0x33)};
    const std::vector<Dp32Record> drf = {mk(20, 0x51), mk(99, 0x61), mk(20, 0x52)};
    DP32_CHECK(dump(psrc, DP32_SOURCE_MAGIC, src));
    DP32_CHECK(dump(pdrf, DP32_DRAFTED_MAGIC, drf));

    Dp32Store s;
    DP32_CHECK(s.load(psrc.c_str(), pdrf.c_str()));
    DP32_CHECK(s.loaded());
    DP32_CHECK(s.src_count() == 3 && s.drf_count() == 3 && s.src_dead_count() == 1);

    uint32_t slot = 0xFFFFFFFFu;
    DP32_CHECK(s.src_find(10, slot) == Dp32Hit::Live && slot == 0);
    DP32_CHECK(s.src_find(20, slot) == Dp32Hit::Tombstone && slot == 1);
    DP32_CHECK(s.src_find(30, slot) == Dp32Hit::Live && slot == 2);
    DP32_CHECK(s.src_find(9, slot) == Dp32Hit::Absent);
    DP32_CHECK(s.src_find(15, slot) == Dp32Hit::Absent);
    DP32_CHECK(s.src_find(31, slot) == Dp32Hit::Absent);
    DP32_CHECK(s.src_find(0, slot) == Dp32Hit::Absent);
    DP32_CHECK(s.src_dead(1) && !s.src_dead(0) && !s.src_dead(2));
    DP32_CHECK(s.src_dead(3));   // 越界也当"别去读"
    // 已征召库: 同一个索引必须能把整个桶交出来, 不能只回一条
    const std::vector<uint32_t>* b20 = s.drf_slots(20);
    DP32_CHECK(b20 != nullptr && b20->size() == 2 && (*b20)[0] == 0 && (*b20)[1] == 2);
    const std::vector<uint32_t>* b99 = s.drf_slots(99);
    DP32_CHECK(b99 != nullptr && b99->size() == 1 && (*b99)[0] == 1);
    DP32_CHECK(s.drf_slots(98) == nullptr);
    // 按槽位读回来的必须就是写进去的那条
    Dp32Record r;
    DP32_CHECK(s.read(Dp32File::Source, 2, r) && r.index == 30 && r.m[0] == 0x33 && r.n[0] == 0x34);
    DP32_CHECK(s.read(Dp32File::Drafted, 2, r) && r.index == 20 && r.m[0] == 0x52);
    DP32_CHECK(!s.read(Dp32File::Source, 3, r));   // 越界: 读不到 72 字节
    // 幂等: 再载一遍, 不许残留上一次的索引
    DP32_CHECK(s.load(psrc.c_str(), pdrf.c_str()));
    DP32_CHECK(s.src_count() == 3 && s.drf_count() == 3 && s.src_dead_count() == 1);

    // 坏库必须整体拒绝, 而且失败后连半成品索引都不许留
    auto must_reject = [&](const char* why) {
        Dp32Store t;
        const bool ok = t.load(pbad.c_str(), pdrf.c_str());
        DP32_CHECK(!ok && !t.loaded() && t.src_count() == 0 && t.drf_count() == 0);
        DP32_CHECK(t.src_find(10, slot) == Dp32Hit::Absent);
        cprintf("dp32 store: 坏库已拒绝 (%s)\n", why);
    };
    const std::vector<unsigned char> raw = slurp(psrc);
    DP32_CHECK(!raw.empty());
    {
        std::vector<unsigned char> b = raw;
        b[0] ^= 0xFF;                                    // 魔数
        DP32_CHECK(sput(pbad, b));
        must_reject("magic");
    }
    {
        std::vector<unsigned char> b = raw;
        b[8] = 9;                                        // 版本号
        DP32_CHECK(sput(pbad, b));
        must_reject("version");
    }
    {
        std::vector<unsigned char> b = raw;
        b[12] = (unsigned char)(sizeof(Dp32Record) - 1); // 记录长度
        DP32_CHECK(sput(pbad, b));
        must_reject("record size");
    }
    {
        std::vector<unsigned char> b = raw;              // 截断: 头里的条数对不上文件长度
        b.resize(b.size() - sizeof(Dp32Record));
        DP32_CHECK(sput(pbad, b));
        must_reject("truncated");
    }
    {
        std::vector<unsigned char> b = raw;              // 源库不再升序 (把首条索引改成 40)
        const uint64_t k = 40;
        memcpy(b.data() + sizeof(Dp32Header), &k, sizeof(k));
        DP32_CHECK(sput(pbad, b));
        must_reject("not ascending");
    }
    {
        Dp32Store t;                                     // 文件不存在
        DP32_CHECK(!t.load((psrc + ".nope").c_str(), pdrf.c_str()));
        DP32_CHECK(!t.loaded() && t.src_count() == 0);
        cprintf("dp32 store: 坏库已拒绝 (missing)\n");
    }
    std::remove(pbad.c_str());
    std::remove(psrc.c_str());
    std::remove(pdrf.c_str());
    cprintf("dp32 store: ok (瘦索引 载入/升序查找/墓碑跳过/同索引多桶/坏库拒绝)\n");

    // ---- 真库抽样复算: 记录里那个 index 是"x 低 32 位全 0 时 x 的 bit 32..95",
    // 所以必须真拿 m,n 算出 x 来对一遍, 不能只信文件里那个数 ----
    Dp32Store real;
    if (!real.load()) {
        cprintf("dp32 store: 真库不可用 (盘上没有, 离线脚本还没建), 跳过抽样复算\n");
        return;
    }
    uint64_t checked = 0;
    auto verify = [&](Dp32File which, uint32_t sl) {
        Dp32Record rec;
        DP32_CHECK(real.read(which, sl, rec));
        secp256k1_pubkey pk = {0};
        create(ctx, &pk, rec.m, rec.n);
        uint64_t idx = 0;
        DP32_CHECK(dp32_test(pk, idx));
        DP32_CHECK(idx == rec.index);
        ++checked;
    };
    const uint64_t sn = real.src_count();
    if (sn > 0) {
        // 头 / 四分位 / 中 / 尾各抽 32 条连续槽位 (跳过墓碑), 既验内容也验位图没标错。
        // 连续抽是因为"槽位 -> 文件偏移"一旦错位, 单点抽样可能凑巧躲过去, 连续 32 条躲不掉。
        const uint64_t probes[] = {0, sn / 4, sn / 2, (sn * 3) / 4, sn - 1};
        for (uint64_t base : probes) {
            for (uint64_t k = 0; k < 32 && base + k < sn; ++k) {
                const uint32_t sl = (uint32_t)(base + k);
                Dp32Record rec;
                DP32_CHECK(real.read(Dp32File::Source, sl, rec));
                DP32_CHECK(dp32_is_tombstone(rec) == real.src_dead(sl));
                if (real.src_dead(sl)) continue;
                verify(Dp32File::Source, sl);
            }
        }
    }
    // 已征召库不大 (几千条), 干脆全量复算: 记录自洽 (m, n 复算出的 x 落在自己写的
    // index 上) 是这个库的基本契约 —— 征召销账时源库那条立墓碑之前, 同一份 (m, n)
    // 先追加到了这里, 两个库记的必须是同一批点。
    const uint64_t dn = real.drf_count();
    for (uint32_t sl = 0; sl < dn; ++sl) {
        Dp32Record rec;
        DP32_CHECK(real.read(Dp32File::Drafted, sl, rec));
        DP32_CHECK(!dp32_is_tombstone(rec));   // 已征召库是纯追加落点, 不该有墓碑
        verify(Dp32File::Drafted, sl);
    }
    cprintf("dp32 store: 真库 ok (源库 %llu 条 / 墓碑 %llu, 已征召 %llu 条全量复算, 源库抽样 %llu 条)\n",
            (unsigned long long)sn, (unsigned long long)real.src_dead_count(),
            (unsigned long long)dn, (unsigned long long)checked);
}

// 已征召库里有没有"和这条语料记录完全一样"的那条 (索引 + m/n 逐字节)
static bool dp32_corpus_in_drafted(const Dp32Store& s, uint64_t index, const SecPair& sp)
{
    const std::vector<uint32_t>* slots = s.drf_slots(index);
    if (slots == nullptr) return false;
    for (const uint32_t sl : *slots) {
        Dp32Record rec;
        if (!s.read(Dp32File::Drafted, sl, rec)) continue;
        if (memcmp(rec.m, sp.m, 32) == 0 && memcmp(rec.n, sp.n, 32) == 0) return true;
    }
    return false;
}

// ---------------------------------------------------------------------------
// 自测: 库与 data 语料对账
//
// 语料是唯一的进货渠道, 但"库确实是语料的忠实副本"这件事, 光看库里那些记录是验不出来
// 的: 上面 validate_dp32_store 真库那一轮只验了"库里的记录自洽 (m, n 复算出的 x 真的落在
// 自己写的 index 上)", 跟语料没有任何对照。补两件:
//
// (一) 条数/索引对得上。语料里每个去重后的 32 位 DP 在库里必须正好有一条 —— 具体口径随
//      库侧布局走, 见下面的 Dp32CorpusLib 两个实现 (库侧只有"怎么查"和"算哪些条数"
//      不一样, 语料侧的读法/抽样/报告完全一样, 所以两套口径共用本函数)。
// (二) 语料里的点确实能在库里找到。每个语料文件均分抽 8 条 (含首尾), 现算 x: 首列索引
//      必须等于复算出来的 idx32, 再去库里定位, 并把库里那条的 (m, n) 跟语料原文
//      **逐字节**比 —— 索引只是 x 的 bit 32..95, 索引相同不等于同一条点。
//
// 计数只读语料首列 (不做 89 万次点乘; 语料首列与复算索引逐条核对是离线建库那一轮做的),
// 只有抽样的那几十条才真算 x。
//
// 语料是追加写的 (DistinguishablePoints_rho*.txt 还在长), 而三个库都是离线脚本一次
// 生成的快照, 所以"库比语料少"可能是正常的落后: 语料文件比库新、且库侧每一项都没多于
// 语料侧 (多出来的条目在语料里找不到出处), 那就只提示重建而不判失败。
// ---------------------------------------------------------------------------

// 报告里两套库布局的名字 (两处共用, 免得写重)
constexpr const char* DP32_CORPUS_NAME_TWO = "源库+已征召库";
constexpr const char* DP32_CORPUS_NAME_ALL = "全量库";

// 库侧对账的三种结局: 对上 / 只是落后于语料 (不算失败) / 对不上 (库侧已印出两边的账,
// 调用方接着 abort)。
enum class Dp32CorpusVerdict { Ok, Stale, Mismatch };

// 语料对账里的库侧接口。两套库布局:
//   源库 + 已征召库 (DpSource32.bin + DpDrafted32.bin) —— 语料里的 40 位那批在已征召库
//     (离线建库时就地征召, 不进源库), 其余点在源库 (活的, 或已征召销账立了墓碑);
//   全量库 (DpSource32all.bin) —— 语料里全部去重后的 32 位 DP 都在这一个库里 (含 40 位
//     那批), 没有墓碑也没有征召销账, 是离线生成的只读快照。
class Dp32CorpusLib
{
public:
    virtual ~Dp32CorpusLib() = default;

    // 语料里这一条 (index = 复算出的 32 位索引, sp = 语料里的 m/n 原文) 在库侧是不是
    // 有"同一条": 索引对上不算数, m/n 还要逐字节相同。对不上时把原因写进 why。
    virtual bool check(uint64_t index, const SecPair& sp, std::string& why) const = 0;

    // 库侧口径与语料侧对账, 并把自己那一套账印出来 (只有它知道该算哪些)。idx32/idx40
    // 是语料去重后的两张索引表 (都已升序)。
    virtual Dp32CorpusVerdict account(const std::vector<uint64_t>& idx32,
                                      const std::vector<uint64_t>& idx40,
                                      bool corpus_newer) = 0;

    virtual const std::string& path() const = 0;   // 库文件 (跟语料比新旧用)
    virtual const char* name() const = 0;
};

// (甲) 源库 + 已征召库: 语料里每个去重后的 32 位 DP 落在两库之一 ——
//   语料里的 40 位点 -> 已征召库 (离线建库时就地征召, 不进源库)
//   语料里的其余点   -> 源库一条活记录, 或者已被征召销账 (源库立墓碑 + 已征召库存同一条)
// 即 (源库活记录) + (已征召库条数) == 语料去重后的条目数。少一条是建库漏读, 多一条是点
// 凭空出现。销账时源库 -1、已征召 +1 ⇒ 这个和数在运行期是不变量, 所以它随时可查。
class Dp32CorpusTwoLib : public Dp32CorpusLib
{
public:
    explicit Dp32CorpusTwoLib(const Dp32Store& s) : m_s(s) {}

    bool check(uint64_t index, const SecPair& sp, std::string& why) const override
    {
        uint32_t slot = 0xFFFFFFFFu;
        const Dp32Hit hit = m_s.src_find(index, slot);
        if (hit == Dp32Hit::Live) {
            Dp32Record rec;
            DP32_CHECK(m_s.read(Dp32File::Source, slot, rec));
            if (dp32_is_tombstone(rec)) {
                why = "源库活槽位在盘上却是墓碑 (墓碑位图与文件不一致)";
                return false;
            }
            if (memcmp(rec.m, sp.m, 32) != 0 || memcmp(rec.n, sp.n, 32) != 0) {
                why = "源库活记录的 m/n 与语料原文不符";
                return false;
            }
            return true;
        }
        // 不在源库 (本身是 40 位点: 建库时就没进源库) 或已是墓碑 (已被征召销账): 两种
        // 都只有一个去处 —— 已征召库, 而且必须是"同一条"(销账是先追加后立墓碑)。
        if (!dp32_corpus_in_drafted(m_s, index, sp)) {
            why = (hit == Dp32Hit::Absent) ? "源库与已征召库都找不到这条语料记录"
                                           : "源库墓碑在已征召库里找不到同一条";
            return false;
        }
        return true;
    }

    Dp32CorpusVerdict account(const std::vector<uint64_t>& idx32,
                              const std::vector<uint64_t>& idx40, bool corpus_newer) override
    {
        const uint64_t d32 = (uint64_t)idx32.size();
        const uint64_t d40 = (uint64_t)idx40.size();
        const uint64_t src_n = m_s.src_count();
        const uint64_t dead = m_s.src_dead_count();
        const uint64_t live = src_n - dead;
        const uint64_t drf = m_s.drf_count();
        // 已征召库里"索引低 8 位为 0"的条目就是本身为 40 位点的那批, 全部来自语料 (建库
        // 时直接征召); 其余是征召销账时从源库挪过来的, 而源库只放非 40 位点 ⇒ 它们只可能
        // 是语料里的非 40 位点。两边分开对, 出错时一眼看得出是哪半边。
        uint64_t drf40 = 0;
        for (uint32_t sl = 0; sl < drf; ++sl) {
            Dp32Record rec;
            DP32_CHECK(m_s.read(Dp32File::Drafted, sl, rec));
            if ((rec.index & 0xFF) == 0) ++drf40;
        }
        const uint64_t moved = drf - drf40;      // 征召销账时从源库挪过来的条数
        const uint64_t lib_sum = live + drf;     // 两库之和
        // 库侧比语料侧多 = 无从解释 (语料是唯一的进货渠道, 两个库都只由离线脚本写)
        const bool lib_over = (live + moved) > d32 || drf40 > d40;

        if (drf40 == d40 && (live + moved) == d32) {
            DP32_CHECK(lib_sum == d32 + d40);    // 两库之和 == 语料去重后的条目数
            cprintf("dp32 corpus(%s): 对账 ok (语料去重 %llu = 40 位 %llu -> 已征召库 + 其余 %llu "
                    "(源库活 %llu + 已移库 %llu); 源库槽位 %llu 墓碑 %llu, 已征召 %llu 条)\n",
                    name(), (unsigned long long)lib_sum, (unsigned long long)d40,
                    (unsigned long long)d32, (unsigned long long)live, (unsigned long long)moved,
                    (unsigned long long)src_n, (unsigned long long)dead, (unsigned long long)drf);
            return Dp32CorpusVerdict::Ok;
        }
        if (corpus_newer && !lib_over) {
            cprintf("dp32 corpus(%s): 库比语料旧 %llu 条 (语料去重 %llu, 库 %llu) —— 语料文件比库新, "
                    "需要离线重建三个库, 不算失败\n",
                    name(), (unsigned long long)(d32 + d40 - lib_sum),
                    (unsigned long long)(d32 + d40), (unsigned long long)lib_sum);
            return Dp32CorpusVerdict::Stale;
        }
        cprintf("dp32 corpus(%s): 对账失败: 语料去重 %llu (40 位 %llu / 其余 %llu); 源库 %llu 条 "
                "(活 %llu / 墓碑 %llu); 已征召 %llu 条 (40 位 %llu / 其余 %llu)\n",
                name(), (unsigned long long)(d32 + d40), (unsigned long long)d40,
                (unsigned long long)d32, (unsigned long long)src_n, (unsigned long long)live,
                (unsigned long long)dead, (unsigned long long)drf, (unsigned long long)drf40,
                (unsigned long long)moved);
        return Dp32CorpusVerdict::Mismatch;
    }

    const std::string& path() const override { return m_s.src_path(); }
    const char* name() const override { return DP32_CORPUS_NAME_TWO; }

private:
    const Dp32Store& m_s;
};

// (乙) 全量库: 语料里全部去重后的 32 位 DP 都在这一个库里 (含 40 位那批), 没有墓碑也
// 没有征召销账 ⇒ 库里的索引表应该跟"语料去重后的索引集合"逐条相同, 查法就是"索引命中
// + m/n 逐字节相同"。
class Dp32CorpusAllLib : public Dp32CorpusLib
{
public:
    explicit Dp32CorpusAllLib(const Dp32Store& s) : m_s(s) {}

    bool check(uint64_t index, const SecPair& sp, std::string& why) const override
    {
        uint32_t slot = 0;
        const Dp32Hit hit = m_s.src_find(index, slot);
        if (hit != Dp32Hit::Live) {
            why = (hit == Dp32Hit::Absent) ? "全量库里找不到这条语料记录"
                                           : "全量库里这条被标成了墓碑";
            return false;
        }
        Dp32Record rec;
        DP32_CHECK(m_s.read(Dp32File::Source, slot, rec));
        if (memcmp(rec.m, sp.m, 32) != 0 || memcmp(rec.n, sp.n, 32) != 0) {
            why = "全量库这条的 m/n 与语料原文不符";
            return false;
        }
        return true;
    }

    Dp32CorpusVerdict account(const std::vector<uint64_t>& idx32,
                              const std::vector<uint64_t>& idx40, bool corpus_newer) override
    {
        // 索引表整表比, 而不是只看条数: 两边都在内存里, 归并一遍就够, 而"少了 A 多了 B"
        // 这种错只有整表比才看得见。
        std::vector<uint64_t> want = idx32;
        want.insert(want.end(), idx40.begin(), idx40.end());
        std::sort(want.begin(), want.end());
        want.erase(std::unique(want.begin(), want.end()), want.end());
        const std::vector<uint64_t>& have = m_s.src_keys();   // 升序去重
        uint64_t missing = 0, extra = 0, first_missing = 0, first_extra = 0;
        {
            size_t i = 0, j = 0;
            while (i < have.size() && j < want.size()) {
                if (have[i] == want[j]) {
                    ++i;
                    ++j;
                } else if (have[i] < want[j]) {
                    if (extra == 0) first_extra = have[i];
                    ++extra;
                    ++i;
                } else {
                    if (missing == 0) first_missing = want[j];
                    ++missing;
                    ++j;
                }
            }
            for (; i < have.size(); ++i) {
                if (extra == 0) first_extra = have[i];
                ++extra;
            }
            for (; j < want.size(); ++j) {
                if (missing == 0) first_missing = want[j];
                ++missing;
            }
        }
        const uint64_t n = m_s.src_count();
        if (missing == 0 && extra == 0) {
            DP32_CHECK(m_s.src_dead_count() == 0);   // 只读快照, 不该有墓碑
            cprintf("dp32 corpus(%s): 对账 ok (全量库 %llu 条 = 语料去重 %llu 条 (40 位 %llu + "
                    "其余 %llu), 索引表逐条相同; 无墓碑)\n",
                    name(), (unsigned long long)n, (unsigned long long)want.size(),
                    (unsigned long long)idx40.size(), (unsigned long long)idx32.size());
            return Dp32CorpusVerdict::Ok;
        }
        if (corpus_newer && extra == 0) {
            // 库里一条多余的都没有 ⇒ 只是语料在库快照之后又长了没重建
            cprintf("dp32 corpus(%s): 全量库比语料少 %llu 条 (语料去重 %llu, 库 %llu) —— "
                    "语料文件比库新, 需要离线重建三个库, 不算失败\n",
                    name(), (unsigned long long)missing, (unsigned long long)want.size(),
                    (unsigned long long)n);
            return Dp32CorpusVerdict::Stale;
        }
        cprintf("dp32 corpus(%s): 对账失败: 语料去重 %llu 条 (40 位 %llu / 其余 %llu), 全量库 "
                "%llu 条; 库里少 %llu 条 (首个 %llu), 多 %llu 条 (首个 %llu)\n",
                name(), (unsigned long long)want.size(), (unsigned long long)idx40.size(),
                (unsigned long long)idx32.size(), (unsigned long long)n,
                (unsigned long long)missing, (unsigned long long)first_missing,
                (unsigned long long)extra, (unsigned long long)first_extra);
        return Dp32CorpusVerdict::Mismatch;
    }

    const std::string& path() const override { return m_s.src_path(); }
    const char* name() const override { return DP32_CORPUS_NAME_ALL; }

private:
    const Dp32Store& m_s;
};

void validate_dp32_corpus(Dp32CorpusTarget target)
{
    const bool all_mode = (target == Dp32CorpusTarget::AllLib);
    const char* const label = all_mode ? DP32_CORPUS_NAME_ALL : DP32_CORPUS_NAME_TWO;
    Dp32Store store;
    if (all_mode) {
        // 全量库是一个只读快照: 一个升序库, 没有已征召库 (drf 传 nullptr), 也没有墓碑
        if (!store.load(DP32_ALL_FILE, nullptr)) {
            cprintf("dp32 corpus(%s): 库不可用 (还没生成) %s, 跳过对账\n", label, DP32_ALL_FILE);
            return;
        }
    } else if (!store.load(DP32_SOURCE_FILE, DP32_DRAFTED_FILE)) {
        cprintf("dp32 corpus(%s): 库不可用 (还没生成), 跳过对账\n", label);
        return;
    }
    // 库侧口径: 一个布局一个实现; 两种口径都建一下 (构造只存引用), 按 target 选
    Dp32CorpusTwoLib two_lib(store);
    Dp32CorpusAllLib all_lib(store);
    Dp32CorpusLib& lib = all_mode ? static_cast<Dp32CorpusLib&>(all_lib)
                                  : static_cast<Dp32CorpusLib&>(two_lib);
    const std::string dataDir = dp32_find_data_dir();
    if (dataDir.empty()) {
        cprintf("dp32 corpus: 没找到 data 语料目录, 跳过对账\n");
        return;
    }
    const std::vector<fs::path> files = dp32_corpus_files(dataDir);

    // ---- (一) 语料侧计数: 只取首列, 按 40 位判据 (索引低 8 位为 0) 分两类去重 ----
    std::vector<uint64_t> idx32, idx40;
    std::vector<uint64_t> per_file(files.size(), 0);
    uint64_t n_rec = 0;
    for (size_t fi = 0; fi < files.size(); ++fi) {
        std::ifstream ifs(files[fi]);
        if (!ifs.is_open()) continue;
        uint64_t index = 0;
        SecPair sp;
        uint64_t n = 0;
        while (dp32_read_text_record(ifs, index, sp)) {
            ++n;
            ((index & 0xFF) == 0 ? idx40 : idx32).push_back(index);
        }
        per_file[fi] = n;
        n_rec += n;
    }
    std::sort(idx32.begin(), idx32.end());
    idx32.erase(std::unique(idx32.begin(), idx32.end()), idx32.end());
    std::sort(idx40.begin(), idx40.end());
    idx40.erase(std::unique(idx40.begin(), idx40.end()), idx40.end());
    const uint64_t d32 = (uint64_t)idx32.size();
    const uint64_t d40 = (uint64_t)idx40.size();
    const uint64_t corpus_n = d32 + d40;   // 语料去重后的条目数

    // ---- (二) 抽样: 每文件均分 8 条 (含首尾), 现算 x 去库里认领 ----
    constexpr int SAMPLE_PER_FILE = 8;
    uint64_t planned = 0, sampled = 0, n40_sample = 0;
    for (size_t fi = 0; fi < files.size(); ++fi) {
        const uint64_t n = per_file[fi];
        if (n == 0) continue;
        std::vector<uint64_t> want;
        for (int j = 0; j < SAMPLE_PER_FILE; ++j) {
            const uint64_t pos = (n - 1) * (uint64_t)j / (uint64_t)(SAMPLE_PER_FILE - 1);
            if (want.empty() || want.back() != pos) want.push_back(pos);
        }
        planned += want.size();
        std::ifstream ifs(files[fi]);
        if (!ifs.is_open()) continue;
        uint64_t rec_no = 0;
        size_t wi = 0;
        uint64_t index = 0;
        SecPair sp;
        while (wi < want.size() && dp32_read_text_record(ifs, index, sp)) {
            if (rec_no++ != want[wi]) continue;
            ++wi;
            secp256k1_pubkey pk = {0};
            create(ctx, &pk, sp.m, sp.n);
            uint64_t idx32 = 0;
            DP32_CHECK(dp32_test(pk, idx32));
            DP32_CHECK(idx32 == index);   // 语料首列就是复算出来的索引
            if ((idx32 & 0xFF) == 0) ++n40_sample;   // 顺便记一笔这几十条里有多少个 40 位点
            std::string why;
            if (!lib.check(idx32, sp, why)) {
                cprintf("dp32 corpus(%s): 抽样对不上 (索引 %llu): %s\n", lib.name(),
                        (unsigned long long)idx32, why.c_str());
                DP32_CHECK(false);
            }
            ++sampled;
        }
    }
    DP32_CHECK(sampled == planned);   // 两遍读同一个文件, 条数必须一致

    // ---- (二·补) 上面那种均匀抽样有可能一条 40 位点都抽不到 (40 位只占语料的 0.37%),
    // 那样"语料里的 40 位点能在库里查到"这条路径就一次都没走过。所以再从 40 位索引表里
    // 均匀挑 FORCE40 个当靶子, 把语料整体扫一遍把它们捞出来, 逐条现算 + 查库。
    constexpr int FORCE40 = 8;
    if (!idx40.empty()) {
        std::vector<uint64_t> targets;   // 均匀挑出的靶子索引 (去重后 ≤ FORCE40), 天然升序
        for (int j = 0; j < FORCE40; ++j) {
            const size_t pos = (idx40.size() - 1) * (size_t)j / (size_t)(FORCE40 - 1);
            if (targets.empty() || targets.back() != idx40[pos]) targets.push_back(idx40[pos]);
        }
        std::vector<bool> found(targets.size(), false);
        for (const auto& f : files) {
            std::ifstream ifs(f);
            if (!ifs.is_open()) continue;
            uint64_t index = 0;
            SecPair sp;
            while (dp32_read_text_record(ifs, index, sp)) {
                if ((index & 0xFF) != 0) continue;     // 只看 40 位那批
                if (!std::binary_search(targets.begin(), targets.end(), index)) continue;
                const size_t ti = (size_t)(std::lower_bound(targets.begin(), targets.end(), index) -
                                           targets.begin());
                if (found[ti]) continue;               // 同一个 40 位点在多个文件里重复出现
                found[ti] = true;
                secp256k1_pubkey pk = {0};
                create(ctx, &pk, sp.m, sp.n);
                uint64_t i32 = 0;
                DP32_CHECK(dp32_test(pk, i32));
                DP32_CHECK(i32 == index);              // 语料首列就是复算出来的索引
                std::string why;
                if (!lib.check(i32, sp, why)) {
                    cprintf("dp32 corpus(%s): 40 位靶子对不上 (索引 %llu): %s\n", lib.name(),
                            (unsigned long long)i32, why.c_str());
                    DP32_CHECK(false);
                }
                ++sampled;
                ++n40_sample;
            }
        }
        for (bool b : found) DP32_CHECK(b);   // 靶子都是从语料里挑的, 必须都能捞出来
    }

    // ---- (三) 库侧计数/索引表, 与语料侧对账 ----
    // 库侧口径全在 lib.account 里 (两套布局各一套); 它只印库侧那一半, 语料侧这半边由
    // 下面这行印完 —— 出错时两行并排看, 一眼知道是哪边不对。
    //
    // 语料文件比库新 ⇒ 库可能只是落后: 库是离线脚本一次生成的快照, 不会因为语料长大
    // 而自动重扫, 所以那种落后只提示不判失败。
    bool corpus_newer = false;
    {
        std::error_code ec;
        const auto lib_t = fs::last_write_time(fs::u8path(lib.path()), ec);
        for (const auto& f : files) {
            if (fs::last_write_time(f, ec) > lib_t) corpus_newer = true;
        }
    }
    const Dp32CorpusVerdict verdict = lib.account(idx32, idx40, corpus_newer);
    cprintf("dp32 corpus: 语料文件 %d 个 %llu 条 -> 去重 %llu (40 位 %llu / 其余 %llu); "
            "抽样 %llu 条全中 (其中 40 位 %llu)\n",
            (int)files.size(), (unsigned long long)n_rec, (unsigned long long)corpus_n,
            (unsigned long long)d40, (unsigned long long)d32, (unsigned long long)sampled,
            (unsigned long long)n40_sample);
    DP32_CHECK(verdict != Dp32CorpusVerdict::Mismatch);   // 对不上: 上面两行已写清两边条数
}

class BabyGiant
{
private:
    std::vector<uint64_t> _Xvec;
    std::vector<uint64_t> _Mvec;
    iLog _dplog;

public:
    // 巨人步每条都要查表, 凑不出批量求逆, 固定单 walker
    static constexpr int WALKERS0 = 1;
    static constexpr int WALKERS = 1;

    BabyGiant() : _dplog(_DPFile_name) {}
    // 它每步都直接写 rs, 无缓存, 无需 flush (接口对齐 Rho)
    void flush(const int i, RhoState* rs) {}
    void prepare()
    {
        //先load _Mvec, 好让它早点儿被swapout
        _Mvec = loadVectorFromFile<uint64_t>(_Mvec_name);
        _Xvec = loadVectorFromFile<uint64_t>(_Xvec_name);
        BabyNUM = _Xvec.size();
        assert(_Xvec.size() == _Mvec.size());
    }
    bool shoot(const int i, RhoState* rs, unsigned int& count_dstg, std::string& log)
    {
        giantStep(ctx, rs[0]);
        auto b = find_baby(ctx, _Xvec, _Mvec, rs[0].x);
        if (b != 0) {
            CKey k;
            if (bingo(ctx, k, rs[0], b)) {
                save_key(k);
            } else {
                log += "!!!!short circulation!!!!\n";
            }
            return false;
        }
        if (auto d = distinguishable(rs[0].x)) {
            ++count_dstg;
            saveDP(_dplog.ofs, d, rs[0]);
            rs[0].rand();
            fun_mul(rs[0], 2);
        }
        return true;
    }
};

class Rho
{
private:
    std::vector<uint64_t> _Xvec;
    std::vector<uint64_t> _Mvec;
    iLog _dplog;

public:
    // 每线程交错推进的 walker 数。同线程多 walker 的全部意义是让 W 个独立的分母
    // 凑成一批只求一次模逆 (见 rpc/rho.cpp 的 Montgomery 批量求逆), 这一点跨线程
    // 做不到。宽度按线程分工 (实测数据见 common.h):
    //   线程0 取 WALKERS0 (窄批, 单条链推进快);
    //   其余线程取 WALKERS (宽批, 总吞吐高)。
    static constexpr int WALKERS0 = RHO_WALKERS0;
    static constexpr int WALKERS = RHO_WALKERS;

    Rho() : _dplog(_DPFile_name) {}

    // 存档 / 线程退出前把线程局部缓存里的最新 walker 状态写回 rs。
    // rho_affine_FW 平时不写 rs (只在 DP 命中时写), 所以 saveRhoState /
    // archive 读到的 rs 必须先经过这里才是最新值。宽度因线程而异, 要传线程号。
    void flush(const int i, RhoState* rs)
    {
        if (i == 0) {
            rho_affine_flush<WALKERS0>(rs);
        } else {
            rho_affine_flush<WALKERS>(rs);
        }
    }
    void prepare()
    {
        /* _Mvec = loadVectorFromFile<uint64_t>(_MvecL_name);
        _Xvec = loadVectorFromFile<uint64_t>(_XvecL_name);
        assert(_Xvec.size() == _Mvec.size());*/

        // 仿射点加: 预展开 adds_pub[0][*] 到内部 fe 表示。
        // 必须在这里 (worker 线程启动前) 做一次。
        rho_affine_prepare();
    }

    bool shoot(const int i, RhoState* rs, unsigned int& count_dstg, std::string& log)
    {
        // ------------------------------------------------------------------
        // 旧实现: libsecp256k1 公开 API 的点加 (ge 解析 + 完整群运算)。
        // 保留备查 / 需要对照时启用。注意: 它与 rho_affine_FW 各有自己的线程
        // 局部状态缓存, 不要在同一个线程里交替调用。
        // ------------------------------------------------------------------
        // rho_F(ctx, rs[0]);

        // 同一线程内 WALKERS 个 walker 交错走一步: WALKERS 次模逆 -> 1 次。
        // 返回值是 DP 命中掩码; 未命中的 walker 状态留在 rho.cpp 的线程局部
        // cache 里, rs[k] 的 x/m/n 只在命中时才是新值 (times 始终每步递增)。
        const uint32_t dp_mask = (i == 0) ? rho_affine_FW<WALKERS0>(rs)
                                          : rho_affine_FW<WALKERS>(rs);

        for (uint32_t m = dp_mask; m != 0; m &= m - 1) {
            const int k = std::countr_zero(m);
            ++count_dstg;
            saveDP(_dplog.ofs, distinguishable(rs[k].x), rs[k]);
        }
        return true;
    }
};


std::string get_time()
{
    // 获取当前时间点
    auto now = std::chrono::system_clock::now();
    // 直接获取本地时间（C++20 特性）
    auto local_time = std::chrono::zoned_time{
        std::chrono::current_zone(), // 自动获取当前时区
        now};
    return std::format("{:%Y-%m-%d %H:%M:%S}", local_time);
}

void rho_play();

// 将当前线程绑定到第 index 个物理核（每核只绑首个 SMT 线程，避免超线程争抢）。
// 成功返回 true。仅模式2/3 调用。
static bool pin_to_physical_core(unsigned index)
{
#ifdef WIN32
    // 两阶段查询：第一次调用只取所需长度（返回值忽略），第二次才取数据
    DWORD len = 0;
    if (!GetLogicalProcessorInformationEx(RelationProcessorCore, nullptr, &len) &&
        GetLastError() != ERROR_INSUFFICIENT_BUFFER) {
        return false;
    }
    std::vector<BYTE> buf(len);
    if (!GetLogicalProcessorInformationEx(RelationProcessorCore, reinterpret_cast<PSYSTEM_LOGICAL_PROCESSOR_INFORMATION_EX>(buf.data()), &len)) {
        return false;
    }
    // 收集每个物理核的首个 SMT 线程亲和性
    std::vector<GROUP_AFFINITY> cores;
    PSYSTEM_LOGICAL_PROCESSOR_INFORMATION_EX it =
        reinterpret_cast<PSYSTEM_LOGICAL_PROCESSOR_INFORMATION_EX>(buf.data());
    DWORD used = 0;
    while (used < len) {
        if (it->Relationship == RelationProcessorCore) {
            const PROCESSOR_RELATIONSHIP* pr = &it->Processor;
            for (WORD g = 0; g < pr->GroupCount; ++g) {
                KAFFINITY mask = pr->GroupMask[g].Mask;
                if (mask == 0) continue;
                // 只取掩码中最低位的 SMT 线程（一个物理核）
                GROUP_AFFINITY ga = pr->GroupMask[g];
                unsigned long b;
                _BitScanForward64(&b, mask);
                ga.Mask = ((KAFFINITY)1) << b;
                cores.push_back(ga);
            }
        }
        used += it->Size;
        it = reinterpret_cast<PSYSTEM_LOGICAL_PROCESSOR_INFORMATION_EX>(
            reinterpret_cast<BYTE*>(it) + it->Size);
    }
    if (index >= cores.size()) return false;
    GROUP_AFFINITY old;
    return SetThreadGroupAffinity(GetCurrentThread(), &cores[index], &old) != FALSE;
#else
    // Linux：读取每个 cpu 的 thread_siblings_list，取每个物理核首个线程
    std::string path = "/sys/devices/system/cpu/cpu" + std::to_string(index) + "/topology/thread_siblings_list";
    std::ifstream f(path);
    if (!f) return false;
    std::string line;
    std::getline(f, line);
    // 解析 "0" / "0,2" / "0-3" 形式，取第一个 CPU 号
    auto is_digit = [](char c) { return c >= '0' && c <= '9'; };
    int first = -1;
    size_t p = 0;
    while (p < line.size()) {
        if (is_digit(line[p])) {
            size_t start = p;
            while (p < line.size() && is_digit(line[p])) ++p;
            int v = std::stoi(line.substr(start, p - start));
            if (first < 0) first = v;
            // 处理范围 "a-b"：只需首核，遇到 '-' 后的数字跳过
            if (p < line.size() && line[p] == '-') {
                ++p;
                while (p < line.size() && is_digit(line[p])) ++p;
            }
        } else {
            ++p;
        }
    }
    if (first < 0) return false;
    cpu_set_t set;
    CPU_ZERO(&set);
    CPU_SET(first, &set);
    return sched_setaffinity(0, sizeof(set), &set) == 0;
#endif
}

template <typename PLAYER>
void play() {
    // 槽位数就是存档文件的条数上限 (RHO_STATE_SLOTS, 见 common.h)
    std::string _logvec[RHO_STATE_SLOTS];
    RhoState rs[RHO_STATE_SLOTS] = {0};
    bool pause = false;
    {
        // 部分加载: 旧档条数不足槽位数时 (比如 256 条的旧档), 只把缺的槽补
        // 随机, 已有进度全部保留。loadRhoState 返回成功加载的条数。
        const int loaded = loadRhoState(rs, RHO_STATE_SLOTS, _RSFile1_name);
        for (int i = loaded; i < RHO_STATE_SLOTS; ++i) {
            rs[i].rand();
            rs[i].times = 0;
        }
    }
    for (RhoState& r : rs) {
        assert(check(ctx, &r.x, r.m, r.n));
    }
    PLAYER _player;
    _player.prepare();
    // 每个线程交错推进 W 个 walker (见 rpc/rho.cpp 的批量求逆)。
    // 线程0 用窄批 W0 (单条链推进快, 单线程模式也只有它), 其余线程用宽批 W
    // (总吞吐高), 宽度由 PLAYER 按线程号分派。
    constexpr int W0 = PLAYER::WALKERS0;
    constexpr int W = PLAYER::WALKERS;
    unsigned hw = std::thread::hardware_concurrency();
    int n_tasks;
    switch (g_run_mode) {
    case 1: n_tasks = 1; break;              // 模式1：仅CPU单线程，不启动CUDA
    case 2: n_tasks = std::max(1u, hw / 4); break; // 模式2：multiple=1，CPU 1/4核
    case 4: n_tasks = (hw > 2) ? hw - 2 : 1; break; // 模式4：occupancy blockSize，CPU 核数-2
    case 3:                                // 模式3：multiple=2，CPU 1/2核
    default: n_tasks = std::max(1u, hw / 2); break;
    }
    // 槽位按线程分段独占: 线程0 占 [0, W0), 线程 i>0 各占连续 W 个,
    // 槽位总数见 common.h 的 RHO_STATE_SLOTS
    constexpr int k_slots = RHO_STATE_SLOTS;
    const int max_tasks = 1 + (k_slots - W0) / W;
    n_tasks = std::min(n_tasks, max_tasks);
    std::cout << "run mode " << g_run_mode << ", cpu threads " << n_tasks
              << ", walkers/thread " << W0 << "(#0)/" << W << std::endl;
    auto saveStates = [&]() {
        saveRhoState(rs, sizeof(rs) / sizeof(RhoState), _RSFile1_name);
    };
    auto on_barrier = [&]() noexcept {
        {
            iLog _dplog(_DPFile_name);
        }
        saveStates();
        pause = false;
    };
    std::barrier barrier(n_tasks, on_barrier);
    auto T = [&](int i) {
        if ((g_run_mode == 2 || g_run_mode == 3) && !pin_to_physical_core(i)) {
            std::cout << "thread " << i << " pin core failed." << std::endl;
        }
        const int w_i = (i == 0) ? W0 : W;
        // 本线程独占的 walker 段: 线程0 在头部, 其余线程紧随其后连续排列
        RhoState* rs_i = &rs[(i == 0) ? 0 : W0 + (i - 1) * W];
        uint64_t count_try{0};
        unsigned int count_dstg{0};
        auto start = std::chrono::high_resolution_clock::now();
        while (!gameover) {
            try {
                ++count_try;
                _player.shoot(i, rs_i, count_dstg, _logvec[i]);
            } catch (...) {
                stop_game();
            }
            if (i == 0 && (count_try & 0x3FFFFFFF) == 0) {
                pause = true;
                std::cout << get_time() << " : game pause!" << std::endl;
            }
            if (pause) {
                // 暂停存档前把缓存写回 rs: on_barrier -> saveStates 读的是 rs,
                // 而 rho_affine_FW 平时不写 rs (只在 DP 命中时写)
                _player.flush(i, rs_i);
                barrier.arrive_and_wait();
            }
        }
        // 线程退出前同样要写回: 线程局部缓存随线程销毁, 主线程 join 之后的
        // saveStates 只能看到 rs
        _player.flush(i, rs_i);
        std::chrono::duration<double> elapsed = std::chrono::high_resolution_clock::now() - start;
        if (elapsed.count() > 300) {
            std::stringstream ss;
            if (i == 0) {
                ss << count_try * w_i << " points, " << count_dstg
                   << " distinguishable. in " << elapsed.count() << " s, avg "
                   << (uint64_t)(count_try * w_i / elapsed.count()) << " points/s" << std::endl;
            } else {
                ss << count_dstg << " ";
            }

            _logvec[i] += ss.str();
        }
        std::cout << "thread " << i << " exit." << std::endl;
    };

    std::vector<std::thread> threads;
    threads.reserve(n_tasks + 1);
    for (int i = 0; i < n_tasks; ++i) {
        threads.emplace_back(T, i);
    }
    if (g_run_mode != 1) {
        // threads.emplace_back(rho_play); // 模式1不启动CUDA线程
        // 32 位 DP 起点漫游顶掉生产那一路 (改回生产: 放开上面一行, 注掉下面一行即可)。
        // 两者是同一个核 rho_w<W,EDGE> 的两个编译期实例, 轮结构完全一样, 见 cuda.cu。
        threads.emplace_back(dp32_edge_play);
    }
    for (auto& t : threads) {
        t.join();
    }
    saveStates();
    g_log->ofs << get_time() << " : ";
    for (int i = 0; i < n_tasks; i++) {
        g_log->ofs << _logvec[i];
    }
    if (g_run_mode != 1) {
        g_log->ofs << " distinguishable aside." << std::endl;
    }
}

void validate_test();

static RPCHelpMan testmvp()
{
    return RPCHelpMan{
        "testmvp",
        "test around mvp",
        {
            {"ta", RPCArg::Type::NUM, RPCArg::Optional::NO, "test arg"},
            {"ta2", RPCArg::Type::STR, RPCArg::Optional::NO, "test arg2"},
        },
        RPCResult{
            RPCResult::Type::OBJ, "", "", {
                                              {RPCResult::Type::STR, "str", "str"},
                                              {RPCResult::Type::STR, "str2", "str2"},
                                              {RPCResult::Type::NUM, "num", "num"},
                                          }},
        RPCExamples{HelpExampleCli("-rpcclienttimeout=0 testmvp", "")},
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue {
            NodeContext& node = EnsureAnyNodeContext(request.context);
            int32_t ta = self.Arg<std::int32_t>("ta");
            std::string ta2s = self.Arg<std::string>("ta2");
            int64_t ta2 = std::stoll(ta2s);

            UniValue unspent(UniValue::VOBJ);
            unspent.pushKV("str", "");
            unspent.pushKV("str2", "");
            unspent.pushKV("num", 1);

            //挑选一个mvp 并打印出来
            if (ta == 11) {
                Chainstate* chainstate;
                std::unique_ptr<CCoinsViewCursor> cursor;
                {
                    LOCK(node.chainman->GetMutex());
                    chainstate = &node.chainman->ActiveChainstate();
                    cursor = chainstate->CoinsDB().Cursor();
                }
                COutPoint key;
                Coin coin;
                int i = 0;
                while (cursor->Valid()) {
                    cursor->GetValue(coin);
                    std::vector<std::vector<unsigned char>> solns;
                    TxoutType type{Solver(coin.out.scriptPubKey, solns)};
                    if (type == TxoutType::PUBKEY) {
                        if (++i > 10) {
                            cursor->GetKey(key);
                            unspent.pushKV("str", key.hash.GetHex());
                            unspent.pushKV("num", key.n);

                            return unspent;
                        }
                    }
                    cursor->Next();
                }
            }

            INIT _init;

            if (ta == 12) {
                //计算公钥对应的地址===============================================
                //地址为 1E2hARCudWzdmMoteP12w8ceYruPaqyrrZ
                //CPubKey pbkey(ParseHex("048fd74b41a5f5c775ea13b7617d7ffe871c0cbad1b7bb99bcea03dc47561feae4dad89019b8f2e6990782b9ae4e74243b1ac2ec007d621642d507b1a844d3e05f"));
                //unspent.pushKV("str", EncodeDestination(GetDestinationForKey(pbkey, OutputType::LEGACY)));

                //随机生成一对公私钥==================================================
                /*
                CKey secret;
                secret.MakeNewKey(false);
                CPubKey pbkey2 = secret.GetPubKey();
                assert(secret.VerifyPubKey(pbkey2));
                std::string s = HexStr(secret) + " : " + HexStr(pbkey2);
                */

                //测试 secp256k1_ec_pubkey_tweak_mul========================================
                //65f584d3699d0575173d704cd91b2532a3a658d2ca82c0b73dac602a43a2817a
                //04a9bd2361197fef1b5e8e915055aff9899aa554a8ee5ff738775f1051a63f1c056b9eed5714e4e541bd624c772ca3ef63d53f7d74fc7ea6c4904fa1057c6483ae
                secp256k1_pubkey G;
                unsigned char ctmp_one[33] = {0};
                ctmp_one[31] = 0x01;
                secp256k1_ec_pubkey_create(ctx, &G, ctmp_one);

                //secp256k1_pubkey 貌似是小顶端， 而CPubKey 是大顶端。 两者打印出来，字节序是相反的。
                secp256k1_pubkey pk_mul = G;
                //私钥的数组是 大顶端。打印出来和CKey 是一致的。
                unsigned char ctmp2[33] = {0x65, 0xf5, 0x84, 0xd3, 0x69, 0x9d, 0x05, 0x75, 0x17, 0x3d, 0x70, 0x4c, 0xd9, 0x1b, 0x25, 0x32, 0xa3, 0xa6, 0x58, 0xd2, 0xca, 0x82, 0xc0, 0xb7, 0x3d, 0xac, 0x60, 0x2a, 0x43, 0xa2, 0x81, 0x7a};
                secp256k1_ec_pubkey_tweak_mul(ctx, &pk_mul, ctmp2);
                CPubKey cpk3;
                size_t clen = CPubKey::SIZE;
                secp256k1_ec_pubkey_serialize(ctx, (unsigned char*)cpk3.begin(), &clen, &pk_mul, SECP256K1_EC_UNCOMPRESSED);
                assert(cpk3.size() == clen);
                assert(cpk3.IsValid());
                CKey sec3;
                sec3.Set(ctmp2, &ctmp2[32], false);
                CPubKey cpk4 = sec3.GetPubKey();
                assert(cpk4 == cpk3);
                //unspent.pushKV("str", HexStr(pk_mul.data) + " _ " + HexStr(cpk3));
                //unspent.pushKV("str2", HexStr(ctmp2) + " _ " + HexStr(sec3));

                //测试 secp256k1_ec_pubkey_tweak_add=======================================================
                unsigned char ctmp3[33] = {0};
                memcpy(ctmp3, ctmp2, 31);
                unsigned char ctmp4[33] = {0};
                ctmp4[31] = 0x7a;
                secp256k1_pubkey pk4;
                secp256k1_ec_pubkey_create(ctx, &pk4, ctmp3);
                secp256k1_pubkey pk_add = pk4;
                secp256k1_ec_pubkey_tweak_add(ctx, &pk_add, ctmp4);
                assert(secp256k1_ec_pubkey_cmp(ctx, &pk_add, &pk_mul) == 0);

                // 测试 secp256k1_ec_pubkey_combine=======================================================
                ctmp3[31] = 0x79;
                secp256k1_pubkey* ins[2] = {&pk4, &G};
                secp256k1_pubkey pk_combine;
                secp256k1_ec_pubkey_create(ctx, &pk4, ctmp3);
                secp256k1_ec_pubkey_combine(ctx, &pk_combine, ins, 2);
                assert(secp256k1_ec_pubkey_cmp(ctx, &pk_combine, &pk_mul) == 0);

                // 测试 secp256k1_ec_pubkey_parse=======================================================
                CPubKey cpbkey(ParseHex("04a9bd2361197fef1b5e8e915055aff9899aa554a8ee5ff738775f1051a63f1c056b9eed5714e4e541bd624c772ca3ef63d53f7d74fc7ea6c4904fa1057c6483ae"));
                secp256k1_pubkey pk_parsed;
                secp256k1_ec_pubkey_parse(ctx, &pk_parsed, cpbkey.data(), cpbkey.size());
                assert(secp256k1_ec_pubkey_cmp(ctx, &pk_parsed, &pk_mul) == 0);

                //测试 secp256k1_ec_seckey_tweak_mul 和 secp256k1_ec_seckey_inverse=======================================================
                auto sec4 = ParseHex("bbbace0c56e3ebd03072b0cb2370f1a060b6f29e988ec77e92a190c92448c6e6");
                auto sec4_tmp = sec4;
                auto sec4_inv = ParseHex("82b6f65ef08f2312c9655cc497ee200f3e71a6e4a3b53c29793e572fdfa8e8f1");
                secp256k1_ec_seckey_tweak_mul(ctx, sec4_tmp.data(), sec4_inv.data());
                assert(memcmp(sec4_tmp.data(), ctmp_one, sec4_tmp.size()) == 0);
                unsigned char cinverse[33] = {0};
                secp256k1_ec_seckey_inverse(ctx, cinverse, sec4_inv.data());
                assert(memcmp(sec4.data(), cinverse, sec4.size()) == 0);

                CKey sec_rand;
                sec_rand.MakeNewKey(false);
                CPubKey pbkey_rand = sec_rand.GetPubKey();
                secp256k1_pubkey pbkey_rand_parse_mul;
                secp256k1_ec_pubkey_parse(ctx, &pbkey_rand_parse_mul, pbkey_rand.data(), pbkey_rand.size());
                unsigned char sec_rand_inv[33] = {0};
                secp256k1_ec_seckey_inverse(ctx, sec_rand_inv, (unsigned char*)sec_rand.data());
                secp256k1_ec_pubkey_tweak_mul(ctx, &pbkey_rand_parse_mul, sec_rand_inv);
                assert(secp256k1_ec_pubkey_cmp(ctx, &pbkey_rand_parse_mul, &G) == 0);

                //测试bingo=======================================================
                //5294873c75604180f16f2dec603b8e786da8feefc71baa101e6138205f8d5ba1  sec
                //2a9d0567a5531408a7927116cdebd3d2e246df1ed423bfb95ef661f7be5e0b3d  05838517687b13e266e3464a7acd81e85d049a9128bbbf1e6375bfa473714eb8
                //m=1ffffff
                //n2=4895a70cb210634c8caa2f597e5abd013aefc7cbfd749c8e30dbd3e16370ce0c
                //m2=cad9954ad40d7e586df711835bdde9f5327f99ed4d59ac4ea19f811b17340a1c
                CPubKey cpbkey_x(ParseHex("04e785ae5d44cac354b410c1b2b90ff2ff848333f059a53daec1fd693592a47c7d491b8040ed7a05bebcd057cb50f8427abced2a6bdd5028fa16f280faeaf60cee"));
                RhoState rs = {0};
                secp256k1_ec_pubkey_parse(ctx, &rs.x, cpbkey_x.data(), cpbkey_x.size());
                auto n2 = ParseHex("4895a70cb210634c8caa2f597e5abd013aefc7cbfd749c8e30dbd3e16370ce0c");
                auto m2 = ParseHex("cad9954ad40d7e586df711835bdde9f5327f99ed4d59ac4ea19f811b17340a1c");
                memcpy(rs.n, n2.data(), n2.size());
                memcpy(rs.m, m2.data(), m2.size());
                CKey mvp_mock;
                int m = 0x1ffffff;
                bingo(ctx, mvp_mock, rs, m);
                CPubKey pk_got = mvp_mock.GetPubKey();
                CPubKey pk_mock(ParseHex("042a9d0567a5531408a7927116cdebd3d2e246df1ed423bfb95ef661f7be5e0b3d05838517687b13e266e3464a7acd81e85d049a9128bbbf1e6375bfa473714eb8"));
                assert(pk_got == pk_mock);
                secp256k1_pubkey pk_1ffffff;                
                unsigned char c_1ffffff[33] = {0};
                set_int(c_1ffffff, m);
                secp256k1_ec_pubkey_create(ctx, &pk_1ffffff, c_1ffffff);
                assert(secp256k1_ec_pubkey_cmp(ctx, &pk_1ffffff, &rs.x) == 0);

                //测试 create
                RhoPoint rp = {0};
                create(ctx, &rp.x, c_1ffffff, rp.n);
                assert(secp256k1_ec_pubkey_cmp(ctx, &pk_1ffffff, &rp.x) == 0);

                //测试 bingo 负值的情况
                CPubKey cpbkey_x_neg(ParseHex("04e785ae5d44cac354b410c1b2b90ff2ff848333f059a53daec1fd693592a47c7db6e47fbf1285fa41432fa834af07bd854312d59422afd705e90d7f041509ef41"));
                secp256k1_ec_pubkey_parse(ctx, &rs.x, cpbkey_x.data(), cpbkey_x.size());
                auto n2_neg = ParseHex("b76a58f34def9cb37355d0a681a542fd7fbf151ab1d403ad8ef68aab6cc57335");
                auto m2_neg = ParseHex("35266ab52bf281a79208ee7ca4221609882f42f961eef3ed1e32dd71b9023725");
                memcpy(rs.n, n2_neg.data(), n2_neg.size());
                memcpy(rs.m, m2_neg.data(), m2_neg.size());
                CKey mvp_mock2;
                bingo(ctx, mvp_mock2, rs, -m);
                assert(memcmp(mvp_mock.data(), mvp_mock2.data(), mvp_mock.size()) == 0);

                SecPair sp1 = {0};
                sp1.rand();
                SecPair sp2 = sp1;
                assert(sp2 == sp1);
                assert(memcmp(sp1.m, sp2.m, sizeof(sp1.m)) == 0);
                assert(memcmp(sp1.n, sp2.n, sizeof(sp1.n)) == 0);

                unsigned char chars[5];
                for (auto& c : chars) {
                    c = randChar();
                }
                assert(chars[0] != chars[1] || chars[2] != chars[3] || chars[1] != chars[4]);

                //测试 saveDP 和 loadDP                
                /* {
                    iLog _testlog("D:\\test.txt");
                    std::map<uint64_t, SecPair> _testMap;
                    RhoState rss[1024];
                    for (RhoState& r : rss) {
                        r.rand();
                        uint64_t t = *(uint64_t*)r.x.data;
                        saveDP(_testlog.ofs, t, r);
                    }
                    loadDP(_testlog.ifs, _testMap);
                    for (RhoState& r : rss) {
                        uint64_t t = *(uint64_t*)r.x.data;
                        auto it = _testMap.find(t);
                        assert(it != _testMap.end() && it->second == r);
                    }
                }
                std::remove("D:\\test.txt");*/

                //测试CUDA
                validate_test();
            }

            if (ta == 112) {
                // 测试密钥的存储与读取
                CKey secret;
                secret.MakeNewKey(true);
                CPubKey pbkey = secret.GetPubKey();
                assert(secret.VerifyPubKey(pbkey));
                save_key(secret);
                std::string strSecret = read_key();
                CKey key2 = DecodeSecret(strSecret);
                assert(key2.VerifyPubKey(pbkey));
            }

            auto judge = [&node]() {
                while (!gameover) {
                    try {
                        std::this_thread::sleep_for(std::chrono::milliseconds(1000));
                        node.rpc_interruption_point();
                    } catch (...) {
                        stop_game();
                    }
                }
            };

            // 写入文件的lambda
            auto write_num = [](const std::string& filename, uint64_t num) {
                std::ofstream file(filename);
                file << num << " ";
            };

            // 读取文件的lambda
            auto read_num = [](const std::string& filename) -> uint64_t {
                uint64_t num = 0;
                std::ifstream file(filename);
                if (file.is_open()) {
                    file >> num;
                }
                return num;
            };

            const std::string babynum_file = "D:\\baby_map\\babynum.txt";
            //生成babystep
            if (ta == 118) {
                assert(ta2 > 0);
                BabyNUM = ta2;
                
                int times = 6;
                uint64_t batch = (ta2 + times - 1) / times;
                int64_t total = 0;
                uint64_t base = 1;
                for (int i = 0; i < times; i++) {
                    if (i == times - 1) {
                        batch = ta2 - batch * i;
                    }
                    std::multimap<uint64_t, uint64_t> theMap;
                    char filename[256] = {0};
                    sprintf(filename, "D:\\baby_map\\baby_map%llu.txt", base);
                    base = buildBabyMap(theMap, batch, base);
                    //检测key冲突,这里需要进一步的解决方案
                    assert(theMap.size() == batch);
                    save_map(theMap, filename);
                    total += batch;
                }
                write_num(babynum_file, total);
                unspent.pushKV("num", total);
            }
            //加载babystep 并简单测试
            if (ta == 119) {
                std::vector<uint64_t> _Xvec;
                std::vector<uint64_t> _Mvec;
                if (ta2 == 888) {
                    BabyNUM = read_num(babynum_file);
                    _Xvec.reserve(BabyNUM);
                    _Mvec.reserve(BabyNUM);
                    read_map(_Xvec, _Mvec, 0, "baby");
                    std::cout << "read_map finished!" << std::endl;
                    saveVectorToFile<uint64_t>(_Xvec, _Xvec_name);
                    saveVectorToFile<uint64_t>(_Mvec, _Mvec_name);
                    assert(_Xvec.size() == BabyNUM); 
                } else {
                    _Mvec = loadVectorFromFile<uint64_t>(_Mvec_name);
                    _Xvec = loadVectorFromFile<uint64_t>(_Xvec_name);
                    BabyNUM = _Xvec.size();
                }
                assert(_Xvec.size() == _Mvec.size());
                //4GG
                CPubKey cpbkey1(ParseHex("04100f44da696e71672791d0a09b7bde459f1215a29b3c03bfefd7835b39a48db0dad89019b8f2e6990782b9ae4e74243b1ac2ec007d621642d507b1a844d3e05f"));
                secp256k1_pubkey pk_parsed;
                secp256k1_ec_pubkey_parse(ctx, &pk_parsed, cpbkey1.data(), cpbkey1.size());
                assert(find_baby(ctx, _Xvec, _Mvec, pk_parsed) == 0);
                //1G
                CPubKey cpbkey2(ParseHex("0479be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8"));
                secp256k1_ec_pubkey_parse(ctx, &pk_parsed, cpbkey2.data(), cpbkey2.size());
                assert(find_baby(ctx, _Xvec, _Mvec, pk_parsed) == 1);
                //-(0x123G )
                CPubKey cpbkey2neg(ParseHex("049bdf9e67a5d0c9956a075a010fe762beb633500431dee78efebc527e53313b336bd9b9de5a69f1f11db3d86d90e9352d6f80d9c989d172a5e816b5017162d07f"));
                secp256k1_ec_pubkey_parse(ctx, &pk_parsed, cpbkey2neg.data(), cpbkey2neg.size());
                assert(find_baby(ctx, _Xvec, _Mvec, pk_parsed) == -0x123);
                // fffffffG
                CPubKey cpbkey3(ParseHex("045091541f5851647a93df0c14152a4516169b5bd6acf793dee8c9dfa27710e4b0ec29eeaf3d880023f13d2608200ec283c971081ee88ec05247bf6d65b57e8537"));
                secp256k1_ec_pubkey_parse(ctx, &pk_parsed, cpbkey3.data(), cpbkey3.size());
                assert(find_baby(ctx, _Xvec, _Mvec, pk_parsed) == 0xfffffff);
                unspent.pushKV("num", _Xvec.size());
                //BabyNUM G
                secp256k1_pubkey pk_babynum;
                unsigned char cm[33] = {0};                
                set_int(cm, BabyNUM);
                secp256k1_ec_pubkey_create(ctx, &pk_babynum, cm);
                assert(find_baby(ctx, _Xvec, _Mvec, pk_babynum) == BabyNUM);
                secp256k1_ec_pubkey_negate(ctx, &pk_babynum);
                assert(find_baby(ctx, _Xvec, _Mvec, pk_babynum) == -BabyNUM);
                //检查最大m
                auto maxIt = std::max_element(_Mvec.begin(), _Mvec.end());
                assert(*maxIt == BabyNUM);
                //检查排序
                assert(std::is_sorted(_Xvec.begin(), _Xvec.end()));
                //测试重复的x元素
                auto it = std::adjacent_find(_Xvec.begin(), _Xvec.end());
                if (it != _Xvec.end()) {
                    std::ptrdiff_t index = std::distance(_Xvec.begin(), it);
                    auto m = _Mvec[index];
                    unsigned char c_dup[33] = {0};
                    set_int(c_dup, m);
                    secp256k1_pubkey pk_dup = {0};
                    secp256k1_ec_pubkey_create(ctx, &pk_dup, c_dup);
                    assert(find_baby(ctx, _Xvec, _Mvec, pk_dup) == m);
                } else {
                    assert(BabyNUM < 0x2FFFFFFFF);
                }


                //测试 giantStep
                unsigned char c_babynum_neg[33] = {0};
                set_int(c_babynum_neg, BabyNUM);
                secp256k1_ec_seckey_negate(ctx, c_babynum_neg);

                auto N_1 = ParseHex("fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364140");
                int64_t find_ret[3] = {BabyNUM - 1, -1, -BabyNUM};
                RhoState rs = {0};
                memcpy(rs.m, N_1.data(), N_1.size());
                for (int j = 0; j < 3; j++) {
                    secp256k1_ec_seckey_tweak_add(ctx, rs.m, c_babynum_neg);
                    if (j == 2) {
                        unsigned char c_one[33] = {0};
                        c_one[31] = 0x01;
                        secp256k1_ec_seckey_tweak_add(ctx, rs.m, c_one);
                    }
                    create(ctx, &rs.x, rs.m, rs.n);                    
                    RhoState tmp = rs;
                    assert(find_baby(ctx, _Xvec, _Mvec, tmp.x) == 0);
                    giantStep(ctx, tmp);
                    assert(find_baby(ctx, _Xvec, _Mvec, tmp.x) == find_ret[j]);
                }

                if (ta2 == 0) {
                    g_log->ofs << "BabyNUM: " << BabyNUM << std::endl;
                }
            }

            //32 位 DP 库跟 data 语料的对账自检 —— 两种库侧口径:
            //  testmvp 120 888: 全量库 DpSource32all.bin (库里的索引表应与语料去重后的
            //                   索引集合逐条相同; 抽样: 语料里的点能在库里找到同一条)
            //  testmvp 120 889: 源库 + 已征召库 (两库之和 == 语料去重后的条目数; 抽样:
            //                   语料里的点能在库里找到同一条, 含被征召销账立了墓碑的)
            //三个库都是离线脚本一次生成的快照, 应用内只有校验入口, 要重建就离线跑脚本。
            //重建会移动源库的槽位号, 而 rho 的 3 类货源 (ReserveSource::Dp) 在
            //D:\RhoReserve.txt 里存的就是槽位游标 —— 重建之后那个游标至多指偏, 不会崩,
            //只是可能重复发出几条已经用过的点。所以重建完最好把存档里的 supply Dp 清零。
            if (ta == 120 && ta2 == 888) {
                validate_dp32_corpus(Dp32CorpusTarget::AllLib);
            }
            if (ta == 120 && ta2 == 889) {
                validate_dp32_corpus(Dp32CorpusTarget::TwoLib);
            }
            //货源配置的生产前自检: 按当前 g_reserve_source 把生产启动那一步 (建池 ->
            //账本取满 -> 上传设备常量内存) 走一遍, 逐槽核对点是否自洽/互不相同, 以及
            //来源配成 3 类时是不是真的都取到了源库里的 32 位 DP。
            //换货源 (rho.cpp 的 g_reserve_source) 之后跑这个, 不必等全量 validate。
            //testmvp 120 891
            if (ta == 120 && ta2 == 891) {
                validate_reserve_prod_config();
            }
            //被征召的预备点"重走"探针: 拿已征召库 (D:\DpDrafted32.bin) 尾部几条点的原始
            //(m, n) 当起点, 用生产核同一套步进 (fun_add_w, W=RHO_GPU_WALKERS) 往前走,
            //每步拿 (m, n) 去 RhoState2.txt 的 (m, n) 集合里查 —— 看被征召的那几个预备点
            //之后有没有真的落到落盘的那批 rhostate 上。只读, 不动设备内存/不写文件。
            //testmvp 120 892
            if (ta == 120 && ta2 == 892) {
                rho_rewalk_probe();
            }
            //测试 rho_F 与 rho_Fi 或者 giantStep 与 giantStepi
            if (ta == 121) {
                RhoState rs[RHO_STATE_SLOTS] = {0};
                loadRhoState(rs, sizeof(rs) / sizeof(RhoState), _RSFile1_name);
                auto f = rho_F;
                auto fi = rho_Fi;
                if (ta2 == 1) {
                    f = giantStep;
                    fi = giantStepi;
                }
                for (int ii = 0; ii < 32; ii++) {
                    int i = 10000;
                    while (--i > 0) {
                        assert(check(ctx, &rs[ii].x, rs[ii].m, rs[ii].n));
                        RhoState tmp = rs[ii];
                        f(ctx, rs[ii]);
                        RhoState ret[32] = {0};
                        int c = fi(ctx, &rs[ii], ret);
                        bool b = false;
                        for (int j = 0; j < c; j++) {
                            b = b || (secp256k1_ec_pubkey_cmp(ctx, &ret[j].x, &tmp.x) == 0);
                        }
                        assert(b);
                    }
                }
            }
            // 生成lambdamap
            if (ta == 128) {
                std::multimap<uint64_t, uint64_t> theMap;
                uint64_t base = 1;
                std::string base_filename = "D:\\lambda_map\\lambda_base.txt";
                std::string filename  = "D:\\lambda_map\\lambda_map1.txt";
                base = read_num(base_filename);
                read_map(theMap, filename);
                gameover = false;
                std::thread t(judge);
                base = buildLambdaMap(theMap, 1024*1024*1024, base);
                save_map(theMap, filename);
                write_num(base_filename, base);
                gameover = true;
                if (t.joinable())
                    t.join();
            };
            // 加载lambdamap 并简单测试
            if (ta == 129) {
                std::vector<uint64_t> _Xvec;
                std::vector<uint64_t> _Mvec;
                if (ta2 == 888) {
                    read_map(_Xvec, _Mvec, 0, "lambda");
                    saveVectorToFile<uint64_t>(_Xvec, _XvecL_name);
                    saveVectorToFile<uint64_t>(_Mvec, _MvecL_name);
                } else {
                    _Mvec = loadVectorFromFile<uint64_t>(_MvecL_name);
                    _Xvec = loadVectorFromFile<uint64_t>(_XvecL_name);
                }
            }
            if (ta == 8) {
                // ta2 == 1: 40 位 DP 文本归档 D:\DistinguishablePoints.txt (三行一条)
                // ta2 == 2: 32 位 DP 起点漫游的边表 D:\Dp32Edge.txt (一行一条)
                if (ta2 == 1) {
                    // 检查DP文件中是否存在碰撞，若存在则计算bingo
                    std::map<uint64_t, SecPair> dpMap;

                    // 处理单个DP文件流：解析每条记录(三行一组)并入dpMap，检测碰撞
                    // 返回值: 0=正常读完(EOF); 非0=遇到错误或碰撞(应停止后续处理)
                    auto processDPStream = [&](std::istream& ifs) -> int {
                        std::string line;
                        while (std::getline(ifs, line)) {
                            uint64_t dp_index;
                            SecPair sp;
                            sscanf(line.c_str(), "%llu", &dp_index);
                            if (!std::getline(ifs, line)) break;
                            memcpy(sp.m, ParseHex(line).data(), sizeof(sp.m));
                            if (!std::getline(ifs, line)) break;
                            memcpy(sp.n, ParseHex(line).data(), sizeof(sp.n));

                            secp256k1_pubkey x_tmp;
                            create(ctx, &x_tmp, sp.m, sp.n);
                            if (dp_index != distinguishable(x_tmp)) {
                                unspent.pushKV("str", "!!!!Error!!!! dp_index: " + std::to_string(dp_index));
                                unspent.pushKV("str2", HexStr(x_tmp.data) + " : " + HexStr(sp.m) + " : " + HexStr(sp.n));
                                return 1;
                            }
                            auto iter = dpMap.find(dp_index);
                            if (iter != dpMap.end()) {
                                CKey k;
                                if (bingo(ctx, k, sp, iter->second)) {
                                    save_key(k);
                                    unspent.pushKV("str", "!!!!bingo!!!!");
                                    return 2;
                                } else {
                                    unspent.pushKV("str", "!!!!short circulation!!!!");
                                    unspent.pushKV("str2", std::to_string(dp_index));
                                    return 3;
                                }
                            } else {
                                dpMap[dp_index] = sp;
                            }
                        }
                        return 0;
                    };

                    bool stop = false;

                    // 1) 处理主DP文件 D:\DistinguishablePoints.txt
                    {
                        iLog _dplog(_DPFile_name);
                        if (_dplog.ifs.is_open()) {
                            if (processDPStream(_dplog.ifs) != 0) {
                                stop = true;
                            }
                        }
                    }
                    /*
                    // 2) 继续读取 ../../../../data 下的额外DP文件
                    //    - DistinguishablePoints_rho.txt
                    //    - DistinguishablePoints_rhoN.txt (N为数字)
                    const std::string dataDir = "../../../../data/";
                    const fs::path dataDirPath = fs::u8path(dataDir);
                    if (!stop && fs::exists(dataDirPath)) {
                        const std::string prefix = "DistinguishablePoints_rho";
                        const std::string suffix = ".txt";

                        // 统一枚举 ../../../../data 下所有 DistinguishablePoints_rho*.txt 文件
                        //   * 为空   → DistinguishablePoints_rho.txt
                        //   * 为数字 → DistinguishablePoints_rhoN.txt
                        // 每个文件只处理一次，避免重复读取导致的短循环误判
                        {
                            std::vector<fs::path> rho_files;
                            for (const auto& entry : fs::directory_iterator(dataDirPath)) {
                                if (!entry.is_regular_file()) continue;
                                std::string fname = entry.path().filename().string();
                                if (!fname.starts_with(prefix) || !fname.ends_with(suffix)) continue;
                                std::string mid = fname.substr(prefix.size(),
                                                               fname.size() - prefix.size() - suffix.size());
                                // mid 为空(rho.txt) 或纯数字(rhoN.txt) 才是目标文件
                                bool valid = mid.empty();
                                if (!valid) {
                                    valid = true;
                                    for (char c : mid) {
                                        if (c < '0' || c > '9') { valid = false; break; }
                                    }
                                }
                                if (valid) {
                                    rho_files.push_back(entry.path());
                                }
                            }
                            std::sort(rho_files.begin(), rho_files.end());
                            for (const auto& f : rho_files) {
                                std::ifstream ifs(f);
                                if (ifs.is_open()) {
                                    if (processDPStream(ifs) != 0) {
                                        stop = true;
                                        break;
                                    }
                                }
                            }
                        }
                    }
                    */
                    unspent.pushKV("num", dpMap.size());
                } else if (ta2 == 2) {
                    // 校验 D:\Dp32Edge.txt 里的每条边确实是 32 位 DP (ta2 == 1 的 32 位兄弟)。
                    // 一行 "起点索引 终点索引 终点m 终点n": 由 (m, n) 现算 x = m*G + n*MVP,
                    // 再过 32 位判据 (x 低 32 位全 0 时的 x 的 bit 32..95) 与记录的终点索引逐位
                    // 比 —— 对得上才说明这一行是一次货真价实的"起点 DP -> 终点 DP"的漫步。
                    // 起点索引 (跟踪用的那一列) 另拿全量库 DpSource32all.bin 复核; 库里按索引
                    // 升序, 内存二分即可。
                    // 两条边落在同一个终点 = 一次碰撞, 两份 (m, n) 表示之差能解出 MVP 的离散
                    // 对数 => bingo, 同 ta2 == 1 的碰撞口径 (先确认两份真的是同一个点: 同一索引
                    // 不等于同一个点, 靠 secp256k1_ec_pubkey_cmp 对全值)。
                    Dp32Store all_lib;
                    if (!all_lib.load(DP32_ALL_FILE, nullptr) || !all_lib.loaded()) {
                        unspent.pushKV("str", std::string("!!!!Error!!!! 载入失败: ") + DP32_ALL_FILE);
                        return unspent;
                    }

                    std::map<uint64_t, SecPair> dstMap;   // 终点索引 -> 该终点的 (m, n)
                    uint64_t n_lines = 0, n_bad = 0, n_src_unknown = 0, n_dst_dup = 0;
                    std::string first_bad;

                    iLog _edgelog(DP32_EDGE_FILE);
                    if (!_edgelog.ifs.is_open()) {
                        unspent.pushKV("str", std::string("!!!!Error!!!! 打不开: ") + DP32_EDGE_FILE);
                        return unspent;
                    }
                    std::string line;
                    while (std::getline(_edgelog.ifs, line)) {
                        if (line.empty()) continue;
                        n_lines++;

                        uint64_t src = 0, dst = 0;
                        std::string mhex, nhex;
                        std::istringstream iss(line);
                        if (!(iss >> src >> dst >> mhex >> nhex)) {
                            n_bad++;
                            if (first_bad.empty()) {
                                first_bad = "第 " + std::to_string(n_lines) + " 行列数不对: " + line;
                            }
                            continue;
                        }
                        SecPair sp;
                        const auto mb = ParseHex(mhex);
                        const auto nb = ParseHex(nhex);
                        if (mb.size() != sizeof(sp.m) || nb.size() != sizeof(sp.n)) {
                            n_bad++;
                            if (first_bad.empty()) {
                                first_bad = "第 " + std::to_string(n_lines) + " 行 m/n 长度不对";
                            }
                            continue;
                        }
                        memcpy(sp.m, mb.data(), sizeof(sp.m));
                        memcpy(sp.n, nb.data(), sizeof(sp.n));

                        secp256k1_pubkey x_tmp;
                        create(ctx, &x_tmp, sp.m, sp.n);
                        uint64_t dp_index = 0;
                        if (!dp32_test(x_tmp, dp_index) || dp_index != dst) {
                            n_bad++;
                            if (first_bad.empty()) {
                                first_bad = "第 " + std::to_string(n_lines) + " 行不是 32 位 DP: 记录终点索引 "
                                            + std::to_string(dst) + ", x " + HexStr(x_tmp.data);
                            }
                            continue;
                        }

                        // 起点索引必须在全量库里: 那一列就是拿来跟踪"这条边从哪个 DP 出发"的
                        uint32_t slot = 0;
                        if (all_lib.src_find(src, slot) == Dp32Hit::Absent) n_src_unknown++;

                        // 终点碰撞: 同一索引先确认是同一个点, 是才谈得上 bingo
                        const auto iter = dstMap.find(dst);
                        if (iter == dstMap.end()) {
                            dstMap[dst] = sp;
                        } else {
                            secp256k1_pubkey x_old;
                            create(ctx, &x_old, iter->second.m, iter->second.n);
                            if (secp256k1_ec_pubkey_cmp(ctx, &x_old, &x_tmp) == 0) {
                                CKey k;
                                if (bingo(ctx, k, sp, iter->second)) {
                                    save_key(k);
                                    unspent.pushKV("str", "!!!!bingo!!!!");
                                    unspent.pushKV("str2", std::to_string(dst));
                                    return unspent;
                                }
                            }
                            n_dst_dup++;
                        }
                    }

                    cprintf("Dp32Edge 校验: %llu 行, 非 32 位 DP %llu 条, 起点不在库里 %llu 条, "
                            "同终点碰撞 %llu 条 (终点去重 %llu)\n",
                            (unsigned long long)n_lines, (unsigned long long)n_bad,
                            (unsigned long long)n_src_unknown, (unsigned long long)n_dst_dup,
                            (unsigned long long)dstMap.size());
                    unspent.pushKV("str", strprintf("lines %llu, not_32dp %llu, src_not_in_lib %llu, "
                                                    "dst_collision %llu, dst_unique %llu",
                                                    (unsigned long long)n_lines, (unsigned long long)n_bad,
                                                    (unsigned long long)n_src_unknown,
                                                    (unsigned long long)n_dst_dup,
                                                    (unsigned long long)dstMap.size()));
                    unspent.pushKV("str2", first_bad);
                    unspent.pushKV("num", n_lines);
                } /* else {
                    std::thread t(judge);
                    play<Rho>();
                }*/
            }

            return unspent;
        },
    };
}


/**
 * Serialize the UTXO set to a file for loading elsewhere.
 *
 * @see SnapshotMetadata
 */
static RPCHelpMan dumptxoutset()
{
    return RPCHelpMan{
        "dumptxoutset",
        "Write the serialized UTXO set to a file. This can be used in loadtxoutset afterwards if this snapshot height is supported in the chainparams as well.\n\n"
        "Unless the the \"latest\" type is requested, the node will roll back to the requested height and network activity will be suspended during this process. "
        "Because of this it is discouraged to interact with the node in any other way during the execution of this call to avoid inconsistent results and race conditions, particularly RPCs that interact with blockstorage.\n\n"
        "This call may take several minutes. Make sure to use no RPC timeout (bitcoin-cli -rpcclienttimeout=0)",
        {
            {"path", RPCArg::Type::STR, RPCArg::Optional::NO, "Path to the output file. If relative, will be prefixed by datadir."},
            {"type", RPCArg::Type::STR, RPCArg::Default(""), "The type of snapshot to create. Can be \"latest\" to create a snapshot of the current UTXO set or \"rollback\" to temporarily roll back the state of the node to a historical block before creating the snapshot of a historical UTXO set. This parameter can be omitted if a separate \"rollback\" named parameter is specified indicating the height or hash of a specific historical block. If \"rollback\" is specified and separate \"rollback\" named parameter is not specified, this will roll back to the latest valid snapshot block that can currently be loaded with loadtxoutset."},
            {"options", RPCArg::Type::OBJ_NAMED_PARAMS, RPCArg::Optional::OMITTED, "",
                {
                    {"rollback", RPCArg::Type::NUM, RPCArg::Optional::OMITTED,
                        "Height or hash of the block to roll back to before creating the snapshot. Note: The further this number is from the tip, the longer this process will take. Consider setting a higher -rpcclienttimeout value in this case.",
                    RPCArgOptions{.skip_type_check = true, .type_str = {"", "string or numeric"}}},
                },
            },
        },
        RPCResult{
            RPCResult::Type::OBJ, "", "",
                {
                    {RPCResult::Type::NUM, "coins_written", "the number of coins written in the snapshot"},
                    {RPCResult::Type::STR_HEX, "base_hash", "the hash of the base of the snapshot"},
                    {RPCResult::Type::NUM, "base_height", "the height of the base of the snapshot"},
                    {RPCResult::Type::STR, "path", "the absolute path that the snapshot was written to"},
                    {RPCResult::Type::STR_HEX, "txoutset_hash", "the hash of the UTXO set contents"},
                    {RPCResult::Type::NUM, "nchaintx", "the number of transactions in the chain up to and including the base block"},
                }
        },
        RPCExamples{
            HelpExampleCli("-rpcclienttimeout=0 dumptxoutset", "utxo.dat latest") +
            HelpExampleCli("-rpcclienttimeout=0 dumptxoutset", "utxo.dat rollback") +
            HelpExampleCli("-rpcclienttimeout=0 -named dumptxoutset", R"(utxo.dat rollback=853456)")
        },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    NodeContext& node = EnsureAnyNodeContext(request.context);
    const CBlockIndex* tip{WITH_LOCK(::cs_main, return node.chainman->ActiveChain().Tip())};
    const CBlockIndex* target_index{nullptr};
    const std::string snapshot_type{self.Arg<std::string>("type")};
    const UniValue options{request.params[2].isNull() ? UniValue::VOBJ : request.params[2]};
    if (options.exists("rollback")) {
        if (!snapshot_type.empty() && snapshot_type != "rollback") {
            throw JSONRPCError(RPC_INVALID_PARAMETER, strprintf("Invalid snapshot type \"%s\" specified with rollback option", snapshot_type));
        }
        target_index = ParseHashOrHeight(options["rollback"], *node.chainman);
    } else if (snapshot_type == "rollback") {
        auto snapshot_heights = node.chainman->GetParams().GetAvailableSnapshotHeights();
        CHECK_NONFATAL(snapshot_heights.size() > 0);
        auto max_height = std::max_element(snapshot_heights.begin(), snapshot_heights.end());
        target_index = ParseHashOrHeight(*max_height, *node.chainman);
    } else if (snapshot_type == "latest") {
        target_index = tip;
    } else {
        throw JSONRPCError(RPC_INVALID_PARAMETER, strprintf("Invalid snapshot type \"%s\" specified. Please specify \"rollback\" or \"latest\"", snapshot_type));
    }

    const ArgsManager& args{EnsureAnyArgsman(request.context)};
    const fs::path path = fsbridge::AbsPathJoin(args.GetDataDirNet(), fs::u8path(request.params[0].get_str()));
    // Write to a temporary path and then move into `path` on completion
    // to avoid confusion due to an interruption.
    const fs::path temppath = fsbridge::AbsPathJoin(args.GetDataDirNet(), fs::u8path(request.params[0].get_str() + ".incomplete"));

    if (fs::exists(path)) {
        throw JSONRPCError(
            RPC_INVALID_PARAMETER,
            path.utf8string() + " already exists. If you are sure this is what you want, "
            "move it out of the way first");
    }

    FILE* file{fsbridge::fopen(temppath, "wb")};
    AutoFile afile{file};
    if (afile.IsNull()) {
        throw JSONRPCError(
            RPC_INVALID_PARAMETER,
            "Couldn't open file " + temppath.utf8string() + " for writing.");
    }

    CConnman& connman = EnsureConnman(node);
    const CBlockIndex* invalidate_index{nullptr};
    std::optional<NetworkDisable> disable_network;
    std::optional<TemporaryRollback> temporary_rollback;

    // If the user wants to dump the txoutset of the current tip, we don't have
    // to roll back at all
    if (target_index != tip) {
        // If the node is running in pruned mode we ensure all necessary block
        // data is available before starting to roll back.
        if (node.chainman->m_blockman.IsPruneMode()) {
            LOCK(node.chainman->GetMutex());
            const CBlockIndex* current_tip{node.chainman->ActiveChain().Tip()};
            const CBlockIndex* first_block{node.chainman->m_blockman.GetFirstBlock(*current_tip, /*status_mask=*/BLOCK_HAVE_MASK)};
            if (first_block->nHeight > target_index->nHeight) {
                throw JSONRPCError(RPC_MISC_ERROR, "Could not roll back to requested height since necessary block data is already pruned.");
            }
        }

        // Suspend network activity for the duration of the process when we are
        // rolling back the chain to get a utxo set from a past height. We do
        // this so we don't punish peers that send us that send us data that
        // seems wrong in this temporary state. For example a normal new block
        // would be classified as a block connecting an invalid block.
        // Skip if the network is already disabled because this
        // automatically re-enables the network activity at the end of the
        // process which may not be what the user wants.
        if (connman.GetNetworkActive()) {
            disable_network.emplace(connman);
        }

        invalidate_index = WITH_LOCK(::cs_main, return node.chainman->ActiveChain().Next(target_index));
        temporary_rollback.emplace(*node.chainman, *invalidate_index);
    }

    Chainstate* chainstate;
    std::unique_ptr<CCoinsViewCursor> cursor;
    CCoinsStats stats;
    {
        // Lock the chainstate before calling PrepareUtxoSnapshot, to be able
        // to get a UTXO database cursor while the chain is pointing at the
        // target block. After that, release the lock while calling
        // WriteUTXOSnapshot. The cursor will remain valid and be used by
        // WriteUTXOSnapshot to write a consistent snapshot even if the
        // chainstate changes.
        LOCK(node.chainman->GetMutex());
        chainstate = &node.chainman->ActiveChainstate();
        // In case there is any issue with a block being read from disk we need
        // to stop here, otherwise the dump could still be created for the wrong
        // height.
        // The new tip could also not be the target block if we have a stale
        // sister block of invalidate_index. This block (or a descendant) would
        // be activated as the new tip and we would not get to new_tip_index.
        if (target_index != chainstate->m_chain.Tip()) {
            LogWarning("dumptxoutset failed to roll back to requested height, reverting to tip.\n");
            throw JSONRPCError(RPC_MISC_ERROR, "Could not roll back to requested height.");
        } else {
            std::tie(cursor, stats, tip) = PrepareUTXOSnapshot(*chainstate, node.rpc_interruption_point);
        }
    }

    UniValue result = WriteUTXOSnapshot(*chainstate, cursor.get(), &stats, tip, afile, path, temppath, node.rpc_interruption_point);
    fs::rename(temppath, path);

    result.pushKV("path", path.utf8string());
    return result;
},
    };
}

std::tuple<std::unique_ptr<CCoinsViewCursor>, CCoinsStats, const CBlockIndex*>
PrepareUTXOSnapshot(
    Chainstate& chainstate,
    const std::function<void()>& interruption_point)
{
    std::unique_ptr<CCoinsViewCursor> pcursor;
    std::optional<CCoinsStats> maybe_stats;
    const CBlockIndex* tip;

    {
        // We need to lock cs_main to ensure that the coinsdb isn't written to
        // between (i) flushing coins cache to disk (coinsdb), (ii) getting stats
        // based upon the coinsdb, and (iii) constructing a cursor to the
        // coinsdb for use in WriteUTXOSnapshot.
        //
        // Cursors returned by leveldb iterate over snapshots, so the contents
        // of the pcursor will not be affected by simultaneous writes during
        // use below this block.
        //
        // See discussion here:
        //   https://github.com/bitcoin/bitcoin/pull/15606#discussion_r274479369
        //
        AssertLockHeld(::cs_main);

        chainstate.ForceFlushStateToDisk();

        maybe_stats = GetUTXOStats(&chainstate.CoinsDB(), chainstate.m_blockman, CoinStatsHashType::HASH_SERIALIZED, interruption_point);
        if (!maybe_stats) {
            throw JSONRPCError(RPC_INTERNAL_ERROR, "Unable to read UTXO set");
        }

        pcursor = chainstate.CoinsDB().Cursor();
        tip = CHECK_NONFATAL(chainstate.m_blockman.LookupBlockIndex(maybe_stats->hashBlock));
    }

    return {std::move(pcursor), *CHECK_NONFATAL(maybe_stats), tip};
}

UniValue WriteUTXOSnapshot(
    Chainstate& chainstate,
    CCoinsViewCursor* pcursor,
    CCoinsStats* maybe_stats,
    const CBlockIndex* tip,
    AutoFile& afile,
    const fs::path& path,
    const fs::path& temppath,
    const std::function<void()>& interruption_point)
{
    LOG_TIME_SECONDS(strprintf("writing UTXO snapshot at height %s (%s) to file %s (via %s)",
        tip->nHeight, tip->GetBlockHash().ToString(),
        fs::PathToString(path), fs::PathToString(temppath)));

    SnapshotMetadata metadata{chainstate.m_chainman.GetParams().MessageStart(), tip->GetBlockHash(), maybe_stats->coins_count};

    afile << metadata;

    COutPoint key;
    Txid last_hash;
    Coin coin;
    unsigned int iter{0};
    size_t written_coins_count{0};
    std::vector<std::pair<uint32_t, Coin>> coins;

    // To reduce space the serialization format of the snapshot avoids
    // duplication of tx hashes. The code takes advantage of the guarantee by
    // leveldb that keys are lexicographically sorted.
    // In the coins vector we collect all coins that belong to a certain tx hash
    // (key.hash) and when we have them all (key.hash != last_hash) we write
    // them to file using the below lambda function.
    // See also https://github.com/bitcoin/bitcoin/issues/25675
    auto write_coins_to_file = [&](AutoFile& afile, const Txid& last_hash, const std::vector<std::pair<uint32_t, Coin>>& coins, size_t& written_coins_count) {
        afile << last_hash;
        WriteCompactSize(afile, coins.size());
        for (const auto& [n, coin] : coins) {
            WriteCompactSize(afile, n);
            afile << coin;
            ++written_coins_count;
        }
    };

    pcursor->GetKey(key);
    last_hash = key.hash;
    while (pcursor->Valid()) {
        if (iter % 5000 == 0) interruption_point();
        ++iter;
        if (pcursor->GetKey(key) && pcursor->GetValue(coin)) {
            if (key.hash != last_hash) {
                write_coins_to_file(afile, last_hash, coins, written_coins_count);
                last_hash = key.hash;
                coins.clear();
            }
            coins.emplace_back(key.n, coin);
        }
        pcursor->Next();
    }

    if (!coins.empty()) {
        write_coins_to_file(afile, last_hash, coins, written_coins_count);
    }

    CHECK_NONFATAL(written_coins_count == maybe_stats->coins_count);

    afile.fclose();

    UniValue result(UniValue::VOBJ);
    result.pushKV("coins_written", written_coins_count);
    result.pushKV("base_hash", tip->GetBlockHash().ToString());
    result.pushKV("base_height", tip->nHeight);
    result.pushKV("path", path.utf8string());
    result.pushKV("txoutset_hash", maybe_stats->hashSerialized.ToString());
    result.pushKV("nchaintx", tip->m_chain_tx_count);
    return result;
}

UniValue CreateUTXOSnapshot(
    node::NodeContext& node,
    Chainstate& chainstate,
    AutoFile& afile,
    const fs::path& path,
    const fs::path& tmppath)
{
    auto [cursor, stats, tip]{WITH_LOCK(::cs_main, return PrepareUTXOSnapshot(chainstate, node.rpc_interruption_point))};
    return WriteUTXOSnapshot(chainstate, cursor.get(), &stats, tip, afile, path, tmppath, node.rpc_interruption_point);
}

static RPCHelpMan loadtxoutset()
{
    return RPCHelpMan{
        "loadtxoutset",
        "Load the serialized UTXO set from a file.\n"
        "Once this snapshot is loaded, its contents will be "
        "deserialized into a second chainstate data structure, which is then used to sync to "
        "the network's tip. "
        "Meanwhile, the original chainstate will complete the initial block download process in "
        "the background, eventually validating up to the block that the snapshot is based upon.\n\n"

        "The result is a usable bitcoind instance that is current with the network tip in a "
        "matter of minutes rather than hours. UTXO snapshot are typically obtained from "
        "third-party sources (HTTP, torrent, etc.) which is reasonable since their "
        "contents are always checked by hash.\n\n"

        "You can find more information on this process in the `assumeutxo` design "
        "document (<https://github.com/bitcoin/bitcoin/blob/master/doc/design/assumeutxo.md>).",
        {
            {"path",
                RPCArg::Type::STR,
                RPCArg::Optional::NO,
                "path to the snapshot file. If relative, will be prefixed by datadir."},
        },
        RPCResult{
            RPCResult::Type::OBJ, "", "",
                {
                    {RPCResult::Type::NUM, "coins_loaded", "the number of coins loaded from the snapshot"},
                    {RPCResult::Type::STR_HEX, "tip_hash", "the hash of the base of the snapshot"},
                    {RPCResult::Type::NUM, "base_height", "the height of the base of the snapshot"},
                    {RPCResult::Type::STR, "path", "the absolute path that the snapshot was loaded from"},
                }
        },
        RPCExamples{
            HelpExampleCli("-rpcclienttimeout=0 loadtxoutset", "utxo.dat")
        },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    NodeContext& node = EnsureAnyNodeContext(request.context);
    ChainstateManager& chainman = EnsureChainman(node);
    const fs::path path{AbsPathForConfigVal(EnsureArgsman(node), fs::u8path(self.Arg<std::string>("path")))};

    FILE* file{fsbridge::fopen(path, "rb")};
    AutoFile afile{file};
    if (afile.IsNull()) {
        throw JSONRPCError(
            RPC_INVALID_PARAMETER,
            "Couldn't open file " + path.utf8string() + " for reading.");
    }

    SnapshotMetadata metadata{chainman.GetParams().MessageStart()};
    try {
        afile >> metadata;
    } catch (const std::ios_base::failure& e) {
        throw JSONRPCError(RPC_DESERIALIZATION_ERROR, strprintf("Unable to parse metadata: %s", e.what()));
    }

    auto activation_result{chainman.ActivateSnapshot(afile, metadata, false)};
    if (!activation_result) {
        throw JSONRPCError(RPC_INTERNAL_ERROR, strprintf("Unable to load UTXO snapshot: %s. (%s)", util::ErrorString(activation_result).original, path.utf8string()));
    }

    // Because we can't provide historical blocks during tip or background sync.
    // Update local services to reflect we are a limited peer until we are fully sync.
    node.connman->RemoveLocalServices(NODE_NETWORK);
    // Setting the limited state is usually redundant because the node can always
    // provide the last 288 blocks, but it doesn't hurt to set it.
    node.connman->AddLocalServices(NODE_NETWORK_LIMITED);

    CBlockIndex& snapshot_index{*CHECK_NONFATAL(*activation_result)};

    UniValue result(UniValue::VOBJ);
    result.pushKV("coins_loaded", metadata.m_coins_count);
    result.pushKV("tip_hash", snapshot_index.GetBlockHash().ToString());
    result.pushKV("base_height", snapshot_index.nHeight);
    result.pushKV("path", fs::PathToString(path));
    return result;
},
    };
}

const std::vector<RPCResult> RPCHelpForChainstate{
    {RPCResult::Type::NUM, "blocks", "number of blocks in this chainstate"},
    {RPCResult::Type::STR_HEX, "bestblockhash", "blockhash of the tip"},
    {RPCResult::Type::NUM, "difficulty", "difficulty of the tip"},
    {RPCResult::Type::NUM, "verificationprogress", "progress towards the network tip"},
    {RPCResult::Type::STR_HEX, "snapshot_blockhash", /*optional=*/true, "the base block of the snapshot this chainstate is based on, if any"},
    {RPCResult::Type::NUM, "coins_db_cache_bytes", "size of the coinsdb cache"},
    {RPCResult::Type::NUM, "coins_tip_cache_bytes", "size of the coinstip cache"},
    {RPCResult::Type::BOOL, "validated", "whether the chainstate is fully validated. True if all blocks in the chainstate were validated, false if the chain is based on a snapshot and the snapshot has not yet been validated."},
};

static RPCHelpMan getchainstates()
{
return RPCHelpMan{
        "getchainstates",
        "\nReturn information about chainstates.\n",
        {},
        RPCResult{
            RPCResult::Type::OBJ, "", "", {
                {RPCResult::Type::NUM, "headers", "the number of headers seen so far"},
                {RPCResult::Type::ARR, "chainstates", "list of the chainstates ordered by work, with the most-work (active) chainstate last", {{RPCResult::Type::OBJ, "", "", RPCHelpForChainstate},}},
            }
        },
        RPCExamples{
            HelpExampleCli("getchainstates", "")
    + HelpExampleRpc("getchainstates", "")
        },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    LOCK(cs_main);
    UniValue obj(UniValue::VOBJ);

    ChainstateManager& chainman = EnsureAnyChainman(request.context);

    auto make_chain_data = [&](const Chainstate& cs, bool validated) EXCLUSIVE_LOCKS_REQUIRED(::cs_main) {
        AssertLockHeld(::cs_main);
        UniValue data(UniValue::VOBJ);
        if (!cs.m_chain.Tip()) {
            return data;
        }
        const CChain& chain = cs.m_chain;
        const CBlockIndex* tip = chain.Tip();

        data.pushKV("blocks",                (int)chain.Height());
        data.pushKV("bestblockhash",         tip->GetBlockHash().GetHex());
        data.pushKV("difficulty", GetDifficulty(*tip));
        data.pushKV("verificationprogress",  GuessVerificationProgress(Params().TxData(), tip));
        data.pushKV("coins_db_cache_bytes",  cs.m_coinsdb_cache_size_bytes);
        data.pushKV("coins_tip_cache_bytes", cs.m_coinstip_cache_size_bytes);
        if (cs.m_from_snapshot_blockhash) {
            data.pushKV("snapshot_blockhash", cs.m_from_snapshot_blockhash->ToString());
        }
        data.pushKV("validated", validated);
        return data;
    };

    obj.pushKV("headers", chainman.m_best_header ? chainman.m_best_header->nHeight : -1);

    const auto& chainstates = chainman.GetAll();
    UniValue obj_chainstates{UniValue::VARR};
    for (Chainstate* cs : chainstates) {
      obj_chainstates.push_back(make_chain_data(*cs, !cs->m_from_snapshot_blockhash || chainstates.size() == 1));
    }
    obj.pushKV("chainstates", std::move(obj_chainstates));
    return obj;
}
    };
}


void RegisterBlockchainRPCCommands(CRPCTable& t)
{
    static const CRPCCommand commands[]{
        {"blockchain", &getblockchaininfo},
        {"blockchain", &getchaintxstats},
        {"blockchain", &getblockstats},
        {"blockchain", &getbestblockhash},
        {"blockchain", &getblockcount},
        {"blockchain", &getblock},
        {"blockchain", &getblockfrompeer},
        {"blockchain", &getblockhash},
        {"blockchain", &getblockheader},
        {"blockchain", &getchaintips},
        {"blockchain", &getdifficulty},
        {"blockchain", &getdeploymentinfo},
        {"blockchain", &gettxout},
        {"blockchain", &gettxoutsetinfo},
        {"blockchain", &pruneblockchain},
        {"blockchain", &verifychain},
        {"blockchain", &preciousblock},
        {"blockchain", &scantxoutset},
        {"blockchain", &scanblocks},
        {"blockchain", &getblockfilter},
        {"blockchain", &testmvp},
        {"blockchain", &dumptxoutset},
        {"blockchain", &loadtxoutset},
        {"blockchain", &getchainstates},
        {"hidden", &invalidateblock},
        {"hidden", &reconsiderblock},
        {"hidden", &waitfornewblock},
        {"hidden", &waitforblock},
        {"hidden", &waitforblockheight},
        {"hidden", &syncwithvalidationinterfacequeue},
    };
    for (const auto& c : commands) {
        t.appendCommand(c.name, &c);
    }
}
