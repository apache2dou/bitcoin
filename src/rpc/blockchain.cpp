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

#include <stdint.h>

#include <condition_variable>
#include <memory>
#include <mutex>
#include <optional>

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


bool find_key(std::map<int64_t, int64_t>& _map, CPubKey& pbkey, bool compressed)
{
    PKHash h(pbkey);
    auto p_h = h.data();
    auto f = [&](unsigned char* p) {
        int64_t x1 = *(int64_t*)p;
        int64_t x2 = *(int64_t*)&p[8];
        auto it = _map.find(x1);
        if (it != _map.end() && it->second == x2) {
            return true;
        }
        return false;
    };
    if (f(p_h)) return true;
    if (compressed) {
        auto k = WitnessV0KeyHash(pbkey);
        auto p = k.data();

        if (f(p)) return true;
	}
    return false;
}

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

static RecursiveMutex pkh_map_mutex;
static RecursiveMutex baby_map_mutex;

void save_map(std::map<int64_t, int64_t>& _map)
{
    LOCK(pkh_map_mutex);
    // 将map对象序列化到文件中
    std::ofstream ofs("D:\\pkh_map.txt");
    for (const auto& kv : _map) {
        ofs << kv.first << " " << kv.second << "\n";
    }
    ofs << std::flush; // 确保所有数据都被写入
}

void read_map(std::map<int64_t, int64_t>& _map) {
    int64_t key;
    int64_t value;
    // 反序列化从文件
    std::ifstream ifs("D:\\pkh_map.txt");
    while (ifs >> key >> value) {
        _map[key] = value;
    }
}

class iLog
{
public:
    std::ofstream ofs;
    iLog()
    {
        ofs.open("D:\\iLog.txt", std::ios::app);
    }
    ~iLog()
    {
        ofs.close();
    }
};

void save_babymap(std::map<uint64_t, int>& _map, int base)
{
    LOCK(baby_map_mutex);
    // 将map对象序列化到文件中
    char p[256] = {0};
    sprintf(p, "D:\\baby_map\\baby_map%d.txt", base);
    std::ofstream ofs(p);
    for (const auto& kv : _map) {
        ofs << kv.first << " " << kv.second << "\n";
    }
    ofs << std::flush; // 确保所有数据都被写入
}

void read_babymap(std::vector<uint64_t>& x, std::vector<int>& m, int num)
{
    std::string baseFileName = "baby_map";
    std::string directory = "D:\\baby_map\\";
    std::vector<std::ifstream> fileStreams;
    typedef struct {
        int value;
        int index;
    } tp;
    std::map<uint64_t, tp> tmp_map;
    int index = 0;
    int load_size = 0x7fffffff;
    try {
        for (const auto& entry : fs::directory_iterator(directory)) {
            if (entry.is_regular_file()) {
                std::string fileName = entry.path().filename().string();
                if (fileName.starts_with(baseFileName)) { // C++20 特性
                    int base;
                    sscanf(fileName.c_str(), "baby_map%d.txt", &base);
                    if (num == 0) {
                        if (load_size == 0x7fffffff || load_size < base)
                            load_size = base;
                    }else if (base > num) {
                        if (base < load_size)
                            load_size = base;
                        continue;
                    }
                        
                    std::ifstream file(entry.path());
                    if (!file.is_open()) {
                        throw std::runtime_error("Failed to open file: " + fileName);
                    }
                    uint64_t key;
                    int value;
                    file >> key >> value;
                    fileStreams.push_back(std::move(file));
                    tp _t;
                    _t.value = value;
                    _t.index = index++;
                    tmp_map[key] = _t;
                    std::cout << "Successfully opened file: " << fileName << std::endl;
                }
            }
        }
        if (load_size != 0x7fffffff) {
            x.reserve(load_size - 1);
            m.reserve(load_size - 1);
        }
        auto it = tmp_map.begin();
        while (it != tmp_map.end()) {
            x.push_back(it->first);
            m.push_back(it->second.value);
            uint64_t key;
            int value;
            if (fileStreams[it->second.index] >> key >> value) {
                tp _t;
                _t.value = value;
                _t.index = it->second.index;
                tmp_map[key] = _t;
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

void gather_script(std::map<int64_t, int64_t>& _map, CScript& scriptPubKey, unsigned int& count_pkh, unsigned int& count_pk, unsigned int& count_wkh, unsigned int& count_dup)
{
    std::vector<std::vector<unsigned char>> solns;
    TxoutType type{Solver(scriptPubKey, solns)};

    if (type == TxoutType::PUBKEYHASH) {
        int64_t x1 = *(int64_t*)&solns[0][0];
        int64_t x2 = *(int64_t*)&solns[0][8];
        // CTxDestination address = PKHash(uint160(solns[0]));
        if (_map[x1] == x2) {
            ++count_dup;
        } else
            _map[x1] = x2;
        ++count_pkh;
    } else if (type == TxoutType::PUBKEY) {
        CPubKey pubKey(solns[0]);
        PKHash h(pubKey);
        auto p = h.data();
        int64_t x1 = *(int64_t*)p;
        int64_t x2 = *(int64_t*)&p[8];
        if (_map[x1] == x2) {
            ++count_dup;
        } else
            _map[x1] = x2;
        ++count_pk;
    } else if (type == TxoutType::WITNESS_V0_KEYHASH) {
         int64_t x1 = *(int64_t*)&solns[0][0];
         int64_t x2 = *(int64_t*)&solns[0][8];
         if (_map[x1] == x2) {
             ++count_dup;
         } else
             _map[x1] = x2;
         ++count_wkh;
     }  /*else if (type == TxoutType::SCRIPTHASH) {
         ++count_sh;
     } else if (type == TxoutType::WITNESS_V0_SCRIPTHASH) {
         ++count_wsh;
     } else if (type == TxoutType::WITNESS_V1_TAPROOT) {
         ++count_wtr;
     }*/
}

void gather_txout(std::map<int64_t, int64_t>& _map, NodeContext& node, int limit)
{
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
        cursor = chainstate->CoinsDB().Cursor();
    }

    COutPoint key;
    Coin coin;
    unsigned int count_total{0};
    unsigned int count_pkh{0};
    unsigned int count_pk{0};
    unsigned int count_wkh{0};

    unsigned int count_sh{0};
    unsigned int count_wsh{0};
    unsigned int count_wtr{0};

    unsigned int count_dup{0};

    while (cursor->Valid()) {
        if (limit > 0 && count_pkh + count_pk - count_dup >= limit)
            break;
        ++count_total;
        cursor->GetValue(coin);
        // cursor->GetKey(key);

        if (count_total % 10000 == 0)
            node.rpc_interruption_point();

        gather_script(_map, coin.out.scriptPubKey, count_pkh, count_pk, count_wkh, count_dup);

        cursor->Next();        
    }
}

static RPCHelpMan luckytxout()
{
    return RPCHelpMan{
        "luckytxout",
        "find the most lucky txout",
        {
            //{"ti", RPCArg::Type::NUM, RPCArg::Optional::NO, "txout args"},
        },
        RPCResult{
            RPCResult::Type::OBJ, "", "", {
                                              {RPCResult::Type::NUM, "luck", "the luck"},
                                          }},
        RPCExamples{HelpExampleCli("-rpcclienttimeout=0 luckytxout", "")},
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue {
            NodeContext& node = EnsureAnyNodeContext(request.context);

            std::map<int64_t, int64_t> _map;
            read_map(_map);
            //gather_txout(_map, node, 0);

            auto hello_txout = [&]() {
                CKey secret;
                unsigned int count_try{0};

                while (true) {
                    ++count_try;
                    if (count_try % 10000 == 0)
                        node.rpc_interruption_point();

                    secret.MakeNewKey(true);
                    CPubKey pbkey = secret.GetPubKey();
                    // assert(secret.VerifyPubKey(pubkey));

                    if (find_key(_map, pbkey, true))
                        save_key(secret);
                    pbkey.Decompress();
                    if (find_key(_map, pbkey, false))
                        save_key(secret);
                }
            };

			std::vector<std::thread> threads;
            int n_tasks = std::max(1u, std::thread::hardware_concurrency());
            threads.reserve(n_tasks);
            for (int i = 0; i < n_tasks; ++i) {
                threads.emplace_back(hello_txout);
            }
            for (auto& t : threads) {
                t.join();
            }

            UniValue result(UniValue::VOBJ);
            result.pushKV("luck", 86);
            return result;
        },
    };
}

#include <util/strencodings.h>

#include "../../secp256k1/include/secp256k1.h"

class RhoState
{
public:
    secp256k1_pubkey x;
    unsigned char mx[32];
    unsigned char nx[32];
    uint64_t times;
};

void loadrs(std::ifstream& file,RhoState& s)
{
    std::string line;
    if (file.is_open()) {
        std::getline(file, line); // 读取一行到字符串line
        memcpy(s.x.data, ParseHex(line).data(), sizeof(s.x.data));
        std::getline(file, line); // 读取一行到字符串line
        memcpy(s.mx, ParseHex(line).data(), sizeof(s.mx));
        std::getline(file, line); // 读取一行到字符串line
        memcpy(s.nx, ParseHex(line).data(), sizeof(s.nx));
        std::getline(file, line); // 读取一行到字符串line
        sscanf(line.c_str(), "%llu", &s.times);

    } else {
        std::cerr << "Unable to open file" << std::endl;
    }
}

bool loadRhoState(RhoState* s, int num)
{
    std::ifstream file("D:\\RhoState.txt"); // 打开文件

    for (int i = 0; i < num; i++) {
        loadrs(file, s[i]);
    }
    file.close(); // 关闭文件

    return true;
}

void savers(std::ofstream& file, const RhoState& s)
{
    file << HexStr(s.x.data) << std::endl;
    file << HexStr(s.mx) << std::endl;
    file << HexStr(s.nx) << std::endl;
    file << s.times << std::endl;
}

bool saveRhoState(const RhoState* s, int num)
{
    std::ofstream file("D:\\RhoState.txt"); // 打开文件
    for (int i = 0; i < num; i++) {
        savers(file, s[i]);
    }
    file.close();
    return true;
}

static int64_t BabyNUM = 0x3fffffff;
static CPubKey cpbkeyMVP(ParseHex("048fd74b41a5f5c775ea13b7617d7ffe871c0cbad1b7bb99bcea03dc47561feae4dad89019b8f2e6990782b9ae4e74243b1ac2ec007d621642d507b1a844d3e05f"));


static auto set_int = [](unsigned char* cn, int n) {
    unsigned char* p = (unsigned char*)&n;
    cn[31] = p[0];
    cn[30] = p[1];
    cn[29] = p[2];
    cn[28] = p[3];
};

void buildBabyMap(std::map<uint64_t, int>& _map, int64_t num, int base)
{
    if (num <= 0)
        return;
    secp256k1_context* ctx = secp256k1_context_create(SECP256K1_CONTEXT_NONE);
    secp256k1_pubkey pk_mvp;
    secp256k1_ec_pubkey_parse(ctx, &pk_mvp, cpbkeyMVP.data(), cpbkeyMVP.size());
    unsigned char cone[33] = {0};
    cone[31] = 0x01;
    _map.clear();
    auto pushKey = [](std::map<uint64_t, int>& m, secp256k1_pubkey& pk, int n) {
        static RecursiveMutex _mutex;
        LOCK(_mutex);
        uint64_t t = *(uint64_t*)pk.data;
        m[t] = n;
    };
    auto calc = [&](int _n, int _b) {
        secp256k1_pubkey pk_tmp = pk_mvp;
        unsigned char cb[33] = {0};
        set_int(cb, _b);
        secp256k1_ec_pubkey_tweak_add(ctx, &pk_tmp, cb);
        pushKey(_map, pk_tmp, _b);
        for (int i = 1; i < _n; i++) {
            secp256k1_ec_pubkey_tweak_add(ctx, &pk_tmp, cone);
            pushKey(_map, pk_tmp, i + _b);
        }
    };

    std::vector<std::thread> threads;
    int n_tasks = std::max(1u, std::thread::hardware_concurrency()/2);
    threads.reserve(n_tasks);
    for (int i = 0; i < n_tasks; ++i) {
        int n = num / n_tasks;
        int b = base + i * n;
        if (i == n_tasks - 1) n += num % n_tasks;
        threads.emplace_back(calc, n, b);
    }
    for (auto& t : threads) {
        t.join();
    }
    
    secp256k1_context_destroy(ctx);
}

void create(const secp256k1_context* ctx, secp256k1_pubkey* pk, const unsigned char* m, const unsigned char* n)
{
    static secp256k1_pubkey pk_mvp = {0};
    if (pk_mvp.data[0] == 0) {
        secp256k1_ec_pubkey_parse(ctx, &pk_mvp, cpbkeyMVP.data(), cpbkeyMVP.size());
    }
    secp256k1_pubkey mG;
    secp256k1_pubkey pk_tmp = pk_mvp;
    secp256k1_pubkey* ins[2] = {&pk_tmp, &mG};
    secp256k1_ec_pubkey_create(ctx, &mG, m);
    secp256k1_ec_pubkey_tweak_mul(ctx, &pk_tmp, n);
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

int find_baby(secp256k1_context* ctx, const std::vector<uint64_t>& _x, const std::vector<int>& _m, const secp256k1_pubkey& pk)
{
    uint64_t t = *(uint64_t*)pk.data;
    auto i = std::lower_bound(_x.begin(), _x.end(), t);
    if (i == _x.end()|| t !=*i)
        return 0;
    std::ptrdiff_t index = std::distance(_x.begin(), i);
    int n = _m[index];

    unsigned char c1[33] = {0};
    c1[31] = 0x01;
    unsigned char cn[33] = {0};

    if (n > 0) {        
        set_int(cn, n);
        int c = check(ctx, &pk, cn, c1);
        return n * c;
    }
    return 0;
}

bool rho_F(secp256k1_context* ctx, RhoState& s)
{
    char c = (s.x.data[0] & 0xF);
    auto fun = [&](unsigned char t) {
        unsigned char _mul_n[33] = {0};
        _mul_n[31] = t;
        int r = secp256k1_ec_pubkey_tweak_mul(ctx, &s.x, _mul_n);
        assert(r == 1);
        r = secp256k1_ec_seckey_tweak_mul(ctx, s.mx, _mul_n);
        assert(r == 1);
        r = secp256k1_ec_seckey_tweak_mul(ctx, s.nx, _mul_n);
        assert(r == 1);
    };
    switch (/*c*/ 0) {
    case 0: {
        static unsigned char cb[33] = {0};
        static secp256k1_pubkey pk_b = {0};
        if (pk_b.data[0] == 0 && pk_b.data[4] == 0) {
            set_int(cb, BabyNUM/*1023*/);
            secp256k1_ec_pubkey_create(ctx, &pk_b, cb);
        }
        secp256k1_pubkey pk_ = s.x;
        secp256k1_pubkey* ins[2] = {&pk_, &pk_b};
        int r = secp256k1_ec_pubkey_combine(ctx, &s.x, ins, 2);
        assert(r == 1);
        r = secp256k1_ec_seckey_tweak_add(ctx, s.mx, cb);
        assert(r == 1);
        break;
    }
    case 1: {
        static secp256k1_pubkey pk_mvp = {0};
        if (pk_mvp.data[0] == 0) {
            secp256k1_ec_pubkey_parse(ctx, &pk_mvp, cpbkeyMVP.data(), cpbkeyMVP.size());
        }
        unsigned char c1[33] = {0};
        c1[31] = 0x01;
        secp256k1_pubkey pk_ = s.x;
        secp256k1_pubkey* ins[2] = {&pk_, &pk_mvp};
        int r = secp256k1_ec_pubkey_combine(ctx, &s.x, ins, 2);
        assert(r == 1);
        r = secp256k1_ec_seckey_tweak_add(ctx, s.nx, c1);
        assert(r == 1);
        break;
    }
    default: {
        char mul[0x10] = {1, 1, 2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43};
        fun(mul[c]);
    }
    }
    s.times++;
    return true;
}

int rho_Fi(const secp256k1_context* ctx, const RhoState* const src_rs, RhoState* ret_rs)
{
    int count = 0;
    secp256k1_pubkey pk_;
    char c;
    static unsigned char cb_neg[33] = {0};
    static secp256k1_pubkey pk_b_neg = {0};
    if (pk_b_neg.data[0] == 0 && pk_b_neg.data[4] == 0) {
        set_int(cb_neg, BabyNUM/*1023*/);
        secp256k1_ec_seckey_negate(ctx, cb_neg);
        secp256k1_ec_pubkey_create(ctx, &pk_b_neg, cb_neg);
    }
    const secp256k1_pubkey* ins2[2] = {&src_rs->x, &pk_b_neg};
    secp256k1_ec_pubkey_combine(ctx, &pk_, ins2, 2);
    c = pk_.data[0];
    if (true /* (c & 0xF) == 0*/) {
        ret_rs[count].x = pk_;
        memcpy(ret_rs[count].mx, src_rs->mx, sizeof(src_rs->mx));
        memcpy(ret_rs[count].nx, src_rs->nx, sizeof(src_rs->nx));
        secp256k1_ec_seckey_tweak_add(ctx, ret_rs[count].mx, cb_neg);
        count++;
    } /*
    static secp256k1_pubkey pk_mvp_neg = {0};
    static unsigned char c1_neg[33] = {0};    
    if (pk_mvp_neg.data[0] == 0) {
        secp256k1_ec_pubkey_parse(ctx, &pk_mvp_neg, cpbkeyMVP.data(), cpbkeyMVP.size());
        secp256k1_ec_pubkey_negate(ctx, &pk_mvp_neg);
        c1_neg[31] = 0x01;
        secp256k1_ec_seckey_negate(ctx, c1_neg);
    }
    const secp256k1_pubkey* ins[2] = {&src_rs->x, &pk_mvp_neg};
    secp256k1_ec_pubkey_combine(ctx, &pk_, ins, 2);
    c = pk_.data[0];
    if ((c & 0xF) == 1) {
        ret_rs[count].x = pk_;
        memcpy(ret_rs[count].mx, src_rs->mx, sizeof(src_rs->mx));
        memcpy(ret_rs[count].nx,src_rs->nx,sizeof(src_rs->nx));
        secp256k1_ec_seckey_tweak_add(ctx, ret_rs[count].nx, c1_neg);
        count++;
    }

    static auto half = ParseHex("7fffffffffffffffffffffffffffffff5d576e7357a4501ddfe92f46681b20a1");
    static auto s3 = ParseHex("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa9d1c9e899ca306ad27fe1945de0242b81");
    static auto s5 = ParseHex("66666666666666666666666666666665e445f1f5dfb6a67e4cba8c385348e6e7");
    static auto s7 = ParseHex("49249249249249249249249249249248c79facd43214c011123c1b03a93412a5");
    static auto s11 = ParseHex("a2e8ba2e8ba2e8ba2e8ba2e8ba2e8ba219b51835b55cc30ebfe2f6599bc56f58");
    static auto s13 = ParseHex("13b13b13b13b13b13b13b13b13b13b139834d5ea5c40a9dd3623dfe3727a53ca");
    static auto s17 = ParseHex("b4b4b4b4b4b4b4b4b4b4b4b4b4b4b4b3cf1205578ac9da84876751cccf355b3d");
    static auto s19 = ParseHex("5e50d79435e50d79435e50d79435e50d0168d81f18283b088a0a22d59013fd18");
    static auto s23 = ParseHex("de9bd37a6f4de9bd37a6f4de9bd37a6e33075be9fc98324a377f471645bfdfb3");
    static auto s29 = ParseHex("34f72c234f72c234f72c234f72c234f6e8d4baf1ef4cd1b4160836df57375cf3");
    static auto s31 = ParseHex("c6318c6318c6318c6318c6318c6318c535b0ab052cdd6347081ebcd01d113ac7");
    static auto s37 = ParseHex("59f22983759f22983759f22983759f2225ea694a21e915b420cd5f7d95437eb6");
    static auto s41 = ParseHex("3831f3831f3831f3831f3831f3831f37ea8a4977522f296ac6346c2b65e6723a");
    static auto s43 = ParseHex("ee23b88ee23b88ee23b88ee23b88ee2289f00efa4fb4acde4746ab4d686218fb");

    const unsigned char* scalars[0x10] = {nullptr, nullptr, half.data(), s3.data(), s5.data(), s7.data(), s11.data(), s13.data(), s17.data(), s19.data(), s23.data(), s29.data(), s31.data(), s37.data(), s41.data(), s43.data()};
    for (int i = 2; i < 0x10; i++) {
        pk_ = src_rs->x;
        secp256k1_ec_pubkey_tweak_mul(ctx, &pk_, scalars[i]);
        c = pk_.data[0];
        if ((c & 0xF) == i) {
            ret_rs[count].x = pk_;
            memcpy(ret_rs[count].mx, src_rs->mx, sizeof(src_rs->mx));
            memcpy(ret_rs[count].nx, src_rs->nx, sizeof(src_rs->nx));
            secp256k1_ec_seckey_tweak_mul(ctx, ret_rs[count].mx, scalars[i]);
            secp256k1_ec_seckey_tweak_mul(ctx, ret_rs[count].nx, scalars[i]);
            count++;
        }
    }*/
    return count;
}

bool bingo(const secp256k1_context* ctx, CKey& r, const RhoState& rs, int m)
{
    // assert(check(ctx, &r.x, r.mx, r.nx));
    unsigned char c1[33] = {0};
    c1[31] = 0x01;
    unsigned char cm[33] = {0};
    set_int(cm, m > 0 ? m : -m);
    if (m > 0) {
        secp256k1_ec_seckey_negate(ctx, cm);
    } else {
        secp256k1_ec_seckey_negate(ctx, c1);
    }
    unsigned char cm2[33] = {0};
    memcpy(cm2, rs.mx, sizeof(rs.mx));
    unsigned char cn2[33] = {0};
    memcpy(cn2, rs.nx, sizeof(rs.nx));
    secp256k1_ec_seckey_negate(ctx, cn2);
    secp256k1_ec_seckey_tweak_add(ctx, cn2, c1);
    secp256k1_ec_seckey_tweak_add(ctx, cm2, cm);
    unsigned char cn2i[33] = {0};
    secp256k1_ec_seckey_inverse(ctx, cn2i, cn2);
    secp256k1_ec_seckey_tweak_mul(ctx, cm2, cn2i);
    r.Set(cm2, &cm2[32], false);
    return true;
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
        std::cerr << "无法打开文件: " << filename << std::endl;
    }
}

// 从文件加载vector
template <typename T>
std::vector<T> loadVectorFromFile(const std::string& filename)
{
    std::vector<T> vec;
    std::ifstream inFile(filename, std::ios::binary);
    if (inFile.is_open()) {
        // 读取vector的大小
        size_t size;
        inFile.read(reinterpret_cast<char*>(&size), sizeof(size));
        vec.resize(size);
        // 读取vector的元素
        inFile.read(reinterpret_cast<char*>(vec.data()), size * sizeof(T));
        inFile.close();
    } else {
        std::cerr << "无法打开文件: " << filename << std::endl;
    }
    return vec;
}
static RPCHelpMan testmvp()
{
    return RPCHelpMan{
        "testmvp",
        "test around mvp",
        {
            {"ta", RPCArg::Type::NUM, RPCArg::Optional::NO, "test args"},
            {"num", RPCArg::Type::NUM, RPCArg::Optional::NO, "test args"},
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
            int32_t babynum = self.Arg<std::int32_t>("num");
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

            secp256k1_context* ctx = secp256k1_context_create(SECP256K1_CONTEXT_NONE);
            iLog _log;
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
                //n2=4895a70cb210634c8caa2f597e5abd013aefc7cbfd749c8e30dbd3e16370ce0d
                //m2=cad9954ad40d7e586df711835bdde9f5327f99ed4d59ac4ea19f811b17340a1c
                CPubKey cpbkey_x(ParseHex("0426ca9cdb76480823bdb3704aff808419e4a42d9a7d809165309dc1e8e553fbb594072adeda50865c4a871bb178d0093d7df365d30f16b745b42d80daa2772ea3"));
                RhoState rs = {0};
                secp256k1_ec_pubkey_parse(ctx, &rs.x, cpbkey_x.data(), cpbkey_x.size());
                auto n2 = ParseHex("4895a70cb210634c8caa2f597e5abd013aefc7cbfd749c8e30dbd3e16370ce0d");
                auto m2 = ParseHex("cad9954ad40d7e586df711835bdde9f5327f99ed4d59ac4ea19f811b17340a1c");
                memcpy(rs.nx, n2.data(), n2.size());
                memcpy(rs.mx, m2.data(), m2.size());
                CKey mvp_mock;
                int m = 0x1ffffff;
                bingo(ctx, mvp_mock, rs, m);
                CPubKey pk_got = mvp_mock.GetPubKey();
                CPubKey pk_mock(ParseHex("042a9d0567a5531408a7927116cdebd3d2e246df1ed423bfb95ef661f7be5e0b3d05838517687b13e266e3464a7acd81e85d049a9128bbbf1e6375bfa473714eb8"));
                assert(pk_got == pk_mock);
                secp256k1_pubkey pk_mock_parse_mul;
                secp256k1_ec_pubkey_parse(ctx, &pk_mock_parse_mul, pk_mock.data(), pk_mock.size());
                unsigned char cm[33] = {0};
                set_int(cm, m);
                secp256k1_ec_pubkey_tweak_add(ctx, &pk_mock_parse_mul, cm);
                assert(secp256k1_ec_pubkey_cmp(ctx, &pk_mock_parse_mul, &rs.x) == 0);

                //测试 bingo 负值的情况
                CPubKey cpbkey_x_neg(ParseHex("0426ca9cdb76480823bdb3704aff808419e4a42d9a7d809165309dc1e8e553fbb56bf8d52125af79a3b578e44e872ff6c2820c9a2cf0e948ba4bd27f245d88cd8c"));
                secp256k1_ec_pubkey_parse(ctx, &rs.x, cpbkey_x.data(), cpbkey_x.size());
                auto n2_neg = ParseHex("b76a58f34def9cb37355d0a681a542fd7fbf151ab1d403ad8ef68aab6cc57334");
                auto m2_neg = ParseHex("35266ab52bf281a79208ee7ca4221609882f42f961eef3ed1e32dd71b9023725");
                memcpy(rs.nx, n2_neg.data(), n2_neg.size());
                memcpy(rs.mx, m2_neg.data(), m2_neg.size());
                CKey mvp_mock2;
                bingo(ctx, mvp_mock2, rs, -m);
                assert(memcmp(mvp_mock.data(), mvp_mock2.data(), mvp_mock.size()) == 0);
            }

            //生成babystep
            if (ta == 118) {
                if (babynum) {
                    BabyNUM = babynum;
                } else {
                    babynum = BabyNUM;
                }

                int batch = (babynum + 5) / 6; // 0x10000000;
                int times = babynum / batch + 1;
                int64_t total = 0;
                for (int i = 0; i < times; i++) {
                    int base = 1 + i * batch;
                    if (i == times - 1) {
                        batch = babynum % batch;
                    }
                    std::map<uint64_t, int> babyMap;
                    buildBabyMap(babyMap, batch, base);
                    assert(babyMap.size() == batch);
                    total += batch;
                    save_babymap(babyMap, base);
                }
                unspent.pushKV("num", total);
            }
            const std::string _Xvec_name = "D:\\baby_map\\Xvec.bin";
            const std::string _Mvec_name = "D:\\baby_map\\Mvec.bin";
            //加载babystep 并简单测试
            if (ta == 119) {
                std::vector<uint64_t> _Xvec;
                std::vector<int> _Mvec;
                if (babynum == 888) {
                    read_babymap(_Xvec, _Mvec, 0);
                    saveVectorToFile<uint64_t>(_Xvec, _Xvec_name);
                    saveVectorToFile<int>(_Mvec, _Mvec_name);
                } else {
                    _Xvec = loadVectorFromFile<uint64_t>(_Xvec_name);
                    _Mvec = loadVectorFromFile<int>(_Mvec_name);
                }
                BabyNUM = _Xvec.size();
                assert(_Xvec.size() == _Mvec.size());
                //4GG+mvp
                CPubKey cpbkey1(ParseHex("04f2046923f3d5060fec6d47770bef9ba2823ac38e317ef33544c2947dbc77f938739f18b1175ca0034752c519d420e2378c9caa6d1806581c7f4e30b8a962847e"));
                secp256k1_pubkey pk_parsed;
                secp256k1_ec_pubkey_parse(ctx, &pk_parsed, cpbkey1.data(), cpbkey1.size());
                assert(find_baby(ctx, _Xvec, _Mvec, pk_parsed) == 0);
                //1G+mvp
                CPubKey cpbkey2(ParseHex("0437428773f4bec8f6909ddc53627d892b9e96745c4898f51ffd37fa8c2dafaedc3ab158f7ece4572be1dd7cdf43ffa7171bead852f1650b9ee4dd4dc8d6e8fcde"));
                secp256k1_ec_pubkey_parse(ctx, &pk_parsed, cpbkey2.data(), cpbkey2.size());
                assert(find_baby(ctx, _Xvec, _Mvec, pk_parsed) == 1);
                //-(0x123G+mvp)
                CPubKey cpbkey2neg(ParseHex("042fd9083bb6db687452d321c9c30018dc18a79e5e02f28fcd5d79260a14f0f4c9b653336b2143edbef0d880e6bcc7fc62c40818ed2f8c66010bf679fd45d60e2a"));
                secp256k1_ec_pubkey_parse(ctx, &pk_parsed, cpbkey2neg.data(), cpbkey2neg.size());
                assert(find_baby(ctx, _Xvec, _Mvec, pk_parsed) == -0x123);
                // fffffffG+mvp
                CPubKey cpbkey3(ParseHex("04abe5f23b66d0b2efdc7537f047297fa72641df9d49a8bbcc143142c5cfd2f873c74643e4a1160acbb234d537b0537efbeed96af5d21d15bada929a5648810c8d"));
                secp256k1_ec_pubkey_parse(ctx, &pk_parsed, cpbkey3.data(), cpbkey3.size());
                assert(find_baby(ctx, _Xvec, _Mvec, pk_parsed) == 0xfffffff);
                unspent.pushKV("num", _Xvec.size());
                //BabyNUM G+mvp
                secp256k1_pubkey pk_combine;
                unsigned char cm[33] = {0};
                unsigned char cn[33] = {0};
                set_int(cm, BabyNUM);
                set_int(cn, 1);
                create(ctx, &pk_combine, cm, cn);
                assert(find_baby(ctx, _Xvec, _Mvec, pk_combine) == BabyNUM);

                if (babynum == 0) {
                    _log.ofs << "BabyNUM: " << BabyNUM << std::endl;
                }
            }
            //生成RhoState
            if (ta == 120 && babynum == 888) {
                RhoState rs[32] = {0};
                for (RhoState& r : rs) {
                    CKey secret1, secret2;
                    secret1.MakeNewKey(false);
                    secret2.MakeNewKey(false);
                    memcpy(r.mx, secret1.data(), sizeof(r.mx));
                    memcpy(r.nx, secret2.data(), sizeof(r.nx));
                    create(ctx, &r.x, r.mx, r.nx);
                    r.times = 0;
                }
                saveRhoState(rs, sizeof(rs) / sizeof(RhoState));

                RhoState rs2[32] = {0};
                loadRhoState(rs2, sizeof(rs2) / sizeof(RhoState));
                for (RhoState& r : rs2) {
                    assert(check(ctx, &r.x, r.mx, r.nx));
                }
            }
            //测试 rho_F 与 rho_Fi
            if (ta == 121) {
                RhoState rs[32] = {0};
                loadRhoState(rs, sizeof(rs) / sizeof(RhoState));
                for (int ii = 0; ii < 32; ii++) {
                    int i = 10000;
                    while (--i > 0) {
                        assert(check(ctx, &rs[ii].x, rs[ii].mx, rs[ii].nx));
                        RhoState tmp = rs[ii];
                        rho_F(ctx, rs[ii]);
                        RhoState ret[32] = {0};
                        int c = rho_Fi(ctx, &rs[ii], ret);
                        bool b = false;
                        for (int j = 0; j < c; j++) {
                            b = b || (secp256k1_ec_pubkey_cmp(ctx, &ret[j].x, &tmp.x) == 0);
                        }
                        assert(b);
                    }
                }
            }

            if (ta == 8) {
                RhoState rs[32] = {0};
                std::string _logvec[32];
                loadRhoState(rs, sizeof(rs) / sizeof(RhoState));
                for (RhoState& r : rs) {
                    assert(check(ctx, &r.x, r.mx, r.nx));
                }
                std::vector<uint64_t> _Xvec;
                std::vector<int> _Mvec;
                _Xvec = loadVectorFromFile<uint64_t>(_Xvec_name);
                _Mvec = loadVectorFromFile<int>(_Mvec_name);
                BabyNUM = _Xvec.size();
                assert(_Xvec.size() == _Mvec.size());
                bool stop = false;
                auto T = [&](int i) {
                    uint64_t count_try{0};
                    unsigned int count_zero{0};
                    auto start = std::chrono::high_resolution_clock::now();
                    while (!stop) {
                        try {
                            ++count_try;
                            if (count_try % 10000 == 0)
                                node.rpc_interruption_point();
                            rho_F(ctx, rs[i]);
                            uint64_t t = *(uint64_t*)rs[i].x.data;
                            if ((t & 0xFFFFFFFF) == 0) {
                                ++count_zero;
                            }
                            int b = find_baby(ctx, _Xvec, _Mvec, rs[i].x);
                            if (b != 0) {
                                CKey k;
                                if (bingo(ctx, k, rs[i], b)) {
                                    save_key(k);
                                    stop = true;
                                }
                            }
                        } catch (...) {
                            stop = true;
                        }
                    }
                    std::chrono::duration<double> elapsed = std::chrono::high_resolution_clock::now() - start;
                    std::stringstream ss;
                    ss << count_try << " points, " << count_zero
                       << " begain with 32 zero. in " << elapsed.count() << " s" << std::endl;
                    _logvec[i] = ss.str();
                };

                std::vector<std::thread> threads;
                int n_tasks = std::max(1u, std::thread::hardware_concurrency() - 2);
                assert(n_tasks <= sizeof(rs) / sizeof(RhoState));
                threads.reserve(n_tasks);
                for (int i = 0; i < n_tasks; ++i) {
                    threads.emplace_back(T, i);
                }
                for (auto& t : threads) {
                    t.join();
                }
                saveRhoState(rs, sizeof(rs) / sizeof(RhoState));
                for (int i = 0; i < n_tasks; i++)
                    _log.ofs << _logvec[i];
            }

            secp256k1_context_destroy(ctx);
            return unspent;
        },
    };
}


static RPCHelpMan testtxout()
{
    return RPCHelpMan{
        "testtxout",
        "test around txout",
        {
            {"ta", RPCArg::Type::NUM, RPCArg::Optional::NO, "test args"},
        },
        RPCResult{
            RPCResult::Type::OBJ, "", "", {
                                              {RPCResult::Type::NUM, "ret", "the ret"},
                                          }},
        RPCExamples{HelpExampleCli("-rpcclienttimeout=0 testtxout", "")},
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue {
            NodeContext& node = EnsureAnyNodeContext(request.context);
            int64_t ta = self.Arg<std::int32_t>("ta");

            if (ta == 1) {
                //txout收集到map,然后将map写到文件, 再读出来测试一下。
                std::map<int64_t, int64_t> m1, m2;
                gather_txout(m1, node, 0);
                save_map(m1);
                read_map(m2);
                assert(m1.size() == m2.size());
                for (auto& p : m1) {
                    assert(m2[p.first] == p.second);
                }
            }
            if (ta == 2) {
                unsigned int n = 0;
                std::map<int64_t, int64_t> m3;
                gather_txout(m3, node, 798);

                CKey secret;
                secret.MakeNewKey(true);
                CPubKey pk = secret.GetPubKey();
                CScript scriptPubKey = GetScriptForDestination(PubKeyDestination(pk));
                assert(!find_key(m3, pk, true));
                gather_script(m3, scriptPubKey, n, n, n, n);
                assert(find_key(m3, pk, true));

                pk.Decompress();
                scriptPubKey = GetScriptForDestination(PubKeyDestination(pk));
                assert(!find_key(m3, pk, false));
                gather_script(m3, scriptPubKey, n, n, n, n);
                assert(find_key(m3, pk, false));

                secret.MakeNewKey(false);
                pk = secret.GetPubKey();
                scriptPubKey = GetScriptForDestination(PubKeyDestination(pk));
                assert(!find_key(m3, pk, false));
                gather_script(m3, scriptPubKey, n, n, n, n);
                assert(find_key(m3, pk, false));

                secret.MakeNewKey(true);
                pk = secret.GetPubKey();
                scriptPubKey = GetScriptForDestination(PKHash(pk));
                assert(!find_key(m3, pk, true));
                gather_script(m3, scriptPubKey, n, n, n, n);
                assert(find_key(m3, pk, true));

                pk.Decompress();
                scriptPubKey = GetScriptForDestination(PKHash(pk));
                assert(!find_key(m3, pk, false));
                gather_script(m3, scriptPubKey, n, n, n, n);
                assert(find_key(m3, pk, false));

				secret.MakeNewKey(true);
                pk = secret.GetPubKey();
				scriptPubKey = GetScriptForDestination(WitnessV0KeyHash(pk));
                assert(!find_key(m3, pk, true));
                gather_script(m3, scriptPubKey, n, n, n, n);
                assert(find_key(m3, pk, true));

                UniValue result(UniValue::VOBJ);
                result.pushKV("ret", 0 );
                return result;
            }
            if (ta == 112) {
                //测试密钥的存储与读取
                CKey secret;
                secret.MakeNewKey(true);
                CPubKey pbkey = secret.GetPubKey();
                assert(secret.VerifyPubKey(pbkey));
                save_key(secret);
                std::string strSecret = read_key();
                CKey key2 = DecodeSecret(strSecret);
                assert(key2.VerifyPubKey(pbkey));
            }
            UniValue result(UniValue::VOBJ);
            result.pushKV("ret", 0);
            return result;
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
        {"blockchain", &luckytxout},
        {"blockchain", &testtxout},
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
