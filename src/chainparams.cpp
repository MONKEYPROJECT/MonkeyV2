// Copyright (c) 2010 Satoshi Nakamoto
// Copyright (c) 2009-2014 The Bitcoin developers
// Copyright (c) 2014-2015 The Dash developers
// Copyright (c) 2015-2017 The PIVX developers
// Copyright (c) 2017 The Monkey developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "chainparams.h"
#include "random.h"
#include "util.h"
#include "utilstrencodings.h"

#include <assert.h>

#include <boost/assign/list_of.hpp>

using namespace std;
using namespace boost::assign;

struct SeedSpec6 {
    uint8_t addr[16];
    uint16_t port;
};

#include "chainparamsseeds.h"

/**
 * Main network
 */

//! Convert the pnSeeds6 array into usable address objects.
static void convertSeed6(std::vector<CAddress>& vSeedsOut, const SeedSpec6* data, unsigned int count)
{
    // It'll only connect to one or two seed nodes because once it connects,
    // it'll get a pile of addresses with newer timestamps.
    // Seed nodes are given a random 'last seen time' of between one and two
    // weeks ago.
    const int64_t nOneWeek = 7 * 24 * 60 * 60;
    for (unsigned int i = 0; i < count; i++) {
        struct in6_addr ip;
        memcpy(&ip, data[i].addr, sizeof(ip));
        CAddress addr(CService(ip, data[i].port));
        addr.nTime = GetTime() - GetRand(nOneWeek) - nOneWeek;
        vSeedsOut.push_back(addr);
    }
}

//   What makes a good checkpoint block?
// + Is surrounded by blocks with reasonable timestamps
//   (no blocks before with a timestamp after, none after with
//    timestamp before)
// + Contains no strange transactions
static Checkpoints::MapCheckpoints mapCheckpoints =
    boost::assign::map_list_of
    (0, uint256("0x0000072442df3910d2d8ff1f3bcfe6234025d1bd532f7182927cd559b8e9e386"))
    (10000, uint256("0x87b913e6186c389e5eb8ea15d6923591f000a8693e72313c7e0aca650d0b2868"))
    (20000, uint256("0xeea497fd6ea4bd6b87679f3be0d80753845bac00a12933534b36d649194a81e1"))
    (30000, uint256("0x41ffb679fdf92aab1c08da41776bfbd18031b67085314357a720285b3b0bd03f"))
    (40000, uint256("0x464abbf3e5e2e8e2cd273d1b4e307f4bd4ed4a129fa89ca3aab2dfa8192cc899"))
    (50000, uint256("0xa6c93a0d65b37f14f385ac90cb9d7178ea9380e5a09acd53075ff54d73af8b34"))
    (52000, uint256("0x41a0dc4abf585804e283ff4cf2fd2b8b81d936574f311dc47a2b96e044360431"))
    (52500, uint256("0x573f626e4530bb3de69463d95b03edf3c72b8038c41927a90b5d4e4cf24389a7"))
    (53000, uint256("0x1d6c44ceea31da5ff580735cf61239b85a397c1399ebf441971478561edbc7ee"))
    (53193, uint256("0x2c15c5b40ffad6751459df47c40d6f7d72295b7d62151d45bd51f21cc8bf0b8b"))
    (53500, uint256("0xeb18accb89dc778c26ce8c0d5ccdcf1566e9c1ef373d1bdec52c831dd4dae8f6"))
    (54000, uint256("0xfcff8f632bae55b8233dd5768a908409c8c034e639f65a357eb637f5d2e2a937"))
    (82758, uint256("0x2aaa6d50aef4123b09c88e300939b8ae648bf5657c6cf693667a991b683eb2ee"));

static const Checkpoints::CCheckpointData data = {
    &mapCheckpoints,
    1537658358, // * UNIX timestamp of last checkpoint block
    181136,     // * total number of transactions between genesis and last checkpoint
                //   (the tx=... number in the SetBestChain debug.log lines)
    2000        // * estimated number of transactions per day after checkpoint
};

static Checkpoints::MapCheckpoints mapCheckpointsTestnet =
    boost::assign::map_list_of(0, uint256("0x001"));

static const Checkpoints::CCheckpointData dataTestnet = {
    &mapCheckpointsTestnet,
    1740710,
    0,
    250};

static Checkpoints::MapCheckpoints mapCheckpointsRegtest =
    boost::assign::map_list_of(0, uint256("0x001"));
static const Checkpoints::CCheckpointData dataRegtest = {
    &mapCheckpointsRegtest,
    1454124731,
    0,
    100};

class CMainParams : public CChainParams
{
public:
    CMainParams()
    {
        networkID = CBaseChainParams::MAIN;
        strNetworkID = "main";
        /**
         * The message start string is designed to be unlikely to occur in normal data.
         * The characters are rarely used upper ASCII, not valid as UTF-8, and produce
         * a large 4-byte int at any alignment.
         */
        pchMessageStart[0] = 0x51;
        pchMessageStart[1] = 0x23;
        pchMessageStart[2] = 0x49;
        pchMessageStart[3] = 0x96;
        vAlertPubKey = ParseHex("04f35675a3f24fd836bec1735d65b0dbc7f8cd491423ef50cdb9e1aab39721d4a752d9777be7d699e26f4c6db186e883c87b2fad0428ae216faf5bed61cf8d317f");
        nDefaultPort = 37233;
        bnProofOfWorkLimit = ~uint256(0) >> 1;
        nMaxReorganizationDepth = 100;
        nEnforceBlockUpgradeMajority = 750;
        nRejectBlockOutdatedMajority = 950;
        nToCheckBlockUpgradeMajority = 1000;
        nMinerThreads = 0;
        nTargetTimespan = 1 * 60; // Monkey: 1 minute
        nTargetSpacing = 2 * 60;  // Monkey: 2 minutes
        nMaturity = 10;
        nMasternodeCountDrift = 20;
        nMaxMoneyOut = 21000000 * COIN;

        /** Height or Time Based Activations **/
        nLastPOWBlock = 1000;
        nModifierUpdateBlock = 1; // we use the version 2 for MONK

        /**
         * Build the genesis block. Note that the output of the genesis coinbase cannot
         * be spent as it did not originally exist in the database.
         *
         * genesis.py -a quark-hash -z "2018-07-25 Coinbase Now Offers Crypto currency Gift Cards in Europe and Australia" -t 1532542535 -v 0 -p 04369763df1147595abb2ad01dcf899e67aedaf578ab9abf9c8f7d2c76c736e873d364f3101d8f99aba14ed2e5aba5b668a36d16e3a2758a949a999d36fdeccdf2
         * 04ffff001d01042642544320426c6f636b20353031353932202d20323031372d31322d32392031353a34333a3337
         * algorithm: quark-hash
         * merkle hash: b2d915af3eadbd9f7a0c2d625f9c43bafc20f7a5e19f9d5d0ba858e433ccabcd
         * pszTimestamp: 2018-07-25 Coinbase Now Offers Crypto currency Gift Cards in Europe and Australia
         * pubkey: 04369763df1147595abb2ad01dcf899e67aedaf578ab9abf9c8f7d2c76c736e873d364f3101d8f99aba14ed2e5aba5b668a36d16e3a2758a949a999d36fdeccdf2
         * time: 1532542535
         * bits: 0x1e0ffff0
         * Searching for genesis hash..
         * 16525.0 hash/s, estimate: 72.2 hgenesis hash found!
         * nonce: 20664569
         * genesis_hash: 0000072442df3910d2d8ff1f3bcfe6234025d1bd532f7182927cd559b8e9e386
         */
        const char* pszTimestamp = "2018-07-25 Coinbase Now Offers Crypto currency Gift Cards in Europe and Australia";
        CMutableTransaction txNew;
        txNew.vin.resize(1);
        txNew.vout.resize(1);
        txNew.vin[0].scriptSig = CScript() << 486604799 << CScriptNum(4) << vector<unsigned char>((const unsigned char*)pszTimestamp, (const unsigned char*)pszTimestamp + strlen(pszTimestamp));
        txNew.vout[0].nValue = 0 * COIN;
        txNew.vout[0].scriptPubKey = CScript() << ParseHex("04369763df1147595abb2ad01dcf899e67aedaf578ab9abf9c8f7d2c76c736e873d364f3101d8f99aba14ed2e5aba5b668a36d16e3a2758a949a999d36fdeccdf2") << OP_CHECKSIG;
        genesis.vtx.push_back(txNew);
        genesis.hashPrevBlock = 0;
        genesis.hashMerkleRoot = genesis.BuildMerkleTree();
        genesis.nVersion = 1;
        genesis.nTime = 1532542535;
        genesis.nBits = 0x1e0ffff0;
        genesis.nNonce = 20664569;

        hashGenesisBlock = genesis.GetHash();
        assert(hashGenesisBlock == uint256("0x0000072442df3910d2d8ff1f3bcfe6234025d1bd532f7182927cd559b8e9e386"));
        assert(genesis.hashMerkleRoot == uint256("0xb2d915af3eadbd9f7a0c2d625f9c43bafc20f7a5e19f9d5d0ba858e433ccabcd"));

        // DNS Seeding
        vSeeds.push_back(CDNSSeedData("seed1.monk3y.xyz", "seed1.monk3y.xyz"));
        vSeeds.push_back(CDNSSeedData("seed2.monk3y.xyz", "seed2.monk3y.xyz"));
        vSeeds.push_back(CDNSSeedData("seed3.monk3y.xyz", "seed3.monk3y.xyz"));

        base58Prefixes[PUBKEY_ADDRESS] = std::vector<unsigned char>(1, 51);
        base58Prefixes[SCRIPT_ADDRESS] = std::vector<unsigned char>(1, 28);
        base58Prefixes[SECRET_KEY] = std::vector<unsigned char>(1, 55);
        base58Prefixes[MONK_SECRET_KEY] = std::vector<unsigned char>(1, 53); // N
        // Monkey BIP32 pubkeys start with 'xpub' (Bitcoin defaults)
        base58Prefixes[EXT_PUBLIC_KEY] = boost::assign::list_of(0x04)(0x88)(0xB2)(0x1E).convert_to_container<std::vector<unsigned char> >();
        // Monkey BIP32 prvkeys start with 'xprv' (Bitcoin defaults)
        base58Prefixes[EXT_SECRET_KEY] = boost::assign::list_of(0x04)(0x88)(0xAD)(0xE4).convert_to_container<std::vector<unsigned char> >();
        // Monkey BIP44 coin type is '222' (0x800000de)
        // BIP44 coin type is from https://github.com/satoshilabs/slips/blob/master/slip-0044.md
        base58Prefixes[EXT_COIN_TYPE] = boost::assign::list_of(0x80)(0x00)(0x00)(0xde).convert_to_container<std::vector<unsigned char> >();

        convertSeed6(vFixedSeeds, pnSeed6_main, ARRAYLEN(pnSeed6_main));

        fMiningRequiresPeers = true;
        fAllowMinDifficultyBlocks = false;
        fDefaultConsistencyChecks = false;
        fRequireStandard = true;
        fMineBlocksOnDemand = false;
        fSkipProofOfWorkCheck = false;
        fTestnetToBeDeprecatedFieldRPC = false;
        fHeadersFirstSyncingActive = false;

        nPoolMaxTransactions = 3;
        strSporkKey = "0431a3e4fcb29011df5ac2e47e0da085f9378c7de8174cf9b7ccd8959235c4be2be224b5880c6036c5f7718c12c988c39db7f2af0e392748cca23726a4cfd97815";
        strMasternodePoolDummyAddress = "Mp2YtB2oub5Zbsvu2NUABYmbfzqrnPAD9R";
        nStartMasternodePayments = genesis.nTime + 86400; // 24 hours after genesis creation

        nBudget_Fee_Confirmations = 6; // Number of confirmations for the finalization fee
    }

    const Checkpoints::CCheckpointData& Checkpoints() const
    {
        return data;
    }
};
static CMainParams mainParams;

/**
 * Testnet (v3)
 */
class CTestNetParams : public CMainParams
{
public:
    CTestNetParams()
    {
        networkID = CBaseChainParams::TESTNET;
        strNetworkID = "test";
        pchMessageStart[0] = 0xe1;
        pchMessageStart[1] = 0xbe;
        pchMessageStart[2] = 0x0d;
        pchMessageStart[3] = 0x8c;
        vAlertPubKey = ParseHex("0434ff6edbff4e2b6b1474e80c4436f5b266e292fd203fc8425c788688f96e89975c4ba08fb160181b56048d560e83b5ea8ac118a29f9d3b9f4ab90a6de23a817f");
        nDefaultPort = 47233;
        nEnforceBlockUpgradeMajority = 51;
        nRejectBlockOutdatedMajority = 75;
        nToCheckBlockUpgradeMajority = 100;
        nMinerThreads = 0;
        nTargetTimespan = 1 * 60; // Monkey: 1 minute
        nTargetSpacing = 2 * 60;  // Monkey: 2 minutes
        nLastPOWBlock = 200;
        nMaturity = 15;
        nMasternodeCountDrift = 4;
        nModifierUpdateBlock = 1;
        nMaxMoneyOut = 21000000 * COIN;

        //! Modify the testnet genesis block so the timestamp is valid for a later start.
        genesis.nTime = 1532542535;
        genesis.nNonce = 20664569;

        hashGenesisBlock = genesis.GetHash();
        assert(hashGenesisBlock == uint256("0x0000072442df3910d2d8ff1f3bcfe6234025d1bd532f7182927cd559b8e9e386"));

        vFixedSeeds.clear();
        vSeeds.clear();

        base58Prefixes[PUBKEY_ADDRESS] = std::vector<unsigned char>(1, 127);
        base58Prefixes[SCRIPT_ADDRESS] = std::vector<unsigned char>(1, 196);
        base58Prefixes[SECRET_KEY] = std::vector<unsigned char>(1, 63);
        // Testnet Monkey BIP32 pubkeys start with 'tpub' (Bitcoin defaults)
        base58Prefixes[EXT_PUBLIC_KEY] = boost::assign::list_of(0x04)(0x35)(0x87)(0xCF).convert_to_container<std::vector<unsigned char> >();
        // Testnet Monkey BIP32 prvkeys start with 'tprv' (Bitcoin defaults)
        base58Prefixes[EXT_SECRET_KEY] = boost::assign::list_of(0x04)(0x35)(0x83)(0x94).convert_to_container<std::vector<unsigned char> >();
        // Testnet Monkey BIP44 coin type is '1' (All coin's testnet default)
        base58Prefixes[EXT_COIN_TYPE] = boost::assign::list_of(0x80)(0x00)(0x00)(0x01).convert_to_container<std::vector<unsigned char> >();

        convertSeed6(vFixedSeeds, pnSeed6_test, ARRAYLEN(pnSeed6_test));

        fMiningRequiresPeers = true;
        fAllowMinDifficultyBlocks = false;
        fDefaultConsistencyChecks = false;
        fRequireStandard = false;
        fMineBlocksOnDemand = false;
        fTestnetToBeDeprecatedFieldRPC = true;

        nPoolMaxTransactions = 2;
        strSporkKey = "04bae79cbfbcc3c555643d371388bd02ade4c8b09d1529e191aa6e06becd4d3ab0fde31d320704d1bc6d5e33b107335aa41e3a89eec6b0dfce015c9ab37eee966c";
        strMasternodePoolDummyAddress = "gbJ4Qad4xc77PpLzMx6rUegAs6aUPWkcUq";
        nStartMasternodePayments = genesis.nTime + 86400; // 24 hours after genesis
        nBudget_Fee_Confirmations = 3; // Number of confirmations for the finalization fee. We have to make this very short
                                       // here because we only have a 8 block finalization window on testnet
    }
    const Checkpoints::CCheckpointData& Checkpoints() const
    {
        return dataTestnet;
    }
};
static CTestNetParams testNetParams;

/**
 * Regression test
 */
class CRegTestParams : public CTestNetParams
{
public:
    CRegTestParams()
    {
        networkID = CBaseChainParams::REGTEST;
        strNetworkID = "regtest";
        strNetworkID = "regtest";
        pchMessageStart[0] = 0x8f;
        pchMessageStart[1] = 0x98;
        pchMessageStart[2] = 0xc0;
        pchMessageStart[3] = 0xec;
        nEnforceBlockUpgradeMajority = 750;
        nRejectBlockOutdatedMajority = 950;
        nToCheckBlockUpgradeMajority = 1000;
        nMinerThreads = 1;
        nTargetTimespan = 24 * 60 * 60; // Monkey: 1 day
        nTargetSpacing = 1 * 60;        // Monkey: 1 minutes
        bnProofOfWorkLimit = ~uint256(0) >> 1;
       	nLastPOWBlock = 250;
    	nMaturity = 10;
        genesis.nTime = 1532542535;
        genesis.nBits = 0x207fffff;
        genesis.nNonce = 20542300;

        hashGenesisBlock = genesis.GetHash();
        nDefaultPort = 57233;
        assert(hashGenesisBlock == uint256("0x7c2fa8fe2f7044cb1e5e7c0b5976f506f9bf1cf3bf40c07c1ef6217a87ff6bcf"));

        vFixedSeeds.clear(); //! Regtest mode doesn't have any fixed seeds.
        vSeeds.clear();      //! Regtest mode doesn't have any DNS seeds.

        fMiningRequiresPeers = false;
        fAllowMinDifficultyBlocks = true;
        fDefaultConsistencyChecks = true;
        fRequireStandard = false;
        fMineBlocksOnDemand = true;
       	fSkipProofOfWorkCheck = true;
        fTestnetToBeDeprecatedFieldRPC = false;
    }
    const Checkpoints::CCheckpointData& Checkpoints() const
    {
        return dataRegtest;
    }
};
static CRegTestParams regTestParams;

/**
 * Unit test
 */
class CUnitTestParams : public CMainParams, public CModifiableParams
{
public:
    CUnitTestParams()
    {
        networkID = CBaseChainParams::UNITTEST;
        strNetworkID = "unittest";
        nDefaultPort = 51478;
        vFixedSeeds.clear(); //! Unit test mode doesn't have any fixed seeds.
        vSeeds.clear();      //! Unit test mode doesn't have any DNS seeds.

        fMiningRequiresPeers = false;
        fDefaultConsistencyChecks = true;
        fAllowMinDifficultyBlocks = false;
        fMineBlocksOnDemand = true;
    }

    const Checkpoints::CCheckpointData& Checkpoints() const
    {
        // UnitTest share the same checkpoints as MAIN
        return data;
    }

    //! Published setters to allow changing values in unit test cases
    virtual void setEnforceBlockUpgradeMajority(int anEnforceBlockUpgradeMajority) { nEnforceBlockUpgradeMajority = anEnforceBlockUpgradeMajority; }
    virtual void setRejectBlockOutdatedMajority(int anRejectBlockOutdatedMajority) { nRejectBlockOutdatedMajority = anRejectBlockOutdatedMajority; }
    virtual void setToCheckBlockUpgradeMajority(int anToCheckBlockUpgradeMajority) { nToCheckBlockUpgradeMajority = anToCheckBlockUpgradeMajority; }
    virtual void setDefaultConsistencyChecks(bool afDefaultConsistencyChecks) { fDefaultConsistencyChecks = afDefaultConsistencyChecks; }
    virtual void setAllowMinDifficultyBlocks(bool afAllowMinDifficultyBlocks) { fAllowMinDifficultyBlocks = afAllowMinDifficultyBlocks; }
    virtual void setSkipProofOfWorkCheck(bool afSkipProofOfWorkCheck) { fSkipProofOfWorkCheck = afSkipProofOfWorkCheck; }
};
static CUnitTestParams unitTestParams;


static CChainParams* pCurrentParams = 0;

CModifiableParams* ModifiableParams()
{
    assert(pCurrentParams);
    assert(pCurrentParams == &unitTestParams);
    return (CModifiableParams*)&unitTestParams;
}

const CChainParams& Params()
{
    assert(pCurrentParams);
    return *pCurrentParams;
}

CChainParams& Params(CBaseChainParams::Network network)
{
    switch (network) {
    case CBaseChainParams::MAIN:
        return mainParams;
    case CBaseChainParams::TESTNET:
        return testNetParams;
    case CBaseChainParams::REGTEST:
        return regTestParams;
    case CBaseChainParams::UNITTEST:
        return unitTestParams;
    default:
        assert(false && "Unimplemented network");
        return mainParams;
    }
}

void SelectParams(CBaseChainParams::Network network)
{
    SelectBaseParams(network);
    pCurrentParams = &Params(network);
}

bool SelectParamsFromCommandLine()
{
    CBaseChainParams::Network network = NetworkIdFromCommandLine();
    if (network == CBaseChainParams::MAX_NETWORK_TYPES)
        return false;

    SelectParams(network);
    return true;
}
