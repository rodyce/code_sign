#include <iostream>
#include <string>
#include <stdexcept>
#include <vector>
#include <map>

#include "primitives/transaction.h"
#include "univalue.h"
#include "core_io.h"
#include "chainparams.h"
#include "policy/policy.h"

// From Bitcoin Core in policy/rbf.h
static const uint32_t MAX_BIP125_RBF_SEQUENCE = 0xfffffffd;

const std::string sample_prev_outs =
R"(
[
  {
    "txid": "5209723d5612a46836b3ad1f4ccddd254e24b80cbfb72e002b939a6b33798ded",
    "vout": 0,
    "address": "EHSTekNVcFj5i6XUoFUZ2WKkog6AUabdTo",
    "scriptPubKey": "76a91403217fe1e5f895420b2b30cb5dc4ef990a5f899488ac",
    "amount": 200.00000000,
    "confirmations": 1,
    "spendable": true,
    "solvable": true,
    "safe": true
  },
  {
    "txid": "5209723d5612a46836b3ad1f4ccddd254e24b80cbfb72e002b939a6b33798ded",
    "vout": 1,
    "address": "Ea2AFEGgkXH86HTziLhTNLrbpRn7F7uyHb",
    "scriptPubKey": "76a914b903201a6480907984b74dde59e71149c0c4503f88ac",
    "amount": 200.00000000,
    "confirmations": 1,
    "spendable": true,
    "solvable": true,
    "safe": true
  }
]
)";

const std::string sample_inputs =
R"(
[
    {
        "txid": "5209723d5612a46836b3ad1f4ccddd254e24b80cbfb72e002b939a6b33798ded",
        "vout": 0,
    }
]
)";

const std::string sample_outputs =
R"(
{
    "EKLiqAS8154uEEtRGHZ4PJax64o4nC5Jgw": 15.00000000,
    "EarTiDEmacVgSfFkukqUFBmseeHBCLdrs8": 184.99965400
}
)";

const std::string sample_priv_keys = 
R"(
[
    "EjqkDoVC1pDPZ2Nyq7mtXuFvWKqfJSmZNU2bStrqQ8AW6gjhgHRM"
]
)";

std::string sign_transaction(const std::string& hexTx, const std::string& prevOutsJson, const std::string& str_priv_key);
std::string createrawtransaction(const std::string& inputsJson, const std::string& outputsJson,
    int64_t lockTime = 0, bool replaceable = false);


#include "utilstrencodings.h"
#include "tinyformat.h"
uint256 ParseHashV(const UniValue& v, std::string strName)
{
    std::string strHex;
    if (v.isStr())
        strHex = v.get_str();
    if (!IsHex(strHex)) // Note: IsHex("") is false
        throw std::invalid_argument(strName+" must be hexadecimal string (not '"+strHex+"')");
    if (64 != strHex.length())
        throw std::invalid_argument(strprintf("%s must be of length %d (not %d)", strName, 64, strHex.length()));
    uint256 result;
    result.SetHex(strHex);
    return result;
}
uint256 ParseHashO(const UniValue& o, std::string strKey)
{
    return ParseHashV(find_value(o, strKey), strKey);
}
std::vector<unsigned char> ParseHexV(const UniValue& v, std::string strName)
{
    std::string strHex;
    if (v.isStr())
        strHex = v.get_str();
    if (!IsHex(strHex))
        throw std::invalid_argument(strName+" must be hexadecimal string (not '"+strHex+"')");
    return ParseHex(strHex);
}
std::vector<unsigned char> ParseHexO(const UniValue& o, std::string strKey)
{
    return ParseHexV(find_value(o, strKey), strKey);
}

CAmount AmountFromValue(const UniValue& value)
{
    if (!value.isNum() && !value.isStr())
        throw std::invalid_argument("Amount is not a number or string");
    CAmount amount;
    if (!ParseFixedPoint(value.getValStr(), 8, &amount))
        throw std::invalid_argument("Invalid amount");
    if (!MoneyRange(amount))
        throw std::invalid_argument("Amount out of range");
    return amount;
}


struct TxOutData {
    COutPoint outPoint;
    CScript scriptPubKey;
    CAmount amount;
};


const TxOutData& findTxOutDataByOutPoint(const std::vector<TxOutData>& txOutDataVector, const COutPoint& outPoint) {
    for (auto& txOutData : txOutDataVector) {
        if (txOutData.outPoint == outPoint) {
            return txOutData;
        }
    }
    throw std::invalid_argument("tx out not found");
}


int main(int argc, char* argv[]) {
    SelectParams(CBaseChainParams::MAIN);
    auto txHex = createrawtransaction(sample_inputs, sample_outputs);
    std::cout << "Resulting TX Hex: " << txHex << std::endl;
    auto signedTxHex = sign_transaction(txHex, sample_prev_outs, sample_priv_keys);
    std::cout << "Signed TX Hex: " << signedTxHex << std::endl;
    return 0;
}

#include "script/interpreter.h"
#include "script/sign.h"
#include "keystore.h"
#include "base58.h"
std::string sign_transaction(const std::string& hexTx, const std::string& prevOutsJson,
        const std::string& privKeysJson) {
    ECC_Start();
    ECCVerifyHandle _;

    CMutableTransaction mtx;
    if (!DecodeHexTx(mtx, hexTx, true))
        throw std::invalid_argument("TX decode failed");

    std::cout << "Tx Version: " << mtx.nVersion << std::endl;

    std::vector<TxOutData> outDataVector;

    UniValue prev_outs;
    prev_outs.read(prevOutsJson);

    if (prev_outs.getType() == UniValue::VType::VARR) {
        for (UniValue prev_out : prev_outs.getValues()) {
            if (!prev_out.isObject()) {
                throw std::runtime_error("Not an obj!");
            }
            uint256 txid = ParseHashO(prev_out, "txid");
            int nOut = find_value(prev_out, "vout").get_int();
            if (nOut < 0)
                throw std::invalid_argument("vout must be positive");

            COutPoint out(txid, nOut);
            std::vector<unsigned char> pkData(ParseHexO(prev_out, "scriptPubKey"));
            CScript scriptPubKey(pkData.begin(), pkData.end());

            CAmount amount = AmountFromValue(find_value(prev_out, "amount"));

            TxOutData outData {
                .outPoint = out,
                .scriptPubKey = scriptPubKey,
                .amount = amount
            };
            outDataVector.push_back(outData);
        }
    }

    UniValue priv_keys;
    priv_keys.read(privKeysJson);
    // Declare a basic key store.
    CBasicKeyStore tempKeystore;
    // Map from coin address to its respective private key to sign.
    std::map<std::string, std::string> addrToPrivKeyMap;
    if (priv_keys.getType() == UniValue::VType::VARR) {
        for (UniValue priv_key : priv_keys.getValues()) {
            std::string priv_key_str = priv_key.get_str();
            CBitcoinSecret vchSecret;
            bool fGood = vchSecret.SetString(priv_key_str);
            if (!fGood)
                throw std::runtime_error(priv_key_str + ": Invalid private key");
            else
                std::cout << "The Key is Good to go!" << std::endl;

            // Add key to the keystore.
            CKey key = vchSecret.GetKey();
            if (!key.IsValid())
                throw std::runtime_error("Private key outside allowed range");
            tempKeystore.AddKey(key);
        }
    }

    // TODO: Add support for different hash types (none, single, etc.)
    int nHashType = SIGHASH_ALL;

    bool fHashSingle = ((nHashType & ~SIGHASH_ANYONECANPAY) == SIGHASH_SINGLE);
    const CKeyStore& keystore = tempKeystore;

    // Use CTransaction for the constant parts of the
    // transaction to avoid rehashing.
    const CTransaction txConst(mtx);
    // Sign what we can:
    for (unsigned int i = 0; i < mtx.vin.size(); i++) {
        CTxIn& txin = mtx.vin[i];
        std::cout << txin.nSequence << std::endl;

        auto& prevTxOutData = findTxOutDataByOutPoint(outDataVector, txin.prevout);

        std::vector<uint8_t> vchAmount(8);
        SignatureData sigdata;
        CScript prevPubKey = prevTxOutData.scriptPubKey;
        CAmount amount = prevTxOutData.amount;
        memcpy(&vchAmount[0], &amount, 8);

        // Only sign SIGHASH_SINGLE if there's a corresponding output:
        if (!fHashSingle || (i < mtx.GetNumVOuts()))
            ProduceSignature(MutableTransactionSignatureCreator(&keystore, &mtx, i, vchAmount, nHashType), prevPubKey, sigdata);

        sigdata = CombineSignatures(prevPubKey, TransactionSignatureChecker(&txConst, i, vchAmount), sigdata, DataFromTransaction(mtx, i));
        UpdateTransaction(mtx, i, sigdata);

        ScriptError serror = SCRIPT_ERR_OK;
        if (!VerifyScript(txin.scriptSig, prevPubKey, &txin.scriptWitness, STANDARD_SCRIPT_VERIFY_FLAGS, TransactionSignatureChecker(&txConst, i, vchAmount), &serror)) {
            if (serror == SCRIPT_ERR_INVALID_STACK_OPERATION) {
                // Unable to sign input and verification failed (possible attempt to partially sign).
                throw std::runtime_error("Unable to sign input, invalid stack size (possibly missing key)");
            } else {
                throw std::runtime_error(ScriptErrorString(serror));
            }
        }
    }


/*
    // Fetch previous transactions (inputs):
    CCoinsView viewDummy;
    CCoinsViewCache view(&viewDummy);
    {
        LOCK(mempool.cs);
        CCoinsViewCache &viewChain = *pcoinsTip;
        CCoinsViewMemPool viewMempool(&viewChain, mempool);
        view.SetBackend(viewMempool); // temporarily switch cache backend to db+mempool view

        for (const CTxIn& txin : mtx.vin) {
            view.AccessCoin(txin.prevout); // Load entries from viewChain into view; can fail.
        }

        view.SetBackend(viewDummy); // switch back to avoid locking mempool for too long
    }

    bool fGivenKeys = false;
    CBasicKeyStore tempKeystore;
    if (!request.params[2].isNull()) {
        fGivenKeys = true;
        UniValue keys = request.params[2].get_array();
        for (unsigned int idx = 0; idx < keys.size(); idx++) {
            UniValue k = keys[idx];
            CBitcoinSecret vchSecret;
            bool fGood = vchSecret.SetString(k.get_str());
            if (!fGood)
                throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Invalid private key");
            CKey key = vchSecret.GetKey();
            if (!key.IsValid())
                throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Private key outside allowed range");
            tempKeystore.AddKey(key);
        }
    }
#ifdef ENABLE_WALLET
    else if (pwallet) {
        EnsureWalletIsUnlocked(pwallet);
    }
#endif

    // Add previous txouts given in the RPC call:
    if (!request.params[1].isNull()) {
        UniValue prevTxs = request.params[1].get_array();
        for (unsigned int idx = 0; idx < prevTxs.size(); idx++) {
            const UniValue& p = prevTxs[idx];
            if (!p.isObject())
                throw JSONRPCError(RPC_DESERIALIZATION_ERROR, "expected object with {\"txid'\",\"vout\",\"scriptPubKey\"}");

            UniValue prevOut = p.get_obj();

            RPCTypeCheckObj(prevOut,
                {
                    {"txid", UniValueType(UniValue::VSTR)},
                    {"vout", UniValueType(UniValue::VNUM)},
                    {"scriptPubKey", UniValueType(UniValue::VSTR)},
                });

            uint256 txid = ParseHashO(prevOut, "txid");

            int nOut = find_value(prevOut, "vout").get_int();
            if (nOut < 0)
                throw JSONRPCError(RPC_DESERIALIZATION_ERROR, "vout must be positive");

            COutPoint out(txid, nOut);
            std::vector<unsigned char> pkData(ParseHexO(prevOut, "scriptPubKey"));
            CScript scriptPubKey(pkData.begin(), pkData.end());

            {
                const Coin& coin = view.AccessCoin(out);

                if (coin.nType != OUTPUT_STANDARD)
                    throw JSONRPCError(RPC_MISC_ERROR, "TODO: make work for !StandardOutput");

                if (!coin.IsSpent() && coin.out.scriptPubKey != scriptPubKey) {
                    std::string err("Previous output scriptPubKey mismatch:\n");
                    err = err + ScriptToAsmStr(coin.out.scriptPubKey) + "\nvs:\n"+
                        ScriptToAsmStr(scriptPubKey);
                    throw JSONRPCError(RPC_DESERIALIZATION_ERROR, err);
                }
                Coin newcoin;
                newcoin.out.scriptPubKey = scriptPubKey;
                newcoin.out.nValue = 0;
                if (prevOut.exists("amount")) {
                    newcoin.out.nValue = AmountFromValue(find_value(prevOut, "amount"));
                }
                newcoin.nHeight = 1;
                view.AddCoin(out, std::move(newcoin), true);
            }

            // if redeemScript given and not using the local wallet (private keys
            // given), add redeemScript to the tempKeystore so it can be signed:
            if (fGivenKeys && (scriptPubKey.IsPayToScriptHashAny())) {
                RPCTypeCheckObj(prevOut,
                    {
                        {"txid", UniValueType(UniValue::VSTR)},
                        {"vout", UniValueType(UniValue::VNUM)},
                        {"scriptPubKey", UniValueType(UniValue::VSTR)},
                        {"redeemScript", UniValueType(UniValue::VSTR)},
                    });
                UniValue v = find_value(prevOut, "redeemScript");
                if (!v.isNull()) {
                    std::vector<unsigned char> rsData(ParseHexV(v, "redeemScript"));
                    CScript redeemScript(rsData.begin(), rsData.end());
                    tempKeystore.AddCScript(redeemScript);
                    // Automatically also add the P2WSH wrapped version of the script (to deal with P2SH-P2WSH).
                    tempKeystore.AddCScript(GetScriptForWitness(redeemScript));
                }
            }
        }
    }

#ifdef ENABLE_WALLET
    const CKeyStore& keystore = ((fGivenKeys || !pwallet) ? tempKeystore : *pwallet);
#else
    const CKeyStore& keystore = tempKeystore;
#endif

    int nHashType = SIGHASH_ALL;
    if (!request.params[3].isNull()) {
        static std::map<std::string, int> mapSigHashValues = {
            {std::string("ALL"), int(SIGHASH_ALL)},
            {std::string("ALL|ANYONECANPAY"), int(SIGHASH_ALL|SIGHASH_ANYONECANPAY)},
            {std::string("NONE"), int(SIGHASH_NONE)},
            {std::string("NONE|ANYONECANPAY"), int(SIGHASH_NONE|SIGHASH_ANYONECANPAY)},
            {std::string("SINGLE"), int(SIGHASH_SINGLE)},
            {std::string("SINGLE|ANYONECANPAY"), int(SIGHASH_SINGLE|SIGHASH_ANYONECANPAY)},
        };
        std::string strHashType = request.params[3].get_str();
        if (mapSigHashValues.count(strHashType))
            nHashType = mapSigHashValues[strHashType];
        else
            throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid sighash param");
    }

    bool fHashSingle = ((nHashType & ~SIGHASH_ANYONECANPAY) == SIGHASH_SINGLE);

    // Script verification errors
    UniValue vErrors(UniValue::VARR);

    // Use CTransaction for the constant parts of the
    // transaction to avoid rehashing.
    const CTransaction txConst(mtx);
    // Sign what we can:
    for (unsigned int i = 0; i < mtx.vin.size(); i++) {
        CTxIn& txin = mtx.vin[i];
        const Coin& coin = view.AccessCoin(txin.prevout);
        if (coin.IsSpent()) {
            TxInErrorToJSON(txin, vErrors, "Input not found or already spent");
            continue;
        }
        if (coin.nType != OUTPUT_STANDARD)
            throw JSONRPCError(RPC_MISC_ERROR, "TODO: make work for !StandardOutput");

        std::vector<uint8_t> vchAmount(8);
        SignatureData sigdata;
        CScript prevPubKey = coin.out.scriptPubKey;
        CAmount amount = coin.out.nValue;
        memcpy(&vchAmount[0], &amount, 8);

        // Only sign SIGHASH_SINGLE if there's a corresponding output:
        if (!fHashSingle || (i < mtx.GetNumVOuts()))
            ProduceSignature(MutableTransactionSignatureCreator(&keystore, &mtx, i, vchAmount, nHashType), prevPubKey, sigdata);

        sigdata = CombineSignatures(prevPubKey, TransactionSignatureChecker(&txConst, i, vchAmount), sigdata, DataFromTransaction(mtx, i));
        UpdateTransaction(mtx, i, sigdata);

        ScriptError serror = SCRIPT_ERR_OK;
        if (!VerifyScript(txin.scriptSig, prevPubKey, &txin.scriptWitness, STANDARD_SCRIPT_VERIFY_FLAGS, TransactionSignatureChecker(&txConst, i, vchAmount), &serror)) {
            if (serror == SCRIPT_ERR_INVALID_STACK_OPERATION) {
                // Unable to sign input and verification failed (possible attempt to partially sign).
                TxInErrorToJSON(txin, vErrors, "Unable to sign input, invalid stack size (possibly missing key)");
            } else {
                TxInErrorToJSON(txin, vErrors, ScriptErrorString(serror));
            }
        }
    }
    bool fComplete = vErrors.empty();
*/
    std::string result = EncodeHexTx(mtx);
    //result.push_back(Pair("hex", result));
    //result.push_back(Pair("complete", fComplete));
    /*
    if (!vErrors.empty()) {
        result.push_back(Pair("errors", vErrors));
    }
    */

    return result;
}

std::string createrawtransaction(const std::string& inputsJson, const std::string& outputsJson,
    int64_t lockTime, bool replaceable)
{
    UniValue inputs;
    inputs.read(inputsJson);
    UniValue sendTo;
    sendTo.read(outputsJson);

    fParticlMode = true;

    CMutableTransaction rawTx;
    rawTx.nVersion = fParticlMode ? PARTICL_TXN_VERSION : BTC_TXN_VERSION;

    int64_t nLockTime = lockTime;
    if (nLockTime < 0 || nLockTime > std::numeric_limits<uint32_t>::max())
        throw std::invalid_argument("Invalid parameter, locktime out of range");
    rawTx.nLockTime = nLockTime;

    bool rbfOptIn = replaceable;

    for (unsigned int idx = 0; idx < inputs.size(); idx++) {
        const UniValue& input = inputs[idx];
        const UniValue& o = input.get_obj();

        uint256 txid = ParseHashO(o, "txid");

        const UniValue& vout_v = find_value(o, "vout");
        if (!vout_v.isNum())
            throw std::invalid_argument("Invalid parameter, missing vout key");
        int nOutput = vout_v.get_int();
        if (nOutput < 0)
            throw std::invalid_argument("Invalid parameter, vout must be positive");

        uint32_t nSequence;
        if (rbfOptIn) {
            nSequence = MAX_BIP125_RBF_SEQUENCE;
        } else if (rawTx.nLockTime) {
            nSequence = std::numeric_limits<uint32_t>::max() - 1;
        } else {
            nSequence = std::numeric_limits<uint32_t>::max();
        }

        // set the sequence number if passed in the parameters object
        const UniValue& sequenceObj = find_value(o, "sequence");
        if (sequenceObj.isNum()) {
            int64_t seqNr64 = sequenceObj.get_int64();
            if (seqNr64 < 0 || seqNr64 > std::numeric_limits<uint32_t>::max()) {
                throw std::invalid_argument("Invalid parameter, sequence number is out of range");
            } else {
                nSequence = (uint32_t)seqNr64;
            }
        }

        CTxIn in(COutPoint(txid, nOutput), CScript(), nSequence);

        rawTx.vin.push_back(in);
    }

    std::set<CTxDestination> destinations;
    std::vector<std::string> addrList = sendTo.getKeys();
    for (const std::string& name_ : addrList) {

        if (name_ == "data") {
            std::vector<unsigned char> data = ParseHexV(sendTo[name_].getValStr(),"Data");

            if (fParticlMode)
            {
                std::shared_ptr<CTxOutData> out = MAKE_OUTPUT<CTxOutData>();
                out->vData = data;
                rawTx.vpout.push_back(out);
            } else
            {
                CTxOut out(0, CScript() << OP_RETURN << data);
                rawTx.vout.push_back(out);
            };
        } else {
            CTxDestination destination = DecodeDestination(name_);
            if (!IsValidDestination(destination)) {
                throw std::invalid_argument(std::string("Invalid Particl address: ") + name_);
            }

            if (!destinations.insert(destination).second) {
                throw std::invalid_argument(std::string("Invalid parameter, duplicated address: ") + name_);
            }

            CScript scriptPubKey = GetScriptForDestination(destination);
            CAmount nAmount = AmountFromValue(sendTo[name_]);

            if (fParticlMode)
            {
                std::shared_ptr<CTxOutStandard> out = MAKE_OUTPUT<CTxOutStandard>();
                out->nValue = nAmount;
                /*
                if (destination.type() == typeid(CStealthAddress))
                {
                    CStealthAddress sx = boost::get<CStealthAddress>(destination);
                    std::shared_ptr<CTxOutData> outData = MAKE_OUTPUT<CTxOutData>();
                    std::string sNarration;
                    std::string sError;
                    if (0 != PrepareStealthOutput(sx, sNarration, scriptPubKey, outData->vData, sError))
                        throw JSONRPCError(RPC_INTERNAL_ERROR, std::string("PrepareStealthOutput failed: ") + sError);

                    out->scriptPubKey = scriptPubKey;
                    rawTx.vpout.push_back(out);
                    rawTx.vpout.push_back(outData);
                } else*/
                {
                    out->scriptPubKey = scriptPubKey;
                    rawTx.vpout.push_back(out);
                };
            } else
            {
                CTxOut out(nAmount, scriptPubKey);
                rawTx.vout.push_back(out);
            }
        }
    }

    /*
    if (!request.params[3].isNull() && rbfOptIn != SignalsOptInRBF(rawTx)) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid parameter combination: Sequence number(s) contradict replaceable option");
    }
    */

    return EncodeHexTx(rawTx);
}
