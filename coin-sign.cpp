#include <string>
#include <stdexcept>

#include "primitives/transaction.h"
#include "univalue.h"
#include "core_io.h"


UniValue sign_transaction(const std::string& hexTx);

int main(int argc, char* argv[]) {
    return 0;
}

UniValue sign_transaction(const std::string& hexTx) {
    CMutableTransaction mtx;
    if (!DecodeHexTx(mtx, hexTx, true))
        throw std::invalid_argument("TX decode failed");
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
    UniValue result(UniValue::VOBJ);
    /*
    result.push_back(Pair("hex", EncodeHexTx(mtx)));
    result.push_back(Pair("complete", fComplete));
    if (!vErrors.empty()) {
        result.push_back(Pair("errors", vErrors));
    }
*/
    return result;
}