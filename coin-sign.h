#include <string>

void init();
std::string signrawtransaction(const std::string& hexTx, const std::string& prevOutsJson,
    const std::string& str_priv_key, const std::string& hashType = "ALL");
std::string createrawtransaction(const std::string& inputsJson, const std::string& outputsJson,
    int64_t lockTime = 0);
