// Copyright (c) 2026 The PQBTC Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_WALLET_PQ_SCRIPTPUBKEYMAN_H
#define BITCOIN_WALLET_PQ_SCRIPTPUBKEYMAN_H

#include <crypto/pqsig/pqsig.h>
#include <wallet/scriptpubkeyman.h>

#include <array>
#include <map>
#include <optional>
#include <unordered_map>
#include <vector>

namespace wallet {

class PQDescriptorScriptPubKeyMan final : public ScriptPubKeyMan
{
private:
    using ScriptPubKeyMap = std::map<CScript, int32_t>;
    using PkScriptMap = std::map<int32_t, std::array<unsigned char, pqsig::PK_SCRIPT_SIZE>>;

    mutable RecursiveMutex cs_pq_man;

    uint256 m_id;
    PQWalletDescriptor m_wallet_descriptor GUARDED_BY(cs_pq_man);
    CKeyingMaterial m_root_seed GUARDED_BY(cs_pq_man);
    std::vector<unsigned char> m_crypted_root_seed GUARDED_BY(cs_pq_man);
    ScriptPubKeyMap m_map_script_pub_keys GUARDED_BY(cs_pq_man);
    PkScriptMap m_map_pk_scripts GUARDED_BY(cs_pq_man);
    int32_t m_max_cached_index GUARDED_BY(cs_pq_man){-1};
    int64_t m_keypool_size GUARDED_BY(cs_pq_man){DEFAULT_KEYPOOL_SIZE};
    bool m_decryption_thoroughly_checked GUARDED_BY(cs_pq_man){false};

    bool GetRootSeed(CKeyingMaterial& root_seed) const EXCLUSIVE_LOCKS_REQUIRED(cs_pq_man);
    bool GetChildSeedForIndex(int32_t index, PQSeed& seed) const EXCLUSIVE_LOCKS_REQUIRED(cs_pq_man);
    static CScript MakeWitnessScript(const std::array<unsigned char, pqsig::PK_SCRIPT_SIZE>& pk_script);
    static CScript MakeScriptPubKey(const std::array<unsigned char, pqsig::PK_SCRIPT_SIZE>& pk_script);
    bool GetDestinationForIndex(int32_t index, CTxDestination& dest) const EXCLUSIVE_LOCKS_REQUIRED(cs_pq_man);
    std::unique_ptr<FlatSigningProvider> GetSigningProvider(const CScript& script, bool include_private) const;
    bool WriteMetadata(WalletBatch& batch) EXCLUSIVE_LOCKS_REQUIRED(cs_pq_man);

public:
    PQDescriptorScriptPubKeyMan(WalletStorage& storage, uint256 id, const PQWalletDescriptor& descriptor, int64_t keypool_size);
    PQDescriptorScriptPubKeyMan(WalletStorage& storage,
                                uint256 id,
                                const std::array<unsigned char, 32>& root_seed,
                                bool internal,
                                uint64_t creation_time,
                                int32_t range_start,
                                int32_t range_end,
                                int32_t next_index,
                                int64_t keypool_size);

    static uint256 DeriveID(const std::array<unsigned char, 32>& root_seed, bool internal);

    util::Result<CTxDestination> GetNewDestination(OutputType type) override;
    util::Result<CTxDestination> GetReservedDestination(OutputType type, bool internal, int64_t& index) override;
    void ReturnDestination(int64_t index, bool internal, const CTxDestination& addr) override;
    bool TopUp(unsigned int size = 0) override;
    std::vector<WalletDestination> MarkUnusedAddresses(const CScript& script) override;
    bool IsHDEnabled() const override { return true; }
    bool CanGetAddresses(bool internal = false) const override;
    bool HavePrivateKeys() const override;
    bool HaveCryptedKeys() const override;
    bool IsMine(const CScript& script) const override;
    bool CheckDecryptionKey(const CKeyingMaterial& master_key) override;
    bool Encrypt(const CKeyingMaterial& master_key, WalletBatch* batch) override;
    unsigned int GetKeyPoolSize() const override;
    int64_t GetTimeFirstKey() const override;
    std::unique_ptr<CKeyMetadata> GetMetadata(const CTxDestination& dest) const override;
    std::unique_ptr<SigningProvider> GetSolvingProvider(const CScript& script) const override;
    bool IsSpendable(const CScript& script) const override;
    bool CanProvide(const CScript& script, SignatureData& sigdata) override;
    bool SignTransaction(CMutableTransaction& tx, const std::map<COutPoint, Coin>& coins, int sighash, std::map<int, bilingual_str>& input_errors) const override;
    std::optional<common::PSBTError> FillPSBT(PartiallySignedTransaction& psbt, const PrecomputedTransactionData& txdata, std::optional<int> sighash_type = std::nullopt, bool sign = true, bool bip32derivs = false, int* n_signed = nullptr, bool finalize = true) const override;
    uint256 GetID() const override;
    std::unordered_set<CScript, SaltedSipHasher> GetScriptPubKeys() const override;
    std::unordered_set<CScript, SaltedSipHasher> GetScriptPubKeys(int32_t minimum_index) const;

    bool GetDescriptorString(std::string& out, bool priv) const;
    PQWalletDescriptor GetWalletDescriptor() const;
    bool IsInternal() const;
    int32_t GetEndRange() const;

    bool UpdateWalletDescriptor(const PQWalletDescriptor& descriptor);
    bool LoadRootSeed(const std::vector<unsigned char>& root_seed);
    bool LoadCryptedRootSeed(const std::vector<unsigned char>& crypted_root_seed);
    bool LoadCachedPkScript(int32_t index, const std::vector<unsigned char>& pk_script);
};

} // namespace wallet

#endif // BITCOIN_WALLET_PQ_SCRIPTPUBKEYMAN_H
