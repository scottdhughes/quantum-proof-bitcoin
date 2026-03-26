// Copyright (c) 2026 The PQBTC Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <wallet/pq_scriptpubkeyman.h>

#include <crypto/sha256.h>
#include <script/script.h>
#include <script/solver.h>
#include <tinyformat.h>
#include <util/check.h>
#include <util/strencodings.h>

#include <algorithm>
#include <set>
#include <string>
#include <utility>

namespace wallet {
namespace {

std::vector<unsigned char> ToVector(const std::array<unsigned char, pqsig::PK_SCRIPT_SIZE>& pk_script)
{
    return std::vector<unsigned char>(pk_script.begin(), pk_script.end());
}

} // namespace

PQDescriptorScriptPubKeyMan::PQDescriptorScriptPubKeyMan(WalletStorage& storage, const uint256 id, const PQWalletDescriptor& descriptor, const int64_t keypool_size)
    : ScriptPubKeyMan(storage),
      m_id(id),
      m_wallet_descriptor(descriptor),
      m_keypool_size(keypool_size)
{
}

PQDescriptorScriptPubKeyMan::PQDescriptorScriptPubKeyMan(WalletStorage& storage,
                                                         const uint256 id,
                                                         const std::array<unsigned char, 32>& root_seed,
                                                         const bool internal,
                                                         const uint64_t creation_time,
                                                         const int32_t range_start,
                                                         const int32_t range_end,
                                                         const int32_t next_index,
                                                         const int64_t keypool_size)
    : ScriptPubKeyMan(storage),
      m_id(id),
      m_wallet_descriptor{creation_time, range_start, range_end, next_index, static_cast<uint8_t>(internal ? 1 : 0)},
      m_keypool_size(keypool_size)
{
    m_root_seed.assign(root_seed.begin(), root_seed.end());
}

uint256 PQDescriptorScriptPubKeyMan::DeriveID(const std::array<unsigned char, 32>& root_seed, const bool internal)
{
    const std::string desc = GetPQPrivateDescriptorString(root_seed, internal);
    uint256 id;
    CSHA256().Write(UCharCast(desc.data()), desc.size()).Finalize(id.begin());
    return id;
}

CScript PQDescriptorScriptPubKeyMan::MakeWitnessScript(const std::array<unsigned char, pqsig::PK_SCRIPT_SIZE>& pk_script)
{
    return CScript() << ToVector(pk_script) << OP_CHECKSIG;
}

CScript PQDescriptorScriptPubKeyMan::MakeScriptPubKey(const std::array<unsigned char, pqsig::PK_SCRIPT_SIZE>& pk_script)
{
    return GetScriptForDestination(WitnessV0ScriptHash(MakeWitnessScript(pk_script)));
}

bool PQDescriptorScriptPubKeyMan::GetRootSeed(CKeyingMaterial& root_seed) const
{
    AssertLockHeld(cs_pq_man);
    if (!m_root_seed.empty()) {
        root_seed = m_root_seed;
        return root_seed.size() == pqsig::MSG32_SIZE;
    }
    if (m_crypted_root_seed.empty()) {
        return false;
    }
    const std::vector<unsigned char> crypted_root_seed{m_crypted_root_seed};
    return m_storage.WithEncryptionKey([&](const CKeyingMaterial& master_key) {
        return DecryptSecret(master_key, crypted_root_seed, m_id, root_seed) && root_seed.size() == pqsig::MSG32_SIZE;
    });
}

bool PQDescriptorScriptPubKeyMan::GetDestinationForIndex(const int32_t index, CTxDestination& dest) const
{
    AssertLockHeld(cs_pq_man);
    const auto it = m_map_pk_scripts.find(index);
    if (it == m_map_pk_scripts.end()) {
        return false;
    }
    dest = WitnessV0ScriptHash(MakeWitnessScript(it->second));
    return true;
}

bool PQDescriptorScriptPubKeyMan::WriteMetadata(WalletBatch& batch)
{
    AssertLockHeld(cs_pq_man);
    if (!batch.WritePQDescriptor(GetID(), m_wallet_descriptor)) {
        return false;
    }
    if (!m_crypted_root_seed.empty()) {
        return batch.WriteCryptedPQDescriptorSeed(GetID(), m_crypted_root_seed);
    }
    if (!m_root_seed.empty()) {
        return batch.WritePQDescriptorSeed(GetID(), std::vector<unsigned char>(m_root_seed.begin(), m_root_seed.end()));
    }
    return true;
}

util::Result<CTxDestination> PQDescriptorScriptPubKeyMan::GetNewDestination(const OutputType type)
{
    LOCK(cs_pq_man);
    if (type != OutputType::BECH32) {
        return util::Error{Untranslated("PQSIG descriptors only support bech32 destinations")};
    }
    TopUp();
    if (m_wallet_descriptor.next_index >= m_wallet_descriptor.range_end && !TopUp(1)) {
        return util::Error{Untranslated("Error: Keypool ran out, please unlock the wallet or expand the PQ range")};
    }

    CTxDestination dest;
    if (!GetDestinationForIndex(m_wallet_descriptor.next_index, dest)) {
        return util::Error{Untranslated("Error: Cannot extract destination from the generated PQ scriptpubkey")};
    }
    ++m_wallet_descriptor.next_index;
    if (!WalletBatch(m_storage.GetDatabase()).WritePQDescriptor(GetID(), m_wallet_descriptor)) {
        return util::Error{Untranslated("Error: writing PQ descriptor state failed")};
    }
    NotifyCanGetAddressesChanged();
    return dest;
}

util::Result<CTxDestination> PQDescriptorScriptPubKeyMan::GetReservedDestination(const OutputType type, const bool internal, int64_t& index)
{
    LOCK(cs_pq_man);
    if (internal != IsInternal()) {
        return util::Error{Untranslated("Reserved PQ destination requested from the wrong branch")};
    }
    auto op_dest = GetNewDestination(type);
    index = m_wallet_descriptor.next_index - 1;
    return op_dest;
}

void PQDescriptorScriptPubKeyMan::ReturnDestination(const int64_t index, const bool internal, const CTxDestination&)
{
    LOCK(cs_pq_man);
    if (internal != IsInternal()) return;
    if (m_wallet_descriptor.next_index - 1 == index) {
        --m_wallet_descriptor.next_index;
    }
    WalletBatch(m_storage.GetDatabase()).WritePQDescriptor(GetID(), m_wallet_descriptor);
    NotifyCanGetAddressesChanged();
}

bool PQDescriptorScriptPubKeyMan::TopUp(const unsigned int size)
{
    WalletBatch batch(m_storage.GetDatabase());
    LOCK(cs_pq_man);

    const unsigned int target_size = size > 0 ? size : m_keypool_size;
    const int32_t new_range_end = std::max(m_wallet_descriptor.next_index + static_cast<int32_t>(target_size), m_wallet_descriptor.range_end);
    std::set<CScript> new_spks;

    for (int32_t index = m_max_cached_index + 1; index < new_range_end; ++index) {
        std::array<unsigned char, pqsig::PK_SCRIPT_SIZE> pk_script{};
        const auto cached = m_map_pk_scripts.find(index);
        if (cached != m_map_pk_scripts.end()) {
            pk_script = cached->second;
        } else {
            CKeyingMaterial root_seed;
            if (!GetRootSeed(root_seed)) {
                return false;
            }
            if (!pqsig::DeriveWalletPkScript(pk_script, root_seed, IsInternal(), index)) {
                return false;
            }
            if (!batch.WritePQDescriptorCache(GetID(), index, ToVector(pk_script))) {
                throw std::runtime_error(std::string(__func__) + ": writing PQ descriptor cache failed");
            }
            m_map_pk_scripts[index] = pk_script;
        }

        const CScript script_pub_key = MakeScriptPubKey(pk_script);
        m_map_script_pub_keys[script_pub_key] = index;
        new_spks.insert(script_pub_key);
        m_max_cached_index = index;
    }

    m_wallet_descriptor.range_end = new_range_end;
    if (!WriteMetadata(batch)) {
        throw std::runtime_error(std::string(__func__) + ": writing PQ descriptor metadata failed");
    }

    m_storage.TopUpCallback(new_spks, this);
    NotifyCanGetAddressesChanged();
    return true;
}

std::vector<WalletDestination> PQDescriptorScriptPubKeyMan::MarkUnusedAddresses(const CScript& script)
{
    LOCK(cs_pq_man);
    std::vector<WalletDestination> result;
    const auto it = m_map_script_pub_keys.find(script);
    if (it == m_map_script_pub_keys.end()) {
        return result;
    }
    const int32_t used_index = it->second;
    while (used_index >= m_wallet_descriptor.next_index) {
        CTxDestination dest;
        if (!GetDestinationForIndex(m_wallet_descriptor.next_index, dest)) {
            break;
        }
        result.push_back({dest, IsInternal()});
        ++m_wallet_descriptor.next_index;
    }
    if (!TopUp()) {
        WalletLogPrintf("%s: Topping up PQ keypool failed (locked wallet)\n", __func__);
    }
    return result;
}

bool PQDescriptorScriptPubKeyMan::CanGetAddresses(const bool internal) const
{
    LOCK(cs_pq_man);
    if (internal != IsInternal()) {
        return false;
    }
    if (m_wallet_descriptor.next_index < m_wallet_descriptor.range_end) {
        return true;
    }
    if (m_crypted_root_seed.empty()) {
        return !m_root_seed.empty();
    }
    return !m_storage.IsLocked();
}

bool PQDescriptorScriptPubKeyMan::HavePrivateKeys() const
{
    LOCK(cs_pq_man);
    return !m_root_seed.empty() || !m_crypted_root_seed.empty();
}

bool PQDescriptorScriptPubKeyMan::HaveCryptedKeys() const
{
    LOCK(cs_pq_man);
    return !m_crypted_root_seed.empty();
}

bool PQDescriptorScriptPubKeyMan::IsMine(const CScript& script) const
{
    LOCK(cs_pq_man);
    return m_map_script_pub_keys.contains(script);
}

bool PQDescriptorScriptPubKeyMan::CheckDecryptionKey(const CKeyingMaterial& master_key)
{
    LOCK(cs_pq_man);
    if (!m_root_seed.empty()) {
        return false;
    }
    if (m_crypted_root_seed.empty()) {
        return true;
    }

    CKeyingMaterial root_seed;
    if (!DecryptSecret(master_key, m_crypted_root_seed, m_id, root_seed) || root_seed.size() != pqsig::MSG32_SIZE) {
        return false;
    }

    bool pass = true;
    if (!m_map_pk_scripts.empty()) {
        const auto& [index, expected_pk_script] = *m_map_pk_scripts.begin();
        std::array<unsigned char, pqsig::PK_SCRIPT_SIZE> derived_pk_script{};
        if (!pqsig::DeriveWalletPkScript(derived_pk_script, root_seed, IsInternal(), index)) {
            return false;
        }
        pass = derived_pk_script == expected_pk_script;
    }
    if (pass) {
        m_decryption_thoroughly_checked = true;
    }
    return pass;
}

bool PQDescriptorScriptPubKeyMan::Encrypt(const CKeyingMaterial& master_key, WalletBatch* batch)
{
    LOCK(cs_pq_man);
    if (!m_crypted_root_seed.empty() || m_root_seed.empty() || batch == nullptr) {
        return false;
    }

    std::vector<unsigned char> crypted_root_seed;
    if (!EncryptSecret(master_key, m_root_seed, m_id, crypted_root_seed)) {
        return false;
    }
    m_crypted_root_seed = crypted_root_seed;
    m_root_seed.clear();
    m_root_seed.shrink_to_fit();
    return WriteMetadata(*batch);
}

unsigned int PQDescriptorScriptPubKeyMan::GetKeyPoolSize() const
{
    LOCK(cs_pq_man);
    return m_wallet_descriptor.range_end - m_wallet_descriptor.next_index;
}

int64_t PQDescriptorScriptPubKeyMan::GetTimeFirstKey() const
{
    LOCK(cs_pq_man);
    return m_wallet_descriptor.creation_time;
}

std::unique_ptr<CKeyMetadata> PQDescriptorScriptPubKeyMan::GetMetadata(const CTxDestination& dest) const
{
    LOCK(cs_pq_man);
    const auto it = m_map_script_pub_keys.find(GetScriptForDestination(dest));
    if (it == m_map_script_pub_keys.end()) {
        return nullptr;
    }
    auto metadata = std::make_unique<CKeyMetadata>(m_wallet_descriptor.creation_time);
    metadata->hdKeypath = strprintf("m/%u/%d", static_cast<unsigned int>(m_wallet_descriptor.branch), it->second);
    return metadata;
}

std::unique_ptr<SigningProvider> PQDescriptorScriptPubKeyMan::GetSolvingProvider(const CScript& script) const
{
    LOCK(cs_pq_man);
    const auto it = m_map_script_pub_keys.find(script);
    if (it == m_map_script_pub_keys.end()) {
        return nullptr;
    }
    const auto pk_it = m_map_pk_scripts.find(it->second);
    if (pk_it == m_map_pk_scripts.end()) {
        return nullptr;
    }
    auto provider = std::make_unique<FlatSigningProvider>();
    const CScript witness_script = MakeWitnessScript(pk_it->second);
    provider->scripts.emplace(CScriptID(witness_script), witness_script);
    return provider;
}

bool PQDescriptorScriptPubKeyMan::CanProvide(const CScript& script, SignatureData&)
{
    return IsMine(script);
}

uint256 PQDescriptorScriptPubKeyMan::GetID() const
{
    return m_id;
}

std::unordered_set<CScript, SaltedSipHasher> PQDescriptorScriptPubKeyMan::GetScriptPubKeys() const
{
    LOCK(cs_pq_man);
    return GetScriptPubKeys(m_wallet_descriptor.range_start);
}

std::unordered_set<CScript, SaltedSipHasher> PQDescriptorScriptPubKeyMan::GetScriptPubKeys(const int32_t minimum_index) const
{
    LOCK(cs_pq_man);
    std::unordered_set<CScript, SaltedSipHasher> scripts;
    for (const auto& [script, index] : m_map_script_pub_keys) {
        if (index >= minimum_index) {
            scripts.insert(script);
        }
    }
    return scripts;
}

bool PQDescriptorScriptPubKeyMan::GetDescriptorString(std::string& out, const bool priv) const
{
    LOCK(cs_pq_man);
    if (!priv) {
        return false;
    }
    CKeyingMaterial root_seed;
    if (!GetRootSeed(root_seed)) {
        return false;
    }
    std::array<unsigned char, 32> seed{};
    std::copy(root_seed.begin(), root_seed.end(), seed.begin());
    out = GetPQPrivateDescriptorString(seed, IsInternal());
    return true;
}

PQWalletDescriptor PQDescriptorScriptPubKeyMan::GetWalletDescriptor() const
{
    LOCK(cs_pq_man);
    return m_wallet_descriptor;
}

bool PQDescriptorScriptPubKeyMan::IsInternal() const
{
    LOCK(cs_pq_man);
    return m_wallet_descriptor.IsInternal();
}

int32_t PQDescriptorScriptPubKeyMan::GetEndRange() const
{
    LOCK(cs_pq_man);
    return m_wallet_descriptor.range_end;
}

bool PQDescriptorScriptPubKeyMan::UpdateWalletDescriptor(const PQWalletDescriptor& descriptor)
{
    LOCK(cs_pq_man);
    if (descriptor.branch != m_wallet_descriptor.branch) {
        return false;
    }
    m_wallet_descriptor.creation_time = std::min(m_wallet_descriptor.creation_time, descriptor.creation_time);
    m_wallet_descriptor.range_start = std::min(m_wallet_descriptor.range_start, descriptor.range_start);
    m_wallet_descriptor.range_end = std::max(m_wallet_descriptor.range_end, descriptor.range_end);
    m_wallet_descriptor.next_index = std::max(m_wallet_descriptor.next_index, descriptor.next_index);
    return WalletBatch(m_storage.GetDatabase()).WritePQDescriptor(GetID(), m_wallet_descriptor);
}

bool PQDescriptorScriptPubKeyMan::LoadRootSeed(const std::vector<unsigned char>& root_seed)
{
    LOCK(cs_pq_man);
    if (root_seed.size() != pqsig::MSG32_SIZE) {
        return false;
    }
    m_root_seed.assign(root_seed.begin(), root_seed.end());
    return true;
}

bool PQDescriptorScriptPubKeyMan::LoadCryptedRootSeed(const std::vector<unsigned char>& crypted_root_seed)
{
    LOCK(cs_pq_man);
    m_crypted_root_seed = crypted_root_seed;
    return true;
}

bool PQDescriptorScriptPubKeyMan::LoadCachedPkScript(const int32_t index, const std::vector<unsigned char>& pk_script)
{
    LOCK(cs_pq_man);
    if (pk_script.size() != pqsig::PK_SCRIPT_SIZE) {
        return false;
    }
    std::array<unsigned char, pqsig::PK_SCRIPT_SIZE> pk_script_array{};
    std::copy(pk_script.begin(), pk_script.end(), pk_script_array.begin());
    if (!pqsig::IsValidPkScript(pk_script_array)) {
        return false;
    }
    m_map_pk_scripts[index] = pk_script_array;
    m_map_script_pub_keys[MakeScriptPubKey(pk_script_array)] = index;
    m_max_cached_index = std::max(m_max_cached_index, index);
    return true;
}

} // namespace wallet
