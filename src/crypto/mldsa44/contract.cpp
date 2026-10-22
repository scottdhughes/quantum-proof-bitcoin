// Copyright (c) 2026 The PQBTC Core developers
// Distributed under the MIT software license, see the accompanying COPYING.
#include <crypto/mldsa44/contract.h>
#include <crypto/mldsa44/verify.h>
#include <crypto/sha256.h>

#include <algorithm>
#include <bit>
#include <set>
#include <stdexcept>
#include <string_view>

namespace pqbtc::mldsa44 {
namespace {
constexpr size_t MAX_BYTES{1048576}, MAX_ITEMS{100}, MAX_SCRIPT{10000};
constexpr uint64_t MAX_MONEY{2100000000000000};
void Require(bool value) { if (!value) throw std::invalid_argument("invalid ML-DSA transaction contract"); }
void Put(Bytes& out, uint64_t value, size_t size)
{
    for (size_t i = 0; i < size; ++i) out.push_back((value >> (8 * i)) & 255);
}
void Append(Bytes& out, std::span<const unsigned char> data) { out.insert(out.end(), data.begin(), data.end()); }
void Compact(Bytes& out, uint64_t value)
{
    if (value < 253) Put(out, value, 1);
    else if (value <= 65535) { out.push_back(253); Put(out, value, 2); }
    else if (value <= 0xffffffffU) { out.push_back(254); Put(out, value, 4); }
    else { out.push_back(255); Put(out, value, 8); }
}
void Blob(Bytes& out, std::span<const unsigned char> value) { Compact(out, value.size()); Append(out, value); }
Hash Digest(std::span<const unsigned char> bytes)
{
    Hash result{}; CSHA256{}.Write(bytes.data(), bytes.size()).Finalize(result.data()); return result;
}
Hash Tagged(std::string_view tag, std::span<const unsigned char> bytes)
{
    auto tag_hash = Digest({reinterpret_cast<const unsigned char*>(tag.data()), tag.size()});
    Hash result{};
    CSHA256{}.Write(tag_hash.data(), tag_hash.size()).Write(tag_hash.data(), tag_hash.size())
        .Write(bytes.data(), bytes.size()).Finalize(result.data());
    return result;
}
Bytes Unhex(std::string_view text)
{
    Require(text.size() % 2 == 0);
    auto digit = [](char c) -> unsigned char {
        if (c >= '0' && c <= '9') return c - '0';
        if (c >= 'a' && c <= 'f') return c - 'a' + 10;
        throw std::invalid_argument("invalid network constant");
    };
    Bytes out;
    for (size_t i = 0; i < text.size(); i += 2) out.push_back(digit(text[i]) * 16 + digit(text[i + 1]));
    return out;
}
Bytes Binding(Network network)
{
    // Target frozen GENESIS-v1 artifacts, not a claim about effective node params.
    switch (network) {
    case Network::MAIN: return Unhex("8592a7ade4317bee0ed1cbbcac7cd5c87866798740bbfbdf7e34c2dfbf036e0ea21df72a");
    case Network::TEST: return Unhex("a7e29cf779a947a9a6b549d08f256effeebbbcc0790868ee192d960a84aa48a0c639692b");
    case Network::REGTEST: return Unhex("96bd879ee215bd6baf48facc1f79c9be57bcee375d3b1d7afb6c1255d0759ab57211cc36");
    }
    throw std::invalid_argument("unknown network");
}
void Outpoint(Bytes& out, const Input& input) { Append(out, input.hash); Put(out, input.index, 4); }
void TxOutput(Bytes& out, const Output& output) { Put(out, output.amount, 8); Blob(out, output.script); }
void ValidateStructure(const Transaction& tx, std::span<const Output> prevouts)
{
    Require(!tx.inputs.empty() && tx.inputs.size() <= 0xffffffffULL && prevouts.size() == tx.inputs.size());
    Require(!tx.outputs.empty() && tx.outputs.size() <= 0xffffffffULL);
    std::set<std::pair<Hash, uint32_t>> seen;
    uint64_t incoming{0}, outgoing{0};
    for (size_t i = 0; i < tx.inputs.size(); ++i) {
        const auto& input = tx.inputs[i]; const auto& previous = prevouts[i];
        Require(!(input.hash == Hash{} && input.index == 0xffffffffU));
        Require(seen.emplace(input.hash, input.index).second);
        Require(previous.amount <= MAX_MONEY && incoming <= MAX_MONEY - previous.amount);
        incoming += previous.amount;
    }
    for (const auto& output : tx.outputs) {
        Require(output.amount <= MAX_MONEY && outgoing <= MAX_MONEY - output.amount);
        outgoing += output.amount;
    }
    Require(outgoing <= incoming);
}
void ValidateSignerPolicy(const Transaction& tx, std::span<const Output> prevouts)
{
    ValidateStructure(tx, prevouts);
    Require(tx.inputs.size() <= MAX_ITEMS && tx.outputs.size() <= MAX_ITEMS);
    for (const auto& output : prevouts) Require(output.script.size() <= MAX_SCRIPT);
    for (const auto& output : tx.outputs) Require(output.script.size() <= MAX_SCRIPT);
}
class Reader {
    std::span<const unsigned char> m_data;
    size_t m_offset{0};
public:
    explicit Reader(std::span<const unsigned char> data) : m_data(data) { Require(data.size() <= MAX_BYTES); }
    std::span<const unsigned char> Take(size_t size)
    {
        Require(size <= m_data.size() - m_offset);
        auto part = m_data.subspan(m_offset, size); m_offset += size; return part;
    }
    uint64_t Number(size_t size)
    {
        auto bytes = Take(size); uint64_t value{0};
        for (size_t i = 0; i < bytes.size(); ++i) value |= uint64_t{bytes[i]} << (8 * i);
        return value;
    }
    size_t Count(size_t maximum)
    {
        auto first = Number(1); uint64_t value = first;
        if (first >= 253) {
            size_t size = first == 253 ? 2 : first == 254 ? 4 : 8;
            value = Number(size);
            Require(value >= (first == 253 ? 253 : first == 254 ? 65536 : uint64_t{1} << 32));
        }
        Require(value <= maximum); return value;
    }
    Bytes Blob() { auto bytes = Take(Count(MAX_SCRIPT)); return {bytes.begin(), bytes.end()}; }
    void End() { Require(m_offset == m_data.size()); }
};
} // namespace

Bytes SerializeUnsigned(const Transaction& tx, std::span<const Output> prevouts)
{
    ValidateSignerPolicy(tx, prevouts);
    Bytes out; Put(out, std::bit_cast<uint32_t>(tx.version), 4); Compact(out, tx.inputs.size());
    for (const auto& input : tx.inputs) { Outpoint(out, input); out.push_back(0); Put(out, input.sequence, 4); }
    Compact(out, tx.outputs.size()); for (const auto& output : tx.outputs) TxOutput(out, output);
    Put(out, tx.lock_time, 4); Require(out.size() <= MAX_BYTES); return out;
}

Transaction ParseUnsigned(std::span<const unsigned char> wire, std::span<const Output> prevouts)
{
    Reader reader{wire}; Transaction tx{};
    tx.version = std::bit_cast<int32_t>(static_cast<uint32_t>(reader.Number(4)));
    const auto count = reader.Count(MAX_ITEMS); Require(count != 0 && count == prevouts.size());
    for (size_t i = 0; i < count; ++i) {
        Input input{}; auto hash = reader.Take(32); std::copy(hash.begin(), hash.end(), input.hash.begin());
        input.index = reader.Number(4); Require(reader.Blob().empty()); input.sequence = reader.Number(4);
        tx.inputs.push_back(input);
    }
    const auto outputs = reader.Count(MAX_ITEMS); Require(outputs != 0);
    for (size_t i = 0; i < outputs; ++i) {
        Output output{}; output.amount = reader.Number(8); output.script = reader.Blob();
        tx.outputs.push_back(std::move(output));
    }
    tx.lock_time = reader.Number(4); reader.End(); ValidateSignerPolicy(tx, prevouts); return tx;
}

PreparedTransaction::PreparedTransaction(const Transaction& tx, std::span<const Output> prevouts)
{
    ValidateStructure(tx, prevouts);
    std::array<Bytes, 5> parts;
    for (size_t i = 0; i < tx.inputs.size(); ++i) {
        Outpoint(parts[0], tx.inputs[i]); Put(parts[1], prevouts[i].amount, 8);
        Blob(parts[2], prevouts[i].script); Put(parts[3], tx.inputs[i].sequence, 4);
        m_scripts.push_back(prevouts[i].script);
    }
    for (const auto& output : tx.outputs) TxOutput(parts[4], output);
    Put(m_body, std::bit_cast<uint32_t>(tx.version), 4); Put(m_body, tx.lock_time, 4);
    m_body.push_back(1); Put(m_body, tx.inputs.size(), 4); Put(m_body, tx.outputs.size(), 4);
    for (const auto& part : parts) Append(m_body, Digest(part));
}

Bytes NetworkBinding(Network network) { return Binding(network); }

Hash SigningMessage(Network network, const PreparedTransaction& tx, size_t index)
{
    Require(index < tx.m_scripts.size());
    Bytes preimage = Binding(network); Append(preimage, tx.m_body);
    Put(preimage, index, 4); return Tagged("PQBTC/MLDSA44/sighash/v1", preimage);
}

Hash KeyCommitment(Network network, std::span<const unsigned char> pk)
{
    Require(pk.size() == 1312); Bytes data = Binding(network); Append(data, pk);
    return Tagged("PQBTC/MLDSA44/key/v1", data);
}

bool VerifyWitness(Network network, const PreparedTransaction& tx,
    size_t index, std::span<const unsigned char> program, std::span<const Bytes> witness)
{
    try {
        Require(index < tx.m_scripts.size() && program.size() == 32 && witness.size() == 2);
        Require(witness[0].size() == 2420 && witness[1].size() == 1312);
        const auto commitment = KeyCommitment(network, witness[1]);
        Require(std::equal(commitment.begin(), commitment.end(), program.begin()));
        const auto& script = tx.m_scripts[index];
        Require(script.size() == 34 && script[0] == 0x52 && script[1] == 0x20 &&
                std::equal(program.begin(), program.end(), script.begin() + 2));
        const auto message = SigningMessage(network, tx, index);
        return pqbtc_mldsa44_node_verify(witness[0].data(), witness[0].size(),
            witness[1].data(), witness[1].size(), message.data(), message.size()) == 1;
    } catch (const std::invalid_argument&) { return false; }
}
} // namespace pqbtc::mldsa44
