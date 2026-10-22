// Copyright (c) 2026 The PQBTC Core developers
// Distributed under the MIT software license, see the accompanying COPYING.
// PUBLIC fixture only: this is not a wallet, IPC server or production node.
#include <crypto/mldsa44/contract.h>
#include <crypto/mldsa44/verify.h>
#include "../ml-dsa-key-lifecycle/key_lifecycle.h"

#include <algorithm>
#include <iostream>
#include <stdexcept>
#include <string>

using namespace pqbtc::mldsa44;

static void Check(bool condition)
{
    if (!condition) throw std::runtime_error("native integration assertion failed");
}

static std::string Hex(std::span<const unsigned char> data)
{
    constexpr char digits[] = "0123456789abcdef";
    std::string result;
    for (auto c : data) { result += digits[c >> 4]; result += digits[c & 15]; }
    return result;
}

int main()
{
    struct Owner {
        pqbtc_mldsa44_key* key{nullptr};
        ~Owner() { pqbtc_mldsa44_key_destroy(&key); }
    } owner;
    try {
        Check(pqbtc_mldsa44_key_runtime_init() == 0);
        std::array<unsigned char, 32> public_fixture_seed{};
        for (size_t i = 0; i < public_fixture_seed.size(); ++i) public_fixture_seed[i] = i;
        Check(pqbtc_mldsa44_key_import_seed(&owner.key, public_fixture_seed.data(), public_fixture_seed.size()) == 0);
        Bytes pk(1312), signature(2420);
        Check(pqbtc_mldsa44_key_public(owner.key, pk.data(), pk.size()) == 0);
        auto program = KeyCommitment(Network::REGTEST, pk);
        Bytes script{0x52, 0x20};
        script.insert(script.end(), program.begin(), program.end());
        Input input{};
        for (size_t i = 0; i < input.hash.size(); ++i) input.hash[i] = i;
        input.index = 3; input.sequence = 0xfffffffeU;
        Transaction tx{2, {input}, {{99000, script}}, 7};
        std::vector<Output> prevouts{{100000, script}};
        auto wire = SerializeUnsigned(tx, prevouts);
        auto decoded = ParseUnsigned(wire, prevouts);
        Check(SerializeUnsigned(decoded, prevouts) == wire);
        auto message = SigningMessage(Network::REGTEST, tx, prevouts, 0);
        constexpr unsigned char context[] = "PQBTC/MLDSA44/tx/v1";
        Check(pqbtc_mldsa44_key_sign_hedged(owner.key, signature.data(), signature.size(),
                                         message.data(), message.size(), context, sizeof(context) - 1) == 0);
        std::vector<Bytes> witness{signature, pk};
        Check(VerifyWitness(Network::REGTEST, tx, prevouts, 0, program, witness));
        size_t negative_checks{0};
        auto Reject = [&](bool rejected) { Check(rejected); ++negative_checks; };
        for (size_t position : {size_t{0}, size_t{31}, size_t{1200}, size_t{2419}}) {
            auto bad = witness; bad[0][position] ^= 1;
            Reject(!VerifyWitness(Network::REGTEST, tx, prevouts, 0, program, bad));
        }
        for (auto net : {Network::MAIN, Network::TEST}) Reject(!VerifyWitness(net, tx, prevouts, 0, program, witness));
        for (int field = 0; field < 8; ++field) {
            auto changed = tx; auto metadata = prevouts;
            switch (field) {
            case 0: ++changed.version; break;
            case 1: ++changed.lock_time; break;
            case 2: ++changed.inputs[0].index; break;
            case 3: changed.inputs[0].hash[0] ^= 1; break;
            case 4: --changed.inputs[0].sequence; break;
            case 5: --changed.outputs[0].amount; break;
            case 6: changed.outputs[0].script[3] ^= 1; break;
            case 7: ++metadata[0].amount; break;
            }
            Reject(!VerifyWitness(Network::REGTEST, changed, metadata, 0, program, witness));
        }
        auto bad_pk = witness; bad_pk[1][0] ^= 1;
        Reject(!VerifyWitness(Network::REGTEST, tx, prevouts, 0, program, bad_pk));
        auto extra = witness; extra.push_back({});
        Reject(!VerifyWitness(Network::REGTEST, tx, prevouts, 0, program, extra));
        auto wrong_size = witness; wrong_size[0].pop_back();
        Reject(!VerifyWitness(Network::REGTEST, tx, prevouts, 0, program, wrong_size));
        Reject(!VerifyWitness(Network::REGTEST, tx, prevouts, 1, program, witness));
        auto wrong_script = prevouts; wrong_script[0].script[3] ^= 1;
        Reject(!VerifyWitness(Network::REGTEST, tx, wrong_script, 0, program, witness));
        auto RejectTransaction = [&](const Transaction& bad, const std::vector<Output>& metadata) {
            bool failed = false;
            try { (void)SerializeUnsigned(bad, metadata); } catch (const std::invalid_argument&) { failed = true; }
            Reject(failed);
        };
        auto no_inputs = tx; no_inputs.inputs.clear(); RejectTransaction(no_inputs, {});
        auto no_outputs = tx; no_outputs.outputs.clear(); RejectTransaction(no_outputs, prevouts);
        auto duplicate = tx; duplicate.inputs.push_back(input);
        RejectTransaction(duplicate, {prevouts[0], prevouts[0]});
        auto coinbase = tx; coinbase.inputs[0].hash.fill(0); coinbase.inputs[0].index = 0xffffffffU;
        RejectTransaction(coinbase, prevouts);
        auto excess = prevouts; excess[0].amount = 2100000000000001ULL; RejectTransaction(tx, excess);
        auto unfunded = tx; unfunded.outputs[0].amount = 100001; RejectTransaction(unfunded, prevouts);
        auto large_script = tx; large_script.outputs[0].script.resize(10001); RejectTransaction(large_script, prevouts);
        auto too_many = tx; too_many.outputs.resize(101); RejectTransaction(too_many, prevouts);
        Reject(pqbtc_mldsa44_node_verify(nullptr, 2420, pk.data(), pk.size(), message.data(), 32) == 0);
        Reject(pqbtc_mldsa44_node_verify(signature.data(), signature.size(), pk.data(), pk.size(), message.data(), 31) == 0);
        // Valid signature in the wrong context MUST fail the fixed-context verifier.
        Check(pqbtc_mldsa44_key_sign_hedged(owner.key, signature.data(), signature.size(),
                                         message.data(), message.size(), context, sizeof(context) - 2) == 0);
        Reject(pqbtc_mldsa44_node_verify(signature.data(), signature.size(), pk.data(), pk.size(), message.data(), 32) == 0);
        for (size_t end = 0; end < wire.size(); ++end) {
            bool failed = false;
            try { (void)ParseUnsigned(std::span(wire).first(end), prevouts); }
            catch (const std::invalid_argument&) { failed = true; }
            Reject(failed);
        }
        for (auto bad : {Bytes{0xfd,1,0}, Bytes{101}, Bytes{0}}) {
            auto changed = wire; changed.erase(changed.begin() + 4);
            changed.insert(changed.begin() + 4, bad.begin(), bad.end());
            bool failed = false;
            try { (void)ParseUnsigned(changed, prevouts); }
            catch (const std::invalid_argument&) { failed = true; }
            Reject(failed);
        }
        auto trailing = wire; trailing.push_back(0);
        auto scriptsig = wire; scriptsig[41] = 1; scriptsig.insert(scriptsig.begin() + 42, 0);
        bool bad_script = false;
        try { (void)ParseUnsigned(scriptsig, prevouts); } catch (const std::invalid_argument&) { bad_script = true; }
        Reject(bad_script);
        bool failed = false;
        try { (void)ParseUnsigned(trailing, prevouts); } catch (const std::invalid_argument&) { failed = true; }
        Reject(failed);
        std::cout << "{\"public_key\":\"" << Hex(pk) << "\",\"program\":\"" << Hex(program)
                  << "\",\"message\":\"" << Hex(message) << "\",\"unsigned\":\"" << Hex(wire)
                  << "\",\"negative_checks\":" << negative_checks << "}\n";
        return 0;
    } catch (const std::exception& e) { std::cerr << e.what() << '\n'; return 1; }
}
