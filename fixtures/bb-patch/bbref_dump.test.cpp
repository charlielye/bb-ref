// bb-ref fixture dumper (test-only). Writes the UltraHonk proving instance of an ACIR program to disk so
// the Rust reference implementation can prove from the exact same polynomials.
//
//   BBREF_PROGRAM=<program.json> BBREF_WITNESS=<witness.gz> BBREF_OUT=<dir> ./bin/dsl_tests --gtest_filter='BbRefDump.*'
//
// Layout of <dir>/{nozk,zk,mega_app}/: (mega_app: MegaAppFlavor instance, proof.bin = Oink proof) meta.txt (key=value), <ENTITY>.bin (dyadic_size * 32 big-endian bytes, one file per
// unshifted entity in AllEntities order, captured BEFORE Oink), public_inputs.bin, memory_*_records.txt,
// rom_logup_records.txt, proof.bin (the proof bb produces from this instance, 32 bytes per field).
#include "acir_format.hpp"
#include "acir_to_constraint_buf.hpp"
#include "barretenberg/common/get_bytecode.hpp"
#include "barretenberg/flavor/mega_app_flavor.hpp"
#include "barretenberg/flavor/mega_kernel_flavor.hpp"
#include "barretenberg/flavor/mega_zk_flavor.hpp"
#include "barretenberg/commitment_schemes/triple_ipa/triple_ipa.hpp"
#include "barretenberg/goblin/batch_merge_prover.hpp"
#include "barretenberg/goblin/batch_merge_verifier.hpp"
#include "barretenberg/goblin/merge_prover.hpp"
#include "barretenberg/goblin/merge_verifier.hpp"
#include "barretenberg/hypernova/hypernova_decider_prover.hpp"
#include "barretenberg/hypernova/hypernova_decider_verifier.hpp"
#include "barretenberg/hypernova/hypernova_prover.hpp"
#include "barretenberg/hypernova/hypernova_verifier.hpp"
#include "barretenberg/ultra_honk/verifier_instance.hpp"
#include "barretenberg/stdlib/hash/poseidon2/poseidon2_permutation.hpp"
#include "barretenberg/stdlib/primitives/memory/ram_table.hpp"
#include "barretenberg/stdlib/primitives/memory/rom_table.hpp"
#include "barretenberg/stdlib/special_public_inputs/special_public_inputs.hpp"
#include <fstream>
#include <sstream>
#include "barretenberg/flavor/ultra_flavor.hpp"
#include "barretenberg/flavor/ultra_zk_flavor.hpp"
#include "barretenberg/stdlib_circuit_builders/mega_circuit_builder.hpp"
#include "barretenberg/ultra_honk/oink_prover.hpp"
#include "barretenberg/srs/global_crs.hpp"
#include "barretenberg/ultra_honk/prover_instance.hpp"
#include "barretenberg/ultra_honk/ultra_prover.hpp"
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <gtest/gtest.h>

namespace {
using namespace bb;

void write_file(const std::filesystem::path& path, const std::vector<uint8_t>& data)
{
    std::ofstream f(path, std::ios::binary);
    f.write(reinterpret_cast<const char*>(data.data()), static_cast<std::streamsize>(data.size()));
}

void write_frs(const std::filesystem::path& path, const auto& values, size_t n)
{
    std::vector<uint8_t> buf;
    buf.reserve(n * 32);
    for (size_t j = 0; j < n; ++j) {
        auto b = to_buffer(fr(values.get(j)));
        buf.insert(buf.end(), b.begin(), b.end());
    }
    write_file(path, buf);
}

template <typename Flavor> void dump_from_builder(typename Flavor::CircuitBuilder& builder, const std::filesystem::path& out);

template <typename Flavor, typename Builder>
void dump_instance(const std::string& program_json, const std::string& witness_path, const std::filesystem::path& out)
{
    constexpr bool is_mega = std::is_same_v<Builder, MegaCircuitBuilder>;
    auto bytecode = get_bytecode(program_json);
    auto witness = get_bytecode(witness_path);
    acir_format::ProgramMetadata metadata{ .has_ipa_claim = false };
    acir_format::AcirProgram program{ acir_format::circuit_buf_to_acir_format(std::move(bytecode), is_mega), {} };
    program.witness = acir_format::witness_buf_to_witness_vector(std::move(witness));
    auto builder = acir_format::create_circuit<Builder>(program, metadata);
    dump_from_builder<Flavor>(builder, out);
}

/**
 * Write the proving instance of a finalized-or-not builder, its VK, and a proof (full Ultra proof
 * for Ultra flavors, Oink proof for Mega flavors, which have no standalone prover).
 */
template <typename Flavor> void dump_from_builder(typename Flavor::CircuitBuilder& builder, const std::filesystem::path& out)
{
    constexpr bool is_mega = std::is_same_v<typename Flavor::CircuitBuilder, MegaCircuitBuilder>;
    auto instance = std::make_shared<ProverInstance_<Flavor>>(builder);

    std::filesystem::create_directories(out);
    const size_t n = instance->dyadic_size();
    {
        std::ofstream meta(out / "meta.txt");
        meta << "dyadic_size=" << n << "\n"
             << "num_public_inputs=" << instance->num_public_inputs() << "\n"
             << "pub_inputs_offset=" << instance->pub_inputs_offset() << "\n"
             << "final_active_wire_idx=" << instance->get_final_active_wire_idx() << "\n"
             << "max_end_index=" << instance->polynomials.max_end_index() << "\n";
    }
    auto write_indices = [&](const char* name, const std::vector<uint32_t>& v) {
        std::ofstream f(out / name);
        for (auto x : v) {
            f << x << "\n";
        }
    };
    write_indices("memory_read_records.txt", instance->memory_read_records);
    write_indices("memory_write_records.txt", instance->memory_write_records);
    write_indices("rom_logup_records.txt", instance->rom_logup_records);

    const auto& labels = Flavor::template AllEntities<std::string>::get_labels();
    size_t i = 0;
    for (const auto& poly : instance->polynomials.get_unshifted()) {
        write_frs(out / (labels[i] + ".bin"), poly, n);
        ++i;
    }
    {
        std::vector<uint8_t> buf;
        for (const auto& pi : instance->public_inputs) {
            auto b = to_buffer(pi);
            buf.insert(buf.end(), b.begin(), b.end());
        }
        write_file(out / "public_inputs.bin", buf);
    }

    auto vk = std::make_shared<typename Flavor::VerificationKey>(instance->get_precomputed());
    // Ultra flavors: the full proof. Mega flavors have no standalone prover; dump the Oink proof.
    std::vector<fr> proof;
    if constexpr (is_mega) {
        auto transcript = std::make_shared<typename Flavor::Transcript>();
        OinkProver<Flavor> oink{ instance, vk, transcript };
        oink.prove();
        proof = oink.export_proof();
    } else {
        UltraProver_<Flavor> prover{ instance, vk };
        proof = prover.construct_proof();
    }
    std::vector<uint8_t> buf;
    for (const auto& x : proof) {
        auto b = to_buffer(x);
        buf.insert(buf.end(), b.begin(), b.end());
    }
    write_file(out / "proof.bin", buf);
    write_file(out / "vk", to_buffer(*vk));
}

// ---- circuit scripts: one builder call per line (see bb-ref fixtures/scripts/*.txt) ----

std::vector<uint8_t> parse_hex_bytes(std::string s)
{
    if (s.rfind("0x", 0) == 0) {
        s = s.substr(2);
    }
    std::vector<uint8_t> bytes(32, 0);
    size_t n = s.size();
    for (size_t i = 0; i < n; ++i) {
        // right-align: last hex digit is the least significant nibble
        uint8_t v = static_cast<uint8_t>(std::stoi(s.substr(n - 1 - i, 1), nullptr, 16));
        size_t byte = 31 - i / 2;
        bytes[byte] |= static_cast<uint8_t>(i % 2 == 0 ? v : v << 4);
    }
    return bytes;
}

// Decimal (optionally negative) or 0x-prefixed hex.
template <typename F> F parse_field(const std::string& s)
{
    if (s.rfind("0x", 0) == 0) {
        auto bytes = parse_hex_bytes(s);
        return F::serialize_from_buffer(bytes.data());
    }
    bool neg = s[0] == '-';
    F v(std::stoull(neg ? s.substr(1) : s));
    return neg ? -v : v;
}

void run_script(MegaCircuitBuilder& b, const std::string& path)
{
    using field_ct = stdlib::field_t<MegaCircuitBuilder>;
    using Fr = bb::fr;
    std::vector<stdlib::rom_table<MegaCircuitBuilder>> roms;
    std::vector<stdlib::ram_table<MegaCircuitBuilder>> rams;
    std::ifstream in(path);
    std::string line;
    while (std::getline(in, line)) {
        std::istringstream ss(line);
        std::vector<std::string> t;
        for (std::string tok; ss >> tok;) {
            t.push_back(tok);
        }
        if (t.empty() || t[0][0] == '#') {
            continue;
        }
        auto u = [&](size_t i) { return static_cast<uint32_t>(std::stoul(t[i])); };
        auto f = [&](size_t i) { return parse_field<Fr>(t[i]); };
        auto q = [&](size_t i) { return parse_field<bb::fq>(t[i]); };
        auto w = [&](size_t i) { return field_ct::from_witness_index(&b, u(i)); };
        const std::string& op = t[0];
        if (op == "var") {
            b.add_variable(f(1));
        } else if (op == "pub") {
            b.add_public_variable(f(1));
        } else if (op == "add_gate") {
            b.create_big_add_gate({ u(1), u(2), u(3), u(4), f(5), f(6), f(7), f(8), f(9) }, t.size() > 10 && t[10] == "1");
        } else if (op == "mul_gate") {
            b.create_big_mul_add_gate({ u(1), u(2), u(3), u(4), f(5), f(6), f(7), f(8), f(9), f(10) });
        } else if (op == "bool") {
            b.create_bool_gate(u(1));
        } else if (op == "range") {
            b.create_dyadic_range_constraint(u(1), u(2), "script range");
        } else if (op == "bilinear" || op == "batched_eq") {
            const bool bilinear = op == "bilinear";
            b.create_bilinear_batched_eq_gate({ .mode = bilinear ? BilinearBatchedEqMode::Bilinear : BilinearBatchedEqMode::BatchedEq,
                                                .a = u(1),
                                                .b = u(2),
                                                .c = u(3),
                                                .d = u(4),
                                                .q_l = f(5),
                                                .q_r = f(6),
                                                .q_o = f(7),
                                                .q_4 = f(8),
                                                .q_c = f(9),
                                                .q_m = f(10),
                                                .q_5 = bilinear ? f(11) : Fr(0) });
        } else if (op == "calldata") {
            b.add_public_calldata(static_cast<BusId>(u(1)), u(2));
        } else if (op == "retdata") {
            b.add_public_return_data(u(1));
        } else if (op == "read_calldata") {
            b.read_calldata(static_cast<BusId>(u(1)), u(2));
        } else if (op == "read_retdata") {
            b.read_return_data(u(1));
        } else if (op == "ecc_add") {
            b.queue_ecc_add_accum(g1::affine_element(q(1), q(2)));
        } else if (op == "ecc_mul") {
            b.queue_ecc_mul_accum(g1::affine_element(q(1), q(2)), f(3));
        } else if (op == "ecc_eq") {
            b.queue_ecc_eq();
        } else if (op == "ecc_no_op") {
            b.queue_ecc_no_op();
        } else if (op == "poseidon2") {
            typename stdlib::Poseidon2Permutation<MegaCircuitBuilder>::State state{ w(1), w(2), w(3), w(4) };
            stdlib::Poseidon2Permutation<MegaCircuitBuilder>::permutation(&b, state);
        } else if (op == "rom" || op == "ram") {
            std::vector<field_ct> entries;
            for (size_t i = 2; i < 2 + u(1); ++i) {
                entries.push_back(w(i));
            }
            if (op == "rom") {
                roms.emplace_back(&b, entries);
            } else {
                rams.emplace_back(&b, entries);
            }
        } else if (op == "rom_read") {
            roms[u(1)][w(2)];
        } else if (op == "ram_read") {
            rams[u(1)].read(w(2));
        } else if (op == "ram_write") {
            rams[u(1)].write(w(2), w(3));
        } else if (op == "default_io") {
            stdlib::recursion::honk::DefaultIO<MegaCircuitBuilder>::add_default(b);
        } else {
            throw_or_abort("unknown script command: " + op);
        }
    }
}
} // namespace

// BBREF_SCRIPT=<script> BBREF_FLAVOR=app|kernel|zk BBREF_OUT=<dir> ./bin/dsl_tests --gtest_filter='BbRefDump.MegaScript'
TEST(BbRefDump, MegaScript)
{
    const char* script = std::getenv("BBREF_SCRIPT");
    const char* flavor = std::getenv("BBREF_FLAVOR");
    const char* out = std::getenv("BBREF_OUT");
    if (script == nullptr || flavor == nullptr || out == nullptr) {
        GTEST_SKIP() << "set BBREF_SCRIPT, BBREF_FLAVOR, BBREF_OUT";
    }
    bb::srs::init_file_crs_factory(bb::srs::bb_crs_path());
    MegaCircuitBuilder builder{ std::make_shared<ECCOpQueue>() };
    run_script(builder, script);
    const std::string f(flavor);
    if (f == "app") {
        dump_from_builder<MegaAppFlavor>(builder, out);
    } else if (f == "kernel") {
        dump_from_builder<MegaKernelFlavor>(builder, out);
    } else if (f == "zk") {
        dump_from_builder<MegaZKFlavor>(builder, out);
    } else {
        throw_or_abort("BBREF_FLAVOR must be app|kernel|zk");
    }
}

// Serialize an accumulator: challenge, evaluations, then the two commitments as raw 64-byte affine points.
void write_accumulator(const std::filesystem::path& path, const MultilinearBatchingVerifierClaim<curve::BN254>& acc)
{
    std::vector<uint8_t> buf;
    auto push_fr = [&](const fr& x) {
        auto b = to_buffer(x);
        buf.insert(buf.end(), b.begin(), b.end());
    };
    for (const auto& c : acc.challenge) {
        push_fr(c);
    }
    push_fr(acc.non_shifted_evaluation);
    push_fr(acc.shifted_evaluation);
    for (const auto& comm : { acc.non_shifted_commitment, acc.shifted_commitment }) {
        auto b = to_buffer(comm);
        buf.insert(buf.end(), b.begin(), b.end());
    }
    write_file(path, buf);
}

void write_proof(const std::filesystem::path& path, const HonkProof& proof)
{
    std::vector<uint8_t> buf;
    for (const auto& x : proof) {
        auto b = to_buffer(x);
        buf.insert(buf.end(), b.begin(), b.end());
    }
    write_file(path, buf);
}

// BBREF_SCRIPTS=<script>:<kernel|app>,... BBREF_PREV=0|1 BBREF_OUT=<dir> ./bin/dsl_tests --gtest_filter='BbRefDump.Folding'
// Folds the scripted circuits as one HyperNova group (optionally against a previous accumulator built from
// the first circuit on a separate transcript), then runs the decider. Dumps every proof, VK and accumulator, and
// cross-checks natively.
TEST(BbRefDump, Folding)
{
    const char* scripts_env = std::getenv("BBREF_SCRIPTS");
    const char* out_env = std::getenv("BBREF_OUT");
    if (scripts_env == nullptr || out_env == nullptr) {
        GTEST_SKIP() << "set BBREF_SCRIPTS, BBREF_OUT";
    }
    const bool use_prev = std::getenv("BBREF_PREV") != nullptr && std::string(std::getenv("BBREF_PREV")) == "1";
    bb::srs::init_file_crs_factory(bb::srs::bb_crs_path());
    std::filesystem::path out(out_env);
    std::filesystem::create_directories(out);

    std::vector<std::pair<std::string, std::string>> entries;
    {
        std::istringstream ss(scripts_env);
        for (std::string item; std::getline(ss, item, ',');) {
            auto colon = item.rfind(':');
            entries.emplace_back(item.substr(0, colon), item.substr(colon + 1));
        }
    }

    using ProverAccumulator = HypernovaFoldingProver::Accumulator;
    using VerifierAccumulator = MultilinearBatchingVerifierClaim<curve::BN254>;

    // Per-entry accumulate: builds the circuit, runs Oink + sumcheck under the entry's flavor. Returns the proof
    // and registers a verifier callback.
    std::vector<std::function<bool(HypernovaFoldingNativeVerifier&, const HonkProof&)>> verifiers;
    auto accumulate = [&](HypernovaFoldingProver& prover, size_t idx, bool register_verifier) -> HonkProof {
        const auto& [script, kind] = entries[idx];
        MegaCircuitBuilder builder{ std::make_shared<ECCOpQueue>() };
        run_script(builder, script);
        auto run = [&]<typename Flavor>() -> HonkProof {
            auto instance = std::make_shared<ProverInstance_<Flavor>>(builder);
            auto vk = std::make_shared<typename Flavor::VerificationKey>(instance->get_precomputed());
            if (register_verifier) {
                write_file(out / ("vk_" + std::to_string(idx)), to_buffer(*vk));
                verifiers.emplace_back([vk](HypernovaFoldingNativeVerifier& v, const HonkProof& proof) {
                    auto vi = std::make_shared<VerifierInstance_<Flavor>>(std::make_shared<typename Flavor::VKAndHash>(vk));
                    return v.accumulate_instance<Flavor>(vi, proof);
                });
            }
            return prover.accumulate_instance<Flavor>(instance, vk);
        };
        if (kind == "kernel") {
            return run.template operator()<MegaKernelFlavor>();
        }
        if (kind == "app") {
            return run.template operator()<MegaAppFlavor>();
        }
        throw_or_abort("kind must be kernel|app");
    };

    std::optional<ProverAccumulator> prev;
    std::optional<VerifierAccumulator> prev_verifier;
    if (use_prev) {
        auto transcript = std::make_shared<NativeTranscript>();
        HypernovaFoldingProver prover(transcript);
        accumulate(prover, 0, /*register_verifier=*/false);
        auto [_p, acc] = prover.finalize();
        prev_verifier = acc.to_verifier_claim_for_testing();
        write_accumulator(out / "prev_accumulator.bin", *prev_verifier);
        prev = std::move(acc);
    }

    auto transcript = std::make_shared<NativeTranscript>();
    HypernovaFoldingProver prover(transcript);
    std::vector<HonkProof> proofs;
    for (size_t i = 0; i < entries.size(); ++i) {
        proofs.push_back(accumulate(prover, i, /*register_verifier=*/true));
        write_proof(out / ("instance_proof_" + std::to_string(i) + ".bin"), proofs.back());
    }
    auto [batch_proof, accumulator] = prover.finalize(std::move(prev));
    write_proof(out / "batch_proof.bin", batch_proof);
    write_accumulator(out / "accumulator.bin", accumulator.to_verifier_claim_for_testing());
    HypernovaDeciderProver decider(transcript);
    HonkProof decider_proof = decider.construct_proof(accumulator);
    write_proof(out / "decider_proof.bin", decider_proof);

    // Native cross-check: verify the group, compare accumulators, verify the decider.
    auto verifier_transcript = std::make_shared<NativeTranscript>();
    HypernovaFoldingNativeVerifier verifier(verifier_transcript);
    for (size_t i = 0; i < entries.size(); ++i) {
        ASSERT_TRUE(verifiers[i](verifier, proofs[i])) << "instance " << i;
    }
    auto [verified, verifier_acc] = verifier.finalize(batch_proof, prev_verifier);
    ASSERT_TRUE(verified);
    ASSERT_EQ(verifier_acc.non_shifted_commitment, accumulator.non_shifted_commitment);
    ASSERT_EQ(verifier_acc.shifted_evaluation, accumulator.shifted_evaluation);
    HypernovaDeciderVerifier<MegaKernelFlavor> decider_verifier(verifier_transcript);
    auto pairing_points = decider_verifier.verify_proof(verifier_acc, decider_proof);
    ASSERT_TRUE(pairing_points.check());
}

TEST(BbRefDump, UltraInstance)
{
    const char* program = std::getenv("BBREF_PROGRAM");
    const char* witness = std::getenv("BBREF_WITNESS");
    const char* out = std::getenv("BBREF_OUT");
    if (program == nullptr || witness == nullptr || out == nullptr) {
        GTEST_SKIP() << "set BBREF_PROGRAM, BBREF_WITNESS, BBREF_OUT";
    }
    bb::srs::init_file_crs_factory(bb::srs::bb_crs_path());
    dump_instance<UltraFlavor, UltraCircuitBuilder>(program, witness, std::filesystem::path(out) / "nozk");
    dump_instance<UltraZKFlavor, UltraCircuitBuilder>(program, witness, std::filesystem::path(out) / "zk");
    dump_instance<MegaAppFlavor, MegaCircuitBuilder>(program, witness, std::filesystem::path(out) / "mega_app");
}

// --- M6: Goblin merge / batch merge -----------------------------------------------------------------------
// BBREF_MODE=merge|batch BBREF_NUM_SUBTABLES=<N> [BBREF_MAX=<M>] BBREF_OUT=<dir> ./bin/dsl_tests --gtest_filter='BbRefDump.Merge'
// Builds a deterministic op queue (recipe mirrored in bb-ref tests/m6_merge.rs), dumps the random ZK prefix columns so
// the Rust side can inject them, and dumps the (batch) merge proof. Cross-checks natively.
namespace {
// Subtable i: ((1 + i) % 10) + 1 triples of add / mul (with a >128-bit scalar) / eq_and_reset.
void populate_subtable_deterministic(ECCOpQueue& q, size_t subtable_idx)
{
    using Point = curve::BN254::AffineElement;
    const size_t num_triples = ((1 + subtable_idx) % 10) + 1;
    for (size_t j = 0; j < num_triples; ++j) {
        const uint64_t k = 1 + (100 * subtable_idx) + j;
        q.add_accumulate(Point::one() * fr(k));
        q.mul_accumulate(Point::one() * fr(k + 1), fr(k + 2).invert());
        q.eq_and_reset();
    }
}

void write_columns(const std::filesystem::path& path, const auto& columns)
{
    std::vector<uint8_t> buf;
    for (const auto& col : columns) {
        for (size_t j = 0; j < col.size(); ++j) {
            auto b = to_buffer(fr(col[j]));
            buf.insert(buf.end(), b.begin(), b.end());
        }
    }
    write_file(path, buf);
}
} // namespace

TEST(BbRefDump, Merge)
{
    const char* mode_env = std::getenv("BBREF_MODE");
    const char* n_env = std::getenv("BBREF_NUM_SUBTABLES");
    const char* out_env = std::getenv("BBREF_OUT");
    if (mode_env == nullptr || n_env == nullptr || out_env == nullptr) {
        GTEST_SKIP() << "set BBREF_MODE, BBREF_NUM_SUBTABLES, BBREF_OUT";
    }
    const std::string mode(mode_env);
    const size_t num_subtables = std::stoul(n_env);
    const size_t max_subtables = std::getenv("BBREF_MAX") != nullptr ? std::stoul(std::getenv("BBREF_MAX")) : 9;
    bb::srs::init_file_crs_factory(bb::srs::bb_crs_path());
    std::filesystem::path out(out_env);
    std::filesystem::create_directories(out);

    auto op_queue = std::make_shared<ECCOpQueue>();
    for (size_t i = 0; i < num_subtables; ++i) {
        if (i > 0) {
            op_queue->initialize_new_subtable();
        }
        populate_subtable_deterministic(*op_queue, i);
        op_queue->merge();
    }
    if (mode == "merge") {
        write_columns(out / "zk_columns.bin", op_queue->construct_zk_columns());
        op_queue->initialize_new_subtable();
        populate_subtable_deterministic(*op_queue, num_subtables);
        while (op_queue->get_current_subtable_size() < HIDING_KERNEL_ULTRA_OPS) {
            op_queue->add_accumulate(curve::BN254::AffineElement::one() *
                                     fr(1000 + op_queue->get_current_subtable_size()));
        }
        auto transcript = std::make_shared<NativeTranscript>();
        MergeProver prover{ op_queue, transcript };
        auto proof = prover.construct_proof();
        write_proof(out / "merge_proof.bin", proof);
        write_columns(out / "merged.bin", op_queue->construct_ultra_ops_table_columns());

        MergeVerifier::InputCommitments inputs;
        auto t_current = op_queue->construct_current_ultra_ops_subtable_columns();
        auto T_prev = op_queue->construct_table_columns_up_to_tail();
        for (size_t j = 0; j < 4; ++j) {
            inputs.t_commitments[j] = prover.pcs_commitment_key.commit(t_current[j]);
            inputs.T_prev_commitments[j] = prover.pcs_commitment_key.commit(T_prev[j]);
        }
        MergeVerifier verifier;
        auto result = verifier.reduce_to_pairing_check(proof, inputs);
        ASSERT_TRUE(result.reduction_succeeded);
        ASSERT_TRUE(result.pairing_points.check());
        return;
    }
    ASSERT_EQ(mode, "batch");
    // The batch merge prover builds the ZK prefix itself; dump it from the head of the merged table.
    BatchMergeProver prover{ op_queue, max_subtables };
    auto proof = prover.construct_proof();
    write_proof(out / "batch_merge_proof.bin", proof);
    auto merged = op_queue->construct_ultra_ops_table_columns();
    std::array<Polynomial<fr>, 4> zk_columns;
    for (size_t j = 0; j < 4; ++j) {
        zk_columns[j] = Polynomial<fr>(UltraEccOpsTable::ZK_ULTRA_OPS);
        for (size_t r = 0; r < UltraEccOpsTable::ZK_ULTRA_OPS; ++r) {
            zk_columns[j].at(r) = merged[j][r];
        }
    }
    write_columns(out / "zk_columns.bin", zk_columns);

    std::optional<fr> hash;
    for (const auto& cols : op_queue->construct_subtable_columns()) {
        std::vector<curve::BN254::AffineElement> comms;
        for (const auto& col : cols) {
            comms.push_back(prover.pcs_commitment_key.commit(col));
        }
        hash = BatchMergeVerifier::ecc_op_hash_step(comms, hash);
    }
    auto check = [&]<size_t M>() {
        BatchMergeVerifier_<curve::BN254, M> verifier;
        auto result = verifier.reduce_to_pairing_check(proof, *hash);
        ASSERT_TRUE(result.reduction_succeeded);
        ASSERT_TRUE(result.pairing_points.check());
    };
    if (max_subtables == 9) {
        check.template operator()<9>();
    } else {
        ASSERT_EQ(max_subtables, CHONK_MAX_NUM_CIRCUITS);
        check.template operator()<CHONK_MAX_NUM_CIRCUITS>();
    }
}

// --- M7: TripleIPA over Grumpkin ------------------------------------------------------------------------
// BBREF_LOG_N=4|15 BBREF_OUT=<dir> ./bin/dsl_tests --gtest_filter='BbRefDump.TripleIpa'
// Deterministic inputs (mirrored in bb-ref tests/m7_ipa.rs); dumps the proof and cross-checks natively.
namespace {
template <size_t LOG_N> void dump_triple_ipa(const std::filesystem::path& out)
{
    using Curve = curve::Grumpkin;
    using Fq = Curve::ScalarField;
    using PCS = TripleIPA<Curve, LOG_N>;
    constexpr size_t N = 1UL << LOG_N;
    CommitmentKey<Curve> ck(N);

    typename PCS::TripleIpaInput input;
    std::vector<Fq> u;
    for (size_t i = 0; i < LOG_N; ++i) {
        u.emplace_back(7 + i);
    }
    input.claim_data.unshifted.multilinear_challenge = u;
    const auto eq = ProverEqPolynomial<Fq>::construct(std::span<const Fq>(u), LOG_N);
    for (size_t k = 0; k < 5; ++k) {
        Polynomial<Fq> p(N);
        for (size_t i = 0; i < N; ++i) {
            p.at(i) = Fq((k + 1) * 1000 + i + 1);
        }
        input.claim_data.unshifted.evaluations.emplace_back(p.evaluate_mle(std::span<const Fq>(u)));
        input.claim_data.unshifted.commitments.emplace_back(ck.commit(p));
        input.unshifted_polynomials.emplace_back(std::move(p));
    }
    input.claim_data.unshifted.rho_powers = PCS::TripleIpaClaimData::rho_powers(Fq(11), 5);
    input.claim_data.shifted.rho_powers = PCS::TripleIpaClaimData::rho_powers(Fq(13), 2);
    for (const size_t source_idx : std::array<size_t, 2>{ 1, 3 }) {
        input.claim_data.shifted.commitments.emplace_back(input.claim_data.unshifted.commitments[source_idx]);
        input.claim_data.shifted.source_unshifted_evaluations.emplace_back(
            input.claim_data.unshifted.evaluations[source_idx]);
        input.claim_data.shifted.shifted_evaluations.emplace_back(
            ShiftedEqPolynomial<Curve, LOG_N>::evaluate_from_eq(eq, input.unshifted_polynomials[source_idx]));
        input.shifted_polynomials.emplace_back(input.unshifted_polynomials[source_idx].share());
    }
    Polynomial<Fq> q(N);
    for (size_t i = 0; i < N; ++i) {
        q.at(i) = Fq(500 + i);
    }
    input.claim_data.univariate.opening_pair.challenge = Fq(17);
    input.claim_data.univariate.opening_pair.evaluation = q.evaluate(Fq(17));
    input.claim_data.univariate.commitment = ck.commit(q);
    input.univariate_polynomial = std::move(q);

    auto prover_transcript = std::make_shared<NativeTranscript>();
    PCS::compute_opening_proof(ck, input, prover_transcript);
    auto proof = prover_transcript->export_proof();
    write_proof(out / "triple_ipa_proof.bin", proof);

    VerifierCommitmentKey<Curve> vk(N, srs::get_grumpkin_crs_factory());
    auto verifier_transcript = std::make_shared<NativeTranscript>(proof);
    ASSERT_TRUE(PCS::reduce_verify(vk, input.claim_data.batch(), verifier_transcript));
}
} // namespace

TEST(BbRefDump, TripleIpa)
{
    const char* log_n_env = std::getenv("BBREF_LOG_N");
    const char* out_env = std::getenv("BBREF_OUT");
    if (log_n_env == nullptr || out_env == nullptr) {
        GTEST_SKIP() << "set BBREF_LOG_N, BBREF_OUT";
    }
    srs::init_grumpkin_file_crs_factory(srs::bb_crs_path());
    std::filesystem::path out(out_env);
    std::filesystem::create_directories(out);
    const size_t log_n = std::stoul(log_n_env);
    if (log_n == 4) {
        dump_triple_ipa<4>(out);
    } else {
        ASSERT_EQ(log_n, 15UL);
        dump_triple_ipa<15>(out);
    }
}
