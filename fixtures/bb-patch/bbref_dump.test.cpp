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
