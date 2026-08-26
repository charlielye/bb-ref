// bb-ref fixture dumper (test-only). Writes the UltraHonk proving instance of an ACIR program to disk so
// the Rust reference implementation can prove from the exact same polynomials.
//
//   BBREF_PROGRAM=<program.json> BBREF_WITNESS=<witness.gz> BBREF_OUT=<dir> ./bin/dsl_tests --gtest_filter='BbRefDump.*'
//
// Layout of <dir>/{nozk,zk}/: meta.txt (key=value), <ENTITY>.bin (dyadic_size * 32 big-endian bytes, one file per
// unshifted entity in AllEntities order, captured BEFORE Oink), public_inputs.bin, memory_*_records.txt,
// rom_logup_records.txt, proof.bin (the proof bb produces from this instance, 32 bytes per field).
#include "acir_format.hpp"
#include "acir_to_constraint_buf.hpp"
#include "barretenberg/common/get_bytecode.hpp"
#include "barretenberg/flavor/ultra_flavor.hpp"
#include "barretenberg/flavor/ultra_zk_flavor.hpp"
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

template <typename Flavor>
void dump_instance(const std::string& program_json, const std::string& witness_path, const std::filesystem::path& out)
{
    auto bytecode = get_bytecode(program_json);
    auto witness = get_bytecode(witness_path);
    acir_format::ProgramMetadata metadata{ .has_ipa_claim = false };
    acir_format::AcirProgram program{ acir_format::circuit_buf_to_acir_format(std::move(bytecode), false), {} };
    program.witness = acir_format::witness_buf_to_witness_vector(std::move(witness));
    auto builder = acir_format::create_circuit<UltraCircuitBuilder>(program, metadata);
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
    UltraProver_<Flavor> prover{ instance, vk };
    auto proof = prover.construct_proof();
    std::vector<uint8_t> buf;
    for (const auto& x : proof) {
        auto b = to_buffer(x);
        buf.insert(buf.end(), b.begin(), b.end());
    }
    write_file(out / "proof.bin", buf);
    write_file(out / "vk", to_buffer(*vk));
}
} // namespace

TEST(BbRefDump, UltraInstance)
{
    const char* program = std::getenv("BBREF_PROGRAM");
    const char* witness = std::getenv("BBREF_WITNESS");
    const char* out = std::getenv("BBREF_OUT");
    if (program == nullptr || witness == nullptr || out == nullptr) {
        GTEST_SKIP() << "set BBREF_PROGRAM, BBREF_WITNESS, BBREF_OUT";
    }
    bb::srs::init_file_crs_factory(bb::srs::bb_crs_path());
    dump_instance<UltraFlavor>(program, witness, std::filesystem::path(out) / "nozk");
    dump_instance<UltraZKFlavor>(program, witness, std::filesystem::path(out) / "zk");
}
