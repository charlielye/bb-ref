// bb-ref AVM fixture dumper, compiled against the pin's libbb-external-avm.a by regen_avm.sh.
//
//   avm_dump <avm_inputs.bin> <out_dir> [--inner]
//
// Proves the AvmProvingInputs with bb and writes <out_dir>/proof.bin (32 bytes per field) and
// public_inputs.bin (the flattened public-input columns). With --inner it also builds bb's inner
// (MegaAvm-arithmetized) AVM recursive verifier circuit for that proof and writes its proving
// instance to <out_dir>/inner/ in the BbRefDump layout: meta.txt, one <ENTITY>.bin per unshifted
// entity, public_inputs.bin, vk.
#include "barretenberg/flavor/mega_avm_flavor.hpp"
#include "barretenberg/goblin_avm/goblin_avm.hpp"
#include "barretenberg/srs/global_crs.hpp"
#include "barretenberg/ultra_honk/prover_instance.hpp"
#include "barretenberg/vm2/avm_api.hpp"
#include "barretenberg/vm2/constraining/recursion/two_layer_avm_recursive_verifier.hpp"

#include <cstring>
#include <filesystem>
#include <fstream>
#include <iterator>

using namespace bb;

namespace {

std::vector<uint8_t> read_file(const std::filesystem::path& path)
{
    std::ifstream f(path, std::ios::binary);
    return { std::istreambuf_iterator<char>(f), std::istreambuf_iterator<char>() };
}

void write_file(const std::filesystem::path& path, const std::vector<uint8_t>& data)
{
    std::ofstream f(path, std::ios::binary);
    f.write(reinterpret_cast<const char*>(data.data()), static_cast<std::streamsize>(data.size()));
}

void write_fields(const std::filesystem::path& path, const std::vector<fr>& values)
{
    std::vector<uint8_t> buf;
    buf.reserve(values.size() * 32);
    for (const auto& v : values) {
        auto b = to_buffer(v);
        buf.insert(buf.end(), b.begin(), b.end());
    }
    write_file(path, buf);
}

void dump_inner(const HonkProof& proof, const std::vector<std::vector<fr>>& columns, const std::filesystem::path& out)
{
    using UltraFF = stdlib::field_t<UltraCircuitBuilder>;
    UltraCircuitBuilder outer;
    stdlib::Proof<UltraCircuitBuilder> stdlib_proof(outer, proof);
    std::vector<std::vector<UltraFF>> public_inputs;
    for (const auto& column : columns) {
        std::vector<UltraFF> col;
        for (const auto& v : column) {
            col.push_back(UltraFF::from_witness(&outer, v));
        }
        public_inputs.push_back(std::move(col));
    }

    MegaAvmCircuitBuilder inner;
    GoblinAvm goblin(inner);
    avm2::TwoLayerAvmRecursiveVerifier::construct_inner_recursive_verification_circuit(
        inner, stdlib_proof, public_inputs);
    info("inner: num_gates=", inner.get_num_finalized_gates_inefficient(), " failed=", inner.failed());

    auto instance = std::make_shared<ProverInstance_<MegaAvmFlavor>>(inner);
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
    const auto& labels = MegaAvmFlavor::AllEntities<std::string>::get_labels();
    size_t i = 0;
    for (const auto& poly : instance->polynomials.get_unshifted()) {
        std::vector<fr> values(n);
        for (size_t j = 0; j < n; ++j) {
            values[j] = poly.get(j);
        }
        write_fields(out / (labels[i] + ".bin"), values);
        ++i;
    }
    write_fields(out / "public_inputs.bin", instance->public_inputs);
    auto vk = std::make_shared<MegaAvmFlavor::VerificationKey>(instance->get_precomputed());
    write_file(out / "vk", to_buffer(*vk));
}

} // namespace

int main(int argc, char** argv)
{
    if (argc < 3) {
        std::fprintf(stderr, "usage: avm_dump <avm_inputs.bin> <out_dir> [--inner]\n");
        return 2;
    }
    const std::filesystem::path out(argv[2]);
    const bool inner = argc > 3 && std::strcmp(argv[3], "--inner") == 0;
    std::filesystem::create_directories(out);
    srs::init_file_crs_factory(srs::bb_crs_path());

    auto inputs = avm2::AvmAPI::ProvingInputs::from(read_file(argv[1]));
    avm2::AvmAPI avm;
    auto proof = avm.prove(inputs);
    auto columns = inputs.public_inputs.to_columns();
    write_fields(out / "proof.bin", proof);
    write_fields(out / "public_inputs.bin", avm2::PublicInputs::columns_to_flat(columns));
    info("native verify: ", avm.verify(proof, inputs.public_inputs));

    if (inner) {
        dump_inner(proof, columns, out / "inner");
    }
    return 0;
}
