// bb's q1s1 VectorField kernels compiled with bb's own toolchain/flags and linked into the
// bb-ref wasm module: the mul body's scheduling barriers (vector_field_mont_mul_body.inl.hpp)
// are clang-level and cannot be expressed from Rust/LLVM — see bench-results/LADDER.md.
// The wasm stored form on both sides is x*2^261 in 4x64 limbs, so bb::fr/fq apply to bb-ref's
// stored bytes verbatim; bb ops emit coarse [0, 2p), so results are reduced once on the way out
// (bb-ref stores canonically).
// bb asserts are release-active and pull ostringstream + libc++; trap instead (the kernel is
// exercised by bb-ref's byte gates, and a trap is as loud as bb::assert_failure here).
#include "barretenberg/common/assert.hpp"
#undef BB_ASSERT
#undef BB_ASSERT_EQ
#undef BB_ASSERT_NEQ
#undef BB_ASSERT_GT
#undef BB_ASSERT_GTE
#undef BB_ASSERT_LT
#undef BB_ASSERT_LTE
#undef BB_ASSERT_DEBUG
#define BB_TRAP_UNLESS(c)                                                                                                  do {                                                                                                                       if (!(c))                                                                                                                  __builtin_trap();                                                                                              } while (0)
#define BB_ASSERT(expression, ...) BB_TRAP_UNLESS(expression)
#define BB_ASSERT_EQ(a, b, ...) BB_TRAP_UNLESS((a) == (b))
#define BB_ASSERT_NEQ(a, b, ...) BB_TRAP_UNLESS((a) != (b))
#define BB_ASSERT_GT(a, b, ...) BB_TRAP_UNLESS((a) > (b))
#define BB_ASSERT_GTE(a, b, ...) BB_TRAP_UNLESS((a) >= (b))
#define BB_ASSERT_LT(a, b, ...) BB_TRAP_UNLESS((a) < (b))
#define BB_ASSERT_LTE(a, b, ...) BB_TRAP_UNLESS((a) <= (b))
#define BB_ASSERT_DEBUG(expression, ...) BB_TRAP_UNLESS(expression)

#include "barretenberg/ecc/curves/bn254/fq.hpp"
#include "barretenberg/ecc/curves/bn254/fr.hpp"
#include "barretenberg/ecc/fields/vector_field.hpp"

namespace {

template <typename Params, typename Field>
void axpy(uint64_t* dst_, const uint64_t* src_, const uint64_t* scalar_, size_t n)
{
    using VF = bb::VectorField<Params>;
    auto* d = reinterpret_cast<Field*>(dst_);
    const auto* a = reinterpret_cast<const Field*>(src_);
    const Field s = *reinterpret_cast<const Field*>(scalar_);
    const VF sv = VF::broadcast(s);
    size_t i = 0;
    for (; i + VF::SIZE <= n; i += VF::SIZE) {
        VF acc(&d[i]);
        const VF va(&a[i]);
        acc = acc + va * sv;
        acc.store_to(&d[i]);
        for (size_t k = 0; k < VF::SIZE; ++k) {
            d[i + k].self_reduce_once();
        }
    }
    for (; i < n; ++i) {
        d[i] = (d[i] + a[i] * s).reduce_once();
    }
}

// Batched affine chord additions over stored coordinates, split in two phases so the single
// field inversion happens on the Rust side (bb's invert pulls throw_or_abort/std::string).
// n must be a multiple of VF::SIZE (caller pads with a repeated valid pair); dx/prod hold n
// elements each. Phase 1 fills dx = bx - ax and the five-lane running products; the caller
// inverts the last VF::SIZE products; phase 2 unwinds the chain and applies
// lambda = dy/dx, x3 = lambda^2 - ax - bx, y3 = lambda (ax - x3) - ay, reduced once.
template <typename Params, typename Field>
void chord_phase1(const uint64_t* ax_, const uint64_t* bx_, size_t n, uint64_t* dx_, uint64_t* prod_)
{
    using VF = bb::VectorField<Params>;
    constexpr size_t W = VF::SIZE;
    const auto* ax = reinterpret_cast<const Field*>(ax_);
    const auto* bx = reinterpret_cast<const Field*>(bx_);
    auto* dx = reinterpret_cast<Field*>(dx_);
    auto* prod = reinterpret_cast<Field*>(prod_);
    const size_t blocks = n / W;
    for (size_t g = 0; g < blocks; ++g) {
        const VF vax(&ax[g * W]);
        const VF vbx(&bx[g * W]);
        VF d = vbx - vax;
        d.store_to(&dx[g * W]);
        if (g == 0) {
            d.store_to(&prod[0]);
        } else {
            const VF p(&prod[(g - 1) * W]);
            (p * d).store_to(&prod[g * W]);
        }
    }
}

template <typename Params, typename Field>
void chord_phase2(const uint64_t* ax_,
                  const uint64_t* ay_,
                  const uint64_t* bx_,
                  const uint64_t* by_,
                  size_t n,
                  uint64_t* dx_,
                  const uint64_t* prod_,
                  const uint64_t* lane_inv_,
                  uint64_t* ox_,
                  uint64_t* oy_)
{
    using VF = bb::VectorField<Params>;
    constexpr size_t W = VF::SIZE;
    const auto* ax = reinterpret_cast<const Field*>(ax_);
    const auto* ay = reinterpret_cast<const Field*>(ay_);
    const auto* bx = reinterpret_cast<const Field*>(bx_);
    const auto* by = reinterpret_cast<const Field*>(by_);
    auto* dx = reinterpret_cast<Field*>(dx_);
    const auto* prod = reinterpret_cast<const Field*>(prod_);
    const auto* lane_inv = reinterpret_cast<const Field*>(lane_inv_);
    auto* ox = reinterpret_cast<Field*>(ox_);
    auto* oy = reinterpret_cast<Field*>(oy_);
    const size_t blocks = n / W;
    {
        VF vinv(&lane_inv[0]);
        for (size_t g = blocks; g-- > 1;) {
            const VF p(&prod[(g - 1) * W]);
            const VF d(&dx[g * W]);
            (vinv * p).store_to(&dx[g * W]);
            vinv = vinv * d;
        }
        vinv.store_to(&dx[0]);
    }
    for (size_t g = 0; g < blocks; ++g) {
        const VF vax(&ax[g * W]);
        const VF vay(&ay[g * W]);
        const VF vbx(&bx[g * W]);
        const VF vby(&by[g * W]);
        const VF vinv(&dx[g * W]);
        const VF lambda = (vby - vay) * vinv;
        const VF x3 = lambda * lambda - (vax + vbx);
        const VF y3 = lambda * (vax - x3) - vay;
        x3.store_to(&ox[g * W]);
        y3.store_to(&oy[g * W]);
        for (size_t k = 0; k < W; ++k) {
            ox[g * W + k].self_reduce_once();
            oy[g * W + k].self_reduce_once();
        }
    }
}

} // namespace

extern "C" {
void bbref_axpy_fr(uint64_t* dst, const uint64_t* src, const uint64_t* scalar, size_t n)
{
    axpy<bb::Bn254FrParams, bb::fr>(dst, src, scalar, n);
}
void bbref_axpy_fq(uint64_t* dst, const uint64_t* src, const uint64_t* scalar, size_t n)
{
    axpy<bb::Bn254FqParams, bb::fq>(dst, src, scalar, n);
}
size_t bbref_chord_width()
{
    return bb::VectorField<bb::Bn254FrParams>::SIZE;
}
void bbref_chord1_fr(const uint64_t* ax, const uint64_t* bx, size_t n, uint64_t* dx, uint64_t* prod)
{
    chord_phase1<bb::Bn254FrParams, bb::fr>(ax, bx, n, dx, prod);
}
void bbref_chord1_fq(const uint64_t* ax, const uint64_t* bx, size_t n, uint64_t* dx, uint64_t* prod)
{
    chord_phase1<bb::Bn254FqParams, bb::fq>(ax, bx, n, dx, prod);
}
void bbref_chord2_fr(const uint64_t* ax,
                     const uint64_t* ay,
                     const uint64_t* bx,
                     const uint64_t* by,
                     size_t n,
                     uint64_t* dx,
                     const uint64_t* prod,
                     const uint64_t* lane_inv,
                     uint64_t* ox,
                     uint64_t* oy)
{
    chord_phase2<bb::Bn254FrParams, bb::fr>(ax, ay, bx, by, n, dx, prod, lane_inv, ox, oy);
}
void bbref_chord2_fq(const uint64_t* ax,
                     const uint64_t* ay,
                     const uint64_t* bx,
                     const uint64_t* by,
                     size_t n,
                     uint64_t* dx,
                     const uint64_t* prod,
                     const uint64_t* lane_inv,
                     uint64_t* ox,
                     uint64_t* oy)
{
    chord_phase2<bb::Bn254FqParams, bb::fq>(ax, ay, bx, by, n, dx, prod, lane_inv, ox, oy);
}
}
