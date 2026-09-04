// bb's q1s1 VectorField kernels compiled with bb's own toolchain/flags and
// linked into the bb-ref wasm module: the mul body's scheduling barriers
// (vector_field_mont_mul_body.inl.hpp) are clang-level and cannot be expressed
// from Rust/LLVM — see bench-results/LADDER.md. The wasm stored form on both
// sides is x*2^261 in 4x64 limbs, so bb::fr/fq apply to bb-ref's stored bytes
// verbatim; bb ops emit coarse [0, 2p), so results are reduced once on the way
// out (bb-ref stores canonically). bb asserts are release-active and pull
// ostringstream + libc++; trap instead (the kernel is exercised by bb-ref's
// byte gates, and a trap is as loud as bb::assert_failure here).
#include "barretenberg/common/assert.hpp"
#undef BB_ASSERT
#undef BB_ASSERT_EQ
#undef BB_ASSERT_NEQ
#undef BB_ASSERT_GT
#undef BB_ASSERT_GTE
#undef BB_ASSERT_LT
#undef BB_ASSERT_LTE
#undef BB_ASSERT_DEBUG
#define BB_TRAP_UNLESS(c)                                                      \
  do {                                                                         \
    if (!(c))                                                                  \
      __builtin_trap();                                                        \
  } while (0)
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
#include "barretenberg/ecc/fields/bernstein_yang_inverse.hpp"
#include "barretenberg/ecc/fields/vector_field.hpp"
#include "barretenberg/ecc/groups/affine_add_packed.hpp"
#include <string>

// bb's batch_invert / field::invert report a zero input through throw_or_abort
// / assert_failure, which the standalone build must supply (bb links these from
// env / common). Our callers filter equal-x pairs before the drain, so a zero
// denominator is a bug — trap.
extern "C" void throw_or_abort_impl(char const *) { __builtin_trap(); }
namespace bb {
void assert_failure(std::string const &) { __builtin_trap(); }
} // namespace bb

namespace {

// Field inverse via bb's Bernstein-Yang wasm path, bypassing field::invert's
// zero-assert (tree denominators are non-zero by construction) so the hot path
// carries no libc++ / trap machinery.
template <typename Field, typename Params>
[[gnu::always_inline]] inline Field invert_clean(const Field &x) {
  constexpr bb::numeric::uint256_t p_uint = Field::modulus;
  constexpr uint64_t p_inv =
      bb::bernstein_yang::p_inv_mod_2k_from_montgomery_r_inv(Params::r_inv);
  Field non_mont = x.from_montgomery_form_reduced();
  bb::numeric::uint256_t a{non_mont.data[0], non_mont.data[1], non_mont.data[2],
                           non_mont.data[3]};
  bb::numeric::uint256_t inv =
      bb::bernstein_yang::invert_vartime(a, p_uint, p_inv);
  Field r{inv.data[0], inv.data[1], inv.data[2], inv.data[3]};
  r.self_to_montgomery_form();
  return r;
}

template <typename Params, typename Field>
void axpy(uint64_t *dst_, const uint64_t *src_, const uint64_t *scalar_,
          size_t n) {
  using VF = bb::VectorField<Params>;
  auto *d = reinterpret_cast<Field *>(dst_);
  const auto *a = reinterpret_cast<const Field *>(src_);
  const Field s = *reinterpret_cast<const Field *>(scalar_);
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

// Batched affine chord additions over stored coordinates, split in two phases
// so the single field inversion happens on the Rust side (bb's invert pulls
// throw_or_abort/std::string). n must be a multiple of VF::SIZE (caller pads
// with a repeated valid pair); dx/prod hold n elements each. Phase 1 fills dx =
// bx - ax and the five-lane running products; the caller inverts the last
// VF::SIZE products; phase 2 unwinds the chain and applies lambda = dy/dx, x3 =
// lambda^2 - ax - bx, y3 = lambda (ax - x3) - ay, reduced once.
template <typename Params, typename Field>
void chord_phase1(const uint64_t *ax_, const uint64_t *bx_, size_t n,
                  uint64_t *dx_, uint64_t *prod_) {
  using VF = bb::VectorField<Params>;
  constexpr size_t W = VF::SIZE;
  const auto *ax = reinterpret_cast<const Field *>(ax_);
  const auto *bx = reinterpret_cast<const Field *>(bx_);
  auto *dx = reinterpret_cast<Field *>(dx_);
  auto *prod = reinterpret_cast<Field *>(prod_);
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
void chord_phase2(const uint64_t *ax_, const uint64_t *ay_, const uint64_t *bx_,
                  const uint64_t *by_, size_t n, uint64_t *dx_,
                  const uint64_t *prod_, const uint64_t *lane_inv_,
                  uint64_t *ox_, uint64_t *oy_) {
  using VF = bb::VectorField<Params>;
  constexpr size_t W = VF::SIZE;
  const auto *ax = reinterpret_cast<const Field *>(ax_);
  const auto *ay = reinterpret_cast<const Field *>(ay_);
  const auto *bx = reinterpret_cast<const Field *>(bx_);
  const auto *by = reinterpret_cast<const Field *>(by_);
  auto *dx = reinterpret_cast<Field *>(dx_);
  const auto *prod = reinterpret_cast<const Field *>(prod_);
  const auto *lane_inv = reinterpret_cast<const Field *>(lane_inv_);
  auto *ox = reinterpret_cast<Field *>(ox_);
  auto *oy = reinterpret_cast<Field *>(oy_);
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

// Batched affine doublings, same two-phase split as the chords: phase 1 fills
// den = 2y and the five-lane running products; the caller inverts the last
// VF::SIZE products; phase 2 unwinds and applies lambda = 3x^2 / 2y, x3 =
// lambda^2 - 2x, y3 = lambda (x - x3) - y, reduced once. n must be a multiple
// of VF::SIZE (caller pads with a valid point, outputs ignored).
template <typename Params, typename Field>
void dbl_phase1(const uint64_t *y_, size_t n, uint64_t *den_, uint64_t *prod_) {
  using VF = bb::VectorField<Params>;
  constexpr size_t W = VF::SIZE;
  const auto *y = reinterpret_cast<const Field *>(y_);
  auto *den = reinterpret_cast<Field *>(den_);
  auto *prod = reinterpret_cast<Field *>(prod_);
  const size_t blocks = n / W;
  for (size_t g = 0; g < blocks; ++g) {
    const VF vy(&y[g * W]);
    VF d = vy + vy;
    d.store_to(&den[g * W]);
    if (g == 0) {
      d.store_to(&prod[0]);
    } else {
      const VF p(&prod[(g - 1) * W]);
      (p * d).store_to(&prod[g * W]);
    }
  }
}

template <typename Params, typename Field>
void dbl_phase2(const uint64_t *x_, const uint64_t *y_, size_t n,
                uint64_t *den_, const uint64_t *prod_,
                const uint64_t *lane_inv_, uint64_t *ox_, uint64_t *oy_) {
  using VF = bb::VectorField<Params>;
  constexpr size_t W = VF::SIZE;
  const auto *x = reinterpret_cast<const Field *>(x_);
  const auto *y = reinterpret_cast<const Field *>(y_);
  auto *den = reinterpret_cast<Field *>(den_);
  const auto *prod = reinterpret_cast<const Field *>(prod_);
  const auto *lane_inv = reinterpret_cast<const Field *>(lane_inv_);
  auto *ox = reinterpret_cast<Field *>(ox_);
  auto *oy = reinterpret_cast<Field *>(oy_);
  const size_t blocks = n / W;
  {
    VF vinv(&lane_inv[0]);
    for (size_t g = blocks; g-- > 1;) {
      const VF p(&prod[(g - 1) * W]);
      const VF d(&den[g * W]);
      (vinv * p).store_to(&den[g * W]);
      vinv = vinv * d;
    }
    vinv.store_to(&den[0]);
  }
  for (size_t g = 0; g < blocks; ++g) {
    const VF vx(&x[g * W]);
    const VF vy(&y[g * W]);
    const VF vinv(&den[g * W]);
    const VF xx = vx * vx;
    const VF lambda = (xx + xx + xx) * vinv;
    const VF x3 = lambda * lambda - (vx + vx);
    const VF y3 = lambda * (vx - x3) - vy;
    x3.store_to(&ox[g * W]);
    y3.store_to(&oy[g * W]);
    for (size_t k = 0; k < W; ++k) {
      ox[g * W + k].self_reduce_once();
      oy[g * W + k].self_reduce_once();
    }
  }
}

// chord_phase2 variant that scatters results straight into a 64-byte {x,y}
// point array by index (ark Affine<bn254> is exactly {Fq x; Fq y}), avoiding
// the ox/oy roundtrip. Inputs come from the caller's already-staged
// ax/ay/bx/by, so scatter order can't alias the gather.
template <typename Params, typename Field>
void chord_phase2_scatter(const uint64_t *ax_, const uint64_t *ay_,
                          const uint64_t *bx_, const uint64_t *by_, size_t n,
                          uint64_t *dx_, const uint64_t *prod_,
                          const uint64_t *lane_inv_, const uint32_t *dst,
                          uint64_t *points) {
  using VF = bb::VectorField<Params>;
  constexpr size_t W = VF::SIZE;
  const auto *ax = reinterpret_cast<const Field *>(ax_);
  const auto *ay = reinterpret_cast<const Field *>(ay_);
  const auto *bx = reinterpret_cast<const Field *>(bx_);
  const auto *by = reinterpret_cast<const Field *>(by_);
  auto *dx = reinterpret_cast<Field *>(dx_);
  const auto *prod = reinterpret_cast<const Field *>(prod_);
  const auto *lane_inv = reinterpret_cast<const Field *>(lane_inv_);
  auto *pts =
      reinterpret_cast<Field *>(points); // {x,y} pairs, 2 Field per point
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
  Field ox[W];
  Field oy[W];
  for (size_t g = 0; g < blocks; ++g) {
    const VF vax(&ax[g * W]);
    const VF vay(&ay[g * W]);
    const VF vbx(&bx[g * W]);
    const VF vby(&by[g * W]);
    const VF vinv(&dx[g * W]);
    const VF lambda = (vby - vay) * vinv;
    const VF x3 = lambda * lambda - (vax + vbx);
    const VF y3 = lambda * (vax - x3) - vay;
    x3.store_to(&ox[0]);
    y3.store_to(&oy[0]);
    for (size_t k = 0; k < W; ++k) {
      const uint32_t d = dst[g * W + k];
      pts[2 * d] = ox[k].reduce_once();
      pts[2 * d + 1] = oy[k].reduce_once();
    }
  }
}

// Two-phase chord add that keeps its intermediates PACKED between the phases.
// Phase 1 packs the four operands once and stores ax/ay/dx/dy/xsum and the
// prefix products as VectorFields in scratch (plain copies, no unpack); phase 2
// reads them back as VectorFields (no re-pack), unwinds the chain, finishes,
// and scatters. The previous pair of kernels round-tripped every intermediate
// through unpacked Field arrays: 9 packs + 5 unpacks per block around 6
// multiplies. This is 4 packs + 2 unpacks. scratch holds 6 VectorFields per
// W-block; lane_tot gets the W chain totals.
template <typename Params, typename Field>
void chord1_packed(const uint64_t *ax_, const uint64_t *ay_,
                   const uint64_t *bx_, const uint64_t *by_, size_t n,
                   uint64_t *scratch, uint64_t *lane_tot_) {
  using VF = bb::VectorField<Params>;
  constexpr size_t W = VF::SIZE;
  const auto *ax = reinterpret_cast<const Field *>(ax_);
  const auto *ay = reinterpret_cast<const Field *>(ay_);
  const auto *bx = reinterpret_cast<const Field *>(bx_);
  const auto *by = reinterpret_cast<const Field *>(by_);
  const size_t blocks = n / W;
  VF *AX = reinterpret_cast<VF *>(scratch);
  VF *AY = AX + blocks;
  VF *DX = AY + blocks;
  VF *DY = DX + blocks;
  VF *XS = DY + blocks;
  VF *PR = XS + blocks;
  VF acc = VF::broadcast(Field::one());
  for (size_t g = 0; g < blocks; ++g) {
    const VF vax(&ax[g * W]), vay(&ay[g * W]), vbx(&bx[g * W]), vby(&by[g * W]);
    AX[g] = vax;
    AY[g] = vay;
    const VF dx = vbx - vax;
    DX[g] = dx;
    DY[g] = vby - vay;
    XS[g] = vax + vbx;
    acc = acc * dx;
    PR[g] = acc;
  }
  acc.store_to(reinterpret_cast<Field *>(lane_tot_));
}

template <typename Params, typename Field>
void chord2_packed(size_t n, uint64_t *scratch, const uint64_t *lane_inv_,
                   const uint32_t *dst, uint64_t *points) {
  using VF = bb::VectorField<Params>;
  constexpr size_t W = VF::SIZE;
  const size_t blocks = n / W;
  VF *AX = reinterpret_cast<VF *>(scratch);
  VF *AY = AX + blocks;
  VF *DX = AY + blocks;
  VF *DY = DX + blocks;
  VF *XS = DY + blocks;
  VF *PR = XS + blocks;
  auto *pts = reinterpret_cast<Field *>(points);
  VF vinv(reinterpret_cast<const Field *>(lane_inv_));
  for (size_t g = blocks; g-- > 0;) {
    const VF dxg = DX[g];
    DX[g] = (g == 0) ? vinv : vinv * PR[g - 1];
    vinv = vinv * dxg;
  }
  for (size_t g = 0; g < blocks; ++g) {
    const VF slope = DY[g] * DX[g];
    const VF x3 = slope * slope - XS[g];
    const VF y3 = slope * (AX[g] - x3) - AY[g];
    Field ox[W], oy[W];
    x3.store_to(&ox[0]);
    y3.store_to(&oy[0]);
    for (size_t k = 0; k < W; ++k) {
      const uint32_t d = dst[g * W + k];
      pts[2 * d] = ox[k].reduce_once();
      pts[2 * d + 1] = oy[k].reduce_once();
    }
  }
}

} // namespace

// ===== bb Stage 6a inner loop: reduce_chunk -> tree_reduce_in_place ->
// drain_batch ===== Direct port of the anonymous-namespace templates in
// scalar_multiplication_fast.cpp, over caller-owned scratch: `pts` is an AoS
// {x, y} point array (bb-ref's 64 B Affine), `buckets` its parallel 0-based
// bucket ids, `packed` eight VectorField runs of PACK_CAP (lhs.x lhs.y rhs.x
// rhs.y dx dy xsum inv; out aliases lhs), `pair_dest` the BATCH_CAPACITY
// write-back slots. Two deltas from bb, both required by bb-ref: outputs are
// reduced to canonical form on write (bb-ref stores [0,p) and compares
// coordinates), and a same-bucket equal-x pair is settled inline (doubling /
// cancellation) rather than assumed away — bb's "unsafe" path only ever sees
// linearly independent SRS points, but bb-ref's msm() also serves general
// callers.
namespace {

constexpr size_t BB_BATCH_CAPACITY = 256;

template <typename Params, typename Field> struct Reduce6a {
  using VF = bb::VectorField<Params>;
  static constexpr size_t W = VF::SIZE;
  static constexpr size_t PACK_CAP = BB_BATCH_CAPACITY / W + 1;

  Field *pts;
  uint32_t *buckets;
  bb::VectorAffineElementPushSpan<Params> lhs, rhs, out;
  bb::group_elements::BatchAffineAddScratch<Params> add_scratch;
  uint32_t *pair_dest;

  Reduce6a(uint64_t *pts_, uint32_t *buckets_, uint64_t *packed,
           uint32_t *pair_dest_)
      : pts(reinterpret_cast<Field *>(pts_)), buckets(buckets_),
        pair_dest(pair_dest_) {
    VF *runs = reinterpret_cast<VF *>(packed);
    auto run = [&](size_t k) {
      return std::span<VF>(runs + k * PACK_CAP, PACK_CAP);
    };
    lhs = {run(0), run(1)};
    rhs = {run(2), run(3)};
    out = {run(0), run(1)};
    add_scratch = {bb::VectorFieldPushSpan<Params>{run(4)},
                   bb::VectorFieldPushSpan<Params>{run(5)},
                   bb::VectorFieldPushSpan<Params>{run(6)},
                   bb::VectorFieldPushSpan<Params>{run(7)}};
  }

  void drain_batch(size_t pair_count) {
    if (pair_count == 0) {
      return;
    }
    bb::group_elements::batch_affine_add(lhs, rhs, out, add_scratch);
    size_t k = 0;
    for (size_t g = 0; g < out.num_full_vectors(); ++g) {
      const auto xs = out.x[g].to_array();
      const auto ys = out.y[g].to_array();
      for (size_t l = 0; l < W; ++l, ++k) {
        pts[2 * pair_dest[k]] = xs[l].reduce_once();
        pts[2 * pair_dest[k] + 1] = ys[l].reduce_once();
      }
    }
    const auto *xt = out.x.tail_data();
    const auto *yt = out.y.tail_data();
    for (size_t t = 0; t < out.tail(); ++t, ++k) {
      pts[2 * pair_dest[k]] = xt[t].reduce_once();
      pts[2 * pair_dest[k] + 1] = yt[t].reduce_once();
    }
    lhs.reset();
    rhs.reset();
  }

  size_t tree_reduce_in_place(size_t initial_len) {
    size_t curr_len = initial_len;
    lhs.reset();
    rhs.reset();
    while (true) {
      size_t i = 0, next_len = 0, pair_count = 0;
      bool made_pair = false;
      while (i < curr_len) {
        if (i + 1 < curr_len && buckets[i] == buckets[i + 1]) {
          const Field x1 = pts[2 * i], y1 = pts[2 * i + 1];
          const Field x2 = pts[2 * i + 2], y2 = pts[2 * i + 3];
          made_pair = true;
          // Identity handling (bb-ref only; bb's unsafe path never sees
          // infinity). bn254/grumpkin have no 2-torsion, so y == 0 iff the
          // point is the (0,0) identity. a + 0 = a; 0 + 0 = 0.
          const bool z1 = x1.is_zero() && y1.is_zero();
          const bool z2 = x2.is_zero() && y2.is_zero();
          if (z1 || z2) {
            if (!(z1 && z2)) {
              pts[2 * next_len] = z1 ? x2 : x1;
              pts[2 * next_len + 1] = z1 ? y2 : y1;
              buckets[next_len] = buckets[i];
              ++next_len;
            }
            i += 2;
            continue;
          }
          if (x1 == x2) {
            // Equal x: double if same point, else the sum is infinity (drop).
            if (y1 == y2) {
              const Field inv = invert_clean<Field, Params>(y1 + y1);
              const Field xx = x1 * x1;
              const Field lam = (xx + xx + xx) * inv;
              const Field x3 = (lam * lam - x1 - x1).reduce_once();
              const Field y3 = (lam * (x1 - x3) - y1).reduce_once();
              pts[2 * next_len] = x3;
              pts[2 * next_len + 1] = y3;
              buckets[next_len] = buckets[i];
              ++next_len;
            }
            i += 2;
            continue;
          }
          lhs.push_point(x1, y1);
          rhs.push_point(x2, y2);
          buckets[next_len] = buckets[i];
          pair_dest[pair_count] = static_cast<uint32_t>(next_len);
          ++next_len;
          ++pair_count;
          i += 2;
          if (pair_count >= BB_BATCH_CAPACITY) {
            drain_batch(pair_count);
            pair_count = 0;
          }
        } else {
          pts[2 * next_len] = pts[2 * i];
          pts[2 * next_len + 1] = pts[2 * i + 1];
          buckets[next_len] = buckets[i];
          ++next_len;
          ++i;
        }
      }
      drain_batch(pair_count);
      if (!made_pair) {
        break;
      }
      curr_len = next_len;
    }
    return curr_len;
  }

  size_t reduce_chunk(const Field *points, const Field *phi, const Field *beta,
                      const uint32_t *sched, size_t lo, size_t hi,
                      const uint32_t *bstarts, size_t *b_cursor) {
    size_t b = *b_cursor;
    size_t valid = 0;
    for (size_t i = lo; i < hi; ++i) {
      while (bstarts[b + 1] <= i) {
        ++b;
      }
      const uint32_t e = sched[i];
      const size_t idx = e & 0x3fffffffu;
      const Field *src =
          ((e & (1u << 30)) != 0 && phi != nullptr) ? phi : points;
      pts[2 * valid] = src[2 * idx];
      pts[2 * valid + 1] =
          ((e >> 31) != 0) ? -src[2 * idx + 1] : src[2 * idx + 1];
      buckets[valid] = static_cast<uint32_t>(b);
      ++valid;
    }
    *b_cursor = b;
    return tree_reduce_in_place(valid);
  }
};

} // namespace

extern "C" {
size_t bbref_batch_capacity() { return BB_BATCH_CAPACITY; }
size_t bbref_pack_cap() {
  return Reduce6a<bb::Bn254FqParams, bb::fq>::PACK_CAP;
}
size_t bbref_reduce_chunk_fq(const uint64_t *points, const uint64_t *phi, const uint64_t *beta,
                             const uint32_t *sched, size_t lo, size_t hi,
                             const uint32_t *bstarts, size_t *b_cursor,
                             uint64_t *pts, uint32_t *buckets, uint64_t *packed,
                             uint32_t *pair_dest) {
  Reduce6a<bb::Bn254FqParams, bb::fq> r(pts, buckets, packed, pair_dest);
  return r.reduce_chunk(reinterpret_cast<const bb::fq *>(points),
                        reinterpret_cast<const bb::fq *>(phi),
                        reinterpret_cast<const bb::fq *>(beta), sched, lo, hi,
                        bstarts, b_cursor);
}
size_t bbref_reduce_chunk_fr(const uint64_t *points, const uint64_t *phi, const uint64_t *beta,
                             const uint32_t *sched, size_t lo, size_t hi,
                             const uint32_t *bstarts, size_t *b_cursor,
                             uint64_t *pts, uint32_t *buckets, uint64_t *packed,
                             uint32_t *pair_dest) {
  Reduce6a<bb::Bn254FrParams, bb::fr> r(pts, buckets, packed, pair_dest);
  return r.reduce_chunk(reinterpret_cast<const bb::fr *>(points),
                        reinterpret_cast<const bb::fr *>(phi),
                        reinterpret_cast<const bb::fr *>(beta), sched, lo, hi,
                        bstarts, b_cursor);
}
size_t bbref_tree_reduce_fq(uint64_t *pts, uint32_t *buckets, size_t len,
                            uint64_t *packed, uint32_t *pair_dest) {
  Reduce6a<bb::Bn254FqParams, bb::fq> r(pts, buckets, packed, pair_dest);
  return r.tree_reduce_in_place(len);
}
size_t bbref_tree_reduce_fr(uint64_t *pts, uint32_t *buckets, size_t len,
                            uint64_t *packed, uint32_t *pair_dest) {
  Reduce6a<bb::Bn254FrParams, bb::fr> r(pts, buckets, packed, pair_dest);
  return r.tree_reduce_in_place(len);
}
}

extern "C" {
void bbref_axpy_fr(uint64_t *dst, const uint64_t *src, const uint64_t *scalar,
                   size_t n) {
  axpy<bb::Bn254FrParams, bb::fr>(dst, src, scalar, n);
}
void bbref_axpy_fq(uint64_t *dst, const uint64_t *src, const uint64_t *scalar,
                   size_t n) {
  axpy<bb::Bn254FqParams, bb::fq>(dst, src, scalar, n);
}
size_t bbref_chord_width() { return bb::VectorField<bb::Bn254FrParams>::SIZE; }
void bbref_chord1_fr(const uint64_t *ax, const uint64_t *bx, size_t n,
                     uint64_t *dx, uint64_t *prod) {
  chord_phase1<bb::Bn254FrParams, bb::fr>(ax, bx, n, dx, prod);
}
void bbref_chord1_fq(const uint64_t *ax, const uint64_t *bx, size_t n,
                     uint64_t *dx, uint64_t *prod) {
  chord_phase1<bb::Bn254FqParams, bb::fq>(ax, bx, n, dx, prod);
}
void bbref_chord2_fr(const uint64_t *ax, const uint64_t *ay, const uint64_t *bx,
                     const uint64_t *by, size_t n, uint64_t *dx,
                     const uint64_t *prod, const uint64_t *lane_inv,
                     uint64_t *ox, uint64_t *oy) {
  chord_phase2<bb::Bn254FrParams, bb::fr>(ax, ay, bx, by, n, dx, prod, lane_inv,
                                          ox, oy);
}
static_assert(sizeof(bb::VectorField<bb::Bn254FrParams>) ==
              sizeof(bb::VectorField<bb::Bn254FqParams>));
size_t bbref_vf_size() { return sizeof(bb::VectorField<bb::Bn254FrParams>); }
void bbref_chord1p_fr(const uint64_t *ax, const uint64_t *ay,
                      const uint64_t *bx, const uint64_t *by, size_t n,
                      uint64_t *scratch, uint64_t *lane_tot) {
  chord1_packed<bb::Bn254FrParams, bb::fr>(ax, ay, bx, by, n, scratch,
                                           lane_tot);
}
void bbref_chord1p_fq(const uint64_t *ax, const uint64_t *ay,
                      const uint64_t *bx, const uint64_t *by, size_t n,
                      uint64_t *scratch, uint64_t *lane_tot) {
  chord1_packed<bb::Bn254FqParams, bb::fq>(ax, ay, bx, by, n, scratch,
                                           lane_tot);
}
void bbref_chord2p_fr(size_t n, uint64_t *scratch, const uint64_t *lane_inv,
                      const uint32_t *dst, uint64_t *points) {
  chord2_packed<bb::Bn254FrParams, bb::fr>(n, scratch, lane_inv, dst, points);
}
void bbref_chord2p_fq(size_t n, uint64_t *scratch, const uint64_t *lane_inv,
                      const uint32_t *dst, uint64_t *points) {
  chord2_packed<bb::Bn254FqParams, bb::fq>(n, scratch, lane_inv, dst, points);
}
void bbref_chord2s_fr(const uint64_t *ax, const uint64_t *ay,
                      const uint64_t *bx, const uint64_t *by, size_t n,
                      uint64_t *dx, const uint64_t *prod,
                      const uint64_t *lane_inv, const uint32_t *dst,
                      uint64_t *points) {
  chord_phase2_scatter<bb::Bn254FrParams, bb::fr>(ax, ay, bx, by, n, dx, prod,
                                                  lane_inv, dst, points);
}
void bbref_chord2s_fq(const uint64_t *ax, const uint64_t *ay,
                      const uint64_t *bx, const uint64_t *by, size_t n,
                      uint64_t *dx, const uint64_t *prod,
                      const uint64_t *lane_inv, const uint32_t *dst,
                      uint64_t *points) {
  chord_phase2_scatter<bb::Bn254FqParams, bb::fq>(ax, ay, bx, by, n, dx, prod,
                                                  lane_inv, dst, points);
}
void bbref_dbl1_fr(const uint64_t *y, size_t n, uint64_t *den, uint64_t *prod) {
  dbl_phase1<bb::Bn254FrParams, bb::fr>(y, n, den, prod);
}
void bbref_dbl1_fq(const uint64_t *y, size_t n, uint64_t *den, uint64_t *prod) {
  dbl_phase1<bb::Bn254FqParams, bb::fq>(y, n, den, prod);
}
void bbref_dbl2_fr(const uint64_t *x, const uint64_t *y, size_t n,
                   uint64_t *den, const uint64_t *prod,
                   const uint64_t *lane_inv, uint64_t *ox, uint64_t *oy) {
  dbl_phase2<bb::Bn254FrParams, bb::fr>(x, y, n, den, prod, lane_inv, ox, oy);
}
void bbref_dbl2_fq(const uint64_t *x, const uint64_t *y, size_t n,
                   uint64_t *den, const uint64_t *prod,
                   const uint64_t *lane_inv, uint64_t *ox, uint64_t *oy) {
  dbl_phase2<bb::Bn254FqParams, bb::fq>(x, y, n, den, prod, lane_inv, ox, oy);
}
void bbref_chord2_fq(const uint64_t *ax, const uint64_t *ay, const uint64_t *bx,
                     const uint64_t *by, size_t n, uint64_t *dx,
                     const uint64_t *prod, const uint64_t *lane_inv,
                     uint64_t *ox, uint64_t *oy) {
  chord_phase2<bb::Bn254FqParams, bb::fq>(ax, ay, bx, by, n, dx, prod, lane_inv,
                                          ox, oy);
}
}
