#pragma once
#include "poly_matrix.hpp"
#include "polynomial.hpp"
#include "shake128.hpp"

// Algorithms related to Saber Public Key Encryption
namespace saber_pke {

// Compile-time compute constant polynomial h1 ∈ Rq, following section 2.3 of spec.
template<const uint16_t moduli, const uint16_t εq, const uint16_t εp>
inline constexpr poly::poly_t<moduli>
compute_poly_h1()
  requires((εq > εp) && (moduli == (1u << εq)))
{
  constexpr auto v = 1u << (εq - εp - 1);
  constexpr zq::zq_t coeff(v);

  poly::poly_t<moduli> h1;
  for (size_t i = 0; i < poly::N; i++) {
    h1[i] = coeff;
  }

  return h1;
}

// Compile-time compute constant vector h ∈ Rq^(lx1), following section 2.3 of spec.
template<const size_t L, const uint16_t moduli, const uint16_t εq, const uint16_t εp>
inline constexpr mat::poly_matrix_t<L, 1, moduli>
compute_polyvec_h()
{
  const auto h1 = compute_poly_h1<moduli, εq, εp>();

  mat::poly_matrix_t<L, 1, moduli> h;
  for (size_t i = 0; i < L; i++) {
    h[i] = h1;
  }

  return h;
}

// Compile-time compute constant polynomial h2 ∈ Rq, following section 2.3 of spec.
template<const uint16_t moduli, const uint16_t εq, const uint16_t εp, const uint16_t εt>
inline constexpr poly::poly_t<moduli>
compute_poly_h2()
  requires(((εq > εp) && (εp > εt)) && (moduli == (1u << εq)))
{
  constexpr auto v = (1u << (εp - 2)) - (1u << (εp - εt - 1)) + (1u << (εq - εp - 1));
  constexpr zq::zq_t coeff(v);

  poly::poly_t<moduli> h2;
  for (size_t i = 0; i < poly::N; i++) {
    h2[i] = coeff;
  }

  return h2;
}

// Given seedAbytes -bytes `seedA` ( used for generating matrix A ) and seedSbytes
// -bytes `seedS` ( used for generating secret vector s ), this routine can be used for
// generating a Saber PKE public, private keypair.
template<const size_t L,
         const size_t EQ,
         const size_t EP,
         const size_t MU,
         const size_t seedAbytes,
         const size_t seedSbytes>
inline void
keygen(std::span<const uint8_t, seedAbytes> seedA,
       std::span<const uint8_t, seedSbytes> seedS,
       std::span<uint8_t, saber_utils::pke_pklen<L, EP, seedAbytes>()> pkey,
       std::span<uint8_t, saber_utils::pke_sklen<L, EQ>()> skey)
{
  constexpr uint16_t Q = 1u << EQ;
  constexpr uint16_t P = 1u << EP;
  constexpr auto h = compute_polyvec_h<L, Q, EQ, EP>();

  std::array<uint8_t, seedAbytes> hashedSeedA{};

  shake128::shake128 hasher;
  hasher.absorb(seedA.data(), seedA.size());
  hasher.finalize();
  hasher.squeeze(hashedSeedA.data(), hashedSeedA.size());
  hasher.reset();

  auto A = mat::poly_matrix_t<L, L, Q>::template gen_matrix<seedAbytes>(hashedSeedA);
  auto s = mat::poly_matrix_t<L, 1, Q>::template gen_secret<seedSbytes, MU>(seedS);

  auto A_T = A.transpose();
  auto b = A_T.mat_vec_mul<L>(s) + h;
  auto b_p = (b >> (EQ - EP)).template mod<P>();

  s.to_bytes(skey);
  b_p.to_bytes(pkey.subspan(seedAbytes, pkey.size() - seedAbytes));
  std::memcpy(pkey.data(), hashedSeedA.data(), seedAbytes);
}

}
