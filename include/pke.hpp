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
// generating a Saber PKE public, private keypair, following algorithm 17 in
// section 8.4.1 of Saber spec.
template<const size_t L,
         const size_t EQ,
         const size_t EP,
         const size_t MU,
         const size_t seedAbytes,
         const size_t seedSbytes>
inline void
keygen(std::span<const uint8_t, seedAbytes> seedA, // step 1
       std::span<const uint8_t, seedSbytes> seedS, // step 3
       std::span<uint8_t, saber_utils::pke_pklen<L, EP, seedAbytes>()> pkey,
       std::span<uint8_t, saber_utils::pke_sklen<L, EQ>()> skey)
{
  constexpr uint16_t Q = 1u << EQ;
  constexpr uint16_t P = 1u << EP;
  constexpr auto h = compute_polyvec_h<L, Q, EQ, EP>();

  std::array<uint8_t, seedAbytes> hashedSeedA{};

  // step 2
  shake128::shake128 hasher;
  hasher.absorb(seedA.data(), seedA.size());
  hasher.finalize();
  hasher.squeeze(hashedSeedA.data(), hashedSeedA.size());
  hasher.reset();

  // step 4, 5
  auto A = mat::poly_matrix_t<L, L, Q>::template gen_matrix<seedAbytes>(hashedSeedA);
  auto s = mat::poly_matrix_t<L, 1, Q>::template gen_secret<seedSbytes, MU>(seedS);

  // step 6, 7, 8
  auto A_T = A.transpose();
  auto b = A_T.template mat_vec_mul<L>(s) + h;
  auto b_p = (b >> (EQ - EP)).template mod<P>();

  // step 9, 10, 11
  s.to_bytes(skey);
  b_p.to_bytes(pkey.subspan(seedAbytes, pkey.size() - seedAbytes));
  std::memcpy(pkey.data(), hashedSeedA.data(), seedAbytes);
}

// Given 32 -bytes input message, seedSbytes -bytes `seedS` and Saber PKE public key,
// this routine can be used for encrypting fixed length message using Saber public key
// encryption algorithm, computing a cipher text. This routine is an implementation of
// algorithm 18 in section 8.4.2 of Saber spec.
template<const size_t L,
         const size_t EQ,
         const size_t EP,
         const size_t ET,
         const size_t MU,
         const size_t seedSbytes>
inline void
encrypt(std::span<const uint8_t, 32> msg,
        std::span<const uint8_t, seedSbytes> seedS,
        std::span<const uint8_t, saber_utils::pke_pklen<L, EP, seedSbytes>()> pkey,
        std::span<uint8_t, saber_utils::pke_ctlen<L, EP, ET>()> ctxt)
{
  constexpr uint16_t Q = 1u << EQ;
  constexpr uint16_t P = 1u << EP;
  constexpr uint16_t T = 1u << ET;

  constexpr auto h1 = compute_poly_h1<Q, EQ, EP>();
  constexpr auto h = compute_polyvec_h<L, Q, EQ, EP>();

  // step 1
  auto seedA = pkey.subspan(0, seedSbytes);
  auto pk = pkey.subspan(seedSbytes, pkey.size() - seedSbytes);

  // step 2, 3
  auto A = mat::poly_matrix_t<L, L, Q>::template gen_matrix<seedSbytes>(seedA);
  auto s_prm = mat::poly_matrix_t<L, 1, Q>::template gen_secret<seedSbytes, MU>(seedS);

  // step 4, 5, 6
  auto b_prm = A.template mat_vec_mul<L>(s_prm) + h;
  auto b_prm_p = (b_prm >> (EQ - EP)).template mod<P>();

  // step 7, 8
  mat::poly_matrix_t<L, 1, P> b(pk);
  auto s_prm_p = s_prm.template mod<P>();
  auto v_prm = b.inner_prod(s_prm_p);

  // step 9, 10
  poly::poly_t<2> m_p(msg);
  m_p = m_p << (EP - 1);

  // step 11
  auto c_m = (v_prm - m_p + (h1.template mod<P>())) >> (EP - ET);

  constexpr size_t c_m_len = (ET * poly::N) / 8;
  constexpr size_t b_prm_p_len = (L * EP * poly::N) / 8;
  static_assert(c_m_len + b_prm_p_len == ctxt.size(), "Cipher text size must match !");

  // step 12
  (c_m.template mod<T>()).to_bytes(ctxt.subspan(0, c_m_len));
  b_prm_p.to_bytes(ctxt.subspan(c_m_len, b_prm_p_len));
}

// Given Saber PKE cipher text and Saber PKE secret key, this routine can be used for
// decrypting the cipher text to 32 -bytes plain text message, which was encrypted using
// corresponding ( associated with this secret key ) Saber PKE public key. This routine
// is an implementation of algorithm 19 in section 8.4.3 of Saber spec.
template<const size_t L,
         const size_t EQ,
         const size_t EP,
         const size_t ET,
         const size_t MU>
inline void
decrypt(std::span<const uint8_t, saber_utils::pke_ctlen<L, EP, ET>()> ctxt,
        std::span<const uint8_t, saber_utils::pke_sklen<L, EQ>()> skey,
        std::span<uint8_t, 32> msg)
{
  constexpr uint16_t Q = 1u << EQ;
  constexpr uint16_t P = 1u << EP;
  constexpr uint16_t T = 1u << ET;

  constexpr auto h2 = compute_poly_h2<Q, EQ, EP, ET>();

  // step 2
  mat::poly_matrix_t<L, 1, Q> s(skey);

  // step 3, 4, 5
  constexpr size_t cm_len = (ET * poly::N) / 8;
  poly::poly_t<T> c_m(ctxt.subspan(0, cm_len));
  c_m = c_m << (EP - ET);

  // step 6
  constexpr size_t ct_len = (L * EP * poly::N) / 8;
  mat::poly_matrix_t<L, 1, P> b_prm(ctxt.subspan(cm_len, ct_len));

  // step 7, 8
  auto v = b_prm.inner_prod(s.template mod<P>());
  auto m_p = (v - c_m.template mod<P>() + h2.template mod<P>()) >> (EP - 1);

  // step 9
  (m_p.template mod<2>()).to_bytes(msg);
}

}
