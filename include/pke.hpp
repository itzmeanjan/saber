#pragma once
#include "consts.hpp"
#include "params.hpp"
#include "poly_matrix.hpp"
#include "polynomial.hpp"
#include "shake128.hpp"

// Algorithms related to Saber Public Key Encryption
namespace saber_pke {

// Given seedBytes -bytes `seedA` ( used for generating matrix A ) and noiseBytes
// -bytes `seedS` ( used for generating secret vector s ), this routine can be used for
// generating a Saber PKE public, private keypair, following algorithm 17 in
// section 8.4.1 of Saber spec.
template<size_t L, size_t EQ, size_t EP, size_t MU, size_t seedBytes, size_t noiseBytes, bool uniform_sampling>
inline void
keygen(std::span<const uint8_t, seedBytes> seedA,  // step 1
       std::span<const uint8_t, noiseBytes> seedS, // step 3
       std::span<uint8_t, saber_utils::pke_pklen<L, EP, seedBytes>()> pkey,
       std::span<uint8_t, saber_utils::pke_sklen<L, EQ>()> skey)
  requires(saber_params::validate_pke_keygen_args(L, EQ, EP, MU, seedBytes, noiseBytes, uniform_sampling))
{
  constexpr uint16_t Q = 1u << EQ;
  constexpr uint16_t P = 1u << EP;
  constexpr auto h = saber_consts::compute_polyvec_h<L, Q, EQ, EP>();

  std::array<uint8_t, seedBytes> hashedSeedA{};

  // step 2
  shake128::shake128_t hasher;
  hasher.absorb(seedA);
  hasher.finalize();
  hasher.squeeze(hashedSeedA);
  hasher.reset();

  // step 4, 5
  auto A = mat::poly_matrix_t<L, L, Q>::template gen_matrix<seedBytes>(hashedSeedA);
  auto s = mat::poly_matrix_t<L, 1, Q>::template gen_secret<uniform_sampling, noiseBytes, MU>(seedS);

  // step 6, 7, 8
  auto A_T = A.transpose();
  auto b = A_T.template mat_vec_mul<L>(s) + h;
  auto b_p = (b >> (EQ - EP)).template mod<P>();

  // step 9
  s.to_bytes(skey);

  // step 10, 11
  auto pkey_pk = pkey.template subspan<0, pkey.size() - seedBytes>();
  auto pkey_seedA = pkey.template subspan<pkey_pk.size(), seedBytes>();

  b_p.to_bytes(pkey_pk);
  std::memcpy(pkey_seedA.data(), hashedSeedA.data(), seedBytes);
}

// Given 32 -bytes input message, seedBytes -bytes `seedS` and Saber PKE public key,
// this routine can be used for encrypting fixed length message using Saber public key
// encryption algorithm, computing a cipher text. This routine is an implementation of
// algorithm 18 in section 8.4.2 of Saber spec.
template<size_t L, size_t EQ, size_t EP, size_t ET, size_t MU, size_t seedBytes, bool uniform_sampling>
inline void
encrypt(std::span<const uint8_t, 32> msg,
        std::span<const uint8_t, seedBytes> seedS,
        std::span<const uint8_t, saber_utils::pke_pklen<L, EP, seedBytes>()> pkey,
        std::span<uint8_t, saber_utils::pke_ctlen<L, EP, ET>()> ctxt)
  requires(saber_params::validate_pke_encrypt_args(L, EQ, EP, ET, MU, seedBytes, uniform_sampling))
{
  constexpr uint16_t Q = 1u << EQ;
  constexpr uint16_t P = 1u << EP;
  constexpr uint16_t T = 1u << ET;

  constexpr auto h1 = saber_consts::compute_poly_h1<Q, EQ, EP>();
  constexpr auto h = saber_consts::compute_polyvec_h<L, Q, EQ, EP>();

  // step 1
  auto pk = pkey.template subspan<0, pkey.size() - seedBytes>();
  auto seedA = pkey.template subspan<pk.size(), seedBytes>();

  // step 2, 3
  auto A = mat::poly_matrix_t<L, L, Q>::template gen_matrix<seedBytes>(seedA);
  auto s_prm = mat::poly_matrix_t<L, 1, Q>::template gen_secret<uniform_sampling, seedBytes, MU>(seedS);

  // step 4, 5, 6
  auto b_prm = A.template mat_vec_mul<L>(s_prm) + h;
  auto b_prm_p = (b_prm >> (EQ - EP)).template mod<P>();

  // step 7, 8
  mat::poly_matrix_t<L, 1, P> b(pk);
  auto s_prm_p = s_prm.template mod<P>();
  auto v_prm = b.inner_prod(s_prm_p);

  // step 9, 10
  poly::poly_t<2> m(msg);
  auto m_p = (m << (EP - 1)).template mod<P>();

  // step 11
  auto c_m = (v_prm - m_p + (h1.template mod<P>())) >> (EP - ET);

  // step 12
  constexpr size_t b_prm_p_len = (L * EP * poly::N) / 8;
  constexpr size_t c_m_len = (ET * poly::N) / 8;
  static_assert(b_prm_p_len + c_m_len == ctxt.size(), "Cipher text size must match !");

  auto ctxt_ct = ctxt.template subspan<0, b_prm_p_len>();
  auto ctxt_cm = ctxt.template subspan<ctxt_ct.size(), c_m_len>();

  b_prm_p.to_bytes(ctxt_ct);
  (c_m.template mod<T>()).to_bytes(ctxt_cm);
}

// Given Saber PKE cipher text and Saber PKE secret key, this routine can be used for
// decrypting the cipher text to 32 -bytes plain text message, which was encrypted using
// corresponding ( associated with this secret key ) Saber PKE public key. This routine
// is an implementation of algorithm 19 in section 8.4.3 of Saber spec.
template<size_t L, size_t EQ, size_t EP, size_t ET, size_t MU, bool uniform_sampling>
inline void
decrypt(std::span<const uint8_t, saber_utils::pke_ctlen<L, EP, ET>()> ctxt, std::span<const uint8_t, saber_utils::pke_sklen<L, EQ>()> skey, std::span<uint8_t, 32> msg)
  requires(saber_params::validate_pke_decrypt_args(L, EQ, EP, ET, MU, uniform_sampling))
{
  constexpr uint16_t Q = 1u << EQ;
  constexpr uint16_t P = 1u << EP;
  constexpr uint16_t T = 1u << ET;

  constexpr auto h2 = saber_consts::compute_poly_h2<Q, EQ, EP, ET>();

  // step 2
  mat::poly_matrix_t<L, 1, Q> s(skey);

  // step 3
  constexpr size_t ct_len = (L * EP * poly::N) / 8;
  constexpr size_t cm_len = (ET * poly::N) / 8;
  static_assert(ct_len + cm_len == ctxt.size(), "Cipher text size must match !");

  auto ctxt_ct = ctxt.template subspan<0, ct_len>();
  auto ctxt_cm = ctxt.template subspan<ct_len, cm_len>();

  // step 4, 5
  poly::poly_t<T> c_m(ctxt_cm);
  c_m = c_m << (EP - ET);

  // step 6
  mat::poly_matrix_t<L, 1, P> b_prm(ctxt_ct);

  // step 7, 8
  auto v = b_prm.inner_prod(s.template mod<P>());
  auto m_p = (v - c_m.template mod<P>() + h2.template mod<P>()) >> (EP - 1);

  // step 9
  (m_p.template mod<2>()).to_bytes(msg);
}

}
