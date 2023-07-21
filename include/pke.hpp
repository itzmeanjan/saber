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
template<const size_t L,
         const size_t EQ,
         const size_t EP,
         const size_t MU,
         const size_t seedBytes,
         const size_t noiseBytes>
inline void
keygen(std::span<const uint8_t, seedBytes> seedA,  // step 1
       std::span<const uint8_t, noiseBytes> seedS, // step 3
       std::span<uint8_t, saber_utils::pke_pklen<L, EP, seedBytes>()> pkey,
       std::span<uint8_t, saber_utils::pke_sklen<L, EQ>()> skey)
  requires(saber_params::validate_pke_keygen_args(L, EQ, EP, MU, seedBytes, noiseBytes))
{
  constexpr uint16_t Q = 1u << EQ;
  constexpr uint16_t P = 1u << EP;
  constexpr auto h = saber_consts::compute_polyvec_h<L, Q, EQ, EP>();

  std::array<uint8_t, seedBytes> hashedSeedA{};

  // step 2
  shake128::shake128 hasher;
  hasher.absorb(seedA.data(), seedA.size());
  hasher.finalize();
  hasher.squeeze(hashedSeedA.data(), hashedSeedA.size());
  hasher.reset();

  // step 4, 5
  auto A = mat::poly_matrix_t<L, L, Q>::template gen_matrix<seedBytes>(hashedSeedA);
  auto s = mat::poly_matrix_t<L, 1, Q>::template gen_secret<noiseBytes, MU>(seedS);

  // step 6, 7, 8
  auto A_T = A.transpose();
  auto b = A_T.template mat_vec_mul<L>(s) + h;
  auto b_p = (b >> (EQ - EP)).template mod<P>();

  // step 9, 10, 11
  s.to_bytes(skey);
  b_p.to_bytes(pkey.subspan(seedBytes, pkey.size() - seedBytes));
  std::memcpy(pkey.data(), hashedSeedA.data(), seedBytes);
}

// Given 32 -bytes input message, seedBytes -bytes `seedS` and Saber PKE public key,
// this routine can be used for encrypting fixed length message using Saber public key
// encryption algorithm, computing a cipher text. This routine is an implementation of
// algorithm 18 in section 8.4.2 of Saber spec.
template<const size_t L,
         const size_t EQ,
         const size_t EP,
         const size_t ET,
         const size_t MU,
         const size_t seedBytes>
inline void
encrypt(std::span<const uint8_t, 32> msg,
        std::span<const uint8_t, seedBytes> seedS,
        std::span<const uint8_t, saber_utils::pke_pklen<L, EP, seedBytes>()> pkey,
        std::span<uint8_t, saber_utils::pke_ctlen<L, EP, ET>()> ctxt)
  requires(saber_params::validate_pke_encrypt_args(L, EQ, EP, ET, MU, seedBytes))
{
  constexpr uint16_t Q = 1u << EQ;
  constexpr uint16_t P = 1u << EP;
  constexpr uint16_t T = 1u << ET;

  constexpr auto h1 = saber_consts::compute_poly_h1<Q, EQ, EP>();
  constexpr auto h = saber_consts::compute_polyvec_h<L, Q, EQ, EP>();

  // step 1
  auto seedA = pkey.template subspan<0, seedBytes>();
  auto pk = pkey.template subspan<seedBytes, pkey.size() - seedBytes>();

  // step 2, 3
  auto A = mat::poly_matrix_t<L, L, Q>::template gen_matrix<seedBytes>(seedA);
  auto s_prm = mat::poly_matrix_t<L, 1, Q>::template gen_secret<seedBytes, MU>(seedS);

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

  constexpr size_t c_m_len = (ET * poly::N) / 8;
  constexpr size_t b_prm_p_len = (L * EP * poly::N) / 8;
  static_assert(c_m_len + b_prm_p_len == ctxt.size(), "Cipher text size must match !");

  // step 12
  (c_m.template mod<T>()).to_bytes(ctxt.template subspan<0, c_m_len>());
  b_prm_p.to_bytes(ctxt.template subspan<c_m_len, b_prm_p_len>());
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
  requires(saber_params::validate_pke_decrypt_args(L, EQ, EP, ET, MU))
{
  constexpr uint16_t Q = 1u << EQ;
  constexpr uint16_t P = 1u << EP;
  constexpr uint16_t T = 1u << ET;

  constexpr auto h2 = saber_consts::compute_poly_h2<Q, EQ, EP, ET>();

  // step 2
  mat::poly_matrix_t<L, 1, Q> s(skey);

  // step 3, 4, 5
  constexpr size_t cm_len = (ET * poly::N) / 8;
  poly::poly_t<T> c_m(ctxt.template subspan<0, cm_len>());
  c_m = c_m << (EP - ET);

  // step 6
  constexpr size_t ct_len = (L * EP * poly::N) / 8;
  mat::poly_matrix_t<L, 1, P> b_prm(ctxt.template subspan<cm_len, ct_len>());

  // step 7, 8
  auto v = b_prm.inner_prod(s.template mod<P>());
  auto m_p = (v - c_m.template mod<P>() + h2.template mod<P>()) >> (EP - 1);

  // step 9
  (m_p.template mod<2>()).to_bytes(msg);
}

}
