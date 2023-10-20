#pragma once
#include "params.hpp"
#include "pke.hpp"
#include "sha3_256.hpp"
#include "sha3_512.hpp"
#include "utils.hpp"

// Algorithms related to Saber Key Encapsulation Mechanism
namespace _saber_kem {

// Given seedBytes `seedA` ( used for generating matrix A, in Saber PKE keygen algorithm
// ), noiseBytes `seedS` ( used for generating secret vector s, in Saber PKE keygen
// algorithm ) and keyBytes `z` ( random sampled bytes, used for randomizing Saber KEM
// secret key ), this routine can be used for generating a Saber KEM public/ private
// keypair, following algorithm 20 in section 8.5.1 of Saber spec.
template<size_t L, size_t EQ, size_t EP, size_t MU, size_t seedBytes, size_t noiseBytes, size_t keyBytes, bool uniform_sampling>
inline void
keygen(std::span<const uint8_t, seedBytes> seedA,
       std::span<const uint8_t, noiseBytes> seedS,
       std::span<const uint8_t, keyBytes> z,
       std::span<uint8_t, saber_utils::kem_pklen<L, EP, seedBytes>()> pkey,
       std::span<uint8_t, saber_utils::kem_sklen<L, EQ, EP, seedBytes, keyBytes>()> skey)
  requires(saber_params::validate_kem_keygen_args(L, EQ, EP, MU, seedBytes, noiseBytes, keyBytes, uniform_sampling))
{
  constexpr size_t pke_pklen = saber_utils::pke_pklen<L, EP, seedBytes>();
  constexpr size_t pke_sklen = saber_utils::pke_sklen<L, EQ>();

  auto sk_sk = skey.template subspan<0, pke_sklen>();
  constexpr size_t off0 = sk_sk.size();
  auto sk_pk = skey.template subspan<off0, pke_pklen>();
  constexpr size_t off1 = off0 + sk_pk.size();
  auto sk_hpk = skey.template subspan<off1, sha3_256::DIGEST_LEN>();
  constexpr size_t off2 = off1 + sk_hpk.size();
  auto sk_z = skey.template subspan<off2, keyBytes>();

  // step 1
  saber_pke::keygen<L, EQ, EP, MU, seedBytes, noiseBytes, uniform_sampling>(seedA, seedS, pkey, sk_sk);
  // step 4 ( partial )
  std::memcpy(sk_pk.data(), pkey.data(), pkey.size());

  // step 2
  sha3_256::sha3_256_t hasher;
  hasher.absorb(sk_pk);
  hasher.finalize();
  hasher.digest(sk_hpk); // step 4 ( partial )
  hasher.reset();

  // step 4 ( partial )
  std::memcpy(sk_z.data(), z.data(), z.size());
}

// Given keyBytes input `m` ( random sampled ) and Saber KEM public key, this routine
// can be used for generating a session key ( of 32 -bytes ) and Saber KEM cipher text.
// This is an implementation of algorithm 21 in section 8.5.2 of Saber spec.
template<size_t L, size_t EQ, size_t EP, size_t ET, size_t MU, size_t seedBytes, size_t keyBytes, bool uniform_sampling>
inline void
encaps(std::span<const uint8_t, keyBytes> m, // step 1
       std::span<const uint8_t, saber_utils::kem_pklen<L, EP, seedBytes>()> pkey,
       std::span<uint8_t, saber_utils::kem_ctlen<L, EP, ET>()> ctxt,
       std::span<uint8_t, sha3_256::DIGEST_LEN> seskey)
  requires(saber_params::validate_kem_encaps_args(L, EQ, EP, ET, MU, seedBytes, keyBytes, uniform_sampling))
{
  std::array<uint8_t, sha3_256::DIGEST_LEN> hashed_m;
  std::array<uint8_t, sha3_256::DIGEST_LEN> hashed_pk;
  std::array<uint8_t, sha3_512::DIGEST_LEN> rk;
  std::array<uint8_t, sha3_256::DIGEST_LEN> r_prm;

  // step 2
  sha3_256::sha3_256_t h256;
  h256.absorb(m);
  h256.finalize();
  h256.digest(hashed_m);
  h256.reset();

  // step 3
  h256.absorb(pkey);
  h256.finalize();
  h256.digest(hashed_pk);
  h256.reset();

  // step 4, 5
  sha3_512::sha3_512_t h512;
  h512.absorb(hashed_m);
  h512.absorb(hashed_pk);
  h512.finalize();
  h512.digest(rk);
  h512.reset();

  // step 6
  auto k = std::span(rk).template subspan<0, keyBytes>();
  auto r = std::span(rk).template subspan<keyBytes, keyBytes>();

  // step 7
  auto _hm = std::span<const uint8_t, hashed_m.size()>(hashed_m);
  auto _r = std::span<const uint8_t, r.size()>(r);
  saber_pke::encrypt<L, EQ, EP, ET, MU, seedBytes, uniform_sampling>(_hm, _r, pkey, ctxt);

  // step 8
  h256.absorb(ctxt);
  h256.finalize();
  h256.digest(r_prm);
  h256.reset();

  // step 9, 10
  h256.absorb(k);
  h256.absorb(r_prm);
  h256.finalize();
  h256.digest(seskey);
  h256.reset();
}

// Given Saber KEM cipher text and Saber KEM secret key, this routine can be used for
// decapsulating the received cipher text, extracting a shared secret key of 32 -bytes.
// This is an implementation of algorithm 22 in section 8.5.3 of Saber spec.
template<size_t L, size_t EQ, size_t EP, size_t ET, size_t MU, size_t seedBytes, size_t keyBytes, bool uniform_sampling>
inline void
decaps(std::span<const uint8_t, saber_utils::kem_ctlen<L, EP, ET>()> ctxt,
       std::span<const uint8_t, saber_utils::kem_sklen<L, EQ, EP, seedBytes, keyBytes>()> skey,
       std::span<uint8_t, sha3_256::DIGEST_LEN> seskey)
  requires(saber_params::validate_kem_decaps_args(L, EQ, EP, ET, MU, seedBytes, keyBytes, uniform_sampling))
{
  constexpr size_t pke_pklen = saber_utils::pke_pklen<L, EP, seedBytes>();
  constexpr size_t pke_sklen = saber_utils::pke_sklen<L, EQ>();

  // step 1
  auto sk = skey.template subspan<0, pke_sklen>();
  constexpr size_t off0 = pke_sklen;
  auto pk = skey.template subspan<off0, pke_pklen>();
  constexpr size_t off1 = off0 + pke_pklen;
  auto hash_pk = skey.template subspan<off1, sha3_256::DIGEST_LEN>();
  constexpr size_t off2 = off1 + sha3_256::DIGEST_LEN;
  auto z = skey.template subspan<off2, keyBytes>();

  std::array<uint8_t, sha3_256::DIGEST_LEN> m;
  std::array<uint8_t, sha3_512::DIGEST_LEN> rk;
  std::array<uint8_t, ctxt.size()> ctxt_prm;
  std::array<uint8_t, sha3_256::DIGEST_LEN> r_prm;
  std::array<uint8_t, keyBytes> temp;

  // step 2
  saber_pke::decrypt<L, EQ, EP, ET, MU, uniform_sampling>(ctxt, sk, m);

  // step 3, 4
  sha3_512::sha3_512_t h512;
  h512.absorb(m);
  h512.absorb(hash_pk);
  h512.finalize();
  h512.digest(rk);
  h512.reset();

  // step 5
  auto k = std::span(rk).template subspan<0, keyBytes>();
  auto r = std::span(rk).template subspan<keyBytes, keyBytes>();

  // step 6
  auto _m = std::span<const uint8_t, m.size()>(m);
  auto _r = std::span<const uint8_t, r.size()>(r);
  saber_pke::encrypt<L, EQ, EP, ET, MU, seedBytes, uniform_sampling>(_m, _r, pk, ctxt_prm);

  // step 7
  auto c = saber_utils::ct_eq_bytes<ctxt.size()>(ctxt_prm, ctxt);
  // step 9, 10, 11, 12
  saber_utils::ct_sel_bytes<temp.size()>(c, temp, k, z);

  // step 8
  sha3_256::sha3_256_t h256;
  h256.absorb(ctxt);
  h256.finalize();
  h256.digest(r_prm);
  h256.reset();

  // step 13
  h256.absorb(temp);
  h256.absorb(r_prm);
  h256.finalize();
  h256.digest(seskey);
  h256.reset();
}

}
