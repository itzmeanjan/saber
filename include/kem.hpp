#pragma once
#include "pke.hpp"
#include "sha3_256.hpp"
#include "sha3_512.hpp"
#include "utils.hpp"

// Algorithms related to Saber Key Encapsulation Mechanism
namespace saber_kem {

// Given seedBytes `seedA` ( used for generating matrix A, in Saber PKE keygen algorithm
// ), noiseBytes `seedS` ( used for generating secret vector s, in Saber PKE keygen
// algorithm ) and keyBytes `z` ( random sampled bytes, used for randomizing Saber KEM
// secret key ), this routine can be used for generating a Saber KEM public/ private
// keypair, following algorithm 20 in section 8.5.1 of Saber spec.
template<const size_t L,
         const size_t EQ,
         const size_t EP,
         const size_t MU,
         const size_t seedBytes,
         const size_t noiseBytes,
         const size_t keyBytes>
inline void
keygen(
  std::span<const uint8_t, seedBytes> seedA,
  std::span<const uint8_t, noiseBytes> seedS,
  std::span<const uint8_t, keyBytes> z,
  std::span<uint8_t, saber_utils::kem_pklen<L, EP, seedBytes>()> pkey,
  std::span<uint8_t, saber_utils::kem_sklen<L, EQ, EP, seedBytes, keyBytes>()> skey)
{
  constexpr size_t pke_pklen = saber_utils::pke_pklen<L, EP, seedBytes>();
  constexpr size_t pke_sklen = saber_utils::pke_sklen<L, EQ>();

  size_t off = 0;
  auto sk_z = skey.template subspan<0, keyBytes>();
  off += keyBytes;
  auto sk_hpk = skey.template subspan<off, sha3_256::DIGEST_LEN>();
  off += sha3_256::DIGEST_LEN;
  auto sk_pk = skey.template subspan<off, pke_pklen>();
  off += pke_pklen;
  auto sk_sk = skey.template subspan<off, pke_sklen>();

  // step 1
  saber_pke::keygen<L, EQ, EP, MU>(seedA, seedS, pkey, sk_sk);
  // step 4 ( partial )
  std::memcpy(sk_pk.data(), pkey.data(), pkey.size());

  // step 2
  sha3_256::sha3_256 hasher;
  hasher.absorb(sk_pk.data(), sk_pk.size());
  hasher.finalize();
  hasher.digest(sk_hpk.data()); // step 4 ( partial )
  hasher.reset();

  // step 4 ( partial )
  std::memcpy(sk_z.data(), z.data(), z.size());
}

// Given keyBytes input `m` ( random sampled ) and Saber KEM public key, this routine
// can be used for generating a session key ( of 32 -bytes ) and Saber KEM cipher text.
// This is an implementation of algorithm 21 in section 8.5.2 of Saber spec.
template<const size_t L,
         const size_t EQ,
         const size_t EP,
         const size_t ET,
         const size_t MU,
         const size_t seedBytes,
         const size_t keyBytes>
inline void
encaps(std::span<const uint8_t, keyBytes> m, // step 1
       std::span<const uint8_t, saber_utils::kem_pklen<L, EP, seedBytes>()> pkey,
       std::span<uint8_t, saber_utils::kem_ctlen<L, EP, ET>()> ctxt,
       std::span<uint8_t, sha3_256::DIGEST_LEN> seskey)
{
  std::array<uint8_t, sha3_256::DIGEST_LEN> hashed_m;
  std::array<uint8_t, sha3_256::DIGEST_LEN> hashed_pk;
  std::array<uint8_t, sha3_512::DIGEST_LEN> rk;
  std::array<uint8_t, sha3_256::DIGEST_LEN> r_prm;

  // step 2
  sha3_256::sha3_256 h256;
  h256.absorb(m.data(), m.size());
  h256.finalize();
  h256.digest(hashed_m.data());
  h256.reset();

  // step 3
  h256.absorb(pkey.data(), pkey.size());
  h256.finalize();
  h256.digest(hashed_pk.data());
  h256.reset();

  // step 4, 5
  sha3_512::sha3_512 h512;
  h512.absorb(hashed_m.data(), hashed_m.size());
  h512.absorb(hashed_pk.data(), hashed_pk.size());
  h512.finalize();
  h512.digest(rk.data());
  h512.reset();

  // step 6
  auto k = std::span(rk).subspan<0, keyBytes>();
  auto r = std::span(rk).subspan<keyBytes, keyBytes>();

  // step 7
  saber_pke::encrypt<L, EQ, EP, ET, MU>(hashed_m, r, pkey, ctxt);

  // step 8
  h256.absorb(ctxt.data(), ctxt.size());
  h256.finalize();
  h256.digest(r_prm.data());
  h256.reset();

  // step 9, 10
  h256.absorb(k.data(), k.size());
  h256.absorb(r_prm.data(), r_prm.size());
  h256.finalize();
  h256.digest(seskey.data());
  h256.reset();
}

// Given Saber KEM cipher text and Saber KEM secret key, this routine can be used for
// decapsulating the received cipher text, extracting a shared secret key of 32 -bytes.
// This is an implementation of algorithm 22 in section 8.5.3 of Saber spec.
template<const size_t L,
         const size_t EQ,
         const size_t EP,
         const size_t ET,
         const size_t MU,
         const size_t seedBytes,
         const size_t keyBytes>
inline void
decaps(std::span<const uint8_t, saber_utils::kem_ctlen<L, EP, ET>()> ctxt,
       std::span<const uint8_t,
                 saber_utils::kem_sklen<L, EQ, EP, seedBytes, keyBytes>()> skey,
       std::span<uint8_t, sha3_256::DIGEST_LEN> seskey)
{
  constexpr size_t pke_pklen = saber_utils::pke_pklen<L, EP, seedBytes>();
  constexpr size_t pke_sklen = saber_utils::pke_sklen<L, EQ>();

  // step 1
  size_t off = 0;
  auto z = skey.template subspan<off, keyBytes>();
  off += keyBytes;
  auto hash_pk = skey.template subspan<off, sha3_256::DIGEST_LEN>();
  off += sha3_256::DIGEST_LEN;
  auto pk = skey.template subspan<off, pke_pklen>();
  off += pke_pklen;
  auto sk = skey.template subspan<off, pke_sklen>();

  std::array<uint8_t, sha3_256::DIGEST_LEN> m;
  std::array<uint8_t, sha3_512::DIGEST_LEN> rk;
  std::array<uint8_t, ctxt.size()> ctxt_prm;
  std::array<uint8_t, sha3_256::DIGEST_LEN> r_prm;
  std::array<uint8_t, keyBytes> temp;

  // step 2
  saber_pke::decrypt<L, EQ, EP, ET, MU>(ctxt, sk, m);

  // step 3, 4
  sha3_512::sha3_512 h512;
  h512.absorb(m.data(), m.size());
  h512.absorb(hash_pk.data(), hash_pk.size());
  h512.finalize();
  h512.digest(rk.data());
  h512.reset();

  // step 5
  auto k = std::span(rk).subspan<0, keyBytes>();
  auto r = std::span(rk).subspan<keyBytes, keyBytes>();

  // step 6
  saber_pke::encrypt<L, EQ, EP, ET, MU>(m, r, pk, ctxt_prm);

  // step 7
  auto c = saber_utils::ct_eq_bytes(ctxt_prm, ctxt);
  // step 9, 10, 11, 12
  saber_utils::ct_sel_bytes(c, temp, k, z);

  // step 8
  sha3_256::sha3_256 h256;
  h256.absorb(ctxt.data(), ctxt.size());
  h256.finalize();
  h256.digest(r_prm.data());
  h256.reset();

  // step 13
  h256.absorb(temp.data(), temp.size());
  h256.absorb(r_prm.data(), r_prm.size());
  h256.finalize();
  h256.digest(seskey.data());
  h256.reset();
}

}
