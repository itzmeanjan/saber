#pragma once
#include "pke.hpp"
#include "sha3_256.hpp"
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

}
