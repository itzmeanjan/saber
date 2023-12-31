#pragma once
#include "kem.hpp"

// Instantiate uLightSaber KEM
namespace ulightsaber_kem {

// uLightSaber KEM parameters taken from table 9 of section A.2 of Saber spec.
constexpr size_t L = 2;
constexpr size_t EQ = 12;
constexpr size_t EP = 10;
constexpr size_t ET = 3;
constexpr size_t MU = 2;
constexpr size_t seedBytes = 32;
constexpr size_t noiseBytes = 32;
constexpr size_t keyBytes = 32;
constexpr bool uniform_sampling = true;

// 672 -bytes uLightSaber KEM public key
constexpr size_t PK_LEN = saber_utils::kem_pklen<L, EP, seedBytes>();
// 1504 -bytes uLightSaber KEM secret key
constexpr size_t SK_LEN = saber_utils::kem_sklen<L, EQ, EP, seedBytes, keyBytes>();
// 736 -bytes uLightSaber KEM cipher text
constexpr size_t CT_LEN = saber_utils::kem_ctlen<L, EP, ET>();

// Given 32 -bytes random sampled `seedA`, 32 -bytes random sampled `seedS` and 32
// -bytes random sampled `z`, this routine can be used for deterministically deriving a
// uLightSaber KEM public/ private keypair s.t. public key is 672 -bytes and private key
// is 1504 -bytes.
inline void
keygen(std::span<const uint8_t, seedBytes> seedA,
       std::span<const uint8_t, noiseBytes> seedS,
       std::span<const uint8_t, keyBytes> z,
       std::span<uint8_t, PK_LEN> pkey,
       std::span<uint8_t, SK_LEN> skey)
{
  _saber_kem::keygen<L, EQ, EP, MU, seedBytes, noiseBytes, keyBytes, uniform_sampling>(seedA, seedS, z, pkey, skey);
}

// Given 32 -bytes random sampled `m` and 672 -bytes uLightSaber KEM public key, this
// routine generates a 736 -bytes cipher text ( encapsulating fixed width message, which
// will be used for deriving shared secret key ) and 32 -bytes session key.
inline void
encaps(std::span<const uint8_t, keyBytes> m, std::span<const uint8_t, PK_LEN> pkey, std::span<uint8_t, CT_LEN> ctxt, std::span<uint8_t, sha3_256::DIGEST_LEN> seskey)
{
  _saber_kem::encaps<L, EQ, EP, ET, MU, seedBytes, keyBytes, uniform_sampling>(m, pkey, ctxt, seskey);
}

// Given 736 -bytes cipher text and 1504 -bytes uLightSaber KEM secret key, this routine
// can be used for decapsulating the cipher text, deriving 32 -bytes session key.
inline void
decaps(std::span<const uint8_t, CT_LEN> ctxt, std::span<const uint8_t, SK_LEN> skey, std::span<uint8_t, sha3_256::DIGEST_LEN> seskey)
{
  _saber_kem::decaps<L, EQ, EP, ET, MU, seedBytes, keyBytes, uniform_sampling>(ctxt, skey, seskey);
}

}
