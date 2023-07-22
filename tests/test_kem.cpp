#include "kem.hpp"
#include "prng.hpp"
#include <gtest/gtest.h>

// Ensure that Saber KEM algorithms are functioning correctly, by
//
// - generating a new keypair
// - encapsulating message, generating cipher text and 32 -bytes shared secret
// - decapsulating cipher text, generating 32 -bytes shared secret
// - asserting equality of shared secret obtained by both parties
template<const size_t L,
         const size_t EQ,
         const size_t EP,
         const size_t ET,
         const size_t MU,
         const size_t seedBytes,
         const size_t noiseBytes,
         const size_t keyBytes>
void
test_saber_kem()
{
  constexpr size_t pklen = saber_utils::kem_pklen<L, EP, seedBytes>();
  constexpr size_t sklen = saber_utils::kem_sklen<L, EQ, EP, seedBytes, keyBytes>();
  constexpr size_t ctlen = saber_utils::kem_ctlen<L, EP, ET>();
  constexpr size_t sslen = sha3_256::DIGEST_LEN;

  std::vector<uint8_t> seedA(seedBytes);
  std::vector<uint8_t> seedS(noiseBytes);
  std::vector<uint8_t> z(keyBytes);
  std::vector<uint8_t> m(keyBytes);
  std::vector<uint8_t> pkey(pklen);
  std::vector<uint8_t> skey(sklen);
  std::vector<uint8_t> ctxt(ctlen);
  std::vector<uint8_t> seskey_a(sslen);
  std::vector<uint8_t> seskey_b(sslen);

  auto _seedA = std::span<uint8_t, seedBytes>(seedA);
  auto _seedS = std::span<uint8_t, noiseBytes>(seedS);
  auto _z = std::span<uint8_t, keyBytes>(z);
  auto _m = std::span<uint8_t, keyBytes>(m);
  auto _pkey = std::span<uint8_t, pklen>(pkey);
  auto _skey = std::span<uint8_t, sklen>(skey);
  auto _ctxt = std::span<uint8_t, ctlen>(ctxt);
  auto _seskey_a = std::span<uint8_t, sslen>(seskey_a);
  auto _seskey_b = std::span<uint8_t, sslen>(seskey_b);

  prng::prng_t prng;

  prng.read(_seedA);
  prng.read(_seedS);
  prng.read(_z);
  prng.read(_m);

  saber_kem::keygen<L, EQ, EP, MU, seedBytes, noiseBytes, keyBytes>(
    _seedA, _seedS, _z, _pkey, _skey);
  saber_kem::encaps<L, EQ, EP, ET, MU, seedBytes, keyBytes>(
    _m, _pkey, _ctxt, _seskey_a);
  saber_kem::decaps<L, EQ, EP, ET, MU, seedBytes, keyBytes>(_ctxt, _skey, _seskey_b);

  ASSERT_EQ(seskey_a, seskey_b);
}

TEST(SaberKEM, LightSaberKeyEncapsulationMechanism)
{
  test_saber_kem<2, 13, 10, 3, 10, 32, 32, 32>();
}

TEST(SaberKEM, SaberKeyEncapsulationMechanism)
{
  test_saber_kem<3, 13, 10, 4, 8, 32, 32, 32>();
}

TEST(SaberKEM, FireSaberKeyEncapsulationMechanism)
{
  test_saber_kem<4, 13, 10, 6, 6, 32, 32, 32>();
}
