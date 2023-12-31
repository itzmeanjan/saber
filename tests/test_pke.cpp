#include "pke.hpp"
#include "prng.hpp"
#include <gtest/gtest.h>
#include <span>
#include <vector>

// Ensures that Saber public key encryption algorithms are functioning correctly, by
//
// - generating a new public/ private keypair
// - encrypting a 32 -bytes message using public key
// - decrypting the cipher text using secret key
// - asserting equality of original message and decrypted one
template<size_t L, size_t EQ, size_t EP, size_t ET, size_t MU, size_t seedBytes, size_t noiseBytes, bool uniform_sampling>
void
test_saber_pke()
{
  constexpr size_t pklen = saber_utils::pke_pklen<L, EP, seedBytes>();
  constexpr size_t sklen = saber_utils::pke_sklen<L, EQ>();
  constexpr size_t ctlen = saber_utils::pke_ctlen<L, EP, ET>();
  constexpr size_t mlen = 32; // bytes

  std::vector<uint8_t> seedA(seedBytes);
  std::vector<uint8_t> seedS(noiseBytes);
  std::vector<uint8_t> seedS_prm(seedBytes);
  std::vector<uint8_t> msg(mlen);
  std::vector<uint8_t> dec(mlen, 0);
  std::vector<uint8_t> pkey(pklen);
  std::vector<uint8_t> skey(sklen);
  std::vector<uint8_t> ctxt(ctlen);

  prng::prng_t prng;

  prng.read(seedA);
  prng.read(seedS);
  prng.read(seedS_prm);
  prng.read(msg);

  auto _seedA = std::span<const uint8_t, seedBytes>(seedA);
  auto _seedS = std::span<const uint8_t, noiseBytes>(seedS);
  auto _seedS_prm = std::span<const uint8_t, seedBytes>(seedS_prm);
  auto _msg = std::span<uint8_t, mlen>(msg);
  auto _dec = std::span<uint8_t, mlen>(dec);
  auto _pkey = std::span<uint8_t, pklen>(pkey);
  auto _skey = std::span<uint8_t, sklen>(skey);
  auto _ctxt = std::span<uint8_t, ctlen>(ctxt);

  saber_pke::keygen<L, EQ, EP, MU, seedBytes, noiseBytes, uniform_sampling>(_seedA, _seedS, _pkey, _skey);
  saber_pke::encrypt<L, EQ, EP, ET, MU, seedBytes, uniform_sampling>(_msg, _seedS_prm, _pkey, _ctxt);
  saber_pke::decrypt<L, EQ, EP, ET, MU, uniform_sampling>(_ctxt, _skey, _dec);

  EXPECT_EQ(msg, dec);
}

TEST(SaberKEM, LightSaberPublicKeyEncryption)
{
  test_saber_pke<2, 13, 10, 3, 10, 32, 32, false>();
}

TEST(SaberKEM, SaberPublicKeyEncryption)
{
  test_saber_pke<3, 13, 10, 4, 8, 32, 32, false>();
}

TEST(SaberKEM, FireSaberPublicKeyEncryption)
{
  test_saber_pke<4, 13, 10, 6, 6, 32, 32, false>();
}

TEST(SaberKEM, uLightSaberPublicKeyEncryption)
{
  test_saber_pke<2, 12, 10, 3, 2, 32, 32, true>();
}

TEST(SaberKEM, uSaberPublicKeyEncryption)
{
  test_saber_pke<3, 12, 10, 4, 2, 32, 32, true>();
}

TEST(SaberKEM, uFireSaberPublicKeyEncryption)
{
  test_saber_pke<4, 12, 10, 6, 2, 32, 32, true>();
}
