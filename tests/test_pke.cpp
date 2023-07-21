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
template<const size_t L,
         const size_t EQ,
         const size_t EP,
         const size_t ET,
         const size_t MU,
         const size_t seedAbytes,
         const size_t seedSbytes>
void
test_saber_pke()
{
  constexpr size_t pklen = saber_utils::pke_pklen<L, EP, seedAbytes>();
  constexpr size_t sklen = saber_utils::pke_sklen<L, EQ>();
  constexpr size_t ctlen = saber_utils::pke_ctlen<L, EP, ET>();
  constexpr size_t mlen = 32; // bytes

  std::vector<uint8_t> seedA(seedAbytes);
  std::vector<uint8_t> seedS(seedSbytes);
  std::vector<uint8_t> seedS_prm(seedAbytes);
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

  saber_pke::keygen<L, EQ, EP, MU>(std::span<const uint8_t, seedAbytes>(seedA),
                                   std::span<const uint8_t, seedSbytes>(seedS),
                                   std::span<uint8_t, pklen>(pkey),
                                   std::span<uint8_t, sklen>(skey));
  saber_pke::encrypt<L, EQ, EP, ET, MU>(std::span<const uint8_t, mlen>(msg),
                                        std::span<const uint8_t, seedAbytes>(seedS_prm),
                                        std::span<uint8_t, pklen>(pkey),
                                        std::span<uint8_t, ctlen>(ctxt));
  saber_pke::decrypt<L, EQ, EP, ET, MU>(std::span<uint8_t, ctlen>(ctxt),
                                        std::span<uint8_t, sklen>(skey),
                                        std::span<uint8_t, mlen>(dec));

  ASSERT_EQ(msg, dec);
}

TEST(SaberKEM, LightSaberPublicKeyEncryption)
{
  test_saber_pke<2, 13, 10, 3, 10, 32, 32>();
}

TEST(SaberKEM, SaberPublicKeyEncryption)
{
  test_saber_pke<3, 13, 10, 4, 8, 32, 32>();
}

TEST(SaberKEM, FireSaberPublicKeyEncryption)
{
  test_saber_pke<4, 13, 10, 6, 6, 32, 32>();
}
