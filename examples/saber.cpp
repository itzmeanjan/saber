#include "prng.hpp"
#include "saber_kem.hpp"
#include <cassert>
#include <iostream>

// Converts byte array into hex string, taken from
// https://github.com/itzmeanjan/ascon/blob/53b210017373c72bfc51ac7811939786bf2da5f9/include/utils.hpp#L107-L118
inline const std::string
to_hex(std::span<const uint8_t> bytes)
{
  std::stringstream ss;
  ss << std::hex;

  for (size_t i = 0; i < bytes.size(); i++) {
    ss << std::setw(2) << std::setfill('0') << static_cast<uint32_t>(bytes[i]);
  }
  return ss.str();
}

// Compile it using
//
// g++ -std=c++20 -Wall -O3 -march=native -I include -I sha3/include -I subtle/include
// examples/saber.cpp
int
main()
{
  std::vector<uint8_t> seedA(saber_kem::seedBytes);
  std::vector<uint8_t> seedS(saber_kem::noiseBytes);
  std::vector<uint8_t> z(saber_kem::keyBytes);
  std::vector<uint8_t> m(saber_kem::keyBytes);
  std::vector<uint8_t> pkey(saber_kem::PK_LEN);
  std::vector<uint8_t> skey(saber_kem::SK_LEN);
  std::vector<uint8_t> ctxt(saber_kem::CT_LEN);
  std::vector<uint8_t> sskey_peer0(sha3_256::DIGEST_LEN);
  std::vector<uint8_t> sskey_peer1(sha3_256::DIGEST_LEN);

  auto _seedA = std::span<uint8_t, saber_kem::seedBytes>(seedA);
  auto _seedS = std::span<uint8_t, saber_kem::noiseBytes>(seedS);
  auto _z = std::span<uint8_t, saber_kem::keyBytes>(z);
  auto _m = std::span<uint8_t, saber_kem::keyBytes>(m);
  auto _pkey = std::span<uint8_t, saber_kem::PK_LEN>(pkey);
  auto _skey = std::span<uint8_t, saber_kem::SK_LEN>(skey);
  auto _ctxt = std::span<uint8_t, saber_kem::CT_LEN>(ctxt);
  auto _sskey_peer0 = std::span<uint8_t, sha3_256::DIGEST_LEN>(sskey_peer0);
  auto _sskey_peer1 = std::span<uint8_t, sha3_256::DIGEST_LEN>(sskey_peer1);

  // Random sample seeds
  prng::prng_t prng;

  prng.read(_seedA);
  prng.read(_seedS);
  prng.read(_z);
  prng.read(_m);

  // Peer-1 generates a Saber KEM keypair
  saber_kem::keygen(_seedA, _seedS, _z, _pkey, _skey);
  // Peer-0 uses Peer-1's public key for encapsulating a key, also producing session key
  saber_kem::encaps(_m, _pkey, _ctxt, _sskey_peer0);
  // Peer-1 uses its private key to decapsulate cipher text, producing same session key
  saber_kem::decaps(_ctxt, _skey, _sskey_peer1);

  // Both peers must arrive at same session key
  assert(std::ranges::equal(_sskey_peer0, _sskey_peer1));

  std::cout << "Saber KEM :\n\n";
  std::cout << "Public Key  : " << to_hex(_pkey) << "\n";
  std::cout << "Secret Key  : " << to_hex(_skey) << "\n";
  std::cout << "Cipher Text : " << to_hex(_ctxt) << "\n";
  std::cout << "Session Key : " << to_hex(_sskey_peer0) << "\n";

  return 0;
}
