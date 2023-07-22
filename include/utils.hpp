#pragma once
#include "sha3_256.hpp"
#include <bit>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <span>
#include <type_traits>

// Utility functions for Saber KEM
namespace saber_utils {

// Given a 16/ 32/ 64 -bit unsigned integer word, this routine swaps byte order
// and returns a byte swapped 16/ 32/ 64 -bit word.
template<typename T>
static inline constexpr T
bswap(const T v)
  requires(std::is_unsigned_v<T> &&
           ((sizeof(T) == 2) || (sizeof(T) == 4) || (sizeof(T) == 8)))
{
  // For uint16_t
  if constexpr (sizeof(T) == 2) {
#if defined __GNUG__
    return __builtin_bswap16(v);
#else
    return ((v & 0x00ff) << 8) | ((v & 0xff00) >> 8);
#endif
  }
  // For uint32_t
  else if constexpr (sizeof(T) == 4) {
#if defined __GNUG__
    return __builtin_bswap32(v);
#else
    return ((v & 0x000000ffu) << 24) | ((v & 0x0000ff00u) << 8) |
           ((v & 0x00ff0000u) >> 8) | ((v & 0xff000000u) >> 24);
#endif
  }
  // For uint64_t
  else {
#if defined __GNUG__
    return __builtin_bswap64(v);
#else
    return ((v & 0x00000000000000fful) << 56) | ((v & 0x000000000000ff00ul) << 40) |
           ((v & 0x0000000000ff0000ul) << 24) | ((v & 0x00000000ff000000ul) << 0x8) |
           ((v & 0x000000ff00000000ul) >> 0x8) | ((v & 0x0000ff0000000000ul) >> 24) |
           ((v & 0x00ff000000000000ul) >> 40) | ((v & 0xff00000000000000ul) >> 56);
#endif
  }
}

// Given N -bytes as input, this routine can be used for interpreting them in
// little-endian byte order, returning a 16/ 32/ 64 -bit unsigned integer word.
// Meaning `N` must ∈ [0, 8]. In case N -bytes don't fill returned unsigned
// integer word, remaining bytes will be set to 0.
template<typename T>
inline constexpr T
from_le_bytes(std::span<const uint8_t> bytes)
  requires(std::is_unsigned_v<T> && ((sizeof(T) >= 2)))
{
  T res = 0;
  std::memcpy(&res, bytes.data(), bytes.size());

  if constexpr (std::endian::native == std::endian::big) {
    res = bswap(res);
  }

  return res;
}

// Compile-time compute byte length of public key encryption's public key.
template<const size_t L, const size_t EP, const size_t seedBytes>
inline constexpr size_t
pke_pklen()
{
  return seedBytes + (L * EP * 256) / 8;
}

// Compile-time compute byte length of public key encryption's secret key.
template<const size_t L, const size_t EQ>
inline constexpr size_t
pke_sklen()
{
  return (L * EQ * 256) / 8;
}

// Compile-time compute byte length of public key encryption's cipher text.
template<const size_t L, const size_t EP, const size_t ET>
inline constexpr size_t
pke_ctlen()
  requires(EP > ET)
{
  return (ET * 256) / 8 + (L * EP * 256) / 8;
}

// Compile-time compute byte length of key encapsulation mechanism's public key.
template<const size_t L, const size_t EP, const size_t seedBytes>
inline constexpr size_t
kem_pklen()
{
  return pke_pklen<L, EP, seedBytes>();
}

// Compile-time compute byte length of key encapsulation mechanism's secret key.
template<const size_t L,
         const size_t EQ,
         const size_t EP,
         const size_t seedBytes,
         const size_t keyBytes>
inline constexpr size_t
kem_sklen()
{
  return keyBytes + sha3_256::DIGEST_LEN + // randomness + hash(PKE pubkey)
         pke_pklen<L, EP, seedBytes>() +   // PKE pubkey
         pke_sklen<L, EQ>();               // PKE seckey
}

// Compile-time compute byte length of key encapsulation mechanism's cipher text.
template<const size_t L, const size_t EP, const size_t ET>
inline constexpr size_t
kem_ctlen()
{
  return pke_ctlen<L, EP, ET>();
}

}
