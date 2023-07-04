#pragma once
#include <cstddef>
#include <cstdint>
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
    return ((v & 0x00000000000000fful) << 56) |
           ((v & 0x000000000000ff00ul) << 40) |
           ((v & 0x0000000000ff0000ul) << 24) |
           ((v & 0x00000000ff000000ul) << 0x8) |
           ((v & 0x000000ff00000000ul) >> 0x8) |
           ((v & 0x0000ff0000000000ul) >> 24) |
           ((v & 0x00ff000000000000ul) >> 40) |
           ((v & 0xff00000000000000ul) >> 56);
#endif
  }
}

}
