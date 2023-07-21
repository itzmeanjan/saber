#pragma once
#include <bit>
#include <cstddef>
#include <cstdint>
#include <type_traits>

// Compile-time executable checks and parameters for Saber KEM implementation.
namespace saber_params {

// Given an unsigned integer, this routine can be used for checking whether
// value of type T is a power of 2 or not, returning boolean truth value if
// `val` is a power of 2.
template<typename T>
inline constexpr bool
is_power_of_2(const T val)
  requires(std::is_unsigned_v<T>)
{
  return !static_cast<bool>(val & (val - 1));
}

// Given an unsigned power of 2 integer value, this routine can be used for
// computing logarithm base 2.
template<typename T>
inline constexpr T
log2(const T val)
  requires(std::is_unsigned_v<T>)
{
  return std::countr_zero(val);
}

// Given an unsigned integer, this routine returns truth value if it's even.
template<typename T>
inline constexpr bool
is_even(T val)
  requires(std::is_unsigned_v<T>)
{
  return !static_cast<bool>(val & 1);
}

// Compile-time executable check for validating template arguments passed to Saber PKE
// key generation routine.
inline constexpr bool
validate_pke_keygen_args(const size_t L,
                         const size_t EQ,
                         const size_t EP,
                         const size_t MU,
                         const size_t seedBytes,
                         const size_t noiseBytes)
{
  return ((L == 2) && (EQ == 13) && (EP == 10) && (MU == 10) && (seedBytes == 32) &&
          (noiseBytes == 32)) || // LightSaber
         ((L == 3) && (EQ == 13) && (EP == 10) && (MU == 8) && (seedBytes == 32) &&
          (noiseBytes == 32)) || // Saber
         ((L == 4) && (EQ == 13) && (EP == 10) && (MU == 6) && (seedBytes == 32) &&
          (noiseBytes == 32)); // FireSaber
}

// Compile-time executable check for validating template arguments passed to Saber PKE
// encryption routine.
inline constexpr bool
validate_pke_encrypt_args(const size_t L,
                          const size_t EQ,
                          const size_t EP,
                          const size_t ET,
                          const size_t MU,
                          const size_t seedBytes)
{
  return ((L == 2) && (EQ == 13) && (EP == 10) && (ET == 3) && (MU == 10) &&
          (seedBytes == 32)) || // LightSaber
         ((L == 3) && (EQ == 13) && (EP == 10) && (ET == 4) && (MU == 8) &&
          (seedBytes == 32)) || // Saber
         ((L == 4) && (EQ == 13) && (EP == 10) && (ET == 6) && (MU == 6) &&
          (seedBytes == 32)); // FireSaber
}

// Compile-time executable check for validating template arguments passed to Saber PKE
// decryption routine.
inline constexpr bool
validate_pke_decrypt_args(const size_t L,
                          const size_t EQ,
                          const size_t EP,
                          const size_t ET,
                          const size_t MU)
{
  return ((L == 2) && (EQ == 13) && (EP == 10) && (ET == 3) &&
          (MU == 10)) || // LightSaber
         ((L == 3) && (EQ == 13) && (EP == 10) && (ET == 4) && (MU == 8)) || // Saber
         ((L == 4) && (EQ == 13) && (EP == 10) && (ET == 6) && (MU == 6)); // FireSaber
}

}
