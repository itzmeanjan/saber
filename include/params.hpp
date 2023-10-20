#pragma once
#include <algorithm>
#include <array>
#include <bit>
#include <cstddef>
#include <cstdint>
#include <type_traits>
#include <vector>

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

// Given a power of 2 integer moduli, figure, in compile-time, if that's supported in
// polynomial serialization/ deserialization routines. If not supported, it must return
// FALSE, so that translation units can't be compiled anymore.
template<uint16_t moduli>
inline constexpr bool
validate_poly_serialization_args()
{
  constexpr uint16_t lg2_moduli = saber_params::log2(moduli);

  std::array<uint16_t, 9> bit_widths = { 13, 12, 10, 6, 5, 4, 3, 2, 1 };
  auto elm = std::find(bit_widths.begin(), bit_widths.end(), lg2_moduli);
  return elm != bit_widths.end();
}

inline constexpr bool
validate_gen_secret_args(const bool uniform_sampling, const size_t mu)
{
  return is_even(mu) &&                      // μ must be even
         ((uniform_sampling && (mu == 2)) || // μ must be 2, for uniform dist. sampling
          (!uniform_sampling && (mu != 2))   // μ mostly != 2, for binomial dist. sampling
         );
}

// Compile-time executable check for validating template arguments passed to Saber PKE
// key generation routine.
inline constexpr bool
validate_pke_keygen_args(const size_t L, const size_t EQ, const size_t EP, const size_t MU, const size_t seedBytes, const size_t noiseBytes, const bool uniform_sampling)
{
  return (!uniform_sampling && (L == 2) && (EQ == 13) && (EP == 10) && (MU == 10) && (seedBytes == 32) && (noiseBytes == 32)) || // LightSaber
         (uniform_sampling && (L == 2) && (EQ == 12) && (EP == 10) && (MU == 2) && (seedBytes == 32) && (noiseBytes == 32)) ||   // uLightSaber
         (!uniform_sampling && (L == 3) && (EQ == 13) && (EP == 10) && (MU == 8) && (seedBytes == 32) && (noiseBytes == 32)) ||  // Saber
         (uniform_sampling && (L == 3) && (EQ == 12) && (EP == 10) && (MU == 2) && (seedBytes == 32) && (noiseBytes == 32)) ||   // uSaber
         (!uniform_sampling && (L == 4) && (EQ == 13) && (EP == 10) && (MU == 6) && (seedBytes == 32) && (noiseBytes == 32)) ||  // FireSaber
         (uniform_sampling && (L == 4) && (EQ == 12) && (EP == 10) && (MU == 2) && (seedBytes == 32) && (noiseBytes == 32));     // uFireSaber
}

// Compile-time executable check for validating template arguments passed to Saber PKE
// encryption routine.
inline constexpr bool
validate_pke_encrypt_args(const size_t L, const size_t EQ, const size_t EP, const size_t ET, const size_t MU, const size_t seedBytes, const bool uniform_sampling)
{
  return (!uniform_sampling && (L == 2) && (EQ == 13) && (EP == 10) && (ET == 3) && (MU == 10) && (seedBytes == 32)) || // LightSaber
         (uniform_sampling && (L == 2) && (EQ == 12) && (EP == 10) && (ET == 3) && (MU == 2) && (seedBytes == 32)) ||   // uLightSaber
         (!uniform_sampling && (L == 3) && (EQ == 13) && (EP == 10) && (ET == 4) && (MU == 8) && (seedBytes == 32)) ||  // Saber
         (uniform_sampling && (L == 3) && (EQ == 12) && (EP == 10) && (ET == 4) && (MU == 2) && (seedBytes == 32)) ||   // uSaber
         (!uniform_sampling && (L == 4) && (EQ == 13) && (EP == 10) && (ET == 6) && (MU == 6) && (seedBytes == 32)) ||  // FireSaber
         (uniform_sampling && (L == 4) && (EQ == 12) && (EP == 10) && (ET == 6) && (MU == 2) && (seedBytes == 32));     // uFireSaber
}

// Compile-time executable check for validating template arguments passed to Saber PKE
// decryption routine.
inline constexpr bool
validate_pke_decrypt_args(const size_t L, const size_t EQ, const size_t EP, const size_t ET, const size_t MU, const bool uniform_sampling)
{
  return (!uniform_sampling && (L == 2) && (EQ == 13) && (EP == 10) && (ET == 3) && (MU == 10)) || // LightSaber
         (uniform_sampling && (L == 2) && (EQ == 12) && (EP == 10) && (ET == 3) && (MU == 2)) ||   // uLightSaber
         (!uniform_sampling && (L == 3) && (EQ == 13) && (EP == 10) && (ET == 4) && (MU == 8)) ||  // Saber
         (uniform_sampling && (L == 3) && (EQ == 12) && (EP == 10) && (ET == 4) && (MU == 2)) ||   // uSaber
         (!uniform_sampling && (L == 4) && (EQ == 13) && (EP == 10) && (ET == 6) && (MU == 6)) ||  // FireSaber
         (uniform_sampling && (L == 4) && (EQ == 12) && (EP == 10) && (ET == 6) && (MU == 2));     // uFireSaber
}

// Compile-time executable check for validating template arguments passed to Saber KEM
// key generation routine.
inline constexpr bool
validate_kem_keygen_args(const size_t L,
                         const size_t EQ,
                         const size_t EP,
                         const size_t MU,
                         const size_t seedBytes,
                         const size_t noiseBytes,
                         const size_t keyBytes,
                         const bool uniform_sampling)
{
  return (!uniform_sampling && (L == 2) && (EQ == 13) && (EP == 10) && (MU == 10) && (seedBytes == 32) && (noiseBytes == 32) && (keyBytes == 32)) || // LightSaber
         (uniform_sampling && (L == 2) && (EQ == 12) && (EP == 10) && (MU == 2) && (seedBytes == 32) && (noiseBytes == 32) && (keyBytes == 32)) ||   // uLightSaber
         (!uniform_sampling && (L == 3) && (EQ == 13) && (EP == 10) && (MU == 8) && (seedBytes == 32) && (noiseBytes == 32) && (keyBytes == 32)) ||  // Saber
         (uniform_sampling && (L == 3) && (EQ == 12) && (EP == 10) && (MU == 2) && (seedBytes == 32) && (noiseBytes == 32) && (keyBytes == 32)) ||   // uSaber
         (!uniform_sampling && (L == 4) && (EQ == 13) && (EP == 10) && (MU == 6) && (seedBytes == 32) && (noiseBytes == 32) && (keyBytes == 32)) ||  // FireSaber
         (uniform_sampling && (L == 4) && (EQ == 12) && (EP == 10) && (MU == 2) && (seedBytes == 32) && (noiseBytes == 32) && (keyBytes == 32));     // uFireSaber
}

// Compile-time executable check for validating template arguments passed to Saber KEM
// encapsulation routine.
inline constexpr bool
validate_kem_encaps_args(const size_t L,
                         const size_t EQ,
                         const size_t EP,
                         const size_t ET,
                         const size_t MU,
                         const size_t seedBytes,
                         const size_t keyBytes,
                         const bool uniform_sampling)
{
  return (!uniform_sampling && (L == 2) && (EQ == 13) && (EP == 10) && (ET == 3) && (MU == 10) && (seedBytes == 32) && (keyBytes == 32)) || // LightSaber
         (uniform_sampling && (L == 2) && (EQ == 12) && (EP == 10) && (ET == 3) && (MU == 2) && (seedBytes == 32) && (keyBytes == 32)) ||   // uLightSaber
         (!uniform_sampling && (L == 3) && (EQ == 13) && (EP == 10) && (ET == 4) && (MU == 8) && (seedBytes == 32) && (keyBytes == 32)) ||  // Saber
         (uniform_sampling && (L == 3) && (EQ == 12) && (EP == 10) && (ET == 4) && (MU == 2) && (seedBytes == 32) && (keyBytes == 32)) ||   // uSaber
         (!uniform_sampling && (L == 4) && (EQ == 13) && (EP == 10) && (ET == 6) && (MU == 6) && (seedBytes == 32) && (keyBytes == 32)) ||  // FireSaber
         (uniform_sampling && (L == 4) && (EQ == 12) && (EP == 10) && (ET == 6) && (MU == 2) && (seedBytes == 32) && (keyBytes == 32));     // uFireSaber
}

// Compile-time executable check for validating template arguments passed to Saber KEM
// decapsulation routine.
inline constexpr bool
validate_kem_decaps_args(const size_t L,
                         const size_t EQ,
                         const size_t EP,
                         const size_t ET,
                         const size_t MU,
                         const size_t seedBytes,
                         const size_t keyBytes,
                         const bool uniform_sampling)
{
  return validate_kem_encaps_args(L, EQ, EP, ET, MU, seedBytes, keyBytes, uniform_sampling);
}

}
