#pragma once
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

}
