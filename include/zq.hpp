#pragma once
#include "params.hpp"
#include <cstddef>

// Arithmetic operations over Zq s.t. q = 2^i, i >= 0
namespace zq {

// Wrapper type encapsulating arithmetic operations over Zq s.t. log2(q) <= 15.
struct zq_t
{
private:
  uint16_t val = 0;

public:
  //  Constructors
  inline constexpr zq_t() = default;
  inline constexpr zq_t(const uint16_t v) { val = v; }

  // Addition over Zq
  inline constexpr zq_t operator+(const zq_t& rhs) const
  {
    return this->val + rhs.val;
  }

  // Compound addition over Zq
  inline constexpr void operator+=(const zq_t& rhs) { *this = *this + rhs; }

  // Negation over Zq
  inline constexpr zq_t operator-() const { return -this->val; }

  // Subtraction over Zq
  inline constexpr zq_t operator-(const zq_t& rhs) const
  {
    return *this + (-rhs);
  }

  // Multiplication over Zq
  inline constexpr zq_t operator*(const zq_t& rhs) const
  {
    return this->val * rhs.val;
  }

  // Left shift element ∈ Zq
  inline constexpr zq_t operator<<(const size_t off) const
  {
    return this->val << off;
  }

  // Right shift element ∈ Zq
  inline constexpr zq_t operator>>(const size_t off) const
  {
    return this->val >> off;
  }

  // Reduction by integer moduli q s.t. q = power of 2.
  template<const uint16_t moduli>
  inline constexpr zq_t reduce_by() const
    requires(saber_params::is_power_of_2(moduli))
  {
    return this->val & (moduli - 1);
  }

  // Raw value ∈ Zq
  inline constexpr uint16_t as_raw() const { return this->val; }
};

}
