#pragma once
#include "zq.hpp"
#include <array>
#include <cstddef>

// Operations defined over quotient ring Rq
namespace polynomial {

// For all parameter sets of Saber KEM, degree of polynomials over Zq is 255.
constexpr size_t N = 256;

// Wrapper type encapsulating operations over Rq = Zq[X]/(X^N + 1), N = 256
struct poly_t
{
private:
  std::array<zq::zq_t, N> coeffs{};

public:
  // Constructors
  inline constexpr poly_t() = default;
  inline constexpr poly_t(std::array<zq::zq_t, N> arr) { coeffs = arr; }

  // Addition of two polynomials s.t. their coefficients are over Zq.
  inline constexpr poly_t operator+(const poly_t& rhs) const
  {
    std::array<zq::zq_t, N> res{};

    for (size_t i = 0; i < N; i++) {
      res[i] = this->coeffs[i] + rhs.coeffs[i];
    }

    return res;
  }

  // Compound addition of two polynomials s.t. their coefficients are over Zq.
  inline constexpr void operator+=(const poly_t& rhs) { *this = *this + rhs; }
};

}
