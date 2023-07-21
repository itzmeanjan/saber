#pragma once
#include "poly_matrix.hpp"
#include "polynomial.hpp"

namespace saber_consts {

// Compile-time compute constant polynomial h1 ∈ Rq, following section 2.3 of spec.
template<const uint16_t moduli, const uint16_t εq, const uint16_t εp>
inline constexpr poly::poly_t<moduli>
compute_poly_h1()
  requires((εq > εp) && (moduli == (1u << εq)))
{
  constexpr auto v = 1u << (εq - εp - 1);
  constexpr zq::zq_t coeff(v);

  poly::poly_t<moduli> h1;
  for (size_t i = 0; i < poly::N; i++) {
    h1[i] = coeff;
  }

  return h1;
}

// Compile-time compute constant vector h ∈ Rq^(lx1), following section 2.3 of spec.
template<const size_t L, const uint16_t moduli, const uint16_t εq, const uint16_t εp>
inline constexpr mat::poly_matrix_t<L, 1, moduli>
compute_polyvec_h()
{
  const auto h1 = compute_poly_h1<moduli, εq, εp>();

  mat::poly_matrix_t<L, 1, moduli> h;
  for (size_t i = 0; i < L; i++) {
    h[i] = h1;
  }

  return h;
}

// Compile-time compute constant polynomial h2 ∈ Rq, following section 2.3 of spec.
template<const uint16_t moduli, const uint16_t εq, const uint16_t εp, const uint16_t εt>
inline constexpr poly::poly_t<moduli>
compute_poly_h2()
  requires(((εq > εp) && (εp > εt)) && (moduli == (1u << εq)))
{
  constexpr auto v = (1u << (εp - 2)) - (1u << (εp - εt - 1)) + (1u << (εq - εp - 1));
  constexpr zq::zq_t coeff(v);

  poly::poly_t<moduli> h2;
  for (size_t i = 0; i < poly::N; i++) {
    h2[i] = coeff;
  }

  return h2;
}

}
