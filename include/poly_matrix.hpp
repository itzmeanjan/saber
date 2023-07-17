#pragma once
#include "params.hpp"
#include "polynomial.hpp"
#include <array>

// Operations defined over matrix/ vector of polynomials.
namespace poly_matrix {

// Wrapper type encapsulating matrix/ vector operations s.t. its elements are
// polynomials in Rq = Zq[X]/(X^N + 1), N = 256.
template<const size_t rows, const size_t cols, const uint16_t moduli>
struct poly_matrix_t
{
private:
  std::array<polynomial::poly_t<moduli>, rows * cols> elements{};

public:
  // Constructors
  inline constexpr poly_matrix_t() = default;
  inline constexpr poly_matrix_t(
    std::array<polynomial::poly_t<moduli>, rows * cols> arr)
  {
    elements = arr;
  }

  // Given a byte array of length rows * log2(moduli) * 32 -bytes, this routine
  // can be used for transforming it into a vector of polynomials, following
  // algorithm 11 of spec.
  inline explicit poly_matrix_t(std::span<const uint8_t> bstr)
    requires(cols == 1)
  {
    constexpr size_t poly_blen = polynomial::N * saber_params::log2(moduli) / 8;
    for (size_t i = 0; i < rows; i++) {
      polynomial::poly_t<moduli> poly(bstr.subspan(i * poly_blen, poly_blen));
      elements[i] = poly;
    }
  }
};

}
