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

  // Given a vector of polynomials, this routine can transform it into a byte
  // string of length rows * log2(moduli) * 32, following algorithm 12 of spec.
  inline void to_bytes(std::span<uint8_t> bstr)
    requires(cols == 1)
  {
    constexpr size_t poly_blen = polynomial::N * saber_params::log2(moduli) / 8;
    for (size_t i = 0; i < rows; i++) {
      elements[i].to_bytes(bstr.subspan(i * poly_blen, poly_blen));
    }
  }

  // Given a matrix M ∈ Rq^(l×l) and vector v ∈ Rq^(l×1), this routine performs
  // a matrix vector multiplication, returning a vector mv ∈ Rq^(l×1), following
  // algorithm 13 of spec.
  template<const size_t rhs_rows>
  inline poly_matrix_t<rows, 1, moduli> mat_vec_mul(
    const poly_matrix_t<rhs_rows, 1, moduli>& vec)
    requires((rows == cols) && (cols == rhs_rows))
  {
    poly_matrix_t<rows, 1, moduli> res;

    auto mat = this;
    for (size_t i = 0; i < rows; i++) {
      polynomial::poly_t<moduli> poly;

      for (size_t j = 0; j < cols; j++) {
        poly += (mat.elements[i * cols + j] * vec.elements[j]);
      }
      res[i] = poly;
    }

    return res;
  }

  // Given two vectors v_a, v_b ∈ Rp^(l×1), this routine computes their inner
  // product, returning a polynomial c ∈ Rp, following algorithm 14 of spec.
  inline polynomial::poly_t<moduli> inner_prod(
    const poly_matrix_t<rows, cols, moduli>& vec)
    requires(cols == 1)
  {
    polynomial::poly_t<moduli> res;

    for (size_t i = 0; i < rows; i++) {
      res += (this->elements[i] * vec.elements[i]);
    }

    return res;
  }
};

}
