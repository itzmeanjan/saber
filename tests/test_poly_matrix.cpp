#include "poly_matrix.hpp"
#include "prng.hpp"
#include <gtest/gtest.h>
#include <vector>

// Ensure functional correctness of implementation of data conversion algorithms
// i.e. algorithms used for transforming in between byte strings and vector of
// degree-255 polynomials.
//
// `moduli` must be a power of 2 value.
template<const size_t rows, const uint16_t moduli>
void
test_poly_matrix_conversion()
{
  constexpr size_t pblen = (saber_params::log2(moduli) * polynomial::N) / 8;
  constexpr size_t vblen = rows * pblen;

  std::vector<uint8_t> src_bstr(vblen, 0);
  std::vector<uint8_t> dst_bstr(vblen, 0);

  prng::prng_t prng;
  prng.read(src_bstr);

  poly_matrix::poly_matrix_t<rows, 1, moduli> pmat(src_bstr);
  pmat.to_bytes(dst_bstr);

  ASSERT_EQ(src_bstr, dst_bstr);
}

TEST(SaberKEM, PolynomialMatrixConversion)
{
  test_poly_matrix_conversion<2, (1 << 3)>();
  test_poly_matrix_conversion<3, (1 << 4)>();
  test_poly_matrix_conversion<4, (1 << 6)>();
  test_poly_matrix_conversion<2, (1 << 10)>();
  test_poly_matrix_conversion<3, (1 << 10)>();
  test_poly_matrix_conversion<4, (1 << 10)>();
  test_poly_matrix_conversion<2, (1 << 13)>();
  test_poly_matrix_conversion<3, (1 << 13)>();
  test_poly_matrix_conversion<4, (1 << 13)>();
}