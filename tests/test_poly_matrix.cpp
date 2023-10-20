#include "poly_matrix.hpp"
#include "prng.hpp"
#include <gtest/gtest.h>
#include <vector>

// Ensure functional correctness of implementation of data conversion algorithms
// i.e. algorithms used for transforming in between byte strings and vector of
// degree-255 polynomials.
//
// `moduli` must be a power of 2 value.
template<size_t rows, uint16_t moduli>
void
test_poly_matrix_conversion()
{
  constexpr size_t pblen = (saber_params::log2(moduli) * poly::N) / 8;
  constexpr size_t vblen = rows * pblen;

  std::vector<uint8_t> src_bstr(vblen, 0);
  std::vector<uint8_t> dst_bstr(vblen, 0);

  prng::prng_t prng;
  prng.read(src_bstr);

  mat::poly_matrix_t<rows, 1, moduli> pmat(src_bstr);
  pmat.to_bytes(dst_bstr);

  EXPECT_EQ(src_bstr, dst_bstr);
}

TEST(SaberKEM, PolynomialMatrixConversion)
{
  // moduli = 1 << ET
  test_poly_matrix_conversion<2, (1 << 3)>(); // lightsaber
  test_poly_matrix_conversion<3, (1 << 4)>(); // saber
  test_poly_matrix_conversion<4, (1 << 6)>(); // firesaber

  // moduli = 1 << (μ/ 2)
  test_poly_matrix_conversion<2, (1 << 5)>(); // lightsaber
  test_poly_matrix_conversion<3, (1 << 4)>(); // saber
  test_poly_matrix_conversion<4, (1 << 3)>(); // firesaber

  // moduli = 1 << EP
  test_poly_matrix_conversion<2, (1 << 10)>(); // lightsaber
  test_poly_matrix_conversion<3, (1 << 10)>(); // saber
  test_poly_matrix_conversion<4, (1 << 10)>(); // firesaber

  // moduli = 1 << EQ
  test_poly_matrix_conversion<2, (1 << 13)>(); // lightsaber
  test_poly_matrix_conversion<3, (1 << 13)>(); // saber
  test_poly_matrix_conversion<4, (1 << 13)>(); // firesaber
  test_poly_matrix_conversion<2, (1 << 12)>(); // uLightsaber
  test_poly_matrix_conversion<3, (1 << 12)>(); // uSaber
  test_poly_matrix_conversion<4, (1 << 12)>(); // uFiresaber
}
