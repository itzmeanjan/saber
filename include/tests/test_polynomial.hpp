#pragma once
#include "polynomial.hpp"
#include "prng.hpp"
#include <algorithm>
#include <cassert>
#include <vector>

// Test correctness of Saber KEM and its components.
namespace test_saber {

// Ensure functional correctness of implementation of data conversion algorithms
// i.e. algorithms used for transforming in between byte strings and degree-255
// polynomials.
//
// `moduli` must be a power of 2 value.
template<const uint16_t moduli>
inline void
test_poly_conversion()
{
  constexpr size_t blen = (saber_params::log2(moduli) * polynomial::N) / 8;

  std::vector<uint8_t> src_bstr(blen, 0);
  std::vector<uint8_t> dst_bstr(blen, 0);

  prng::prng_t prng;
  prng.read(src_bstr.data(), src_bstr.size());

  polynomial::poly_t<moduli> poly(src_bstr.data());
  poly.to_bytes(dst_bstr.data());

  assert(std::ranges::equal(src_bstr, dst_bstr));
}

}
