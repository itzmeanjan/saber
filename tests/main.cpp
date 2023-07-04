#include "tests/test_polynomial.hpp"
#include <iostream>

int
main()
{
  test_saber::test_poly_conversion<(1 << 3)>();
  test_saber::test_poly_conversion<(1 << 4)>();
  test_saber::test_poly_conversion<(1 << 6)>();
  test_saber::test_poly_conversion<(1 << 10)>();
  test_saber::test_poly_conversion<(1 << 13)>();
  std::cout << "[test] Conversion between byte string and polynomial\n";

  return 0;
}
