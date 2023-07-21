#pragma once
#include "params.hpp"
#include "zq.hpp"
#include <array>

// Karatsuba Multiplication of two Polynomials
namespace karatsuba {

// Given two polynomials of degree N-1 ( s.t. N is power of 2 and N >= 1), this
// routine multiplies them using Karatsuba algorithm, following
// https://github.com/itzmeanjan/falcon/blob/cce934dcd092c95808c0bdaeb034312ee7754d7e/include/karatsuba.hpp,
// computing resulting polynomial of degree 2*N - 1
template<const size_t N>
static inline constexpr std::array<zq::zq_t, 2 * N>
karatsuba(const std::array<zq::zq_t, N>& polya, const std::array<zq::zq_t, N>& polyb)
  requires(saber_params::is_power_of_2(N))
{
  if constexpr (N == 1) {
    return { zq::zq_t(polya[0] * polyb[0]), zq::zq_t(0) };
  } else {
    constexpr size_t Nby2 = N / 2;

    std::array<zq::zq_t, Nby2> polya0;
    std::array<zq::zq_t, Nby2> polya1;
    std::array<zq::zq_t, Nby2> polyb0;
    std::array<zq::zq_t, Nby2> polyb1;
    std::array<zq::zq_t, Nby2> polyax;
    std::array<zq::zq_t, Nby2> polybx;

    for (size_t i = 0; i < Nby2; i++) {
      polya0[i] = polya[i];
      polya1[i] = polya[Nby2 + i];

      polyb0[i] = polyb[i];
      polyb1[i] = polyb[Nby2 + i];

      polyax[i] = polya[i] + polya[Nby2 + i];
      polybx[i] = polyb[i] + polyb[Nby2 + i];
    }

    const std::array<zq::zq_t, N> polya0b0 = karatsuba<Nby2>(polya0, polyb0);
    const std::array<zq::zq_t, N> polya1b1 = karatsuba<Nby2>(polya1, polyb1);
    std::array<zq::zq_t, N> polyaxbx = karatsuba<Nby2>(polyax, polybx);

    for (size_t i = 0; i < N; i++) {
      polyaxbx[i] = polyaxbx[i] - zq::zq_t(polya0b0[i] + polya1b1[i]);
    }

    std::array<zq::zq_t, 2 * N> polyab{};
    for (size_t i = 0; i < N; i++) {
      polyab[i] = polyab[i] + polya0b0[i];
      polyab[N + i] = polyab[N + i] + polya1b1[i];
      polyab[Nby2 + i] = polyab[Nby2 + i] + polyaxbx[i];
    }

    return polyab;
  }
}

// Given two polynomials of degree N-1 ( s.t. N is power of 2 and N>=1 ), this
// routine first multiplies them using Karatsuba algorithm and then reduces it
// modulo  (x ** N + 1), following
// https://github.com/itzmeanjan/falcon/blob/cce934dcd092c95808c0bdaeb034312ee7754d7e/include/karatsuba.hpp
template<const size_t N>
static inline constexpr std::array<zq::zq_t, N>
karamul(const std::array<zq::zq_t, N>& polya, const std::array<zq::zq_t, N>& polyb)
{
  const std::array<zq::zq_t, 2 * N> polyab = karatsuba(polya, polyb);

  std::array<zq::zq_t, N> res{};
  for (size_t i = 0; i < N; i++) {
    res[i] = polyab[i] - polyab[N + i];
  }

  return res;
}

}
