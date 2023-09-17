#pragma once
#include "polynomial.hpp"
#include "utils.hpp"

// Utility functions for Saber KEM
namespace saber_utils {

// Centered Binomial Distribution, which is used for deterministically sampling a
// degree-255 polynomial from output of a pseudo-random function (PRF). This function is
// used for generating secret vector `s` from SHAKE128 output of seed value `seedS`.
//
// While implementing this, I collected some inspiration from
// https://github.com/KULeuven-COSIC/SABER/blob/f7f39e4db2f3e22a21e1dd635e0601caae2b4510/Reference_Implementation_KEM/cbd.c.
// Similar sort of sampling routine can also be found in
// https://github.com/itzmeanjan/kyber/blob/8cbb09472dc5f7e5ae8bc52cbcbf6344f637d4fe/include/sampling.hpp#L88-L152.
template<uint16_t moduli, size_t mu>
inline poly::poly_t<moduli>
cbd(std::span<const uint8_t> bytes)
  requires((mu == 10) || (mu == 8) || (mu == 6))
{
  constexpr size_t poly_blen = (poly::N * mu) / 8;
  constexpr size_t muby2 = mu / 2;

  poly::poly_t<moduli> res;

  if constexpr (muby2 == 5) {
    constexpr uint64_t mask = 0b0000100001000010000100001000010000100001ul;
    constexpr uint64_t mask5 = (1ul << muby2) - 1;

    size_t boff = 0;
    size_t coff = 0;

    while (boff < poly_blen) {
      const uint64_t word = from_le_bytes<uint64_t>(bytes.subspan(boff, 5));
      const uint64_t hw = ((word >> 0) & mask) + ((word >> 1) & mask) +
                          ((word >> 2) & mask) + ((word >> 3) & mask) +
                          ((word >> 4) & mask);

      res[coff + 0] = static_cast<uint16_t>((hw >> 0) & mask5) -
                      static_cast<uint16_t>((hw >> 5) & mask5);
      res[coff + 1] = static_cast<uint16_t>((hw >> 10) & mask5) -
                      static_cast<uint16_t>((hw >> 15) & mask5);
      res[coff + 2] = static_cast<uint16_t>((hw >> 20) & mask5) -
                      static_cast<uint16_t>((hw >> 25) & mask5);
      res[coff + 3] = static_cast<uint16_t>((hw >> 30) & mask5) -
                      static_cast<uint16_t>((hw >> 35) & mask5);

      boff += 5;
      coff += 4;
    }
  } else if constexpr (muby2 == 4) {
    constexpr uint32_t mask = 0b00010001000100010001000100010001u;
    constexpr uint32_t mask4 = (1u << muby2) - 1;

    size_t boff = 0;
    size_t coff = 0;

    while (boff < poly_blen) {
      const uint32_t word = from_le_bytes<uint32_t>(bytes.subspan(boff, 4));
      const uint32_t hw = ((word >> 0) & mask) + ((word >> 1) & mask) +
                          ((word >> 2) & mask) + ((word >> 3) & mask);

      res[coff + 0] = static_cast<uint16_t>((hw >> 0) & mask4) -
                      static_cast<uint16_t>((hw >> 4) & mask4);
      res[coff + 1] = static_cast<uint16_t>((hw >> 8) & mask4) -
                      static_cast<uint16_t>((hw >> 12) & mask4);
      res[coff + 2] = static_cast<uint16_t>((hw >> 16) & mask4) -
                      static_cast<uint16_t>((hw >> 20) & mask4);
      res[coff + 3] = static_cast<uint16_t>((hw >> 24) & mask4) -
                      static_cast<uint16_t>((hw >> 28) & mask4);

      boff += 4;
      coff += 4;
    }
  } else if constexpr (muby2 == 3) {
    constexpr uint32_t mask = 0b001001001001001001001001u;
    constexpr uint32_t mask3 = (1u << muby2) - 1;

    size_t boff = 0;
    size_t coff = 0;

    while (boff < poly_blen) {
      const uint32_t word = from_le_bytes<uint32_t>(bytes.subspan(boff, 3));
      const uint32_t hw = (word & mask) + ((word >> 1) & mask) + ((word >> 2) & mask);

      res[coff + 0] = static_cast<uint16_t>((hw >> 0) & mask3) -
                      static_cast<uint16_t>((hw >> 3) & mask3);
      res[coff + 1] = static_cast<uint16_t>((hw >> 6) & mask3) -
                      static_cast<uint16_t>((hw >> 9) & mask3);
      res[coff + 2] = static_cast<uint16_t>((hw >> 12) & mask3) -
                      static_cast<uint16_t>((hw >> 15) & mask3);
      res[coff + 3] = static_cast<uint16_t>((hw >> 18) & mask3) -
                      static_cast<uint16_t>((hw >> 21) & mask3);

      boff += 3;
      coff += 4;
    }
  }

  return res;
}

}
