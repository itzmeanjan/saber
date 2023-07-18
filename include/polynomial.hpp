#pragma once
#include "karatsuba.hpp"
#include "utils.hpp"
#include "zq.hpp"
#include <array>

// Operations defined over quotient ring Rq
namespace polynomial {

// For all parameter sets of Saber KEM, degree of polynomials over Zq is 255.
constexpr size_t N = 256;

// Wrapper type encapsulating operations over Rq = Zq[X]/(X^N + 1), N = 256
template<const uint16_t moduli>
  requires(saber_params::is_power_of_2(moduli))
struct poly_t
{
private:
  std::array<zq::zq_t, N> coeffs{};

public:
  // Constructors
  inline constexpr poly_t() = default;
  inline constexpr poly_t(std::array<zq::zq_t, N> arr) { coeffs = arr; }

  // Given a byte array of length log2(moduli) * 32 -bytes, this routine can be
  // used for transforming it into a polynomial, following algorithm 9 of spec.
  inline explicit poly_t(std::span<const uint8_t> bstr)
  {
    constexpr size_t lg2_moduli = saber_params::log2(moduli);
    constexpr size_t blen = (lg2_moduli * N) / 8;

    std::array<zq::zq_t, N> res{};

    if constexpr (lg2_moduli == 13) {
      constexpr uint64_t mask13 = (1ul << lg2_moduli) - 1;
      constexpr uint64_t mask1 = mask13 >> 12;

      size_t boff = 0;
      size_t coff = 0;

      while (boff < blen) {
        const auto ptr0 = bstr.subspan(boff, 8);
        const auto word0 = saber_utils::from_le_bytes<uint64_t>(ptr0);
        boff += 8;

        res[coff] = static_cast<uint16_t>(word0 & mask13);
        res[coff + 1] = static_cast<uint16_t>((word0 >> 13) & mask13);
        res[coff + 2] = static_cast<uint16_t>((word0 >> 26) & mask13);
        res[coff + 3] = static_cast<uint16_t>((word0 >> 39) & mask13);

        const auto ptr1 = bstr.subspan(boff, 5);
        const auto word1 = saber_utils::from_le_bytes<uint64_t>(ptr1);
        boff += 5;

        res[coff + 4] = (static_cast<uint16_t>(word1 & mask1) << 12) |
                        static_cast<uint16_t>(word0 >> 52);
        res[coff + 5] = static_cast<uint16_t>((word1 >> 1) & mask13);
        res[coff + 6] = static_cast<uint16_t>((word1 >> 14) & mask13);
        res[coff + 7] = static_cast<uint16_t>((word1 >> 27) & mask13);

        coff += 8;
      }
    } else if constexpr (lg2_moduli == 10) {
      constexpr uint64_t mask10 = (1ul << lg2_moduli) - 1;

      size_t boff = 0;
      size_t coff = 0;

      while (boff < blen) {
        const auto ptr = bstr.subspan(boff, 5);
        const auto word = saber_utils::from_le_bytes<uint64_t>(ptr);
        boff += 5;

        res[coff] = static_cast<uint16_t>(word & mask10);
        res[coff + 1] = static_cast<uint16_t>((word >> 10) & mask10);
        res[coff + 2] = static_cast<uint16_t>((word >> 20) & mask10);
        res[coff + 3] = static_cast<uint16_t>((word >> 30) & mask10);

        coff += 4;
      }
    } else if constexpr (lg2_moduli == 6) {
      constexpr uint32_t mask6 = (1u << lg2_moduli) - 1;

      size_t boff = 0;
      size_t coff = 0;

      while (boff < blen) {
        const auto ptr = bstr.subspan(boff, 3);
        const auto word = saber_utils::from_le_bytes<uint32_t>(ptr);
        boff += 3;

        res[coff] = static_cast<uint16_t>(word & mask6);
        res[coff + 1] = static_cast<uint16_t>((word >> 6) & mask6);
        res[coff + 2] = static_cast<uint16_t>((word >> 12) & mask6);
        res[coff + 3] = static_cast<uint16_t>((word >> 18) & mask6);

        coff += 4;
      }
    } else if constexpr (lg2_moduli == 4) {
      constexpr uint8_t mask = (1u << lg2_moduli) - 1;

      size_t boff = 0;
      size_t coff = 0;

      while (boff < blen) {
        res[coff] = static_cast<uint16_t>((bstr[boff]) & mask);
        res[coff + 1] = static_cast<uint16_t>(bstr[boff] >> 4);

        boff += 1;
        coff += 2;
      }
    } else if constexpr (lg2_moduli == 3) {
      constexpr uint32_t mask3 = (1u << lg2_moduli) - 1;

      size_t boff = 0;
      size_t coff = 0;

      while (boff < blen) {
        const auto ptr = bstr.subspan(boff, 3);
        const auto word = saber_utils::from_le_bytes<uint32_t>(ptr);
        boff += 3;

        res[coff] = static_cast<uint16_t>(word & mask3);
        res[coff + 1] = static_cast<uint16_t>((word >> 3) & mask3);
        res[coff + 2] = static_cast<uint16_t>((word >> 6) & mask3);
        res[coff + 3] = static_cast<uint16_t>((word >> 9) & mask3);
        res[coff + 4] = static_cast<uint16_t>((word >> 12) & mask3);
        res[coff + 5] = static_cast<uint16_t>((word >> 15) & mask3);
        res[coff + 6] = static_cast<uint16_t>((word >> 18) & mask3);
        res[coff + 7] = static_cast<uint16_t>((word >> 21) & mask3);

        coff += 8;
      }
    }

    coeffs = res;
  }

  // Returns coefficient at given polynomial index ∈ [0, N).
  inline constexpr zq::zq_t operator[](const size_t idx) const
  {
    return coeffs[idx];
  }

  // Addition of two polynomials s.t. their coefficients are over Zq.
  inline constexpr poly_t operator+(const poly_t& rhs) const
  {
    std::array<zq::zq_t, N> res{};

    for (size_t i = 0; i < N; i++) {
      res[i] = coeffs[i] + rhs.coeffs[i];
    }

    return res;
  }

  // Compound addition of two polynomials s.t. their coefficients are over Zq.
  inline constexpr void operator+=(const poly_t& rhs) { *this = *this + rhs; }

  // Multiplication of two polynomials s.t. their coefficients are over Zq.
  inline constexpr poly_t operator*(const poly_t& rhs) const
  {
    return karatsuba::karamul(this->coeffs, rhs.coeffs);
  }

  // Left shift each coefficient of the polynomial by factor `off`.
  inline constexpr poly_t operator<<(const size_t off) const
  {
    std::array<zq::zq_t, N> res{};

    for (size_t i = 0; i < N; i++) {
      res[i] = coeffs[i] << off;
    }

    return res;
  }

  // Right shift each coefficient of the polynomial by factor `off`.
  inline constexpr poly_t operator>>(const size_t off) const
  {
    std::array<zq::zq_t, N> res{};

    for (size_t i = 0; i < N; i++) {
      res[i] = coeffs[i] >> off;
    }

    return res;
  }

  // Given a polynomial, this routine can transform it into a byte string of
  // length log2(moduli) * 32, following algorithm 10 of spec.
  inline void to_bytes(std::span<uint8_t> bstr)
  {
    constexpr size_t lg2_moduli = saber_params::log2(moduli);

    if constexpr (lg2_moduli == 13) {
      constexpr uint16_t mask8 = 0xff;
      constexpr uint16_t mask7 = mask8 >> 1;
      constexpr uint16_t mask6 = mask7 >> 1;
      constexpr uint16_t mask5 = mask6 >> 1;
      constexpr uint16_t mask4 = mask5 >> 1;
      constexpr uint16_t mask3 = mask4 >> 1;
      constexpr uint16_t mask2 = mask3 >> 1;
      constexpr uint16_t mask1 = mask2 >> 1;

      size_t boff = 0;
      size_t coff = 0;

      while (coff < N) {
        bstr[boff] = coeffs[coff].as_raw() & mask8;
        bstr[boff + 1] = ((coeffs[coff + 1].as_raw() & mask3) << 5) |
                         ((coeffs[coff].as_raw() >> 8) & mask5);
        bstr[boff + 2] = ((coeffs[coff + 1].as_raw() >> 3) & mask8);
        bstr[boff + 3] = ((coeffs[coff + 2].as_raw() & mask6) << 2) |
                         ((coeffs[coff + 1].as_raw() >> 11) & mask2);
        bstr[boff + 4] = ((coeffs[coff + 3].as_raw() & mask1) << 7) |
                         ((coeffs[coff + 2].as_raw() >> 6) & mask7);
        bstr[boff + 5] = (coeffs[coff + 3].as_raw() >> 1) & mask8;
        bstr[boff + 6] = ((coeffs[coff + 4].as_raw() & mask4) << 4) |
                         ((coeffs[coff + 3].as_raw() >> 9) & mask4);
        bstr[boff + 7] = (coeffs[coff + 4].as_raw() >> 4) & mask8;
        bstr[boff + 8] = ((coeffs[coff + 5].as_raw() & mask7) << 1) |
                         ((coeffs[coff + 4].as_raw() >> 12) & mask1);
        bstr[boff + 9] = ((coeffs[coff + 6].as_raw() & mask2) << 6) |
                         ((coeffs[coff + 5].as_raw() >> 7) & mask6);
        bstr[boff + 10] = (coeffs[coff + 6].as_raw() >> 2) & mask8;
        bstr[boff + 11] = ((coeffs[coff + 7].as_raw() & mask5) << 3) |
                          ((coeffs[coff + 6].as_raw() >> 10) & mask3);
        bstr[boff + 12] = (coeffs[coff + 7].as_raw() >> 5) & mask8;

        boff += 13;
        coff += 8;
      }
    } else if constexpr (lg2_moduli == 10) {
      constexpr uint16_t mask8 = 0xff;
      constexpr uint16_t mask6 = mask8 >> 2;
      constexpr uint16_t mask4 = mask6 >> 2;
      constexpr uint16_t mask2 = mask4 >> 2;

      size_t boff = 0;
      size_t coff = 0;

      while (coff < N) {
        bstr[boff] = coeffs[coff].as_raw() & mask8;
        bstr[boff + 1] = ((coeffs[coff + 1].as_raw() & mask6) << 2) |
                         ((coeffs[coff].as_raw() >> 8) & mask2);
        bstr[boff + 2] = ((coeffs[coff + 2].as_raw() & mask4) << 4) |
                         ((coeffs[coff + 1].as_raw() >> 6) & mask4);
        bstr[boff + 3] = ((coeffs[coff + 3].as_raw() & mask2) << 6) |
                         ((coeffs[coff + 2].as_raw() >> 4) & mask6);
        bstr[boff + 4] = (coeffs[coff + 3].as_raw() >> 2) & mask8;

        boff += 5;
        coff += 4;
      }
    } else if constexpr (lg2_moduli == 6) {
      constexpr uint16_t mask6 = (1u << lg2_moduli) - 1;
      constexpr uint16_t mask4 = mask6 >> 2;
      constexpr uint16_t mask2 = mask4 >> 2;

      size_t boff = 0;
      size_t coff = 0;

      while (coff < N) {
        bstr[boff] = ((coeffs[coff + 1].as_raw() & mask2) << 6) |
                     (coeffs[coff].as_raw() & mask6);
        bstr[boff + 1] = ((coeffs[coff + 2].as_raw() & mask4) << 4) |
                         ((coeffs[coff + 1].as_raw() >> 2) & mask4);
        bstr[boff + 2] = ((coeffs[coff + 3].as_raw() & mask6) << 2) |
                         ((coeffs[coff + 2].as_raw() >> 4) & mask2);

        boff += 3;
        coff += 4;
      }
    } else if constexpr (lg2_moduli == 4) {
      constexpr uint8_t mask = (1u << lg2_moduli) - 1;

      size_t boff = 0;
      size_t coff = 0;

      while (coff < N) {
        bstr[boff] = ((coeffs[coff + 1].as_raw() & mask) << 4) |
                     (coeffs[coff].as_raw() & mask);

        boff += 1;
        coff += 2;
      }
    } else if constexpr (lg2_moduli == 3) {
      constexpr uint16_t mask3 = (1u << lg2_moduli) - 1;
      constexpr uint16_t mask2 = mask3 >> 1;
      constexpr uint16_t mask1 = mask2 >> 1;

      size_t boff = 0;
      size_t coff = 0;

      while (coff < N) {
        bstr[boff] = ((coeffs[coff + 2].as_raw() & mask2) << 6) |
                     ((coeffs[coff + 1].as_raw() & mask3) << 3) |
                     (coeffs[coff].as_raw() & mask3);
        bstr[boff + 1] = ((coeffs[coff + 5].as_raw() & mask1) << 7) |
                         ((coeffs[coff + 4].as_raw() & mask3) << 4) |
                         ((coeffs[coff + 3].as_raw() & mask3) << 1) |
                         ((coeffs[coff + 2].as_raw() >> 2) & mask1);
        bstr[boff + 2] = ((coeffs[coff + 7].as_raw() & mask3) << 5) |
                         ((coeffs[coff + 6].as_raw() & mask3) << 2) |
                         ((coeffs[coff + 5].as_raw() >> 1) & mask2);

        boff += 3;
        coff += 8;
      }
    }
  }
};

}
