#pragma once
#include "params.hpp"
#include "polynomial.hpp"
#include "shake128.hpp"
#include <array>
#include <span>

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

  // Given row and column index of matrix, returns reference to requested
  // element polynomial.
  inline constexpr polynomial::poly_t<moduli>& operator[](std::pair<size_t, size_t> idx)
  {
    return this->elements[idx.first * cols + idx.second];
  }

  // Given row and column index of matrix, returns const reference to requested
  // element polynomial.
  inline constexpr const polynomial::poly_t<moduli>& operator[](
    std::pair<size_t, size_t> idx) const
  {
    return this->elements[idx.first * cols + idx.second];
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

  // Given random byte string ( seed ) of length `seedbytes` as input,
  // this routine generates a matrix A ∈ Rq^(l×l), following algorithm 15 of
  // spec.
  template<const size_t seedbytes>
  inline static poly_matrix_t<rows, cols, moduli> gen_matrix(
    std::span<const uint8_t, seedbytes> seed)
    requires(rows == cols)
  {
    constexpr size_t ϵ = saber_params::log2(moduli);
    constexpr size_t poly_blen = (polynomial::N * ϵ) / 8;
    constexpr size_t buf_blen = rows * cols * poly_blen;

    poly_matrix_t<rows, cols, moduli> mat;

    std::array<uint8_t, buf_blen> buf{};
    auto bufs = std::span<uint8_t, buf_blen>(buf);

    shake128::shake128 hasher;
    hasher.absorb(seed.data(), seed.size());
    hasher.finalize();
    hasher.squeeze(buf.data(), buf.size());
    hasher.reset();

    for (size_t i = 0; i < rows * cols; i++) {
      auto bstr = bufs.subspan(i * poly_blen, poly_blen);
      polynomial::poly_t<moduli> poly(bstr);
      mat.elements[i] = poly;
    }

    return mat;
  }

  // Given random byte string ( seed ) of length `noise_seedbytes` as input,
  // this routine outputs a secret vector v ∈ Rq^(l×1) with its coefficients
  // sampled from a centered binomial distribution β_μ.
  template<const size_t noise_seedbytes, const size_t mu>
  inline static poly_matrix_t<rows, 1, moduli> gen_secret(
    std::span<const uint8_t, noise_seedbytes> seed)
    requires((cols == 1) && saber_params::is_even(mu))
  {
    constexpr uint16_t m = 1u << (mu / 2);
    constexpr size_t poly_blen = (polynomial::N * mu) / 8;
    constexpr size_t buf_blen = rows * poly_blen;

    poly_matrix_t<rows, 1, moduli> vec;

    std::array<uint8_t, buf_blen> buf{};
    auto bufs = std::span<uint8_t, buf_blen>(buf);

    shake128::shake128 hasher;
    hasher.absorb(seed.data(), seed.size());
    hasher.finalize();
    hasher.squeeze(buf.data(), buf.size());
    hasher.reset();

    for (size_t i = 0; i < rows; i++) {
      size_t off = i * poly_blen;

      auto bstr_a = bufs.subspan(off, poly_blen / 2);
      polynomial::poly_t<m> poly_a(bstr_a);

      size_t j = 0, k = 0;
      while (j < polynomial::N / 2) {
        const auto hw0 = poly_a[k].template hamming_weight<m>();
        const auto hw1 = poly_a[k + 1].template hamming_weight<m>();

        vec.elements[i][j] = hw0 - hw1;

        j += 1;
        k += 2;
      }

      off += bstr_a.size();

      auto bstr_b = bufs.subspan(off, poly_blen / 2);
      polynomial::poly_t<m> poly_b(bstr_b);

      k = 0;
      while (j < polynomial::N) {
        const auto hw0 = poly_b[k].template hamming_weight<m>();
        const auto hw1 = poly_b[k + 1].template hamming_weight<m>();

        vec.elements[i][j] = hw0 - hw1;

        j += 1;
        k += 2;
      }
    }

    return vec;
  }

  // Given a matrix M of dimension m x n, this routine is used for computing its
  // transpose M' s.t. resulting matrix's dimension becomes n x m. Note, m == n.
  inline constexpr poly_matrix_t<cols, rows, moduli> transpose() const
    requires(rows == cols)
  {
    poly_matrix_t<cols, rows, moduli> res{};

    for (size_t i = 0; i < cols; i++) {
      for (size_t j = 0; j < rows; j++) {
        res[{ i, j }] = (*this)[{ j, i }];
      }
    }

    return res;
  }
};

}
