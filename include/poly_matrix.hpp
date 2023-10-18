#pragma once
#include "params.hpp"
#include "polynomial.hpp"
#include "sampling.hpp"
#include "shake128.hpp"

// Operations defined over matrix/ vector of polynomials.
namespace mat {

// Wrapper type encapsulating matrix/ vector operations s.t. its elements are
// polynomials in Rq = Zq[X]/(X^N + 1), N = 256.
template<size_t rows, size_t cols, uint16_t moduli>
struct poly_matrix_t
{
private:
  std::array<poly::poly_t<moduli>, rows * cols> elements{};

public:
  // Constructors
  inline constexpr poly_matrix_t() = default;
  inline constexpr poly_matrix_t(std::array<poly::poly_t<moduli>, rows * cols>& arr)
  {
    elements = arr;
  }
  inline constexpr poly_matrix_t(std::array<poly::poly_t<moduli>, rows * cols>&& arr)
  {
    elements = arr;
  }
  inline constexpr poly_matrix_t(
    const std::array<poly::poly_t<moduli>, rows * cols>& arr)
  {
    elements = arr;
  }
  inline constexpr poly_matrix_t(
    const std::array<poly::poly_t<moduli>, rows * cols>&& arr)
  {
    elements = arr;
  }

  // Given linearized matrix index, returns reference to requested element polynomial.
  // `idx` must ∈ [0, rows * cols).
  inline constexpr poly::poly_t<moduli>& operator[](const size_t idx)
  {
    return this->elements[idx];
  }

  // Given linearized matrix index, returns const reference to requested element
  // polynomial. `idx` must ∈ [0, rows * cols).
  inline constexpr const poly::poly_t<moduli>& operator[](const size_t idx) const
  {
    return this->elements[idx];
  }

  // Given row and column index of matrix, returns reference to requested
  // element polynomial.
  inline constexpr poly::poly_t<moduli>& operator[](std::pair<size_t, size_t> idx)
  {
    return this->elements[idx.first * cols + idx.second];
  }

  // Given row and column index of matrix, returns const reference to requested
  // element polynomial.
  inline constexpr const poly::poly_t<moduli>& operator[](
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
    constexpr size_t poly_blen = poly::N * saber_params::log2(moduli) / 8;
    for (size_t i = 0; i < rows; i++) {
      poly::poly_t<moduli> poly(bstr.subspan(i * poly_blen, poly_blen));
      elements[i] = poly;
    }
  }

  // Adds two polynomial matrices/ vectors of equal dimension.
  inline constexpr poly_matrix_t<rows, cols, moduli> operator+(
    const poly_matrix_t<rows, cols, moduli>& rhs) const
  {
    std::array<poly::poly_t<moduli>, rows * cols> res{};

    for (size_t i = 0; i < rows * cols; i++) {
      res[i] = elements[i] + rhs.elements[i];
    }

    return res;
  }

  // Left shift each element of the polynomial matrix by factor `off`.
  inline constexpr poly_matrix_t<rows, cols, moduli> operator<<(const size_t off) const
  {
    std::array<poly::poly_t<moduli>, rows * cols> res{};

    for (size_t i = 0; i < rows * cols; i++) {
      res[i] = elements[i] << off;
    }

    return res;
  }

  // Right shift each element of the polynomial matrix by factor `off`.
  inline constexpr poly_matrix_t<rows, cols, moduli> operator>>(const size_t off) const
  {
    std::array<poly::poly_t<moduli>, rows * cols> res{};

    for (size_t i = 0; i < rows * cols; i++) {
      res[i] = elements[i] >> off;
    }

    return res;
  }

  // Change moduli of each element of polynomial matrix to a different value.
  template<uint16_t new_moduli>
  inline constexpr poly_matrix_t<rows, cols, new_moduli> mod() const
    requires(moduli != new_moduli)
  {
    std::array<poly::poly_t<new_moduli>, rows * cols> res{};

    for (size_t i = 0; i < rows * cols; i++) {
      res[i] = std::move(elements[i].template mod<new_moduli>());
    }

    return res;
  }

  // Given a vector of polynomials, this routine can transform it into a byte
  // string of length rows * log2(moduli) * 32, following algorithm 12 of spec.
  inline void to_bytes(std::span<uint8_t> bstr)
    requires(cols == 1)
  {
    constexpr size_t poly_blen = poly::N * saber_params::log2(moduli) / 8;
    for (size_t i = 0; i < rows; i++) {
      elements[i].to_bytes(bstr.subspan(i * poly_blen, poly_blen));
    }
  }

  // Given a matrix M ∈ Rq^(l×l) and vector v ∈ Rq^(l×1), this routine performs
  // a matrix vector multiplication, returning a vector mv ∈ Rq^(l×1), following
  // algorithm 13 of spec.
  template<size_t rhs_rows>
  inline poly_matrix_t<rows, 1, moduli> mat_vec_mul(
    const poly_matrix_t<rhs_rows, 1, moduli>& vec)
    requires((rows == cols) && (cols == rhs_rows))
  {
    poly_matrix_t<rows, 1, moduli> res;

    for (size_t i = 0; i < rows; i++) {
      poly::poly_t<moduli> poly;

      for (size_t j = 0; j < cols; j++) {
        poly += ((*this)[{ i, j }] * vec[{ j, 0 }]);
      }
      res[i] = poly;
    }

    return res;
  }

  // Given two vectors v_a, v_b ∈ Rp^(l×1), this routine computes their inner
  // product, returning a polynomial c ∈ Rp, following algorithm 14 of spec.
  inline poly::poly_t<moduli> inner_prod(const poly_matrix_t<rows, cols, moduli>& vec)
    requires(cols == 1)
  {
    poly::poly_t<moduli> res;

    for (size_t i = 0; i < rows; i++) {
      res += (this->elements[i] * vec.elements[i]);
    }

    return res;
  }

  // Given random byte string ( seed ) of length `seedBytes` as input,
  // this routine generates a matrix A ∈ Rq^(l×l), following algorithm 15 of
  // spec.
  template<size_t seedBytes>
  inline static poly_matrix_t<rows, cols, moduli> gen_matrix(
    std::span<const uint8_t, seedBytes> seed)
    requires(rows == cols)
  {
    constexpr size_t ϵ = saber_params::log2(moduli);
    constexpr size_t poly_blen = (poly::N * ϵ) / 8;
    constexpr size_t buf_blen = rows * cols * poly_blen;

    poly_matrix_t<rows, cols, moduli> mat;

    std::array<uint8_t, buf_blen> buf{};
    auto bufs = std::span<uint8_t, buf_blen>(buf);

    shake128::shake128_t hasher;
    hasher.absorb(seed);
    hasher.finalize();
    hasher.squeeze(bufs);
    hasher.reset();

    for (size_t i = 0; i < rows * cols; i++) {
      auto bstr = bufs.subspan(i * poly_blen, poly_blen);
      poly::poly_t<moduli> poly(bstr);
      mat.elements[i] = poly;
    }

    return mat;
  }

  // Given random byte string ( seed ) of length `seedBytes` as input, this routine
  // outputs a secret vector v ∈ Rq^(l×1) with its coefficients sampled from a centered
  // binomial distribution β_μ, following algorithm 16 of Saber spec.
  template<bool uniform_sampling, size_t seedBytes, size_t mu>
  inline static poly_matrix_t<rows, 1, moduli> gen_secret(
    std::span<const uint8_t, seedBytes> seed)
    requires((cols == 1) &&
             saber_params::validate_gen_secret_args(uniform_sampling, mu))
  {
    constexpr size_t poly_blen = (poly::N * mu) / 8;
    constexpr size_t buf_blen = rows * poly_blen;

    poly_matrix_t<rows, 1, moduli> vec;

    std::array<uint8_t, buf_blen> buf{};
    auto _buf = std::span<uint8_t, buf_blen>(buf);

    shake128::shake128_t hasher;
    hasher.absorb(seed);
    hasher.finalize();
    hasher.squeeze(_buf);
    hasher.reset();

    using poly_t_ = std::span<const uint8_t, poly_blen>;

    for (size_t i = 0; i < rows; i++) {
      const size_t off = i * poly_blen;
      auto __buf = poly_t_(_buf.subspan(off, poly_blen));

      if constexpr (uniform_sampling) {
        vec[i] = saber_utils::uniform_sample<moduli>(__buf);
      } else {
        vec[i] = saber_utils::cbd<moduli, mu>(__buf);
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
