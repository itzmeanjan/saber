#include "kem.hpp"
#include "prng.hpp"
#include "sha3_256.hpp"
#include <benchmark/benchmark.h>
#include <cassert>

// Benchmark Saber KEM key generation algorithm for various suggested parameters.
template<size_t L,
         size_t EQ,
         size_t EP,
         size_t MU,
         size_t seedBytes,
         size_t noiseBytes,
         size_t keyBytes,
         bool uniform_sampling>
void
keygen(benchmark::State& state)
{
  constexpr size_t pklen = saber_utils::kem_pklen<L, EP, seedBytes>();
  constexpr size_t sklen = saber_utils::kem_sklen<L, EQ, EP, seedBytes, keyBytes>();

  std::vector<uint8_t> seedA(seedBytes);
  std::vector<uint8_t> seedS(noiseBytes);
  std::vector<uint8_t> z(keyBytes);
  std::vector<uint8_t> pkey(pklen);
  std::vector<uint8_t> skey(sklen);

  prng::prng_t prng;

  prng.read(seedA);
  prng.read(seedS);
  prng.read(z);

  auto _seedA = std::span<const uint8_t, seedBytes>(seedA);
  auto _seedS = std::span<const uint8_t, noiseBytes>(seedS);
  auto _z = std::span<const uint8_t, keyBytes>(z);
  auto _pkey = std::span<uint8_t, pklen>(pkey);
  auto _skey = std::span<uint8_t, sklen>(skey);

  for (auto _ : state) {
    _saber_kem::
      keygen<L, EQ, EP, MU, seedBytes, noiseBytes, keyBytes, uniform_sampling>(
        _seedA, _seedS, _z, _pkey, _skey);

    benchmark::DoNotOptimize(_seedA);
    benchmark::DoNotOptimize(_seedS);
    benchmark::DoNotOptimize(_z);
    benchmark::DoNotOptimize(_pkey);
    benchmark::DoNotOptimize(_skey);
    benchmark::ClobberMemory();
  }

  state.SetItemsProcessed(state.iterations());
}

// Benchmark Saber KEM encapsulation algorithm for various suggested parameters.
template<size_t L,
         size_t EQ,
         size_t EP,
         size_t ET,
         size_t MU,
         size_t seedBytes,
         size_t noiseBytes,
         size_t keyBytes,
         bool uniform_sampling>
void
encaps(benchmark::State& state)
{
  constexpr size_t pklen = saber_utils::kem_pklen<L, EP, seedBytes>();
  constexpr size_t sklen = saber_utils::kem_sklen<L, EQ, EP, seedBytes, keyBytes>();
  constexpr size_t ctlen = saber_utils::kem_ctlen<L, EP, ET>();

  std::vector<uint8_t> seedA(seedBytes);
  std::vector<uint8_t> seedS(noiseBytes);
  std::vector<uint8_t> z(keyBytes);
  std::vector<uint8_t> m(keyBytes);
  std::vector<uint8_t> pkey(pklen);
  std::vector<uint8_t> skey(sklen);
  std::vector<uint8_t> ctxt(ctlen);
  std::vector<uint8_t> seskey(sha3_256::DIGEST_LEN);

  prng::prng_t prng;

  prng.read(seedA);
  prng.read(seedS);
  prng.read(z);
  prng.read(m);

  auto _seedA = std::span<const uint8_t, seedBytes>(seedA);
  auto _seedS = std::span<const uint8_t, noiseBytes>(seedS);
  auto _z = std::span<const uint8_t, keyBytes>(z);
  auto _m = std::span<const uint8_t, keyBytes>(m);
  auto _pkey = std::span<uint8_t, pklen>(pkey);
  auto _skey = std::span<uint8_t, sklen>(skey);
  auto _ctxt = std::span<uint8_t, ctlen>(ctxt);
  auto _seskey = std::span<uint8_t, sha3_256::DIGEST_LEN>(seskey);

  _saber_kem::keygen<L, EQ, EP, MU, seedBytes, noiseBytes, keyBytes, uniform_sampling>(
    _seedA, _seedS, _z, _pkey, _skey);

  for (auto _ : state) {
    _saber_kem::encaps<L, EQ, EP, ET, MU, seedBytes, keyBytes, uniform_sampling>(
      _m, _pkey, _ctxt, _seskey);

    benchmark::DoNotOptimize(_m);
    benchmark::DoNotOptimize(_pkey);
    benchmark::DoNotOptimize(_ctxt);
    benchmark::DoNotOptimize(_seskey);
    benchmark::ClobberMemory();
  }

  state.SetItemsProcessed(state.iterations());
}

// Benchmark Saber KEM decapsulation algorithm for various suggested parameters.
template<size_t L,
         size_t EQ,
         size_t EP,
         size_t ET,
         size_t MU,
         size_t seedBytes,
         size_t noiseBytes,
         size_t keyBytes,
         bool uniform_sampling>
void
decaps(benchmark::State& state)
{
  constexpr size_t pklen = saber_utils::kem_pklen<L, EP, seedBytes>();
  constexpr size_t sklen = saber_utils::kem_sklen<L, EQ, EP, seedBytes, keyBytes>();
  constexpr size_t ctlen = saber_utils::kem_ctlen<L, EP, ET>();

  std::vector<uint8_t> seedA(seedBytes);
  std::vector<uint8_t> seedS(noiseBytes);
  std::vector<uint8_t> z(keyBytes);
  std::vector<uint8_t> m(keyBytes);
  std::vector<uint8_t> pkey(pklen);
  std::vector<uint8_t> skey(sklen);
  std::vector<uint8_t> ctxt(ctlen);
  std::vector<uint8_t> seskey0(sha3_256::DIGEST_LEN);
  std::vector<uint8_t> seskey1(sha3_256::DIGEST_LEN);

  prng::prng_t prng;

  prng.read(seedA);
  prng.read(seedS);
  prng.read(z);
  prng.read(m);

  auto _seedA = std::span<const uint8_t, seedBytes>(seedA);
  auto _seedS = std::span<const uint8_t, noiseBytes>(seedS);
  auto _z = std::span<const uint8_t, keyBytes>(z);
  auto _m = std::span<const uint8_t, keyBytes>(m);
  auto _pkey = std::span<uint8_t, pklen>(pkey);
  auto _skey = std::span<uint8_t, sklen>(skey);
  auto _ctxt = std::span<uint8_t, ctlen>(ctxt);
  auto _seskey0 = std::span<uint8_t, sha3_256::DIGEST_LEN>(seskey0);
  auto _seskey1 = std::span<uint8_t, sha3_256::DIGEST_LEN>(seskey1);

  _saber_kem::keygen<L, EQ, EP, MU, seedBytes, noiseBytes, keyBytes, uniform_sampling>(
    _seedA, _seedS, _z, _pkey, _skey);
  _saber_kem::encaps<L, EQ, EP, ET, MU, seedBytes, keyBytes, uniform_sampling>(
    _m, _pkey, _ctxt, _seskey0);

  for (auto _ : state) {
    _saber_kem::decaps<L, EQ, EP, ET, MU, seedBytes, keyBytes, uniform_sampling>(
      _ctxt, _skey, _seskey1);

    benchmark::DoNotOptimize(_ctxt);
    benchmark::DoNotOptimize(_skey);
    benchmark::DoNotOptimize(_seskey1);
    benchmark::ClobberMemory();
  }

  assert(std::ranges::equal(_seskey0, _seskey1));
  state.SetItemsProcessed(state.iterations());
}

const auto compute_min = [](const std::vector<double>& v) -> double {
  return *std::min_element(v.begin(), v.end());
};

const auto compute_max = [](const std::vector<double>& v) -> double {
  return *std::max_element(v.begin(), v.end());
};

// Register for benchmarking LightSaber, Saber, FireSaber, uLightSaber, uSaber and
// uFireSaber KEM routines.
BENCHMARK(keygen<2, 13, 10, 10, 32, 32, 32, false>)
  ->ComputeStatistics("min", compute_min)
  ->ComputeStatistics("max", compute_max)
  ->Name("lightsaber/keygen");
BENCHMARK(encaps<2, 13, 10, 3, 10, 32, 32, 32, false>)
  ->ComputeStatistics("min", compute_min)
  ->ComputeStatistics("max", compute_max)
  ->Name("lightsaber/encaps");
BENCHMARK(decaps<2, 13, 10, 3, 10, 32, 32, 32, false>)
  ->ComputeStatistics("min", compute_min)
  ->ComputeStatistics("max", compute_max)
  ->Name("lightsaber/decaps");

BENCHMARK(keygen<3, 13, 10, 8, 32, 32, 32, false>)
  ->ComputeStatistics("min", compute_min)
  ->ComputeStatistics("max", compute_max)
  ->Name("saber/keygen");
BENCHMARK(encaps<3, 13, 10, 4, 8, 32, 32, 32, false>)
  ->ComputeStatistics("min", compute_min)
  ->ComputeStatistics("max", compute_max)
  ->Name("saber/encaps");
BENCHMARK(decaps<3, 13, 10, 4, 8, 32, 32, 32, false>)
  ->ComputeStatistics("min", compute_min)
  ->ComputeStatistics("max", compute_max)
  ->Name("saber/decaps");

BENCHMARK(keygen<4, 13, 10, 6, 32, 32, 32, false>)
  ->ComputeStatistics("min", compute_min)
  ->ComputeStatistics("max", compute_max)
  ->Name("firesaber/keygen");
BENCHMARK(encaps<4, 13, 10, 6, 6, 32, 32, 32, false>)
  ->ComputeStatistics("min", compute_min)
  ->ComputeStatistics("max", compute_max)
  ->Name("firesaber/encaps");
BENCHMARK(decaps<4, 13, 10, 6, 6, 32, 32, 32, false>)
  ->ComputeStatistics("min", compute_min)
  ->ComputeStatistics("max", compute_max)
  ->Name("firesaber/decaps");

BENCHMARK(keygen<2, 12, 10, 2, 32, 32, 32, true>)
  ->ComputeStatistics("min", compute_min)
  ->ComputeStatistics("max", compute_max)
  ->Name("ulightsaber/keygen");
BENCHMARK(encaps<2, 12, 10, 3, 2, 32, 32, 32, true>)
  ->ComputeStatistics("min", compute_min)
  ->ComputeStatistics("max", compute_max)
  ->Name("ulightsaber/encaps");
BENCHMARK(decaps<2, 12, 10, 3, 2, 32, 32, 32, true>)
  ->ComputeStatistics("min", compute_min)
  ->ComputeStatistics("max", compute_max)
  ->Name("ulightsaber/decaps");

BENCHMARK(keygen<3, 12, 10, 2, 32, 32, 32, true>)
  ->ComputeStatistics("min", compute_min)
  ->ComputeStatistics("max", compute_max)
  ->Name("usaber/keygen");
BENCHMARK(encaps<3, 12, 10, 4, 2, 32, 32, 32, true>)
  ->ComputeStatistics("min", compute_min)
  ->ComputeStatistics("max", compute_max)
  ->Name("usaber/encaps");
BENCHMARK(decaps<3, 12, 10, 4, 2, 32, 32, 32, true>)
  ->ComputeStatistics("min", compute_min)
  ->ComputeStatistics("max", compute_max)
  ->Name("usaber/decaps");

BENCHMARK(keygen<4, 12, 10, 2, 32, 32, 32, true>)
  ->ComputeStatistics("min", compute_min)
  ->ComputeStatistics("max", compute_max)
  ->Name("ufiresaber/keygen");
BENCHMARK(encaps<4, 12, 10, 6, 2, 32, 32, 32, true>)
  ->ComputeStatistics("min", compute_min)
  ->ComputeStatistics("max", compute_max)
  ->Name("ufiresaber/encaps");
BENCHMARK(decaps<4, 12, 10, 6, 2, 32, 32, 32, true>)
  ->ComputeStatistics("min", compute_min)
  ->ComputeStatistics("max", compute_max)
  ->Name("ufiresaber/decaps");
