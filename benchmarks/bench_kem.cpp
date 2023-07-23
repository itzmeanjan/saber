#include "kem.hpp"
#include "prng.hpp"
#include <benchmark/benchmark.h>

// Benchmark Saber KEM key generation algorithm for various suggested parameters.
template<const size_t L,
         const size_t EQ,
         const size_t EP,
         const size_t MU,
         const size_t seedBytes,
         const size_t noiseBytes,
         const size_t keyBytes>
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

  auto _seedA = std::span<uint8_t, seedBytes>(seedA);
  auto _seedS = std::span<uint8_t, noiseBytes>(seedS);
  auto _z = std::span<uint8_t, keyBytes>(z);
  auto _pkey = std::span<uint8_t, pklen>(pkey);
  auto _skey = std::span<uint8_t, sklen>(skey);

  prng::prng_t prng;

  prng.read(_seedA);
  prng.read(_seedS);
  prng.read(_z);

  for (auto _ : state) {
    saber_kem::keygen<L, EQ, EP, MU>(_seedA, _seedS, _z, _pkey, _skey);

    benchmark::DoNotOptimize(_seedA);
    benchmark::DoNotOptimize(_seedS);
    benchmark::DoNotOptimize(_z);
    benchmark::DoNotOptimize(_pkey);
    benchmark::DoNotOptimize(_skey);
    benchmark::ClobberMemory();
  }

  state.SetItemsProcessed(state.iterations());
}
