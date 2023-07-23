# saber
Saber: Post-Quantum Key Encapsulation Mechanism

> **Warning** This header-only library implementation of Saber KEM is attempted to be constant-time though it's not yet audited. If you consider using it in production environment, be careful !

## Overview

Saber is a family of cryptographic primitives that rely on the hardness of the Module Learning With Rounding (Mod-LWR) problem. Saber offers an IND-CPA secure public key encryption algorithm, which is transformed to an IND-CCA secure key encapsulation mechanism, using a version of Fujisaki-Okamoto transform. 

It's a zero-dependency, header-only C++ library implementation of Saber KEM scheme, as described in specification https://www.esat.kuleuven.be/cosic/pqcrypto/saber/files/saberspecround3.pdf and instantiating all parameter sets, suggested in section 8.1 on table 8 of Saber spec.

KEM scheme offers three major algorithms.

Algorithm | Input | Output | How is it used ?
--- | :-: | :-: | --:
keygen | 32 -bytes random seed `seedA`, 32 -bytes random noise `seedS` and 32 -bytes random key `z` | Public and private keypair | Imagine two parties `peer0` & `peer1`, want to securely ( using symmetric key encryption i.e. some AEAD scheme ) communicate over insecure channel. One of them, say `peer0`, generates an ephemeral KEM keypair and publish its public key to other peer i.e. `peer1`.
encaps | 32 -bytes random seed `m` and receiver's public key | Cipher text and 32 -bytes session key | `Peer1` encapsulates 32 -bytes message inside cipher text, using `peer0`'s public key. And then it shares the cipher text with `peer0`, over insecure channel. Finally `peer1` also derives a 32 -bytes session key, which it can now use with symmetric key constructions.
decaps | Cipher text and receiver's private key | 32 -bytes session key | `Peer0` uses its private key for decapsulating the cipher text it received from `peer1`, deriving the same 32 -bytes session key. Now both of the parties have same 32 -bytes session key, they can use it for enciphering their communication.

For learning more about Saber, follow their website @ https://www.esat.kuleuven.be/cosic/pqcrypto/saber. Also note that Saber was a round 3 finalist of NIST PQC standardization effort, more @ https://csrc.nist.gov/Projects/post-quantum-cryptography/post-quantum-cryptography-standardization/round-3-submissions.


## Prerequisites

- A C++ compiler with C++20 standard library.

```bash
$ g++ --version
g++ (Ubuntu 12.2.0-17ubuntu1) 12.2.0

$ clang++ --version
Ubuntu clang version 15.0.7
Target: x86_64-pc-linux-gnu
Thread model: posix
InstalledDir: /usr/bin
```

- Build tools.

```bash
$ make --version
GNU Make 4.3
Built for x86_64-pc-linux-gnu

$ cmake --version
cmake version 3.25.1
```

- For testing functional correctness of Saber KEM and its components, you need to globally install `google-test` headers and library. Follow [this](https://github.com/google/googletest/tree/main/googletest#standalone-cmake-project) guide.
- For benchmarking Saber KEM algorithms, you need to globally install `google-benchmark` headers and library. Follow [this](https://github.com/google/benchmark#installation) guide.
- If you are on a machine running GNU/Linux kernel and you want to obtain CPU cycle count for KEM algorithms, you should consider building `google-benchmark` library with libPFM support, following [this](https://gist.github.com/itzmeanjan/05dc3e946f635d00c5e0b21aae6203a7) step-by-step guide. Find more about libPFM @ https://perfmon2.sourceforge.net.
- Saber KEM has two dependencies ( i.e. `sha3` and `subtle` ), managed by git submodule. After cloning this repository, you must run following command inside root of this repository, so that you can test/ benchmark/ use it.

```bash
git clone https://github.com/itzmeanjan/saber.git

pushd saber
git submodule update --init # <-- Import dependencies
popd
```

## Testing

For testing functional correctness of Saber KEM algorithms and its components, issue following command.

> **Warning** Tests ensuring conformance to Saber specification and reference implementation are still being worked on. Meaning I don't **yet** guarantee that this implementation is fully conformant with the Saber specification.

```bash
make -j $(nproc --all)
```

```bash
[==========] Running 8 tests from 1 test suite.
[----------] Global test environment set-up.
[----------] 8 tests from SaberKEM
[ RUN      ] SaberKEM.LightSaberKeyEncapsulationMechanism
[       OK ] SaberKEM.LightSaberKeyEncapsulationMechanism (0 ms)
[ RUN      ] SaberKEM.SaberKeyEncapsulationMechanism
[       OK ] SaberKEM.SaberKeyEncapsulationMechanism (0 ms)
[ RUN      ] SaberKEM.FireSaberKeyEncapsulationMechanism
[       OK ] SaberKEM.FireSaberKeyEncapsulationMechanism (0 ms)
[ RUN      ] SaberKEM.LightSaberPublicKeyEncryption
[       OK ] SaberKEM.LightSaberPublicKeyEncryption (0 ms)
[ RUN      ] SaberKEM.SaberPublicKeyEncryption
[       OK ] SaberKEM.SaberPublicKeyEncryption (0 ms)
[ RUN      ] SaberKEM.FireSaberPublicKeyEncryption
[       OK ] SaberKEM.FireSaberPublicKeyEncryption (0 ms)
[ RUN      ] SaberKEM.PolynomialMatrixConversion
[       OK ] SaberKEM.PolynomialMatrixConversion (0 ms)
[ RUN      ] SaberKEM.PolynomialConversion
[       OK ] SaberKEM.PolynomialConversion (0 ms)
[----------] 8 tests from SaberKEM (1 ms total)

[----------] Global test environment tear-down
[==========] 8 tests from 1 test suite ran. (1 ms total)
[  PASSED  ] 8 tests.
```

## Benchmarking

For benchmarking Saber KEM algorithms ( i.e. keygen, encaps and decaps ), instantiated with various suggested parameters, targeting CPU systems, issue following command.

> **Warning**  When benchmarking, ensure that you've disabled CPU frequency scaling, by following [this](https://github.com/google/benchmark/blob/main/docs/reducing_variance.md) guide.

> **Note** `make perf` - was issued when collecting following benchmarks. Notice, cycles column, denoting latency of Saber KEM routines. Follow [this](https://github.com/google/benchmark/blob/main/docs/perf_counters.md) for more details.

```bash
make benchmark  # If you haven't built google-benchmark library with libPFM support.
make perf       # Must do if you have built google-benchmark library with libPFM support.
```

### On 12th Gen Intel(R) Core(TM) i7-1260P ( compiled with Clang )

```bash
2023-07-23T11:10:44+04:00
Running ./benchmarks/perf.out
Run on (16 X 4640.91 MHz CPU s)
CPU Caches:
  L1 Data 48 KiB (x8)
  L1 Instruction 32 KiB (x8)
  L2 Unified 1280 KiB (x8)
  L3 Unified 18432 KiB (x1)
Load Average: 0.41, 0.21, 0.13
***WARNING*** There are 9 benchmarks with threads and 1 performance counters were requested. Beware counters will reflect the combined usage across all threads.
----------------------------------------------------------------------------------------
Benchmark                  Time             CPU   Iterations     CYCLES items_per_second
----------------------------------------------------------------------------------------
lightsaber/keygen       16.1 us         16.1 us        43501   75.1952k       62.2169k/s
lightsaber/encaps       23.7 us         23.7 us        29582   110.801k       42.2284k/s
lightsaber/decaps       28.6 us         28.6 us        24472   133.839k         34.93k/s
saber/keygen            35.7 us         35.7 us        19598   166.743k       28.0203k/s
saber/encaps            45.9 us         45.9 us        15285   211.105k       21.7743k/s
saber/decaps            53.6 us         53.6 us        13217   245.731k       18.6595k/s
firesaber/keygen        60.7 us         60.7 us        11512   275.481k       16.4672k/s
firesaber/encaps        75.4 us         75.3 us         9178   339.179k       13.2716k/s
firesaber/decaps        86.1 us         86.1 us         8132   389.051k       11.6189k/s
```

### On 12th Gen Intel(R) Core(TM) i7-1260P ( compiled with GCC )

```bash
2023-07-23T11:33:42+04:00
Running ./benchmarks/perf.out
Run on (16 X 3889.79 MHz CPU s)
CPU Caches:
  L1 Data 48 KiB (x8)
  L1 Instruction 32 KiB (x8)
  L2 Unified 1280 KiB (x8)
  L3 Unified 18432 KiB (x1)
Load Average: 0.74, 0.47, 0.29
***WARNING*** There are 9 benchmarks with threads and 1 performance counters were requested. Beware counters will reflect the combined usage across all threads.
----------------------------------------------------------------------------------------
Benchmark                  Time             CPU   Iterations     CYCLES items_per_second
----------------------------------------------------------------------------------------
lightsaber/keygen       32.3 us         32.3 us        21672   150.556k       30.9795k/s
lightsaber/encaps       47.9 us         47.9 us        14647   223.555k       20.8894k/s
lightsaber/decaps       61.0 us         61.0 us        11451   284.928k       16.3899k/s
saber/keygen            70.0 us         70.0 us         9999   326.935k       14.2863k/s
saber/encaps            92.7 us         92.8 us         7400   433.104k       10.7814k/s
saber/decaps             112 us          112 us         6228   523.627k       8.92189k/s
firesaber/keygen         123 us          123 us         5669   575.465k       8.11279k/s
firesaber/encaps         153 us          153 us         4566   715.346k       6.52661k/s
firesaber/decaps         180 us          180 us         3895   838.883k       5.56453k/s
```

## Usage

Saber is a header-only, zero-dependency C++ library implementing key encapsulation mechanism i.e.

- Key Generation
- Encapsulation
- Decapsulation

Getting started with using Saber in your project is fairly easy.

- Clone Saber repository under `$HOME`.

```bash
cd
git clone https://github.com/itzmeanjan/saber.git
```
- Import git submodule managed dependencies i.e. `sha3` and `subtle`.

```bash
pushd saber
git submodule update --init
popd
```

- Include proper header file in your program and use functions, constants etc. living inside respective namespace. 

Scheme of Interest | Header | Namespace
--- | :-: | --:
LightSaber KEM | include/lightsaber_kem.hpp | `lightsaber_kem::`
Saber KEM | include/saber_kem.hpp | `saber_kem::`
FireSaber KEM | include/firesaber_kem.hpp | `firesaber_kem::`

```cpp
// main.cpp
#include "saber_kem.hpp"
#include "prng.hpp"
#include <cassert>

int main() {
    std::vector<uint8_t> seedA(saber_kem::seedBytes);
    std::vector<uint8_t> seedS(saber_kem::noiseBytes);
    std::vector<uint8_t> z(saber_kem::keyBytes);
    std::vector<uint8_t> m(saber_kem::keyBytes);
    std::vector<uint8_t> pkey(saber_kem::PK_LEN);
    std::vector<uint8_t> skey(saber_kem::SK_LEN);
    std::vector<uint8_t> ctxt(saber_kem::CT_LEN);
    std::vector<uint8_t> sskey_peer0(sha3_256::DIGEST_LEN);
    std::vector<uint8_t> sskey_peer1(sha3_256::DIGEST_LEN);

    // Create non-owning interfaces over heap allocated vectors
    // More @ https://en.cppreference.com/w/cpp/container/span
    auto _seedA = std::span<uint8_t, saber_kem::seedBytes>(seedA);
    auto _seedS = std::span<uint8_t, saber_kem::noiseBytes>(seedS);
    auto _z = std::span<uint8_t, saber_kem::keyBytes>(z);
    auto _m = std::span<uint8_t, saber_kem::keyBytes>(m);
    auto _pkey = std::span<uint8_t, saber_kem::PK_LEN>(pkey);
    auto _skey = std::span<uint8_t, saber_kem::SK_LEN>(skey);
    auto _ctxt = std::span<uint8_t, saber_kem::CT_LEN>(ctxt);
    auto _sskey_peer0 = std::span<uint8_t, sha3_256::DIGEST_LEN>(sskey_peer0);
    auto _sskey_peer1 = std::span<uint8_t, sha3_256::DIGEST_LEN>(sskey_peer1);

    // Random sample seeds using PRNG backed by SHAKE128 Xof
    //
    // !!! I strongly advice you to go through comments in include/prng.hpp
    // header file before you start using it in production for sampling randomness. !!!
    prng::prng_t prng;

    prng.read(_seedA);
    prng.read(_seedS);
    prng.read(_z);
    prng.read(_m);

    // Peer-1 generates a Saber KEM keypair.
    saber_kem::keygen(_seedA, _seedS, _z, _pkey, _skey);
    // Peer-0 uses Peer-1's public key for encapsulating a key, also producing session key.
    saber_kem::encaps(_m, _pkey, _ctxt, _sskey_peer0);
    // Peer-1 uses its private key to decapsulate cipher text, producing same session key.
    saber_kem::decaps(_ctxt, _skey, _sskey_peer1);

    // Both peers must arrive at same session key.
    assert(std::ranges::equal(_sskey_peer0, _sskey_peer1));
    return 0;
}
```

- When it's time to compile your program, let your compiler know where it can find Saber KEM headers ( `./include` directory ) along with Sha3 and Subtle headers, respectively living in `./sha3/include` and `./subtle/include`.

```bash
SABER_HEADERS=~/saber/include
SHA3_HEADERS=~/saber/sha3/include
SUBTLE_HEADERS=~/saber/subtle/include

g++ -std=c++20 -Wall -O3 -march=native -I $SABER_HEADERS -I $SHA3_HEADERS -I $SUBTLE_HEADERS main.cpp
```

I maintain an example [program](./examples/saber.cpp), demonstrating usage of Saber KEM API. Similarly one can use LightSaber or FireSaber KEM API, while just updating header file and namespace.

```bash
$ g++ -std=c++20 -Wall -Wextra -pedantic -O3 -march=native -I include -I sha3/include -I subtle/include examples/saber.cpp && ./a.out
Saber KEM :

Public Key  : 3bdf4809d5dd79700910e80ebcc98f1d68f20ef0efaadf594bb5c15ccce18418116bc77ae1bbafef275f9f224c4c2481ca6d8d7053a8933c5fd8ffebfc1415a94faee5d5b15010f81c1df7accb45df45cb7b8351988c9f381ee5073998097488763c61684d909ae255fe920cd2ee1a15267c6f758a0429af964edd24ee2d0154369f5cd7526bbae9649b3c1c6e64fe229ddaadb26ec6b6808ef072dc6a281c9a7ae64e6590f194198bd9b60f3404c7d9340fc910fc1ee4a93a1a21f09ebb3d099d8c0850330809a12a4cea5a89c6d93e3cf73beab33e27c1ff1908508a92c7e055593a737d416752eba99f066f3c7bc1d436ec94438f1db8f180e0b595effcbd2df50639f5a7f9fde1d0cd923e1dc524f696d3682c3ce540175b275882f27fc30ca306080899517115183cd423ba93a9c8734e5e3e38366163d91a120fc0499902b0917b3131cdd83e8b14415c93f11879583c337b54b515d494bb1dc1236856ed7a0a99611acedcfd8e528d0310d3fac98eba8cfa0d679f9d38df31ffc11b3349c4d89a8696f8b560ad92b38bb201dda0be8b15d5b8aa303c727654ecf3d9d0c7b547bccfef963c00dbf0af825e3e1430d8853befbfbae8aadbdea192ac92cac98e02241a5edc4c3df9a8df5fd13e2e5fc4d9312d6b1509629f9a3c0c5674f886c547a5cc8061e1e175460791bc1b4aa5b98164fcfa40a12d14b774b7e9f815d043c47cc839cfe973a1d118c933d7ec008a4c5811114c4eca24706b8228c794b0a53519368b670b0076ad4c6430225664376d149f8101b3ceb07cb93fbf70cdd97ec55592bfc4ae8d7e153456a7ba1ebfcf1bb75b1a5ee0e448d12816ade6c512f93546e7ccd29fc677ea4599e1fe5a3ef7fb2dc7ace1fb4780a9b28ba18536775413e7eeaf947ed3c8c5373a6204f788164ea08b21e2502b84dd5240c38c48781fa1f1ddf965bed87ace3e20da27e1a9d827c72b59b6238efe392df88dcf0e635c83b26073830583d35acafd63ef52667d2cab4452104418d3ff3d5aaab55b7e6a1c1e5d885c45a2b79fcc81a1268b45c2207d642cb3a5bab85e80e1e0a5c8b68f8a448ec51926c0e4433053b14f17a3e0b55e3127fbc4a98209da6bd6b9e29cbf17491ce20ac3e20a82b7ae417fb95b0005ae5417a04341c481e81a2b9fb9ef930faef3b22995c23da685341c46d1c216e9ae36da20f14dc0e503bb44e9e8745c2972e57786519a77e472dde716c4245fc44ca388b6320eeb4fe154ecdfd7fd2c94a7a280bb65f96aae4a2c76653bc8e5bf84a012aecb1f80d3d63866c5475eb3ef333413964f64cfe2567d8504be374021dc1dca686a1d8b6cf1532d7b1eb7c701d4d46bf48fd12dea72c4a92eee3dc335e294248fcd1cae1df3c9e33c29
Secret Key  : bbdb28be86156fe2bd1126ddc742bdc47865927fe477b50d0d902c360c1a2470055bdf2ef37e5ad8fffd65de17d90d6a0d35df792e912f47b1dea9c299503b0e3bdf4809d5dd79700910e80ebcc98f1d68f20ef0efaadf594bb5c15ccce18418116bc77ae1bbafef275f9f224c4c2481ca6d8d7053a8933c5fd8ffebfc1415a94faee5d5b15010f81c1df7accb45df45cb7b8351988c9f381ee5073998097488763c61684d909ae255fe920cd2ee1a15267c6f758a0429af964edd24ee2d0154369f5cd7526bbae9649b3c1c6e64fe229ddaadb26ec6b6808ef072dc6a281c9a7ae64e6590f194198bd9b60f3404c7d9340fc910fc1ee4a93a1a21f09ebb3d099d8c0850330809a12a4cea5a89c6d93e3cf73beab33e27c1ff1908508a92c7e055593a737d416752eba99f066f3c7bc1d436ec94438f1db8f180e0b595effcbd2df50639f5a7f9fde1d0cd923e1dc524f696d3682c3ce540175b275882f27fc30ca306080899517115183cd423ba93a9c8734e5e3e38366163d91a120fc0499902b0917b3131cdd83e8b14415c93f11879583c337b54b515d494bb1dc1236856ed7a0a99611acedcfd8e528d0310d3fac98eba8cfa0d679f9d38df31ffc11b3349c4d89a8696f8b560ad92b38bb201dda0be8b15d5b8aa303c727654ecf3d9d0c7b547bccfef963c00dbf0af825e3e1430d8853befbfbae8aadbdea192ac92cac98e02241a5edc4c3df9a8df5fd13e2e5fc4d9312d6b1509629f9a3c0c5674f886c547a5cc8061e1e175460791bc1b4aa5b98164fcfa40a12d14b774b7e9f815d043c47cc839cfe973a1d118c933d7ec008a4c5811114c4eca24706b8228c794b0a53519368b670b0076ad4c6430225664376d149f8101b3ceb07cb93fbf70cdd97ec55592bfc4ae8d7e153456a7ba1ebfcf1bb75b1a5ee0e448d12816ade6c512f93546e7ccd29fc677ea4599e1fe5a3ef7fb2dc7ace1fb4780a9b28ba18536775413e7eeaf947ed3c8c5373a6204f788164ea08b21e2502b84dd5240c38c48781fa1f1ddf965bed87ace3e20da27e1a9d827c72b59b6238efe392df88dcf0e635c83b26073830583d35acafd63ef52667d2cab4452104418d3ff3d5aaab55b7e6a1c1e5d885c45a2b79fcc81a1268b45c2207d642cb3a5bab85e80e1e0a5c8b68f8a448ec51926c0e4433053b14f17a3e0b55e3127fbc4a98209da6bd6b9e29cbf17491ce20ac3e20a82b7ae417fb95b0005ae5417a04341c481e81a2b9fb9ef930faef3b22995c23da685341c46d1c216e9ae36da20f14dc0e503bb44e9e8745c2972e57786519a77e472dde716c4245fc44ca388b6320eeb4fe154ecdfd7fd2c94a7a280bb65f96aae4a2c76653bc8e5bf84a012aecb1f80d3d63866c5475eb3ef333413964f64cfe2567d8504be374021dc1dca686a1d8b6cf1532d7b1eb7c701d4d46bf48fd12dea72c4a92eee3dc335e294248fcd1cae1df3c9e33c2902c0ffff7f00f0ff038000f8fffe3f000080ff1f00fe3f00f8ffff3f000000ff0f0000c0ff1f00002000000000f0ff0180ff0f00012000fcff00e0fffdff00100001a0fffb7fffffff0380fff7ff000000040001f0ff030000000000c0ff078000000000000010000340000080ffdfff01000000000320000480ff4f00fc7f00000001e0ff0f0001f0ff05c0fff7ff000000fcff00000002c0ff0700fe1f000480fe0f00084000000000400000800000000040000800fdffff0300000000024000f8ffffffff0380ff1f0002c0ff0f00002000040001f0fffdbffff7fffe1f00f4ffffeffffdbfff070001e0ff07800010000240000800ffffff0700000000febf000000000000f87f001000064000f8ff00c0ff0780ffefff01c0fff7ff0200000480ff1f00fe7f000000012000fcff0110000000000000fc1f00040000e0ff038000f0ff0300000400001000fc7f000800fe1f00008000f0ff0380ff170000e0ff03000120000080ff0700ff1f00000001e0ff0180ff1700012000fc7f010000fc3f00e8ffff3f00f87f0000000200001800004000000001f0ff014000f0ff0220000480ffffffff3f00f8ff0100000c00001000024000080003e0ff038000f0ff0340000000fedffffb7f00e0ff050000e8ff00e0ffff7f01f0fffdffff170001e0ffffff00e0fff9ffff17000100000000002000febfff1f00fe5f00f87f00f0ffff3f0008000100000400001000feffff0700010000000001e0ffffffff0f00010000000000f0ff07c0fff7ff0100000880002000feffff0f00ff1f000480ffffffff3f000000ff3f000480ffffff03c0ffffff00e0ff0b000000000440000800fe3f0000000020000440000000fd3f00f8ffffefff054000f8ff002000fcff001000008000f0ffff1f00fc7f00000000c0ff0f00ff5f000000ff1f00040000080000c0ff0300ffefff0140001000fe1f000c0000f0ff01c000e8ff02000000800100000280ff1700fe3f00008000f0ffffbf001000020000000001f0fffdffff070000e0ff0b80002000febf00f8ff0200000880ff0f00004000f8ff0120000400ffffff014000f8fffedfff0f8000f0ff01c0ffefffff1f00040001000002c0fffffffe3f00fcffff0f00fe7f00f8ff020000f8ff001000fe3f00100001c0ff078000f0ff0300000000ffdffffbff000000fe3f00000001c0fffb7f00d0fffb7f0008000020000080ff0f00024000080001e0ff0b0000f0ffffbfff0700feffff078000e0ffff3f00000002c0fffb7f002000febf00000000000004000020000280ff0f0000e0fffb7f002000048000100000c0ff070001e0ff01c0ffffff0300000480ff0f00040000f8ff0140000480000000004000f0ff010000f87fffffffff7fff0700012000fcffffefffffffff0f00000000fc7f000000060000000001e0fff7ff002000fafffffffffd1f000080011000feffff0700ff1f000080ff3f00020000f0ffffdfff078000000004c000f8ff024000088000f0ff050000000001e0ff070000100006c0ff0700024000f87f001000fe3f011000002000048000100000400000000000000080ff0f0004c0ff070001c0ff0780ff1f00fc7f000800004000fcffff0f000400001000fd5f000080ff0f0000c0ff0f00fe1f00f4fffe1f00faffffffff012000008001f0fffd7f00f8fffe5f000000002000fe7f00000001e0ff0700ff1f000280ff170000a0ff0780ffffff078000f8ff
Cipher Text : f0af922faecdcbcd728c0e1016e008757c761d395fe357f1f7fa91b0dded3e45c0def52a19d5690da3a5712f0d16bc26d9ac7687ebda4936ede50d1ea58c9fb1bc9ef083cbd589527a4d27313af5f936d7c451097df750d0f8117e6ed70d5bea97cd9bec5b59b58cf8cf265237e6e353efe36efc2bb7780d762f17b91819194036a2aeb48871738be906a13711eda41c02d57266f574a169395a25537083f921154644b8b896e5fa1b56f00ac8e980b038fedcffa5f2ccc04a249a9b4db02dab9764d483220ad5f1f64692c5fa3980c9079ff6b65a4cd2339119796aafc51ae55486e2ab473c518cb95d8b94c52b501e4faf5eb4c1328d13584ac337ba02a76bd39643762ac880fecb210609fc399c8836da1c3baeeef257e334d9755bce1b784757820e3b09c8d1273a6dbdc6b1e7d561b33ccafea6d79cd5743d1f85f506c834a04596c8819a8caba4d4d0686a381ddf64d19749fdf32ee805d1505f5eea8d45d211cea4f9ed4b212d7ae8c81235d14ed872635f04b416417255c5b45eca6c9c027ce7892d5d446feea136c2b99b9b6ff1a9585d2d81fe0f351f06bbdf0b1a043167bf262875085437d0db0578d4731dd2ec767eeb0aeeda535f0cb1ba8ea4319a05d06035692ce35ae763229731dac0d725cf357bdf96ad1e8d77744e8900d08b67609dee50229a34ef1b355a8b14c9bb742784972f18ff5416f83a53d7a7d3e8a21abf091218c5bfb755f2d21d775bd690a21053a6838eb935eae23e99bbd6ca802169ed0386bf8241782e69f452a0055230c7c5f4537df0132b43458a80a422a12c407ac8ceb9e608e40b48d23c714a4c01a6e80ed77a48bfcbd7282e1822688eb699f9b1b1fde3f98c4d02e634e2c15402643abb6a91efcedd0d5fad19f7e20b2e7da007c4cbdf23f73b54f16c97aac7a7f7bac5930a498b0134764c203b5bd7638ba78898ebdc0d4964efa3a91afe6ad45e6ea861a88354060ab6b54898acc48d19b2288da0ae1753deffb17c19c6af98061dfebff9eb8eeed95da7df14d5f6dd9e368550e2d2f9b3e2cbd8ba59b68161b49c0b4c508756e6fc60285baa64965201f6e7d53d257a884d5d195edbd8385519032c98b4c1f7d388ad23ff2f2be63f8d11b38fdf4a8d454683952f6dc1ca51c5324561edfab65f5382090bb75b4fb8d3bd6b088d1ac4cd0ec30e4b76779704bb8c32a7749096e77a117cf336e6ee1f743e4bd0cfa12bb67be1c39bb27ee3527b9fa2ab1c4e35087104d68d8821ecca8bdb6a142b6d9e617c135fd309cdab06bf88ded02b0d4ffc4c5c3f917d90f5cc45b3fe45c12ac33d9cd391efc1a348449e6bb394d98b74488cd79a602c786a0e0aa04b1d952c85624f2e9bf68e9a09079fcddd37482ad3727d5897f1391606b267b1e860e881bcacecf1767fed251eadeb9d96b56be5f88bfd37fc4f3e16ccf33af59476610e304578d21e25e1c310552899e1dc2411c87fce4d6b1fa4bebc89c986d5297de07884e523788117f1c930615887a36a19e36eb6572aa9
Session Key : eb8b0fce5ee3f0d15755f7b72726d61a1f11cad9bddeb15b049884bda7eb8b92
```
