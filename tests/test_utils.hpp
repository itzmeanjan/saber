#pragma once
#include <cassert>
#include <charconv>
#include <cstddef>
#include <cstdint>
#include <string_view>
#include <vector>

// Utility functions used for testing Saber KEM
namespace saber_test_utils {

// Given a hex encoded string of length 2*L, this routine can be used for
// parsing it as a byte array of length L.
//
// Taken from
// https://github.com/itzmeanjan/ascon/blob/619973b5bcc35d8d0ee56cbc17acc9da6f385098/include/utils.hpp#L125C1-L151C1
inline std::vector<uint8_t>
from_hex(std::string_view hex)
{
  const size_t hlen = hex.length();
  assert(hlen % 2 == 0);

  const size_t blen = hlen / 2;
  std::vector<uint8_t> res(blen, 0);

  for (size_t i = 0; i < blen; i++) {
    const size_t off = i * 2;

    uint8_t byte = 0;
    auto sstr = hex.substr(off, 2);
    std::from_chars(sstr.data(), sstr.data() + 2, byte, 16);

    res[i] = byte;
  }

  return res;
}

}
