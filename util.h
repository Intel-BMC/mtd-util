/*
 * MIT License
 *
 * Copyright (c) 2017 Intel Corporation
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 *
 *
 * Abstract: misc util functions and macros
 */

#ifndef __UTIL_H__
#define __UTIL_H__

#include <algorithm>
#include <gsl/span>
#include <iterator>
#include <sstream>
#include <string>
#include <vector>

typedef gsl::span<const uint8_t> cbspan;

#ifndef block_round
#define block_round(ODD, BLK) \
  ((ODD) + (((BLK) - ((ODD) & ((BLK)-1))) & ((BLK)-1)))
#endif

template <class TContainer>
static inline bool starts_with(const TContainer &haystack,
                               const TContainer &needle) {
  return haystack.size() >= needle.size() &&
         std::equal(needle.begin(), needle.end(), haystack.begin());
}

static inline void split(const std::string &s, char delim,
    std::vector<std::string>& result) {
  std::string::size_type prev_pos = 0, pos = 0;
  do {
    pos = s.find(delim, pos);
    if (pos == std::string::npos) {
      result.emplace_back(std::move(s.substr(prev_pos)));
    } else {
      result.emplace_back(std::move(s.substr(prev_pos, pos-prev_pos)));
      prev_pos = ++pos;
    }
  } while(pos != std::string::npos);
}

static inline std::vector<std::string> split(const std::string &s, char delim) {
  std::vector<std::string> elems;
  split(s, delim, elems);
  return elems;
}

static constexpr uint64_t prime = 0x100000001B3ull;
static constexpr uint64_t basis = 0xCBF29CE484222325ull;

static constexpr uint64_t const_hash(const char *str,
                                     uint64_t last_value = basis) {
  return *str ? const_hash(str + 1, (*str ^ last_value) * prime) : last_value;
}

static inline uint64_t hash(const std::string &str) {
  uint64_t ret{basis};

  for (auto i : str) {
    ret ^= i;
    ret *= prime;
  }

  return ret;
}

#endif /* __UTIL_H__ */
