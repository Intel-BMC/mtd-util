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
 *    Abstract:   simple FwUpdate debugging
 *
 */

#include <cctype>
#include <cstdint>
#include <gsl/span>
#include <iomanip>
#include <iostream>

#include "debug.h"

static dbg_level __dbg_level = PRINT_ERROR;
dbg_level fw_update_get_dbg_level(void) { return __dbg_level; }

void fw_update_set_dbg_level(dbg_level l) { __dbg_level = l; }

void _dump(dbg_level lvl, const char *fn, int lineno, const char *bname,
           const gsl::span<const uint8_t> &buf) {
  unsigned int i = 0, l;
  std::stringstream hex, ascii;
  auto cb = buf.begin();

  /*  0         1         2         3         4         5         6
   *  0123456789012345678901234567890123456789012345678901234567890123456789
   *  0000000: 0000 0000 0000 0000 0000 0000 0000 0000  ................
   */

  std::cerr << '<' << lvl << '>' << fn << ":" << lineno << ": dumping "
            << buf.length() << " bytes from " << (void *)buf.data() << " ("
            << bname << ")" << std::endl;
  hex << std::hex << std::setfill('0');
  while (cb != buf.end()) {
    hex.str("");
    ascii.str("");
    hex << std::setw(7) << i << ": ";
    for (l = 0; l < 16 && (cb != buf.end()); l++) {
      hex << std::setw(2) << (unsigned int)*cb;
      if (l & 1) hex << ' ';
      if (isprint(*cb))
        ascii << (char)(*cb);
      else
        ascii << '.';
      cb++;
      i++;
    }
    std::cerr << '<' << lvl << '>' << std::left << std::setw(50) << hex.str()
              << ascii.str() << std::endl;
  }
  std::cerr << std::setw(0);
}

void _dump(dbg_level lvl, const char *fn, int lineno, const char *bname,
           const void *buf, size_t len) {
  const uint8_t *ubuf = (const uint8_t *)buf;
  const gsl::span<const uint8_t> bspan{ubuf, ubuf + len};
  _dump(lvl, fn, lineno, bname, bspan);
}
