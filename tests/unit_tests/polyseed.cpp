// Copyright (c) 2026-2026, The Monero Project
//
// All rights reserved.
//
// Redistribution and use in source and binary forms, with or without modification, are
// permitted provided that the following conditions are met:
//
// 1. Redistributions of source code must retain the above copyright notice, this list of
//    conditions and the following disclaimer.
//
// 2. Redistributions in binary form must reproduce the above copyright notice, this list
//    of conditions and the following disclaimer in the documentation and/or other
//    materials provided with the distribution.
//
// 3. Neither the name of the copyright holder nor the names of its contributors may be
//    used to endorse or promote products derived from this software without specific
//    prior written permission.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY
// EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
// MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL
// THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
// SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
// PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
// INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
// STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF
// THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

#include "gtest/gtest.h"
#include <array>
#include <stdexcept>
#include <string>
#include "mnemonics/polyseed/polyseed.hpp"

namespace
{
  std::string phrase_of(const polyseed::data &d, const char *lang_name)
  {
    epee::wipeable_string w;
    d.encode(polyseed::get_lang_by_name(lang_name), w);
    return std::string(w.data(), w.size());
  }
  std::array<uint8_t, 32> key_of(const polyseed::data &d)
  {
    std::array<uint8_t, 32> k{};
    d.keygen(k.data(), k.size());
    return k;
  }
  // a normalization failure must surface as the wrapper's std::runtime_error, never as a polyseed status
  template <class F> void expect_norm_failure(F f)
  {
    try { f(); FAIL() << "no exception"; }
    catch (const polyseed::error &e) { FAIL() << "polyseed::error instead: " << e.what(); }
    catch (const std::runtime_error &e) { EXPECT_STREQ(e.what(), "Unicode normalization failed"); }
  }
  std::string hangul(int n) { std::string s; for (int i = 0; i < n; ++i) s += "\xEA\xB0\x81"; return s; } // U+AC01, 3 jamo = 9 bytes after NFKD
}

TEST(polyseed, roundtrip)
{
  for (const char *lang : {"English", "Korean", "Japanese", "Spanish"})
  {
    polyseed::data d(POLYSEED_MONERO);
    d.create(0, polyseed::get_lang_by_name(lang));
    const std::string phrase = phrase_of(d, lang);
    polyseed::data e(POLYSEED_MONERO);
    const polyseed::language l = e.decode(phrase.c_str());
    EXPECT_STREQ(l.name_en(), lang);
    EXPECT_EQ(key_of(d), key_of(e));
  }
}

TEST(polyseed, invalid_utf8_in_phrase)
{
  polyseed::data d(POLYSEED_MONERO);
  d.create(0, polyseed::get_lang_by_name("Spanish"));
  const std::string phrase = phrase_of(d, "Spanish");
  std::string bad = phrase;
  bad[bad.find(' ') + 1] = '\xE9';   // CP1252 'e acute', not valid UTF-8
  polyseed::data e(POLYSEED_MONERO);
  expect_norm_failure([&] { e.decode(bad.c_str()); });
  EXPECT_FALSE(e.valid());
  EXPECT_NO_THROW(e.decode(phrase.c_str()));   // still usable afterwards
  EXPECT_EQ(key_of(d), key_of(e));
}

TEST(polyseed, overlong_input)
{
  polyseed::data d(POLYSEED_MONERO);
  d.create(0, polyseed::get_lang_by_name("English"));
  const std::string phrase = phrase_of(d, "English");
  const std::string ascii = phrase + " " + std::string(300, 'x');   // pure ASCII never reaches normalization
  polyseed::data e(POLYSEED_MONERO);
  EXPECT_THROW(e.decode(ascii.c_str()), polyseed::error);
  std::string non_ascii = phrase + " ";
  for (int i = 0; i < 300; ++i) non_ascii += "\xC3\xA9";   // NFKD form exceeds POLYSEED_STR_SIZE
  polyseed::data f(POLYSEED_MONERO);
  expect_norm_failure([&] { f.decode(non_ascii.c_str()); });
}

TEST(polyseed, crypt_roundtrip)
{
  polyseed::data d(POLYSEED_MONERO);
  d.create(0, polyseed::get_lang_by_name("English"));
  const auto k0 = key_of(d);
  d.crypt("se\xC3\xB1" "al");
  EXPECT_TRUE(d.encrypted());
  EXPECT_NE(key_of(d), k0);
  d.crypt("se\xC3\xB1" "al");
  EXPECT_FALSE(d.encrypted());
  EXPECT_EQ(key_of(d), k0);
}

TEST(polyseed, crypt_invalid_passphrase_leaves_seed_untouched)
{
  polyseed::data d(POLYSEED_MONERO);
  d.create(0, polyseed::get_lang_by_name("English"));
  const auto k0 = key_of(d);
  expect_norm_failure([&] { d.crypt("caf\xE9"); });
  EXPECT_FALSE(d.encrypted());
  EXPECT_EQ(key_of(d), k0);
  EXPECT_NO_THROW(d.crypt("ok"));
  EXPECT_TRUE(d.encrypted());
}

TEST(polyseed, crypt_passphrase_length_boundary)
{
  polyseed::data d(POLYSEED_MONERO);
  d.create(0, polyseed::get_lang_by_name("English"));
  const auto k0 = key_of(d);
  EXPECT_NO_THROW(d.crypt(hangul(63).c_str()));   // 567 bytes after NFKD
  EXPECT_NO_THROW(d.crypt(hangul(63).c_str()));
  EXPECT_EQ(key_of(d), k0);
  expect_norm_failure([&] { d.crypt(hangul(64).c_str()); });   // 576 bytes: rejected before touching the seed
  EXPECT_FALSE(d.encrypted());
  EXPECT_EQ(key_of(d), k0);
}
