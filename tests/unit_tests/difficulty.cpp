// Copyright (c) 2019-2024, The Monero Project
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

#include <cstddef>
#include <cstring>

#include "gtest/gtest.h"
#include "int-util.h"
#include "cryptonote_basic/difficulty.h"

static cryptonote::difficulty_type MKDIFF(uint64_t high, uint64_t low)
{
  cryptonote::difficulty_type d = high;
  d = (d << 64) | low;
  return d;
}

static void set_hash_word(crypto::hash &hash, std::size_t index, uint64_t value)
{
  ASSERT_LT(index, sizeof(hash.data) / sizeof(value));
  value = SWAP64LE(value);
  memcpy(hash.data + index * sizeof(value), &value, sizeof(value));
}

static crypto::hash MKHASH(uint64_t high, uint64_t low)
{
  cryptonote::difficulty_type hash_target = high;
  hash_target = (hash_target << 64) | low;
  boost::multiprecision::uint256_t hash_value = std::numeric_limits<boost::multiprecision::uint256_t>::max() / hash_target;
  crypto::hash h;
  uint64_t val;
  val = (hash_value & 0xffffffffffffffff).convert_to<uint64_t>();
  set_hash_word(h, 0, val);
  hash_value >>= 64;
  val = (hash_value & 0xffffffffffffffff).convert_to<uint64_t>();
  set_hash_word(h, 1, val);
  hash_value >>= 64;
  val = (hash_value & 0xffffffffffffffff).convert_to<uint64_t>();
  set_hash_word(h, 2, val);
  hash_value >>= 64;
  val = (hash_value & 0xffffffffffffffff).convert_to<uint64_t>();
  set_hash_word(h, 3, val);
  return h;
}

TEST(difficulty, check_hash)
{
  ASSERT_TRUE(cryptonote::check_hash(MKHASH(0, 1), MKDIFF(0, 1)));
  ASSERT_FALSE(cryptonote::check_hash(MKHASH(0, 1), MKDIFF(0, 2)));

  ASSERT_TRUE(cryptonote::check_hash(MKHASH(0, 0xffffffffffffffff), MKDIFF(0, 0xffffffffffffffff)));
  ASSERT_FALSE(cryptonote::check_hash(MKHASH(0, 0xffffffffffffffff), MKDIFF(1, 0)));

  ASSERT_TRUE(cryptonote::check_hash(MKHASH(1, 1), MKDIFF(1, 1)));
  ASSERT_FALSE(cryptonote::check_hash(MKHASH(1, 1), MKDIFF(1, 2)));

  ASSERT_TRUE(cryptonote::check_hash(MKHASH(0xffffffffffffffff, 1), MKDIFF(0xffffffffffffffff, 1)));
  ASSERT_FALSE(cryptonote::check_hash(MKHASH(0xffffffffffffffff, 1), MKDIFF(0xffffffffffffffff, 2)));
}

namespace
{
  struct lcg
  {
    uint64_t x;
    uint64_t next() { x = x * 6364136223846793005ull + 1442695040888963407ull; return x >> 11; }
  };
}

TEST(difficulty, span_floor)
{
  static const struct
  {
    int kind;
    size_t length;
    uint64_t seed, target_seconds, divisor;
    const char *expected, *expected_without_floor;
  } vectors[] = {
    {0, 2, 1, 120, 4, "102673", "102673"},
    {0, 2, 2, 120, 2, "499655", "499655"},
    {0, 2, 3, 120, 7, "181095", "181095"},
    {0, 2, 4, 60, 8, "116152", "116152"},
    {0, 3, 5, 120, 4, "81346", "81346"},
    {0, 3, 6, 120, 2, "209651", "209651"},
    {0, 3, 7, 120, 7, "398231", "398231"},
    {0, 3, 8, 60, 8, "155169", "155169"},
    {0, 10, 9, 120, 4, "487198", "487198"},
    {0, 10, 10, 120, 2, "360601", "360601"},
    {0, 10, 11, 120, 7, "315531", "315531"},
    {0, 10, 12, 60, 8, "315712", "315712"},
    {0, 600, 13, 120, 4, "517111", "517111"},
    {0, 600, 14, 120, 2, "505274", "505274"},
    {0, 600, 15, 120, 7, "505951", "505951"},
    {0, 600, 16, 60, 8, "250408", "250408"},
    {0, 601, 17, 120, 4, "514577", "514577"},
    {0, 601, 18, 120, 2, "500781", "500781"},
    {0, 601, 19, 120, 7, "488598", "488598"},
    {0, 601, 20, 60, 8, "258581", "258581"},
    {0, 720, 21, 120, 4, "499198", "499198"},
    {0, 720, 22, 120, 2, "515651", "515651"},
    {0, 720, 23, 120, 7, "516865", "516865"},
    {0, 720, 24, 60, 8, "261764", "261764"},
    {0, 735, 25, 120, 4, "498935", "498935"},
    {0, 735, 26, 120, 2, "479685", "479685"},
    {0, 735, 27, 120, 7, "509004", "509004"},
    {0, 735, 28, 60, 8, "241316", "241316"},
    {1, 2, 29, 120, 4, "533637", "533637"},
    {1, 2, 30, 120, 2, "218026", "218026"},
    {1, 2, 31, 120, 7, "902415", "902415"},
    {1, 2, 32, 60, 8, "293402", "293402"},
    {1, 3, 33, 120, 4, "291007", "291007"},
    {1, 3, 34, 120, 2, "502845", "502845"},
    {1, 3, 35, 120, 7, "714684", "714684"},
    {1, 3, 36, 60, 8, "213261", "213261"},
    {1, 10, 37, 120, 4, "429321", "429321"},
    {1, 10, 38, 120, 2, "806828", "806828"},
    {1, 10, 39, 120, 7, "431332", "431332"},
    {1, 10, 40, 60, 8, "250140", "250140"},
    {1, 600, 41, 120, 4, "1985489", "2477725"},
    {1, 600, 42, 120, 2, "968648", "2417584"},
    {1, 600, 43, 120, 7, "2529327", "2529327"},
    {1, 600, 44, 60, 8, "1241369", "1241369"},
    {1, 601, 45, 120, 4, "2016761", "2537898"},
    {1, 601, 46, 120, 2, "938030", "2360840"},
    {1, 601, 47, 120, 7, "2556067", "2556067"},
    {1, 601, 48, 60, 8, "1302344", "1302344"},
    {1, 720, 49, 120, 4, "1962909", "4899092"},
    {1, 720, 50, 120, 2, "1010247", "5042815"},
    {1, 720, 51, 120, 7, "3390666", "4835937"},
    {1, 720, 52, 60, 8, "2534312", "2534312"},
    {1, 735, 53, 120, 4, "1941508", "4845680"},
    {1, 735, 54, 120, 2, "973219", "4857985"},
    {1, 735, 55, 120, 7, "3480496", "4964057"},
    {1, 735, 56, 60, 8, "2489082", "2489082"},
    {2, 2, 57, 120, 4, "858192", "25745760"},
    {2, 2, 58, 120, 2, "1797876", "107872560"},
    {2, 2, 59, 120, 7, "3888847", "69999240"},
    {2, 2, 60, 60, 8, "2007870", "16062960"},
    {2, 3, 61, 120, 4, "3407948", "102238440"},
    {2, 3, 62, 120, 2, "1127651", "67659060"},
    {2, 3, 63, 120, 7, "1890264", "33079620"},
    {2, 3, 64, 60, 8, "3900016", "29250120"},
    {2, 10, 65, 120, 4, "2194247", "65827400"},
    {2, 10, 66, 120, 2, "1185471", "71128227"},
    {2, 10, 67, 120, 7, "2661008", "45828467"},
    {2, 10, 68, 60, 8, "4919723", "37171234"},
    {2, 600, 69, 120, 4, "1967106", "59013174"},
    {2, 600, 70, 120, 2, "980596", "58835701"},
    {2, 600, 71, 120, 7, "3424615", "58710120"},
    {2, 600, 72, 60, 8, "4078805", "30594438"},
    {2, 601, 73, 120, 4, "2041041", "61231204"},
    {2, 601, 74, 120, 2, "979739", "58784323"},
    {2, 601, 75, 120, 7, "3501267", "60024216"},
    {2, 601, 76, 60, 8, "4081895", "30617616"},
    {2, 720, 77, 120, 4, "2005169", "60155054"},
    {2, 720, 78, 120, 2, "1060924", "63655381"},
    {2, 720, 79, 120, 7, "3446880", "59091821"},
    {2, 720, 80, 60, 8, "4085875", "30647473"},
    {2, 735, 81, 120, 4, "1991935", "59758049"},
    {2, 735, 82, 120, 2, "992861", "59571604"},
    {2, 735, 83, 120, 7, "3567477", "61159288"},
    {2, 735, 84, 60, 8, "3947676", "29610863"},
    {3, 2, 85, 120, 4, "636452", "636452"},
    {3, 2, 86, 120, 2, "320841", "320841"},
    {3, 2, 87, 120, 7, "5230", "5230"},
    {3, 2, 88, 60, 8, "344810", "344810"},
    {3, 3, 89, 120, 4, "283463", "283463"},
    {3, 3, 90, 120, 2, "495302", "495302"},
    {3, 3, 91, 120, 7, "707141", "707141"},
    {3, 3, 92, 60, 8, "209490", "209490"},
    {3, 10, 93, 120, 4, "445581", "445581"},
    {3, 10, 94, 120, 2, "572086", "572086"},
    {3, 10, 95, 120, 7, "501145", "501145"},
    {3, 10, 96, 60, 8, "229491", "229491"},
    {3, 600, 97, 120, 4, "511106", "511106"},
    {3, 600, 98, 120, 2, "524833", "524833"},
    {3, 600, 99, 120, 7, "510058", "510058"},
    {3, 600, 100, 60, 8, "242976", "242976"},
    {3, 601, 101, 120, 4, "488935", "488935"},
    {3, 601, 102, 120, 2, "487341", "487341"},
    {3, 601, 103, 120, 7, "512326", "512326"},
    {3, 601, 104, 60, 8, "251871", "251871"},
    {3, 720, 105, 120, 4, "510128", "510128"},
    {3, 720, 106, 120, 2, "490523", "490523"},
    {3, 720, 107, 120, 7, "500223", "500223"},
    {3, 720, 108, 60, 8, "252427", "252427"},
    {3, 735, 109, 120, 4, "487471", "487471"},
    {3, 735, 110, 120, 2, "530248", "530248"},
    {3, 735, 111, 120, 7, "491846", "491846"},
    {3, 735, 112, 60, 8, "257823", "257823"},
    {4, 2, 113, 120, 4, "88528497465935808689502414045411324", "88528497465935808689502414045411324"},
    {4, 2, 114, 120, 2, "28591596465842073093344950255522012", "28591596465842073093344950255522012"},
    {4, 2, 115, 120, 7, "98236171156656282557309145657756607", "98236171156656282557309145657756607"},
    {4, 2, 116, 60, 8, "7190802323167565167575869098241054", "7190802323167565167575869098241054"},
    {4, 3, 117, 120, 4, "25934065129335948600199487989671601", "25934065129335948600199487989671601"},
    {4, 3, 118, 120, 2, "66499056602488700867764217322916054", "66499056602488700867764217322916054"},
    {4, 3, 119, 120, 7, "98380538988829455044700791919752444", "98380538988829455044700791919752444"},
    {4, 3, 120, 60, 8, "7459342700823703708014078238228574", "7459342700823703708014078238228574"},
    {4, 10, 121, 120, 4, "114204885343172643218033172288219443", "114204885343172643218033172288219443"},
    {4, 10, 122, 120, 2, "127061461372781989623395795870145075", "127061461372781989623395795870145075"},
    {4, 10, 123, 120, 7, "95331834311567459677798813781298154", "95331834311567459677798813781298154"},
    {4, 10, 124, 60, 8, "44297725778773504816515518644349144", "44297725778773504816515518644349144"},
    {5, 2, 125, 120, 4, "0", "0"},
    {5, 2, 126, 120, 2, "170170679608617090311418510637794899784", "0"},
    {5, 2, 127, 120, 7, "0", "0"},
    {5, 2, 128, 60, 8, "0", "0"},
    {5, 3, 129, 120, 4, "0", "0"},
    {5, 3, 130, 120, 2, "170262629132743915320530445073026446735", "0"},
    {5, 3, 131, 120, 7, "0", "0"},
    {5, 3, 132, 60, 8, "0", "0"},
  };
  for (const auto &v: vectors)
  {
    lcg r{v.seed};
    const uint64_t base = 1600000000 + r.next() % 100000;
    std::vector<uint64_t> timestamps;
    std::vector<cryptonote::difficulty_type> cumulative_difficulties;
    cryptonote::difficulty_type cumulative_difficulty = 0;
    for (size_t i = 0; i < v.length; ++i)
    {
      uint64_t t = base;
      switch (v.kind)
      {
        case 0: t = base + 120 * i + r.next() % 241 - 120; break;
        case 1: t = base + 120 * std::min<size_t>(i, 120); break;
        case 2: t = base + i; break;
        case 3: t = base + 120 * (v.length - i); break;
        case 4: t = base + r.next() % 1000; break;
      }
      cryptonote::difficulty_type d;
      if (v.kind >= 4)
      {
        d = r.next();
        d = (d << 64) | r.next();
        d = v.kind == 4 ? d % (cryptonote::difficulty_type(1) << 120) + 1 : (cryptonote::difficulty_type(1) << 126) + d % (cryptonote::difficulty_type(1) << 125);
      }
      else
        d = 1 + r.next() % 1000000;
      cumulative_difficulty += d;
      timestamps.push_back(t);
      cumulative_difficulties.push_back(cumulative_difficulty);
    }
    ASSERT_EQ(cryptonote::next_difficulty(timestamps, cumulative_difficulties, v.target_seconds, v.divisor), cryptonote::difficulty_type(v.expected)) << v.kind << " " << v.length << " " << v.seed;
    ASSERT_EQ(cryptonote::next_difficulty(timestamps, cumulative_difficulties, v.target_seconds), cryptonote::difficulty_type(v.expected_without_floor)) << v.kind << " " << v.length << " " << v.seed;
  }
}
