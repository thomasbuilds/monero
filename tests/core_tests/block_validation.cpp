// Copyright (c) 2014-2024, The Monero Project
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
// 
// Parts of this file are originally copyright (c) 2012-2013 The Cryptonote developers

#include <chrono>
#include <thread>

#include "chaingen.h"
#include "block_validation.h"

using namespace epee;
using namespace cryptonote;

namespace
{
  bool lift_up_difficulty(std::vector<test_event_entry>& events, std::vector<uint64_t>& timestamps,
                          std::vector<difficulty_type>& cummulative_difficulties, test_generator& generator,
                          size_t new_block_count, const block &blk_last, const account_base& miner_account)
  {
    difficulty_type commulative_diffic = cummulative_difficulties.empty() ? 0 : cummulative_difficulties.back();
    block blk_prev = blk_last;
    for (size_t i = 0; i < new_block_count; ++i)
    {
      block blk_next;
      difficulty_type diffic = next_difficulty(timestamps, cummulative_difficulties,DIFFICULTY_TARGET_V1);
      if (!generator.construct_block_manually(blk_next, blk_prev, miner_account,
        test_generator::bf_timestamp | test_generator::bf_diffic, 0, 0, blk_prev.timestamp, crypto::hash(), diffic))
        return false;

      commulative_diffic += diffic;
      if (timestamps.size() == DIFFICULTY_WINDOW)
      {
        timestamps.erase(timestamps.begin());
        cummulative_difficulties.erase(cummulative_difficulties.begin());
      }
      timestamps.push_back(blk_next.timestamp);
      cummulative_difficulties.push_back(commulative_diffic);

      events.push_back(blk_next);
      blk_prev = blk_next;
    }

    return true;
  }
}

namespace
{
  uint8_t strict_ts_test_version(uint64_t height, uint64_t strict_height)
  {
    return height >= strict_height ? HF_VERSION_STRICT_TIMESTAMPS : HF_VERSION_STRICT_TIMESTAMPS - 1;
  }

  bool make_strict_ts_test_block(test_generator& generator, block& blk, const block& prev, const account_base& miner_account,
                                 uint64_t strict_height, uint64_t timestamp, const difficulty_type& diffic = 1)
  {
    const uint8_t version = strict_ts_test_version(get_block_height(prev) + 1, strict_height);
    return generator.construct_block_manually(blk, prev, miner_account,
      test_generator::bf_major_ver | test_generator::bf_minor_ver | test_generator::bf_timestamp | test_generator::bf_diffic | test_generator::bf_hf_version,
      version, version, timestamp, crypto::hash(), diffic, transaction(), std::vector<crypto::hash>(), 0, 0, version);
  }

  difficulty_type expected_difficulty(const std::vector<uint64_t>& timestamps, const std::vector<difficulty_type>& cumulative_difficulties,
                                      bool span_floor)
  {
    const size_t height = timestamps.size();
    const size_t begin = std::max<size_t>(1, height - std::min<size_t>(height, DIFFICULTY_BLOCKS_COUNT));
    return next_difficulty(std::vector<uint64_t>(timestamps.begin() + begin, timestamps.end()),
      std::vector<difficulty_type>(cumulative_difficulties.begin() + begin, cumulative_difficulties.end()),
      DIFFICULTY_TARGET_V2, span_floor ? DIFFICULTY_SPAN_FLOOR_DIVISOR : 0);
  }

  bool make_strict_ts_test_chain(std::vector<test_event_entry>& events, test_generator& generator, block& blk_last, const block& blk_0,
                                 const account_base& miner_account, uint64_t strict_height, size_t n)
  {
    blk_last = blk_0;
    for (size_t i = 0; i < n; ++i)
    {
      block blk;
      if (!make_strict_ts_test_block(generator, blk, blk_last, miner_account, strict_height, blk_last.timestamp + 2 * DIFFICULTY_TARGET_V2))
        return false;
      events.push_back(blk);
      blk_last = blk;
    }
    return true;
  }

  uint64_t median_of_last_timestamps(const std::vector<test_event_entry>& events)
  {
    std::vector<uint64_t> timestamps;
    for (size_t i = events.size() - BLOCKCHAIN_TIMESTAMP_CHECK_WINDOW; i < events.size(); ++i)
      timestamps.push_back(boost::get<block>(events[i]).timestamp);
    return epee::misc_utils::median(timestamps);
  }

  bool make_future_test_chain(std::vector<test_event_entry>& events, test_generator& generator, const block& blk_0,
                              const account_base& miner_account, size_t lift, difficulty_type& diffic)
  {
    REWIND_BLOCKS_N(events, blk_0r, blk_0, miner_account, BLOCKCHAIN_TIMESTAMP_CHECK_WINDOW - 1);
    std::vector<uint64_t> timestamps;
    std::vector<difficulty_type> cumulative_difficulties;
    for (size_t i = 1; i < events.size(); ++i)
    {
      timestamps.push_back(boost::get<block>(events[i]).timestamp);
      cumulative_difficulties.push_back(i + 1);
    }
    if (!lift_up_difficulty(events, timestamps, cumulative_difficulties, generator, lift, blk_0r, miner_account))
      return false;
    diffic = next_difficulty(timestamps, cumulative_difficulties, DIFFICULTY_TARGET_V1);
    return true;
  }

  bool make_strict_ts_median_chain(std::vector<test_event_entry>& events, test_generator& generator, block& blk_last, const block& blk_0,
                                   const account_base& miner_account, uint64_t strict_height)
  {
    if (!make_strict_ts_test_chain(events, generator, blk_last, blk_0, miner_account, strict_height, 68))
      return false;
    block blk;
    if (!make_strict_ts_test_block(generator, blk, blk_last, miner_account, strict_height, median_of_last_timestamps(events)))
      return false;
    events.push_back(blk);
    blk_last = blk;
    return median_of_last_timestamps(events) > blk_last.timestamp;
  }
}

#define BLOCK_VALIDATION_INIT_GENERATE()                                                \
  GENERATE_ACCOUNT(miner_account);                                                      \
  MAKE_GENESIS_BLOCK(events, blk_0, miner_account, 1338224400);

//----------------------------------------------------------------------------------------------------------------------
// Tests

bool gen_block_big_major_version::generate(std::vector<test_event_entry>& events) const
{
  BLOCK_VALIDATION_INIT_GENERATE();

  block blk_1;
  generator.construct_block_manually(blk_1, blk_0, miner_account, test_generator::bf_major_ver, 255);
  events.push_back(blk_1);

  DO_CALLBACK(events, "check_block_purged");

  return true;
}

bool gen_block_big_minor_version::generate(std::vector<test_event_entry>& events) const
{
  BLOCK_VALIDATION_INIT_GENERATE();

  block blk_1;
  generator.construct_block_manually(blk_1, blk_0, miner_account, test_generator::bf_minor_ver, 0, 255);
  events.push_back(blk_1);

  DO_CALLBACK(events, "check_block_accepted");

  return true;
}

bool gen_block_ts_not_checked::generate(std::vector<test_event_entry>& events) const
{
  BLOCK_VALIDATION_INIT_GENERATE();
  REWIND_BLOCKS_N(events, blk_0r, blk_0, miner_account, BLOCKCHAIN_TIMESTAMP_CHECK_WINDOW - 2);

  block blk_1;
  generator.construct_block_manually(blk_1, blk_0r, miner_account, test_generator::bf_timestamp, 0, 0, blk_0.timestamp - 60 * 60);
  events.push_back(blk_1);

  DO_CALLBACK(events, "check_block_accepted");

  return true;
}

bool gen_block_ts_in_past::generate(std::vector<test_event_entry>& events) const
{
  BLOCK_VALIDATION_INIT_GENERATE();
  REWIND_BLOCKS_N(events, blk_0r, blk_0, miner_account, BLOCKCHAIN_TIMESTAMP_CHECK_WINDOW - 1);

  uint64_t ts_below_median = boost::get<block>(events[BLOCKCHAIN_TIMESTAMP_CHECK_WINDOW / 2 - 1]).timestamp;
  block blk_1;
  generator.construct_block_manually(blk_1, blk_0r, miner_account, test_generator::bf_timestamp, 0, 0, ts_below_median);
  events.push_back(blk_1);

  DO_CALLBACK(events, "check_block_purged");

  return true;
}

bool gen_block_ts_in_future::generate(std::vector<test_event_entry>& events) const
{
  BLOCK_VALIDATION_INIT_GENERATE();

  block blk_1;
  generator.construct_block_manually(blk_1, blk_0, miner_account, test_generator::bf_timestamp, 0, 0, time(NULL) + 60*60 + CRYPTONOTE_BLOCK_FUTURE_TIME_LIMIT);
  events.push_back(blk_1);

  DO_CALLBACK(events, "check_block_purged");

  return true;
}

bool gen_block_invalid_prev_id::generate(std::vector<test_event_entry>& events) const
{
  BLOCK_VALIDATION_INIT_GENERATE();

  block blk_1;
  crypto::hash prev_id = get_block_hash(blk_0);
  reinterpret_cast<char &>(prev_id) ^= 1;
  generator.construct_block_manually(blk_1, blk_0, miner_account, test_generator::bf_prev_id, 0, 0, 0, prev_id);
  events.push_back(blk_1);

  DO_CALLBACK(events, "check_block_purged");

  return true;
}

bool gen_block_invalid_prev_id::check_block_verification_context(const cryptonote::block_verification_context& bvc, size_t event_idx, const cryptonote::block& /*blk*/)
{
  if (1 == event_idx)
    return bvc.m_marked_as_orphaned && !bvc.m_added_to_main_chain && !bvc.m_verifivation_failed;
  else
    return !bvc.m_marked_as_orphaned && bvc.m_added_to_main_chain && !bvc.m_verifivation_failed;
}

bool gen_block_invalid_nonce::generate(std::vector<test_event_entry>& events) const
{
  BLOCK_VALIDATION_INIT_GENERATE();

  std::vector<uint64_t> timestamps;
  std::vector<difficulty_type> commulative_difficulties;
  if (!lift_up_difficulty(events, timestamps, commulative_difficulties, generator, 2, blk_0, miner_account))
    return false;

  // Create invalid nonce
  difficulty_type diffic = next_difficulty(timestamps, commulative_difficulties,DIFFICULTY_TARGET_V1);
  assert(1 < diffic);
  const block& blk_last = boost::get<block>(events.back());
  uint64_t timestamp = blk_last.timestamp;
  block blk_3;
  do
  {
    ++timestamp;
    blk_3.miner_tx.set_null();
    if (!generator.construct_block_manually(blk_3, blk_last, miner_account,
      test_generator::bf_diffic | test_generator::bf_timestamp, 0, 0, timestamp, crypto::hash(), diffic))
      return false;
  }
  while (0 == blk_3.nonce);
  --blk_3.nonce;
  events.push_back(blk_3);

  return true;
}

bool gen_block_no_miner_tx::generate(std::vector<test_event_entry>& events) const
{
  BLOCK_VALIDATION_INIT_GENERATE();

  transaction miner_tx;
  miner_tx.set_null();

  block blk_1;
  generator.construct_block_manually(blk_1, blk_0, miner_account, test_generator::bf_miner_tx, 0, 0, 0, crypto::hash(), 0, miner_tx);
  events.push_back(blk_1);

  DO_CALLBACK(events, "check_block_purged");

  return true;
}

bool gen_block_unlock_time_is_low::generate(std::vector<test_event_entry>& events) const
{
  BLOCK_VALIDATION_INIT_GENERATE();

  MAKE_MINER_TX_MANUALLY(miner_tx, blk_0);
  --miner_tx.unlock_time;

  block blk_1;
  generator.construct_block_manually(blk_1, blk_0, miner_account, test_generator::bf_miner_tx, 0, 0, 0, crypto::hash(), 0, miner_tx);
  events.push_back(blk_1);

  DO_CALLBACK(events, "check_block_purged");

  return true;
}

bool gen_block_unlock_time_is_high::generate(std::vector<test_event_entry>& events) const
{
  BLOCK_VALIDATION_INIT_GENERATE();

  MAKE_MINER_TX_MANUALLY(miner_tx, blk_0);
  ++miner_tx.unlock_time;

  block blk_1;
  generator.construct_block_manually(blk_1, blk_0, miner_account, test_generator::bf_miner_tx, 0, 0, 0, crypto::hash(), 0, miner_tx);
  events.push_back(blk_1);

  DO_CALLBACK(events, "check_block_purged");

  return true;
}

bool gen_block_unlock_time_is_timestamp_in_past::generate(std::vector<test_event_entry>& events) const
{
  BLOCK_VALIDATION_INIT_GENERATE();

  MAKE_MINER_TX_MANUALLY(miner_tx, blk_0);
  miner_tx.unlock_time = blk_0.timestamp - 10 * 60;

  block blk_1;
  generator.construct_block_manually(blk_1, blk_0, miner_account, test_generator::bf_miner_tx, 0, 0, 0, crypto::hash(), 0, miner_tx);
  events.push_back(blk_1);

  DO_CALLBACK(events, "check_block_purged");

  return true;
}

bool gen_block_unlock_time_is_timestamp_in_future::generate(std::vector<test_event_entry>& events) const
{
  BLOCK_VALIDATION_INIT_GENERATE();

  MAKE_MINER_TX_MANUALLY(miner_tx, blk_0);
  miner_tx.unlock_time = blk_0.timestamp + 3 * CRYPTONOTE_MINED_MONEY_UNLOCK_WINDOW * DIFFICULTY_BLOCKS_ESTIMATE_TIMESPAN;

  block blk_1;
  generator.construct_block_manually(blk_1, blk_0, miner_account, test_generator::bf_miner_tx, 0, 0, 0, crypto::hash(), 0, miner_tx);
  events.push_back(blk_1);

  DO_CALLBACK(events, "check_block_purged");

  return true;
}

bool gen_block_height_is_low::generate(std::vector<test_event_entry>& events) const
{
  BLOCK_VALIDATION_INIT_GENERATE();

  MAKE_MINER_TX_MANUALLY(miner_tx, blk_0);
  boost::get<txin_gen>(miner_tx.vin[0]).height--;

  block blk_1;
  generator.construct_block_manually(blk_1, blk_0, miner_account, test_generator::bf_miner_tx, 0, 0, 0, crypto::hash(), 0, miner_tx);
  events.push_back(blk_1);

  DO_CALLBACK(events, "check_block_purged");

  return true;
}

bool gen_block_height_is_high::generate(std::vector<test_event_entry>& events) const
{
  BLOCK_VALIDATION_INIT_GENERATE();

  MAKE_MINER_TX_MANUALLY(miner_tx, blk_0);
  boost::get<txin_gen>(miner_tx.vin[0]).height++;

  block blk_1;
  generator.construct_block_manually(blk_1, blk_0, miner_account, test_generator::bf_miner_tx, 0, 0, 0, crypto::hash(), 0, miner_tx);
  events.push_back(blk_1);

  DO_CALLBACK(events, "check_block_purged");

  return true;
}

bool gen_block_miner_tx_has_2_tx_gen_in::generate(std::vector<test_event_entry>& events) const
{
  BLOCK_VALIDATION_INIT_GENERATE();

  MAKE_MINER_TX_MANUALLY(miner_tx, blk_0);

  txin_gen in;
  in.height = get_block_height(blk_0) + 1;
  miner_tx.vin.push_back(in);

  block blk_1;
  generator.construct_block_manually(blk_1, blk_0, miner_account, test_generator::bf_miner_tx, 0, 0, 0, crypto::hash(), 0, miner_tx);
  events.push_back(blk_1);

  DO_CALLBACK(events, "check_block_purged");

  return true;
}

bool gen_block_miner_tx_has_2_in::generate(std::vector<test_event_entry>& events) const
{
  BLOCK_VALIDATION_INIT_GENERATE();
  REWIND_BLOCKS(events, blk_0r, blk_0, miner_account);

  GENERATE_ACCOUNT(alice);

  tx_source_entry se;
  se.amount = blk_0.miner_tx.vout[0].amount;
  se.push_output(0, boost::get<txout_to_key>(blk_0.miner_tx.vout[0].target).key, se.amount);
  se.real_output = 0;
  se.rct = false;
  se.real_out_tx_key = get_tx_pub_key_from_extra(blk_0.miner_tx);
  se.real_output_in_tx_index = 0;
  std::vector<tx_source_entry> sources;
  sources.push_back(se);

  tx_destination_entry de;
  de.addr = miner_account.get_keys().m_account_address;
  de.amount = se.amount;
  std::vector<tx_destination_entry> destinations;
  destinations.push_back(de);

  transaction tmp_tx;
  if (!construct_tx(miner_account.get_keys(), sources, destinations, boost::none, std::vector<uint8_t>(), tmp_tx))
    return false;

  MAKE_MINER_TX_MANUALLY(miner_tx, blk_0);
  miner_tx.vin.push_back(tmp_tx.vin[0]);

  block blk_1;
  generator.construct_block_manually(blk_1, blk_0r, miner_account, test_generator::bf_miner_tx, 0, 0, 0, crypto::hash(), 0, miner_tx);
  events.push_back(blk_1);

  DO_CALLBACK(events, "check_block_purged");

  return true;
}

bool gen_block_miner_tx_with_txin_to_key::generate(std::vector<test_event_entry>& events) const
{
  BLOCK_VALIDATION_INIT_GENERATE();

  // This block has only one output
  block blk_1;
  generator.construct_block_manually(blk_1, blk_0, miner_account, test_generator::bf_none);
  events.push_back(blk_1);

  REWIND_BLOCKS(events, blk_1r, blk_1, miner_account);

  tx_source_entry se;
  se.amount = blk_1.miner_tx.vout[0].amount;
  se.push_output(0, boost::get<txout_to_key>(blk_1.miner_tx.vout[0].target).key, se.amount);
  se.real_output = 0;
  se.rct = false;
  se.real_out_tx_key = get_tx_pub_key_from_extra(blk_1.miner_tx);
  se.real_output_in_tx_index = 0;
  std::vector<tx_source_entry> sources;
  sources.push_back(se);

  tx_destination_entry de;
  de.addr = miner_account.get_keys().m_account_address;
  de.amount = se.amount;
  std::vector<tx_destination_entry> destinations;
  destinations.push_back(de);

  transaction tmp_tx;
  if (!construct_tx(miner_account.get_keys(), sources, destinations, boost::none, std::vector<uint8_t>(), tmp_tx))
    return false;

  MAKE_MINER_TX_MANUALLY(miner_tx, blk_1);
  miner_tx.vin[0] = tmp_tx.vin[0];

  block blk_2;
  generator.construct_block_manually(blk_2, blk_1r, miner_account, test_generator::bf_miner_tx, 0, 0, 0, crypto::hash(), 0, miner_tx);
  events.push_back(blk_2);

  DO_CALLBACK(events, "check_block_purged");

  return true;
}

bool gen_block_miner_tx_out_is_small::generate(std::vector<test_event_entry>& events) const
{
  BLOCK_VALIDATION_INIT_GENERATE();

  MAKE_MINER_TX_MANUALLY(miner_tx, blk_0);
  miner_tx.vout[0].amount /= 2;

  block blk_1;
  generator.construct_block_manually(blk_1, blk_0, miner_account, test_generator::bf_miner_tx, 0, 0, 0, crypto::hash(), 0, miner_tx);
  events.push_back(blk_1);

  DO_CALLBACK(events, "check_block_purged");

  return true;
}

bool gen_block_miner_tx_out_is_big::generate(std::vector<test_event_entry>& events) const
{
  BLOCK_VALIDATION_INIT_GENERATE();

  MAKE_MINER_TX_MANUALLY(miner_tx, blk_0);
  miner_tx.vout[0].amount *= 2;

  block blk_1;
  generator.construct_block_manually(blk_1, blk_0, miner_account, test_generator::bf_miner_tx, 0, 0, 0, crypto::hash(), 0, miner_tx);
  events.push_back(blk_1);

  DO_CALLBACK(events, "check_block_purged");

  return true;
}

bool gen_block_miner_tx_has_no_out::generate(std::vector<test_event_entry>& events) const
{
  BLOCK_VALIDATION_INIT_GENERATE();

  MAKE_MINER_TX_MANUALLY(miner_tx, blk_0);
  miner_tx.vout.clear();

  block blk_1;
  generator.construct_block_manually(blk_1, blk_0, miner_account, test_generator::bf_miner_tx, 0, 0, 0, crypto::hash(), 0, miner_tx);
  events.push_back(blk_1);

  DO_CALLBACK(events, "check_block_purged");

  return true;
}

bool gen_block_miner_tx_has_out_to_alice::generate(std::vector<test_event_entry>& events) const
{
  BLOCK_VALIDATION_INIT_GENERATE();

  GENERATE_ACCOUNT(alice);

  keypair txkey;
  MAKE_MINER_TX_AND_KEY_MANUALLY(miner_tx, blk_0, &txkey);

  crypto::key_derivation derivation;
  crypto::public_key out_eph_public_key;
  crypto::generate_key_derivation(alice.get_keys().m_account_address.m_view_public_key, txkey.sec, derivation);
  crypto::derive_public_key(derivation, 1, alice.get_keys().m_account_address.m_spend_public_key, out_eph_public_key);

  tx_out out_to_alice;
  out_to_alice.amount = miner_tx.vout[0].amount / 2;
  miner_tx.vout[0].amount -= out_to_alice.amount;
  out_to_alice.target = txout_to_key(out_eph_public_key);
  miner_tx.vout.push_back(out_to_alice);

  block blk_1;
  generator.construct_block_manually(blk_1, blk_0, miner_account, test_generator::bf_miner_tx, 0, 0, 0, crypto::hash(), 0, miner_tx);
  events.push_back(blk_1);

  DO_CALLBACK(events, "check_block_accepted");

  return true;
}

bool gen_block_has_invalid_tx::generate(std::vector<test_event_entry>& events) const
{
  BLOCK_VALIDATION_INIT_GENERATE();

  std::vector<crypto::hash> tx_hashes;
  tx_hashes.push_back(crypto::hash());

  block blk_1;
  generator.construct_block_manually_tx(blk_1, blk_0, miner_account, tx_hashes, 0);
  events.push_back(blk_1);

  DO_CALLBACK(events, "check_block_purged");

  return true;
}

bool gen_block_is_too_big::generate(std::vector<test_event_entry>& events) const
{
  BLOCK_VALIDATION_INIT_GENERATE();

  // Creating a huge miner_tx, it will have a lot of outs
  MAKE_MINER_TX_MANUALLY(miner_tx, blk_0);
  static const size_t tx_out_count = CRYPTONOTE_BLOCK_GRANTED_FULL_REWARD_ZONE_V1 / 2;
  uint64_t amount = get_outs_money_amount(miner_tx);
  uint64_t portion = amount / tx_out_count;
  uint64_t remainder = amount % tx_out_count;
  txout_target_v target = miner_tx.vout[0].target;
  miner_tx.vout.clear();
  for (size_t i = 0; i < tx_out_count; ++i)
  {
    tx_out o;
    o.amount = portion;
    o.target = target;
    miner_tx.vout.push_back(o);
  }
  if (0 < remainder)
  {
    tx_out o;
    o.amount = remainder;
    o.target = target;
    miner_tx.vout.push_back(o);
  }

  // Block reward will be incorrect, as it must be reduced if cumulative block size is very big,
  // but in this test it doesn't matter
  block blk_1;
  if (!generator.construct_block_manually(blk_1, blk_0, miner_account, test_generator::bf_miner_tx, 0, 0, 0, crypto::hash(), 0, miner_tx))
    return false;

  events.push_back(blk_1);

  DO_CALLBACK(events, "check_block_purged");

  return true;
}

gen_block_invalid_binary_format::gen_block_invalid_binary_format()
  : m_corrupt_blocks_begin_idx(0)
{
  REGISTER_CALLBACK("check_all_blocks_purged", gen_block_invalid_binary_format::check_all_blocks_purged);
  REGISTER_CALLBACK("corrupt_blocks_boundary", gen_block_invalid_binary_format::corrupt_blocks_boundary);
}

bool gen_block_invalid_binary_format::generate(std::vector<test_event_entry>& events) const
{
  BLOCK_VALIDATION_INIT_GENERATE();

  std::vector<uint64_t> timestamps;
  std::vector<difficulty_type> cummulative_difficulties;
  difficulty_type cummulative_diff = 1;

  // Unlock blk_0 outputs
  block blk_last = blk_0;
  assert(CRYPTONOTE_MINED_MONEY_UNLOCK_WINDOW < DIFFICULTY_WINDOW);
  for (size_t i = 0; i < CRYPTONOTE_MINED_MONEY_UNLOCK_WINDOW; ++i)
  {
    MAKE_NEXT_BLOCK(events, blk_curr, blk_last, miner_account);
    timestamps.push_back(blk_curr.timestamp);
    cummulative_difficulties.push_back(++cummulative_diff);
    blk_last = blk_curr;
  }

  // Lifting up takes a while
  difficulty_type diffic;
  do
  {
    blk_last = boost::get<block>(events.back());
    diffic = next_difficulty(timestamps, cummulative_difficulties,DIFFICULTY_TARGET_V1);
    if (!lift_up_difficulty(events, timestamps, cummulative_difficulties, generator, 1, blk_last, miner_account))
      return false;
    std::cout << "Block #" << events.size() << ", difficulty: " << diffic << std::endl;
  }
  while (diffic < 1500);

  blk_last = boost::get<block>(events.back());
  MAKE_TX(events, tx_0, miner_account, miner_account, MK_COINS(30), blk_last);
  DO_CALLBACK(events, "corrupt_blocks_boundary");

  block blk_test;
  std::vector<crypto::hash> tx_hashes;
  tx_hashes.push_back(get_transaction_hash(tx_0));
  size_t txs_weight = get_transaction_weight(tx_0);
  diffic = next_difficulty(timestamps, cummulative_difficulties,DIFFICULTY_TARGET_V1);
  if (!generator.construct_block_manually(blk_test, blk_last, miner_account,
    test_generator::bf_diffic | test_generator::bf_timestamp | test_generator::bf_tx_hashes, 0, 0, blk_last.timestamp,
    crypto::hash(), diffic, transaction(), tx_hashes, txs_weight))
    return false;

  blobdata blob = t_serializable_object_to_blob(blk_test);
  for (size_t i = 0; i < blob.size(); ++i)
  {
    for (size_t bit_idx = 0; bit_idx < sizeof(blobdata::value_type) * 8; ++bit_idx)
    {
      serialized_block sr_block(blob);
      blobdata::value_type& ch = sr_block.data[i];
      ch ^= 1 << bit_idx;

      events.push_back(sr_block);
    }
  }

  DO_CALLBACK(events, "check_all_blocks_purged");

  return true;
}

bool gen_block_invalid_binary_format::check_block_verification_context(const cryptonote::block_verification_context& bvc,
                                                                       size_t event_idx, const cryptonote::block& blk)
{
  if (0 == m_corrupt_blocks_begin_idx || event_idx < m_corrupt_blocks_begin_idx)
  {
    return bvc.m_added_to_main_chain;
  }
  else
  {
    return (!bvc.m_added_to_main_chain && (bvc.m_already_exists || bvc.m_marked_as_orphaned || bvc.m_verifivation_failed))
      || (bvc.m_added_to_main_chain && bvc.m_partial_block_reward);
  }
}

bool gen_block_invalid_binary_format::corrupt_blocks_boundary(cryptonote::core& c, size_t ev_index, const std::vector<test_event_entry>& events)
{
  m_corrupt_blocks_begin_idx = ev_index + 1;
  return true;
}

bool gen_block_invalid_binary_format::check_all_blocks_purged(cryptonote::core& c, size_t ev_index, const std::vector<test_event_entry>& events)
{
  DEFINE_TESTS_ERROR_CONTEXT("gen_block_invalid_binary_format::check_all_blocks_purged");

  CHECK_EQ(1, c.get_pool_transactions_count());
  CHECK_EQ(m_corrupt_blocks_begin_idx - 2, c.get_current_blockchain_height());

  return true;
}

bool gen_block_late_v1_coinbase_tx::generate(std::vector<test_event_entry>& events) const
{
  BLOCK_VALIDATION_INIT_GENERATE();

  block blk_1;
  generator.construct_block_manually(blk_1, blk_0, miner_account,
      test_generator::bf_major_ver | test_generator::bf_minor_ver,
      HF_VERSION_MIN_V2_COINBASE_TX, HF_VERSION_MIN_V2_COINBASE_TX);
  events.push_back(blk_1);

  DO_CALLBACK(events, "check_block_purged");

  return true;
}

bool gen_block_low_coinbase::generate(std::vector<test_event_entry>& events) const
{
  BLOCK_VALIDATION_INIT_GENERATE();

  block blk_1;
  std::vector<size_t> block_weights;
  generator.construct_block(blk_1, cryptonote::get_block_height(blk_0) + 1, cryptonote::get_block_hash(blk_0),
    miner_account, blk_0.timestamp + DIFFICULTY_TARGET_V2, COIN + generator.get_already_generated_coins(cryptonote::get_block_hash(blk_0)),
    block_weights, {}, HF_VERSION_EXACT_COINBASE);
  events.push_back(blk_1);

  DO_CALLBACK(events, "check_block_purged");

  return true;
}

bool gen_block_miner_tx_out_has_no_view_tag_before_hf_view_tags::generate(std::vector<test_event_entry>& events) const
{
  bool use_view_tags = false;

  BLOCK_VALIDATION_INIT_GENERATE();

  MAKE_MINER_TX_MANUALLY(miner_tx, blk_0);

  CHECK_AND_ASSERT_MES(!cryptonote::get_output_view_tag(miner_tx.vout[0]), false, "output should not have a view tag");

  crypto::public_key output_public_key;
  crypto::view_tag view_tag;
  cryptonote::get_output_public_key(miner_tx.vout[0], output_public_key);

  // explicitly call the setter to ensure it does not set a view tag on the miner tx output
  cryptonote::set_tx_out(miner_tx.vout[0].amount, output_public_key, use_view_tags, view_tag, miner_tx.vout[0]);
  CHECK_AND_ASSERT_MES(!cryptonote::get_output_view_tag(miner_tx.vout[0]), false, "output should still not have a view tag");

  block blk_1;
  generator.construct_block_manually(blk_1, blk_0, miner_account, test_generator::bf_miner_tx, 0, 0, 0, crypto::hash(), 0, miner_tx);
  events.push_back(blk_1);

  DO_CALLBACK(events, "check_block_accepted");

  return true;
}

bool gen_block_miner_tx_out_has_no_view_tag_from_hf_view_tags::generate(std::vector<test_event_entry>& events) const
{
  bool use_view_tags = false;

  BLOCK_VALIDATION_INIT_GENERATE();

  keypair txkey;
  MAKE_MINER_TX_AND_KEY_AT_HF_MANUALLY(miner_tx, blk_0, HF_VERSION_VIEW_TAGS+1, &txkey);

  crypto::public_key output_public_key;
  crypto::view_tag view_tag;
  cryptonote::get_output_public_key(miner_tx.vout[0], output_public_key);

  // remove the view tag that is currently set on the miner tx output at this point
  cryptonote::set_tx_out(miner_tx.vout[0].amount, output_public_key, use_view_tags, view_tag, miner_tx.vout[0]);
  CHECK_AND_ASSERT_MES(!cryptonote::get_output_view_tag(miner_tx.vout[0]), false, "output should not have a view tag");

  block blk_1;
  generator.construct_block_manually(blk_1, blk_0, miner_account,
      test_generator::bf_major_ver | test_generator::bf_minor_ver | test_generator::bf_miner_tx,
      HF_VERSION_VIEW_TAGS+1, HF_VERSION_VIEW_TAGS+1, 0, crypto::hash(), 0, miner_tx);
  events.push_back(blk_1);

  DO_CALLBACK(events, "check_block_purged");

  return true;
}

bool gen_block_miner_tx_out_has_view_tag_before_hf_view_tags::generate(std::vector<test_event_entry>& events) const
{
  bool use_view_tags = true;

  BLOCK_VALIDATION_INIT_GENERATE();

  keypair txkey;
  MAKE_MINER_TX_AND_KEY_MANUALLY(miner_tx, blk_0, &txkey);

  // derive the view tag for the miner tx output
  crypto::key_derivation derivation;
  crypto::public_key output_public_key;
  crypto::view_tag view_tag;
  crypto::generate_key_derivation(miner_account.get_keys().m_account_address.m_view_public_key, txkey.sec, derivation);
  crypto::derive_public_key(derivation, 0, miner_account.get_keys().m_account_address.m_spend_public_key, output_public_key);
  crypto::derive_view_tag(derivation, 0, view_tag);

  // set the view tag on the miner tx output
  cryptonote::set_tx_out(miner_tx.vout[0].amount, output_public_key, use_view_tags, view_tag, miner_tx.vout[0]);
  boost::optional<crypto::view_tag> actual_vt = cryptonote::get_output_view_tag(miner_tx.vout[0]);
  CHECK_AND_ASSERT_MES(actual_vt && *actual_vt == view_tag, false, "unexpected output view tag");

  block blk_1;
  generator.construct_block_manually(blk_1, blk_0, miner_account, test_generator::bf_miner_tx, 0, 0, 0, crypto::hash(), 0, miner_tx);
  events.push_back(blk_1);

  DO_CALLBACK(events, "check_block_purged");

  return true;
}

bool gen_block_miner_tx_out_has_view_tag_from_hf_view_tags::generate(std::vector<test_event_entry>& events) const
{
  bool use_view_tags = true;

  BLOCK_VALIDATION_INIT_GENERATE();

  keypair txkey;
  MAKE_MINER_TX_AND_KEY_AT_HF_MANUALLY(miner_tx, blk_0, HF_VERSION_VIEW_TAGS, &txkey);

  CHECK_AND_ASSERT_MES(cryptonote::get_output_view_tag(miner_tx.vout[0]), false, "output should have a view tag");

  // derive the view tag for the miner tx output
  crypto::key_derivation derivation;
  crypto::public_key output_public_key;
  crypto::view_tag view_tag;
  crypto::generate_key_derivation(miner_account.get_keys().m_account_address.m_view_public_key, txkey.sec, derivation);
  crypto::derive_public_key(derivation, 0, miner_account.get_keys().m_account_address.m_spend_public_key, output_public_key);
  crypto::derive_view_tag(derivation, 0, view_tag);

  boost::optional<crypto::view_tag> actual_vt = cryptonote::get_output_view_tag(miner_tx.vout[0]);
  CHECK_AND_ASSERT_MES(actual_vt && *actual_vt == view_tag, false, "unexpected output view tag");

  // set the view tag on the miner tx output
  cryptonote::set_tx_out(miner_tx.vout[0].amount, output_public_key, use_view_tags, view_tag, miner_tx.vout[0]);
  boost::optional<crypto::view_tag> actual_vt_after_setting = cryptonote::get_output_view_tag(miner_tx.vout[0]);
  CHECK_AND_ASSERT_MES(actual_vt_after_setting && *actual_vt_after_setting == view_tag, false, "unexpected output view tag after setting");

  block blk_1;
  generator.construct_block_manually(blk_1, blk_0, miner_account,
      test_generator::bf_major_ver | test_generator::bf_minor_ver | test_generator::bf_miner_tx,
      HF_VERSION_VIEW_TAGS, HF_VERSION_VIEW_TAGS, 0, crypto::hash(), 0, miner_tx);
  events.push_back(blk_1);

  DO_CALLBACK(events, "check_block_accepted");

  return true;
}

bool gen_block_ts_equal_prev_before_strict::generate(std::vector<test_event_entry>& events) const
{
  BLOCK_VALIDATION_INIT_GENERATE();

  block blk_last, blk_1;
  CHECK_AND_ASSERT_MES(make_strict_ts_test_chain(events, generator, blk_last, blk_0, miner_account, 100, 10), false, "Failed to make chain");
  CHECK_AND_ASSERT_MES(make_strict_ts_test_block(generator, blk_1, blk_last, miner_account, 100, blk_last.timestamp), false, "Failed to make block");
  events.push_back(blk_1);

  DO_CALLBACK(events, "check_block_accepted");

  return true;
}

bool gen_block_ts_equal_prev_strict::generate(std::vector<test_event_entry>& events) const
{
  BLOCK_VALIDATION_INIT_GENERATE();

  block blk_last, blk_1;
  CHECK_AND_ASSERT_MES(make_strict_ts_test_chain(events, generator, blk_last, blk_0, miner_account, 3, 10), false, "Failed to make chain");
  CHECK_AND_ASSERT_MES(make_strict_ts_test_block(generator, blk_1, blk_last, miner_account, 3, blk_last.timestamp), false, "Failed to make block");
  events.push_back(blk_1);

  DO_CALLBACK(events, "check_block_purged");

  return true;
}

bool gen_block_ts_equal_median_before_strict::generate(std::vector<test_event_entry>& events) const
{
  BLOCK_VALIDATION_INIT_GENERATE();

  block blk_last, blk_1;
  CHECK_AND_ASSERT_MES(make_strict_ts_median_chain(events, generator, blk_last, blk_0, miner_account, 100), false, "Failed to make chain");
  CHECK_AND_ASSERT_MES(make_strict_ts_test_block(generator, blk_1, blk_last, miner_account, 100, median_of_last_timestamps(events)), false, "Failed to make block");
  events.push_back(blk_1);

  DO_CALLBACK(events, "check_block_accepted");

  return true;
}

bool gen_block_ts_equal_median_strict::generate(std::vector<test_event_entry>& events) const
{
  BLOCK_VALIDATION_INIT_GENERATE();

  block blk_last, blk_1;
  CHECK_AND_ASSERT_MES(make_strict_ts_median_chain(events, generator, blk_last, blk_0, miner_account, 70), false, "Failed to make chain");
  CHECK_AND_ASSERT_MES(make_strict_ts_test_block(generator, blk_1, blk_last, miner_account, 70, median_of_last_timestamps(events)), false, "Failed to make block");
  events.push_back(blk_1);

  DO_CALLBACK(events, "check_block_purged");

  return true;
}

bool gen_block_ts_above_median_strict::generate(std::vector<test_event_entry>& events) const
{
  BLOCK_VALIDATION_INIT_GENERATE();

  block blk_last, blk_1;
  CHECK_AND_ASSERT_MES(make_strict_ts_median_chain(events, generator, blk_last, blk_0, miner_account, 70), false, "Failed to make chain");
  CHECK_AND_ASSERT_MES(make_strict_ts_test_block(generator, blk_1, blk_last, miner_account, 70, median_of_last_timestamps(events) + 1), false, "Failed to make block");
  events.push_back(blk_1);

  DO_CALLBACK(events, "check_block_accepted");

  return true;
}

gen_block_ts_template_strict::gen_block_ts_template_strict()
{
  REGISTER_CALLBACK_METHOD(gen_block_ts_template_strict, check_templates);
}

bool gen_block_ts_template_strict::generate(std::vector<test_event_entry>& events) const
{
  BLOCK_VALIDATION_INIT_GENERATE();

  block blk_last;
  CHECK_AND_ASSERT_MES(make_strict_ts_test_chain(events, generator, blk_last, blk_0, miner_account, 2, 9), false, "Failed to make chain");
  const uint64_t future = time(NULL) + CRYPTONOTE_BLOCK_FUTURE_TIME_LIMIT / 2;
  for (size_t i = 0; i <= BLOCKCHAIN_TIMESTAMP_CHECK_WINDOW; ++i)
  {
    block blk;
    CHECK_AND_ASSERT_MES(make_strict_ts_test_block(generator, blk, blk_last, miner_account, 2, future + i), false, "Failed to make block");
    events.push_back(blk);
    blk_last = blk;
  }

  DO_CALLBACK(events, "check_templates");

  return true;
}

bool gen_block_ts_template_strict::check_templates(cryptonote::core& c, size_t ev_index, const std::vector<test_event_entry>& events)
{
  DEFINE_TESTS_ERROR_CONTEXT("gen_block_ts_template_strict::check_templates");

  account_base acc;
  acc.generate();
  const uint64_t height = c.get_current_blockchain_height();
  const block &tip = boost::get<block>(events[ev_index - 1]);
  const block &tip_parent = boost::get<block>(events[ev_index - 2]);

  block b;
  difficulty_type diffic;
  uint64_t h, expected_reward, cumulative_weight, seed_height;
  crypto::hash seed_hash;
  CHECK_TEST_CONDITION(c.get_block_template(b, acc.get_keys().m_account_address, diffic, h, expected_reward, cumulative_weight, blobdata(), seed_height, seed_hash));
  CHECK_EQ(b.timestamp, tip.timestamp + 1);
  CHECK_EQ(diffic, 1);

  block old_fallback = b;
  old_fallback.timestamp = median_of_last_timestamps(std::vector<test_event_entry>(events.begin() + ev_index - BLOCKCHAIN_TIMESTAMP_CHECK_WINDOW, events.begin() + ev_index));
  old_fallback.invalidate_hashes();
  block_verification_context bvc{};
  c.handle_block_found(old_fallback, bvc);
  CHECK_TEST_CONDITION(bvc.m_verifivation_failed);
  CHECK_EQ(height, c.get_current_blockchain_height());

  bvc = {};
  c.handle_block_found(b, bvc);
  CHECK_TEST_CONDITION(bvc.m_added_to_main_chain && !bvc.m_verifivation_failed);
  CHECK_EQ(height + 1, c.get_current_blockchain_height());

  const crypto::hash alt_parent = get_block_hash(tip_parent);
  block alt;
  CHECK_TEST_CONDITION(c.get_block_template(alt, &alt_parent, acc.get_keys().m_account_address, diffic, h, expected_reward, cumulative_weight, blobdata(), seed_height, seed_hash));
  CHECK_EQ(alt.timestamp, tip_parent.timestamp + 1);
  bvc = {};
  c.handle_block_found(alt, bvc);
  CHECK_TEST_CONDITION(!bvc.m_added_to_main_chain && !bvc.m_verifivation_failed);
  CHECK_EQ(height + 1, c.get_current_blockchain_height());
  CHECK_EQ(1, c.get_alternative_blocks_count());

  const crypto::hash alt_tip = get_block_hash(alt);
  block alt_child;
  CHECK_TEST_CONDITION(c.get_block_template(alt_child, &alt_tip, acc.get_keys().m_account_address, diffic, h, expected_reward, cumulative_weight, blobdata(), seed_height, seed_hash));
  CHECK_EQ(alt_child.timestamp, alt.timestamp + 1);
  bvc = {};
  c.handle_block_found(alt_child, bvc);
  CHECK_TEST_CONDITION(!bvc.m_added_to_main_chain && !bvc.m_verifivation_failed);
  CHECK_EQ(2, c.get_alternative_blocks_count());

  return true;
}

gen_block_ts_template_below_strict::gen_block_ts_template_below_strict()
{
  REGISTER_CALLBACK_METHOD(gen_block_ts_template_below_strict, check_template);
}

bool gen_block_ts_template_below_strict::generate(std::vector<test_event_entry>& events) const
{
  BLOCK_VALIDATION_INIT_GENERATE();

  block blk_last, blk_tip;
  CHECK_AND_ASSERT_MES(make_strict_ts_test_chain(events, generator, blk_last, blk_0, miner_account, 68, 69), false, "Failed to make chain");
  CHECK_AND_ASSERT_MES(make_strict_ts_test_block(generator, blk_tip, blk_last, miner_account, 68, time(NULL) + 600), false, "Failed to make block");
  events.push_back(blk_tip);

  DO_CALLBACK(events, "check_template");

  return true;
}

bool gen_block_ts_template_below_strict::check_template(cryptonote::core& c, size_t /*ev_index*/, const std::vector<test_event_entry>& events)
{
  DEFINE_TESTS_ERROR_CONTEXT("gen_block_ts_template_below_strict::check_template");

  account_base acc;
  acc.generate();
  block b;
  difficulty_type diffic;
  uint64_t h, expected_reward, cumulative_weight, seed_height;
  crypto::hash seed_hash;
  const uint64_t now = time(NULL);
  const crypto::hash parent = get_block_hash(boost::get<block>(events[64]));
  CHECK_TEST_CONDITION(c.get_block_template(b, &parent, acc.get_keys().m_account_address, diffic, h, expected_reward, cumulative_weight, blobdata(), seed_height, seed_hash));
  CHECK_TEST_CONDITION(b.major_version < HF_VERSION_STRICT_TIMESTAMPS);
  CHECK_TEST_CONDITION(b.timestamp >= now);
  block_verification_context bvc{};
  c.handle_block_found(b, bvc);
  CHECK_TEST_CONDITION(!bvc.m_added_to_main_chain && !bvc.m_verifivation_failed);
  CHECK_EQ(1, c.get_alternative_blocks_count());

  return true;
}

gen_block_ts_template_median_strict::gen_block_ts_template_median_strict()
{
  REGISTER_CALLBACK_METHOD(gen_block_ts_template_median_strict, check_templates);
}

bool gen_block_ts_template_median_strict::generate(std::vector<test_event_entry>& events) const
{
  BLOCK_VALIDATION_INIT_GENERATE();

  block blk_last = blk_0, blk_median;
  const uint64_t start = time(NULL) - 3010;
  for (uint64_t i = 1; i <= 68; ++i)
  {
    block blk;
    CHECK_AND_ASSERT_MES(make_strict_ts_test_block(generator, blk, blk_last, miner_account, 70, start + 150 * i), false, "Failed to make block");
    events.push_back(blk);
    blk_last = blk;
  }
  CHECK_AND_ASSERT_MES(make_strict_ts_test_block(generator, blk_median, blk_last, miner_account, 70, median_of_last_timestamps(events)), false, "Failed to make block");
  events.push_back(blk_median);

  DO_CALLBACK(events, "check_templates");

  return true;
}

bool gen_block_ts_template_median_strict::check_templates(cryptonote::core& c, size_t ev_index, const std::vector<test_event_entry>& events)
{
  DEFINE_TESTS_ERROR_CONTEXT("gen_block_ts_template_median_strict::check_templates");

  const block &tip = boost::get<block>(events[ev_index - 1]);
  const uint64_t median = median_of_last_timestamps(std::vector<test_event_entry>(events.begin() + ev_index - BLOCKCHAIN_TIMESTAMP_CHECK_WINDOW, events.begin() + ev_index));
  CHECK_TEST_CONDITION(median > tip.timestamp && median > (uint64_t)time(NULL));

  account_base acc;
  acc.generate();
  difficulty_type diffic;
  uint64_t h, expected_reward, cumulative_weight, seed_height;
  crypto::hash seed_hash;
  const crypto::hash tip_id = get_block_hash(tip);
  block alt, b;
  CHECK_TEST_CONDITION(c.get_block_template(alt, &tip_id, acc.get_keys().m_account_address, diffic, h, expected_reward, cumulative_weight, blobdata(), seed_height, seed_hash));
  CHECK_EQ(alt.timestamp, median + 1);
  CHECK_TEST_CONDITION(c.get_block_template(b, acc.get_keys().m_account_address, diffic, h, expected_reward, cumulative_weight, blobdata(), seed_height, seed_hash));
  CHECK_EQ(b.timestamp, median + 1);
  block_verification_context bvc{};
  c.handle_block_found(b, bvc);
  CHECK_TEST_CONDITION(bvc.m_added_to_main_chain && !bvc.m_verifivation_failed);

  return true;
}

gen_block_ts_template_alt_before_strict::gen_block_ts_template_alt_before_strict()
{
  REGISTER_CALLBACK_METHOD(gen_block_ts_template_alt_before_strict, check_template);
}

bool gen_block_ts_template_alt_before_strict::generate(std::vector<test_event_entry>& events) const
{
  BLOCK_VALIDATION_INIT_GENERATE();

  block blk_last;
  CHECK_AND_ASSERT_MES(make_strict_ts_test_chain(events, generator, blk_last, blk_0, miner_account, 100000, 100), false, "Failed to make chain");
  const uint64_t future = time(NULL) + CRYPTONOTE_BLOCK_FUTURE_TIME_LIMIT / 2;
  blk_last = boost::get<block>(events[50]);
  for (uint64_t i = 0; i < 35; ++i)
  {
    block blk;
    CHECK_AND_ASSERT_MES(make_strict_ts_test_block(generator, blk, blk_last, miner_account, 100000, future + i), false, "Failed to make block");
    events.push_back(blk);
    blk_last = blk;
  }

  DO_CALLBACK(events, "check_template");

  return true;
}

bool gen_block_ts_template_alt_before_strict::check_template(cryptonote::core& c, size_t ev_index, const std::vector<test_event_entry>& events)
{
  DEFINE_TESTS_ERROR_CONTEXT("gen_block_ts_template_alt_before_strict::check_template");

  CHECK_EQ(35, c.get_alternative_blocks_count());
  account_base acc;
  acc.generate();
  block b;
  difficulty_type diffic;
  uint64_t h, expected_reward, cumulative_weight, seed_height;
  crypto::hash seed_hash;
  const crypto::hash alt_tip = get_block_hash(boost::get<block>(events[ev_index - 1]));
  CHECK_TEST_CONDITION(c.get_block_template(b, &alt_tip, acc.get_keys().m_account_address, diffic, h, expected_reward, cumulative_weight, blobdata(), seed_height, seed_hash));
  CHECK_TEST_CONDITION(b.major_version < HF_VERSION_STRICT_TIMESTAMPS);
  block_verification_context bvc{};
  c.handle_block_found(b, bvc);
  CHECK_TEST_CONDITION(!bvc.m_added_to_main_chain && !bvc.m_verifivation_failed);
  CHECK_EQ(36, c.get_alternative_blocks_count());

  return true;
}

static bool make_strict_ts_alt_prev_events(std::vector<test_event_entry>& events, test_generator& generator, const block& blk_0,
                                           const account_base& miner_account, uint64_t strict_height)
{
  block blk_last, blk_tip, blk_alt;
  if (!make_strict_ts_test_chain(events, generator, blk_last, blk_0, miner_account, strict_height, 10))
    return false;
  if (!make_strict_ts_test_block(generator, blk_tip, blk_last, miner_account, strict_height, blk_last.timestamp + 2 * DIFFICULTY_TARGET_V2))
    return false;
  events.push_back(blk_tip);
  if (!make_strict_ts_test_block(generator, blk_alt, blk_last, miner_account, strict_height, blk_last.timestamp))
    return false;
  events.push_back(blk_alt);
  return true;
}

static bool make_strict_ts_alt_median_events(std::vector<test_event_entry>& events, test_generator& generator, const block& blk_0,
                                             const account_base& miner_account, uint64_t strict_height)
{
  block blk_last, blk_tip, blk_alt;
  if (!make_strict_ts_median_chain(events, generator, blk_last, blk_0, miner_account, strict_height))
    return false;
  const uint64_t median = median_of_last_timestamps(events);
  if (!make_strict_ts_test_block(generator, blk_tip, blk_last, miner_account, strict_height, blk_last.timestamp + 2 * DIFFICULTY_TARGET_V2))
    return false;
  events.push_back(blk_tip);
  if (!make_strict_ts_test_block(generator, blk_alt, blk_last, miner_account, strict_height, median))
    return false;
  events.push_back(blk_alt);
  return true;
}

bool gen_block_ts_alt_equal_prev_before_strict::generate(std::vector<test_event_entry>& events) const
{
  BLOCK_VALIDATION_INIT_GENERATE();
  CHECK_AND_ASSERT_MES(make_strict_ts_alt_prev_events(events, generator, blk_0, miner_account, 100), false, "Failed to make events");
  DO_CALLBACK(events, "check_alt");
  return true;
}

bool gen_block_ts_alt_equal_prev_strict::generate(std::vector<test_event_entry>& events) const
{
  BLOCK_VALIDATION_INIT_GENERATE();
  CHECK_AND_ASSERT_MES(make_strict_ts_alt_prev_events(events, generator, blk_0, miner_account, 3), false, "Failed to make events");
  DO_CALLBACK(events, "check_alt");
  return true;
}

bool gen_block_ts_alt_equal_median_before_strict::generate(std::vector<test_event_entry>& events) const
{
  BLOCK_VALIDATION_INIT_GENERATE();
  CHECK_AND_ASSERT_MES(make_strict_ts_alt_median_events(events, generator, blk_0, miner_account, 100), false, "Failed to make events");
  DO_CALLBACK(events, "check_alt");
  return true;
}

bool gen_block_ts_alt_equal_median_strict::generate(std::vector<test_event_entry>& events) const
{
  BLOCK_VALIDATION_INIT_GENERATE();
  CHECK_AND_ASSERT_MES(make_strict_ts_alt_median_events(events, generator, blk_0, miner_account, 70), false, "Failed to make events");
  DO_CALLBACK(events, "check_alt");
  return true;
}

gen_block_ts_alt_chain_equal_prev_strict::gen_block_ts_alt_chain_equal_prev_strict()
{
  REGISTER_CALLBACK_METHOD(gen_block_ts_alt_chain_equal_prev_strict, check_alt_chain);
}

bool gen_block_ts_alt_chain_equal_prev_strict::generate(std::vector<test_event_entry>& events) const
{
  BLOCK_VALIDATION_INIT_GENERATE();

  block blk_last, blk_alt_1, blk_alt_2, blk_alt_3;
  CHECK_AND_ASSERT_MES(make_strict_ts_test_chain(events, generator, blk_last, blk_0, miner_account, 3, 13), false, "Failed to make chain");
  const block blk_fork = boost::get<block>(events[10]);
  CHECK_AND_ASSERT_MES(make_strict_ts_test_block(generator, blk_alt_1, blk_fork, miner_account, 3, blk_fork.timestamp + 1), false, "Failed to make block");
  events.push_back(blk_alt_1);
  CHECK_AND_ASSERT_MES(make_strict_ts_test_block(generator, blk_alt_2, blk_alt_1, miner_account, 3, blk_alt_1.timestamp + 1), false, "Failed to make block");
  events.push_back(blk_alt_2);
  CHECK_AND_ASSERT_MES(make_strict_ts_test_block(generator, blk_alt_3, blk_alt_2, miner_account, 3, blk_alt_2.timestamp), false, "Failed to make block");
  events.push_back(blk_alt_3);

  DO_CALLBACK(events, "check_alt_chain");

  return true;
}

bool gen_block_ts_alt_chain_equal_prev_strict::check_block_verification_context(const cryptonote::block_verification_context& bvc, size_t event_idx, const cryptonote::block& /*blk*/)
{
  if (event_idx == 16)
    return bvc.m_verifivation_failed;
  if (event_idx >= 14)
    return !bvc.m_verifivation_failed && !bvc.m_added_to_main_chain;
  return !bvc.m_verifivation_failed;
}

bool gen_block_ts_alt_chain_equal_prev_strict::check_alt_chain(cryptonote::core& c, size_t /*ev_index*/, const std::vector<test_event_entry>& /*events*/)
{
  DEFINE_TESTS_ERROR_CONTEXT("gen_block_ts_alt_chain_equal_prev_strict::check_alt_chain");

  CHECK_EQ(14, c.get_current_blockchain_height());
  CHECK_EQ(2, c.get_alternative_blocks_count());

  return true;
}

gen_block_difficulty_span_floor::gen_block_difficulty_span_floor()
{
  REGISTER_CALLBACK_METHOD(gen_block_difficulty_span_floor, check_difficulties);
}

bool gen_block_difficulty_span_floor::generate(std::vector<test_event_entry>& events) const
{
  BLOCK_VALIDATION_INIT_GENERATE();
  generator.set_events(&events);

  std::vector<uint64_t> timestamps{blk_0.timestamp};
  std::vector<difficulty_type> cumulative_difficulties{1};
  block blk_last = blk_0;
  const auto add_block = [&](uint64_t timestamp)
  {
    const bool span_floor = strict_ts_test_version(timestamps.size(), 22) >= HF_VERSION_DIFFICULTY_SPAN_FLOOR;
    const difficulty_type diffic = expected_difficulty(timestamps, cumulative_difficulties, span_floor);
    block blk;
    if (!make_strict_ts_test_block(generator, blk, blk_last, miner_account, 22, timestamp, diffic))
      return false;
    events.push_back(blk);
    timestamps.push_back(timestamp);
    cumulative_difficulties.push_back(cumulative_difficulties.back() + diffic);
    blk_last = blk;
    return true;
  };

  for (uint64_t height = 1; height <= 31; ++height)
    CHECK_AND_ASSERT_MES(add_block(blk_last.timestamp + (height <= 5 ? DIFFICULTY_TARGET_V2 : 1)), false, "Failed to make block");

  blk_last = boost::get<block>(events[28]);
  timestamps.resize(29);
  cumulative_difficulties.resize(29);
  for (uint64_t height = 29; height <= 32; ++height)
    CHECK_AND_ASSERT_MES(add_block(blk_last.timestamp + 2), false, "Failed to make block");

  DO_CALLBACK(events, "check_difficulties");

  return true;
}

bool gen_block_difficulty_span_floor::check_difficulties(cryptonote::core& c, size_t ev_index, const std::vector<test_event_entry>& events)
{
  DEFINE_TESTS_ERROR_CONTEXT("gen_block_difficulty_span_floor::check_difficulties");

  Blockchain& bc = c.get_blockchain_storage();
  const uint64_t height = c.get_current_blockchain_height();
  CHECK_EQ(height, 33);
  CHECK_EQ(c.get_tail_id(), get_block_hash(boost::get<block>(events[ev_index - 1])));
  CHECK_EQ(c.get_alternative_blocks_count(), 3);

  account_base acc;
  acc.generate();
  block b;
  difficulty_type diffic;
  uint64_t h, expected_reward, cumulative_weight, seed_height;
  crypto::hash seed_hash;

  std::vector<uint64_t> timestamps;
  std::vector<difficulty_type> cumulative_difficulties;
  size_t floor_binds_before = 0, floor_binds_from = 0;
  for (uint64_t i = 0; i <= height; ++i)
  {
    difficulty_type expected = 1;
    if (i > 0)
    {
      const bool span_floor = strict_ts_test_version(i, 22) >= HF_VERSION_DIFFICULTY_SPAN_FLOOR;
      expected = expected_difficulty(timestamps, cumulative_difficulties, span_floor);
      if (expected != expected_difficulty(timestamps, cumulative_difficulties, !span_floor))
        ++(span_floor ? floor_binds_from : floor_binds_before);
      const crypto::hash parent = c.get_block_id_by_height(i - 1);
      CHECK_TEST_CONDITION(c.get_block_template(b, &parent, acc.get_keys().m_account_address, diffic, h, expected_reward, cumulative_weight, blobdata(), seed_height, seed_hash));
      CHECK_EQ(diffic, expected);
    }
    if (i == height)
      break;
    cumulative_difficulties.push_back((i > 0 ? cumulative_difficulties.back() : 0) + expected);
    CHECK_EQ(bc.get_db().get_block_cumulative_difficulty(i), cumulative_difficulties.back());
    timestamps.push_back(bc.get_db().get_block_timestamp(i));
  }
  CHECK_TEST_CONDITION(floor_binds_before > 0 && floor_binds_from > 0);

  std::vector<uint64_t> alt_timestamps(timestamps.begin(), timestamps.begin() + 29);
  std::vector<difficulty_type> alt_cumulative_difficulties(cumulative_difficulties.begin(), cumulative_difficulties.begin() + 29);
  for (uint64_t i = 29; i <= 31; ++i)
  {
    const bool span_floor = strict_ts_test_version(i, 22) >= HF_VERSION_DIFFICULTY_SPAN_FLOOR;
    alt_cumulative_difficulties.push_back(alt_cumulative_difficulties.back() + expected_difficulty(alt_timestamps, alt_cumulative_difficulties, span_floor));
    alt_timestamps.push_back(boost::get<block>(events[i]).timestamp);
  }
  const crypto::hash alt_tip = get_block_hash(boost::get<block>(events[31]));
  CHECK_TEST_CONDITION(c.get_block_template(b, &alt_tip, acc.get_keys().m_account_address, diffic, h, expected_reward, cumulative_weight, blobdata(), seed_height, seed_hash));
  CHECK_EQ(diffic, expected_difficulty(alt_timestamps, alt_cumulative_difficulties, strict_ts_test_version(32, 22) >= HF_VERSION_DIFFICULTY_SPAN_FLOOR));

  size_t corrected = bc.recalculate_difficulties(1);
  CHECK_EQ(corrected, 0);
  std::vector<difficulty_type> wrong(cumulative_difficulties.begin() + 20, cumulative_difficulties.end());
  for (difficulty_type &d: wrong)
    ++d;
  bc.get_db().correct_block_cumulative_difficulties(20, wrong);
  corrected = bc.recalculate_difficulties(1);
  CHECK_EQ(corrected, height - 20);
  for (uint64_t i = 0; i < height; ++i)
    CHECK_EQ(bc.get_db().get_block_cumulative_difficulty(i), cumulative_difficulties[i]);

  return true;
}

static bool make_strict_ts_alt_window_events(std::vector<test_event_entry>& events, test_generator& generator, const block& blk_0,
                                             const account_base& miner_account, uint64_t strict_height)
{
  block blk_last;
  if (!make_strict_ts_test_chain(events, generator, blk_last, blk_0, miner_account, strict_height, 64))
    return false;
  blk_last = boost::get<block>(events[1]);
  std::vector<uint64_t> timestamps;
  for (size_t i = 1; i <= BLOCKCHAIN_TIMESTAMP_CHECK_WINDOW; ++i)
    timestamps.push_back(blk_last.timestamp + 2 * DIFFICULTY_TARGET_V2 * i + (i > BLOCKCHAIN_TIMESTAMP_CHECK_WINDOW / 2 ? 86400 : 0));
  std::vector<uint64_t> sorted = timestamps;
  const uint64_t median_all = epee::misc_utils::median(sorted);
  timestamps.push_back(median_all);
  for (const uint64_t timestamp: timestamps)
  {
    block blk;
    if (!make_strict_ts_test_block(generator, blk, blk_last, miner_account, strict_height, timestamp))
      return false;
    events.push_back(blk);
    blk_last = blk;
  }
  sorted.assign(timestamps.begin() + 1, timestamps.end());
  const uint64_t median_newest = epee::misc_utils::median(sorted);
  if (median_newest <= median_all + 1)
    return false;
  block blk_test, blk_ok;
  if (!make_strict_ts_test_block(generator, blk_test, blk_last, miner_account, strict_height, median_all + 1))
    return false;
  events.push_back(blk_test);
  if (!make_strict_ts_test_block(generator, blk_ok, blk_last, miner_account, strict_height, median_newest + 1))
    return false;
  events.push_back(blk_ok);
  return true;
}

bool gen_block_ts_alt_window_before_strict::generate(std::vector<test_event_entry>& events) const
{
  BLOCK_VALIDATION_INIT_GENERATE();
  CHECK_AND_ASSERT_MES(make_strict_ts_alt_window_events(events, generator, blk_0, miner_account, 100), false, "Failed to make events");
  DO_CALLBACK(events, "check_alt_window");
  return true;
}

bool gen_block_ts_alt_window_strict::generate(std::vector<test_event_entry>& events) const
{
  BLOCK_VALIDATION_INIT_GENERATE();
  CHECK_AND_ASSERT_MES(make_strict_ts_alt_window_events(events, generator, blk_0, miner_account, 63), false, "Failed to make events");
  DO_CALLBACK(events, "check_alt_window");
  return true;
}

template<uint64_t strict_height, bool median_chain>
gen_block_ts_miner_data_base<strict_height, median_chain>::gen_block_ts_miner_data_base()
{
  REGISTER_CALLBACK_METHOD(gen_block_ts_miner_data_base, check_miner_data);
}

template<uint64_t strict_height, bool median_chain>
bool gen_block_ts_miner_data_base<strict_height, median_chain>::generate(std::vector<test_event_entry>& events) const
{
  BLOCK_VALIDATION_INIT_GENERATE();

  block blk_last;
  if (median_chain)
    CHECK_AND_ASSERT_MES(make_strict_ts_median_chain(events, generator, blk_last, blk_0, miner_account, strict_height), false, "Failed to make chain");
  else
    CHECK_AND_ASSERT_MES(make_strict_ts_test_chain(events, generator, blk_last, blk_0, miner_account, strict_height, 70), false, "Failed to make chain");

  DO_CALLBACK(events, "check_miner_data");

  return true;
}

template<uint64_t strict_height, bool median_chain>
bool gen_block_ts_miner_data_base<strict_height, median_chain>::check_miner_data(cryptonote::core& c, size_t ev_index, const std::vector<test_event_entry>& events)
{
  DEFINE_TESTS_ERROR_CONTEXT("gen_block_ts_miner_data_base::check_miner_data");

  uint8_t major_version;
  uint64_t height, median_weight, already_generated_coins, min_timestamp;
  crypto::hash prev_id, seed_hash;
  difficulty_type diffic;
  std::vector<tx_block_template_backlog_entry> tx_backlog;
  CHECK_TEST_CONDITION(c.get_miner_data(major_version, height, prev_id, seed_hash, diffic, median_weight, already_generated_coins, min_timestamp, tx_backlog));
  const uint64_t median = median_of_last_timestamps(std::vector<test_event_entry>(events.begin() + ev_index - BLOCKCHAIN_TIMESTAMP_CHECK_WINDOW, events.begin() + ev_index));
  const uint64_t parent = boost::get<block>(events[ev_index - 1]).timestamp;
  const bool strict = height >= strict_height;
  CHECK_EQ(min_timestamp, (strict ? std::max(parent, median) + 1 : median));

  account_base acc;
  acc.generate();
  block b;
  uint64_t h, expected_reward, cumulative_weight, seed_height;
  CHECK_TEST_CONDITION(c.get_block_template(b, acc.get_keys().m_account_address, diffic, h, expected_reward, cumulative_weight, blobdata(), seed_height, seed_hash));
  block_verification_context bvc{};
  b.timestamp = min_timestamp - 1;
  b.invalidate_hashes();
  c.handle_block_found(b, bvc);
  CHECK_TEST_CONDITION(bvc.m_verifivation_failed);
  bvc = {};
  b.timestamp = min_timestamp;
  b.invalidate_hashes();
  const auto notified_min_timestamp = std::make_shared<uint64_t>(0);
  c.get_blockchain_storage().add_miner_notify([notified_min_timestamp](uint8_t, uint64_t, const crypto::hash&, const crypto::hash&, difficulty_type, uint64_t, uint64_t, uint64_t notified, const std::vector<tx_block_template_backlog_entry>&)
  {
    *notified_min_timestamp = notified;
  });
  c.handle_block_found(b, bvc);
  CHECK_TEST_CONDITION(bvc.m_added_to_main_chain && !bvc.m_verifivation_failed);
  CHECK_TEST_CONDITION(c.get_miner_data(major_version, height, prev_id, seed_hash, diffic, median_weight, already_generated_coins, min_timestamp, tx_backlog));
  CHECK_EQ(*notified_min_timestamp, min_timestamp);

  return true;
}

template struct gen_block_ts_miner_data_base<100, true>;
template struct gen_block_ts_miner_data_base<70, true>;
template struct gen_block_ts_miner_data_base<2, false>;

gen_block_ts_future_flag::gen_block_ts_future_flag()
{
  REGISTER_CALLBACK_METHOD(gen_block_ts_future_flag, check_future_flags);
}

bool gen_block_ts_future_flag::generate(std::vector<test_event_entry>& events) const
{
  BLOCK_VALIDATION_INIT_GENERATE();

  difficulty_type diffic;
  CHECK_AND_ASSERT_MES(make_future_test_chain(events, generator, blk_0, miner_account, 1, diffic), false, "Failed to make chain");
  CHECK_AND_ASSERT_MES(diffic > 1, false, "Difficulty too low for an invalid proof of work");
  const block blk_1 = boost::get<block>(events.back());

  const auto add_block = [&](uint64_t timestamp, bool bad_pow)
  {
    block blk;
    do
    {
      blk = block();
      if (!generator.construct_block_manually(blk, blk_1, miner_account, test_generator::bf_diffic | test_generator::bf_timestamp, 0, 0, timestamp++, crypto::hash(), diffic))
        return false;
    }
    while (bad_pow && blk.nonce == 0);
    if (bad_pow)
    {
      --blk.nonce;
      blk.invalidate_hashes();
    }
    events.push_back(blk);
    return true;
  };

  const uint64_t future = time(NULL) + 60*60 + CRYPTONOTE_BLOCK_FUTURE_TIME_LIMIT;
  const uint64_t far_future = time(NULL) + 60*60 + 2 * CRYPTONOTE_BLOCK_FUTURE_TIME_LIMIT;
  CHECK_AND_ASSERT_MES(add_block(future, false), false, "Failed to make block");
  const block blk_future = boost::get<block>(events.back());
  CHECK_AND_ASSERT_MES(add_block(future, true), false, "Failed to make block");
  events.push_back(events.back());
  CHECK_AND_ASSERT_MES(add_block(boost::get<block>(events[BLOCKCHAIN_TIMESTAMP_CHECK_WINDOW / 2 - 1]).timestamp, false), false, "Failed to make block");
  CHECK_AND_ASSERT_MES(add_block(far_future, false), false, "Failed to make block");
  CHECK_AND_ASSERT_MES(add_block(far_future, true), false, "Failed to make block");
  events.push_back(blk_future);
  CHECK_AND_ASSERT_MES(add_block(blk_1.timestamp + DIFFICULTY_TARGET_V1, false), false, "Failed to make block");
  CHECK_AND_ASSERT_MES(add_block(future, false), false, "Failed to make block");
  const block blk_alt_future = boost::get<block>(events.back());
  CHECK_AND_ASSERT_MES(add_block(future, true), false, "Failed to make block");
  events.push_back(events.back());
  CHECK_AND_ASSERT_MES(add_block(far_future, false), false, "Failed to make block");
  events.push_back(blk_alt_future);

  DO_CALLBACK(events, "check_future_flags");

  return true;
}

bool gen_block_ts_future_flag::check_block_verification_context(const cryptonote::block_verification_context& bvc, size_t event_idx, const cryptonote::block& /*blk*/)
{
  switch (event_idx)
  {
    case BLOCKCHAIN_TIMESTAMP_CHECK_WINDOW + 1:
    case BLOCKCHAIN_TIMESTAMP_CHECK_WINDOW + 7:
    case BLOCKCHAIN_TIMESTAMP_CHECK_WINDOW + 9:
    case BLOCKCHAIN_TIMESTAMP_CHECK_WINDOW + 13:
      return bvc.m_verifivation_failed && bvc.m_future_timestamp && !bvc.m_bad_pow;
    case BLOCKCHAIN_TIMESTAMP_CHECK_WINDOW + 2:
    case BLOCKCHAIN_TIMESTAMP_CHECK_WINDOW + 3:
    case BLOCKCHAIN_TIMESTAMP_CHECK_WINDOW + 10:
    case BLOCKCHAIN_TIMESTAMP_CHECK_WINDOW + 11:
      return bvc.m_verifivation_failed && !bvc.m_future_timestamp && bvc.m_bad_pow;
    case BLOCKCHAIN_TIMESTAMP_CHECK_WINDOW + 4:
    case BLOCKCHAIN_TIMESTAMP_CHECK_WINDOW + 5:
    case BLOCKCHAIN_TIMESTAMP_CHECK_WINDOW + 6:
    case BLOCKCHAIN_TIMESTAMP_CHECK_WINDOW + 12:
      return bvc.m_verifivation_failed && !bvc.m_future_timestamp && !bvc.m_bad_pow;
    default:
      return !bvc.m_verifivation_failed && !bvc.m_future_timestamp;
  }
}

bool gen_block_ts_future_flag::check_future_flags(cryptonote::core& c, size_t /*ev_index*/, const std::vector<test_event_entry>& /*events*/)
{
  DEFINE_TESTS_ERROR_CONTEXT("gen_block_ts_future_flag::check_future_flags");

  CHECK_EQ(BLOCKCHAIN_TIMESTAMP_CHECK_WINDOW + 2, c.get_current_blockchain_height());
  CHECK_EQ(0, c.get_alternative_blocks_count());
  CHECK_EQ(0, c.get_pool_transactions_count());

  return true;
}

gen_block_ts_future_cache::gen_block_ts_future_cache()
{
  REGISTER_CALLBACK_METHOD(gen_block_ts_future_cache, wait_for_expiry);
  REGISTER_CALLBACK_METHOD(gen_block_ts_future_cache, check_future_cache);
}

bool gen_block_ts_future_cache::generate(std::vector<test_event_entry>& events) const
{
  BLOCK_VALIDATION_INIT_GENERATE();

  const auto make_block = [&](uint64_t timestamp)
  {
    block blk;
    if (!generator.construct_block_manually(blk, blk_0, miner_account, test_generator::bf_timestamp, 0, 0, timestamp))
      throw std::runtime_error("Failed to make block");
    return blk;
  };

  const uint64_t limit = time(NULL) + CRYPTONOTE_BLOCK_FUTURE_TIME_LIMIT;
  events.push_back(make_block(limit + 60));
  for (uint64_t i = 1; i < CRYPTONOTE_FUTURE_BLOCKS_MAX_COUNT; ++i)
    events.push_back(make_block(limit + 1800 + i));
  const block blk_more = make_block(limit + 1800 + CRYPTONOTE_FUTURE_BLOCKS_MAX_COUNT);
  events.push_back(blk_more);
  events.push_back(events[2]);
  DO_CALLBACK(events, "wait_for_expiry");
  events.push_back(events[1]);
  events.push_back(make_block(limit + 1800 + CRYPTONOTE_FUTURE_BLOCKS_MAX_COUNT + 1));
  events.push_back(blk_more);
  DO_CALLBACK(events, "check_future_cache");

  return true;
}

bool gen_block_ts_future_cache::check_block_verification_context(const cryptonote::block_verification_context& bvc, size_t event_idx, const cryptonote::block& /*blk*/)
{
  if (event_idx == 0)
    return !bvc.m_verifivation_failed;
  if (event_idx == CRYPTONOTE_FUTURE_BLOCKS_MAX_COUNT + 4)
    return !bvc.m_verifivation_failed && bvc.m_added_to_main_chain;
  const bool remembered = event_idx <= CRYPTONOTE_FUTURE_BLOCKS_MAX_COUNT + 5 && event_idx != CRYPTONOTE_FUTURE_BLOCKS_MAX_COUNT + 1;
  return bvc.m_verifivation_failed && !bvc.m_bad_pow && bvc.m_future_timestamp == remembered;
}

bool gen_block_ts_future_cache::wait_for_expiry(cryptonote::core& /*c*/, size_t /*ev_index*/, const std::vector<test_event_entry>& events)
{
  const uint64_t timestamp = boost::get<block>(events[1]).timestamp;
  while (timestamp > (uint64_t)time(NULL) + CRYPTONOTE_BLOCK_FUTURE_TIME_LIMIT)
    std::this_thread::sleep_for(std::chrono::seconds(1));
  return true;
}

bool gen_block_ts_future_cache::check_future_cache(cryptonote::core& c, size_t /*ev_index*/, const std::vector<test_event_entry>& /*events*/)
{
  DEFINE_TESTS_ERROR_CONTEXT("gen_block_ts_future_cache::check_future_cache");

  CHECK_EQ(2, c.get_current_blockchain_height());
  CHECK_EQ(0, c.get_alternative_blocks_count());

  return true;
}

bool gen_block_ts_future_low_difficulty_alt::generate(std::vector<test_event_entry>& events) const
{
  BLOCK_VALIDATION_INIT_GENERATE();

  difficulty_type diffic;
  CHECK_AND_ASSERT_MES(make_future_test_chain(events, generator, blk_0, miner_account, 50, diffic), false, "Failed to make chain");
  CHECK_AND_ASSERT_MES(diffic / CRYPTONOTE_FUTURE_BLOCKS_MIN_DIFFICULTY_DIVISOR > 1, false, "Difficulty too low");
  block blk_alt;
  CHECK_AND_ASSERT_MES(generator.construct_block_manually(blk_alt, blk_0, miner_account, test_generator::bf_timestamp, 0, 0,
    time(NULL) + 60*60 + CRYPTONOTE_BLOCK_FUTURE_TIME_LIMIT), false, "Failed to make block");
  events.push_back(blk_alt);

  return true;
}

bool gen_block_ts_future_low_difficulty_alt::check_block_verification_context(const cryptonote::block_verification_context& bvc, size_t event_idx, const cryptonote::block& /*blk*/)
{
  if (event_idx == BLOCKCHAIN_TIMESTAMP_CHECK_WINDOW + 50)
    return bvc.m_verifivation_failed && !bvc.m_future_timestamp && !bvc.m_bad_pow;
  return !bvc.m_verifivation_failed;
}
