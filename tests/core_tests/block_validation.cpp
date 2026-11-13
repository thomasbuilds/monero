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

namespace
{
  const uint64_t first_strict_ts_slack = CRYPTONOTE_BLOCK_FUTURE_TIME_LIMIT - CRYPTONOTE_BLOCK_FUTURE_TIME_LIMIT_V17;

  bool make_strict_ts_test_block(test_generator& generator, block& blk, const block& prev, const account_base& miner_account,
                                 uint64_t strict_height, uint64_t timestamp, const difficulty_type& diffic = 1)
  {
    const uint8_t version = get_block_height(prev) + 1 >= strict_height ? HF_VERSION_STRICT_TIMESTAMPS : HF_VERSION_STRICT_TIMESTAMPS - 1;
    return generator.construct_block_manually(blk, prev, miner_account,
      test_generator::bf_major_ver | test_generator::bf_minor_ver | test_generator::bf_timestamp | test_generator::bf_diffic | test_generator::bf_hf_version,
      version, version, timestamp, crypto::hash(), diffic, transaction(), std::vector<crypto::hash>(), 0, 0, version);
  }

  // n blocks on top of blk_last, `step` seconds apart, the last one stamped `last`
  bool make_strict_ts_test_chain(std::vector<test_event_entry>& events, test_generator& generator, block& blk_last, const account_base& miner_account,
                                 uint64_t strict_height, size_t n, uint64_t last, uint64_t step)
  {
    for (size_t i = 1; i <= n; ++i)
    {
      block blk;
      if (!make_strict_ts_test_block(generator, blk, blk_last, miner_account, strict_height, last - step * (n - i)))
        return false;
      events.push_back(blk);
      blk_last = blk;
    }
    return true;
  }

  // median of the timestamps of the BLOCKCHAIN_TIMESTAMP_CHECK_WINDOW blocks before events[end]
  uint64_t median_timestamp(const std::vector<test_event_entry>& events, size_t end)
  {
    std::vector<uint64_t> timestamps;
    for (size_t i = end - BLOCKCHAIN_TIMESTAMP_CHECK_WINDOW; i < end; ++i)
      timestamps.push_back(boost::get<block>(events[i]).timestamp);
    return epee::misc_utils::median(timestamps);
  }

  // 10 blocks, or 69 blocks the last of which is stamped below the median of the last BLOCKCHAIN_TIMESTAMP_CHECK_WINDOW
  bool make_strict_ts_base_chain(std::vector<test_event_entry>& events, test_generator& generator, block& blk_last, const account_base& miner_account,
                                 uint64_t strict_height, bool median_chain)
  {
    const size_t n = median_chain ? 68 : 10;
    if (!make_strict_ts_test_chain(events, generator, blk_last, miner_account, strict_height, n, blk_last.timestamp + 2 * DIFFICULTY_TARGET_V2 * n, 2 * DIFFICULTY_TARGET_V2))
      return false;
    if (!median_chain)
      return true;
    if (!make_strict_ts_test_chain(events, generator, blk_last, miner_account, strict_height, 1, median_timestamp(events, events.size()), 0))
      return false;
    return median_timestamp(events, events.size()) > blk_last.timestamp;
  }

  // timestamp of the block under test, from its parent and the median of the last BLOCKCHAIN_TIMESTAMP_CHECK_WINDOW
  typedef uint64_t strict_ts_choice(const block& parent, uint64_t median);
  uint64_t ts_equal_prev(const block& parent, uint64_t) { return parent.timestamp; }
  uint64_t ts_future(const block&, uint64_t) { return time(NULL) + 2 * CRYPTONOTE_BLOCK_FUTURE_TIME_LIMIT_V17; }
  uint64_t ts_median(const block&, uint64_t median) { return median; }
  uint64_t ts_first_strict_min(const block&, uint64_t median) { return median - first_strict_ts_slack; }
  uint64_t ts_below_first_strict_min(const block&, uint64_t median) { return median - first_strict_ts_slack - 1; }

#define STRICT_TS_INIT_GENERATE() \
  GENERATE_ACCOUNT(miner_account); \
  MAKE_GENESIS_BLOCK(events, blk_0, miner_account, 1338224400); \
  block blk_last = blk_0;

  // the chain and a block on top of it
  bool make_strict_ts_block_events(std::vector<test_event_entry>& events, uint64_t strict_height, bool median_chain, strict_ts_choice *timestamp, const char *callback)
  {
    STRICT_TS_INIT_GENERATE();

    block blk;
    CHECK_AND_ASSERT_MES(make_strict_ts_base_chain(events, generator, blk_last, miner_account, strict_height, median_chain), false, "Failed to make chain");
    const uint64_t median = median_chain ? median_timestamp(events, events.size()) : 0;
    CHECK_AND_ASSERT_MES(make_strict_ts_test_block(generator, blk, blk_last, miner_account, strict_height, timestamp(blk_last, median)), false, "Failed to make block");
    events.push_back(blk);

    DO_CALLBACK(events, callback);

    return true;
  }

  // the chain, a block that extends it and an alternative block on the same parent
  bool make_strict_ts_alt_events(std::vector<test_event_entry>& events, uint64_t strict_height, bool median_chain, strict_ts_choice *timestamp)
  {
    STRICT_TS_INIT_GENERATE();

    block blk_alt;
    CHECK_AND_ASSERT_MES(make_strict_ts_base_chain(events, generator, blk_last, miner_account, strict_height, median_chain), false, "Failed to make chain");
    const uint64_t median = median_chain ? median_timestamp(events, events.size()) : 0;
    CHECK_AND_ASSERT_MES(make_strict_ts_test_block(generator, blk_alt, blk_last, miner_account, strict_height, timestamp(blk_last, median)), false, "Failed to make block");
    CHECK_AND_ASSERT_MES(make_strict_ts_test_chain(events, generator, blk_last, miner_account, strict_height, 1, blk_last.timestamp + 2 * DIFFICULTY_TARGET_V2, 0), false, "Failed to make block");
    events.push_back(blk_alt);

    DO_CALLBACK(events, "check_alt");

    return true;
  }

  bool get_test_block_template(cryptonote::core& c, const crypto::hash *parent, block& b, difficulty_type& diffic)
  {
    account_base acc;
    acc.generate();
    uint64_t height, expected_reward, cumulative_weight, seed_height;
    crypto::hash seed_hash;
    return parent
      ? c.get_block_template(b, parent, acc.get_keys().m_account_address, diffic, height, expected_reward, cumulative_weight, blobdata(), seed_height, seed_hash)
      : c.get_block_template(b, acc.get_keys().m_account_address, diffic, height, expected_reward, cumulative_weight, blobdata(), seed_height, seed_hash);
  }

  // hands the block to the node as found by its own miner, with another timestamp if one is given
  block_verification_context handle_test_block(cryptonote::core& c, block b, uint64_t timestamp = 0)
  {
    if (timestamp)
    {
      b.timestamp = timestamp;
      b.invalidate_hashes();
    }
    block_verification_context bvc{};
    c.handle_block_found(b, bvc);
    return bvc;
  }

  bool added_to_main_chain(const block_verification_context& bvc) { return bvc.m_added_to_main_chain && !bvc.m_verifivation_failed; }
  bool added_as_alternative(const block_verification_context& bvc) { return !bvc.m_added_to_main_chain && !bvc.m_verifivation_failed; }
}

bool gen_block_ts_equal_prev_before_strict::generate(std::vector<test_event_entry>& events) const
{
  return make_strict_ts_block_events(events, strict_height, false, ts_equal_prev, "check_block_accepted");
}

bool gen_block_ts_equal_prev_strict::generate(std::vector<test_event_entry>& events) const
{
  return make_strict_ts_block_events(events, strict_height, false, ts_equal_prev, "check_block_purged");
}

bool gen_block_ts_equal_prev_first_strict::generate(std::vector<test_event_entry>& events) const
{
  return make_strict_ts_block_events(events, strict_height, false, ts_equal_prev, "check_block_accepted");
}

bool gen_block_ts_future_before_strict::generate(std::vector<test_event_entry>& events) const
{
  return make_strict_ts_block_events(events, strict_height, false, ts_future, "check_block_accepted");
}

bool gen_block_ts_future_strict::generate(std::vector<test_event_entry>& events) const
{
  return make_strict_ts_block_events(events, strict_height, false, ts_future, "check_block_purged");
}

bool gen_block_ts_future_first_strict::generate(std::vector<test_event_entry>& events) const
{
  return make_strict_ts_block_events(events, strict_height, false, ts_future, "check_block_purged");
}

bool gen_block_ts_equal_median_before_strict::generate(std::vector<test_event_entry>& events) const
{
  return make_strict_ts_block_events(events, strict_height, true, ts_median, "check_block_accepted");
}

bool gen_block_ts_min_first_strict::generate(std::vector<test_event_entry>& events) const
{
  return make_strict_ts_block_events(events, strict_height, true, ts_first_strict_min, "check_block_accepted");
}

bool gen_block_ts_below_min_first_strict::generate(std::vector<test_event_entry>& events) const
{
  return make_strict_ts_block_events(events, strict_height, true, ts_below_first_strict_min, "check_block_purged");
}

bool gen_block_ts_below_median_strict::generate(std::vector<test_event_entry>& events) const
{
  STRICT_TS_INIT_GENERATE();

  CHECK_AND_ASSERT_MES(make_strict_ts_base_chain(events, generator, blk_last, miner_account, strict_height, true), false, "Failed to make chain");
  CHECK_AND_ASSERT_MES(make_strict_ts_test_chain(events, generator, blk_last, miner_account, strict_height, 2, blk_last.timestamp + 2, 1), false, "Failed to make blocks");
  CHECK_AND_ASSERT_MES(median_timestamp(events, events.size() - 1) > blk_last.timestamp, false, "Median not above the last timestamp");

  DO_CALLBACK(events, "check_block_accepted");

  return true;
}

bool gen_block_ts_alt_equal_prev_before_strict::generate(std::vector<test_event_entry>& events) const
{
  return make_strict_ts_alt_events(events, strict_height, false, ts_equal_prev);
}

bool gen_block_ts_alt_equal_prev_strict::generate(std::vector<test_event_entry>& events) const
{
  return make_strict_ts_alt_events(events, strict_height, false, ts_equal_prev);
}

bool gen_block_ts_alt_future_before_strict::generate(std::vector<test_event_entry>& events) const
{
  return make_strict_ts_alt_events(events, strict_height, false, ts_future);
}

bool gen_block_ts_alt_future_strict::generate(std::vector<test_event_entry>& events) const
{
  return make_strict_ts_alt_events(events, strict_height, false, ts_future);
}

bool gen_block_ts_alt_future_first_strict::generate(std::vector<test_event_entry>& events) const
{
  return make_strict_ts_alt_events(events, strict_height, false, ts_future);
}

bool gen_block_ts_alt_equal_median_before_strict::generate(std::vector<test_event_entry>& events) const
{
  return make_strict_ts_alt_events(events, strict_height, true, ts_median);
}

bool gen_block_ts_alt_min_first_strict::generate(std::vector<test_event_entry>& events) const
{
  return make_strict_ts_alt_events(events, strict_height, true, ts_first_strict_min);
}

bool gen_block_ts_alt_below_min_first_strict::generate(std::vector<test_event_entry>& events) const
{
  return make_strict_ts_alt_events(events, strict_height, true, ts_below_first_strict_min);
}

bool gen_block_ts_alt_below_median_strict::generate(std::vector<test_event_entry>& events) const
{
  STRICT_TS_INIT_GENERATE();

  block blk_alt;
  CHECK_AND_ASSERT_MES(make_strict_ts_base_chain(events, generator, blk_last, miner_account, strict_height, true), false, "Failed to make chain");
  CHECK_AND_ASSERT_MES(make_strict_ts_test_chain(events, generator, blk_last, miner_account, strict_height, 1, blk_last.timestamp + 1, 0), false, "Failed to make block");
  CHECK_AND_ASSERT_MES(median_timestamp(events, events.size()) > blk_last.timestamp + 1, false, "Median not above the next timestamp");
  CHECK_AND_ASSERT_MES(make_strict_ts_test_block(generator, blk_alt, blk_last, miner_account, strict_height, blk_last.timestamp + 1), false, "Failed to make block");
  CHECK_AND_ASSERT_MES(make_strict_ts_test_chain(events, generator, blk_last, miner_account, strict_height, 1, blk_last.timestamp + 2 * DIFFICULTY_TARGET_V2, 0), false, "Failed to make block");
  events.push_back(blk_alt);

  DO_CALLBACK(events, "check_alt");

  return true;
}

gen_block_ts_alt_chain_equal_prev_strict::gen_block_ts_alt_chain_equal_prev_strict()
{
  REGISTER_CALLBACK_METHOD(gen_block_ts_alt_chain_equal_prev_strict, check_alt_chain);
}

bool gen_block_ts_alt_chain_equal_prev_strict::generate(std::vector<test_event_entry>& events) const
{
  STRICT_TS_INIT_GENERATE();

  // two alternative blocks on block 10, then one with the timestamp of its alternative parent
  CHECK_AND_ASSERT_MES(make_strict_ts_test_chain(events, generator, blk_last, miner_account, strict_height, 13, blk_last.timestamp + 13 * 2 * DIFFICULTY_TARGET_V2, 2 * DIFFICULTY_TARGET_V2), false, "Failed to make chain");
  blk_last = boost::get<block>(events[10]);
  CHECK_AND_ASSERT_MES(make_strict_ts_test_chain(events, generator, blk_last, miner_account, strict_height, 2, blk_last.timestamp + 2, 1), false, "Failed to make blocks");
  CHECK_AND_ASSERT_MES(make_strict_ts_test_chain(events, generator, blk_last, miner_account, strict_height, 1, blk_last.timestamp, 0), false, "Failed to make block");

  DO_CALLBACK(events, "check_alt_chain");

  return true;
}

bool gen_block_ts_alt_chain_equal_prev_strict::check_block_verification_context(const cryptonote::block_verification_context& bvc, size_t event_idx, const cryptonote::block& /*blk*/)
{
  if (event_idx == 16)
    return bvc.m_verifivation_failed;
  if (event_idx >= 14)
    return added_as_alternative(bvc);
  return !bvc.m_verifivation_failed;
}

bool gen_block_ts_alt_chain_equal_prev_strict::check_alt_chain(cryptonote::core& c, size_t /*ev_index*/, const std::vector<test_event_entry>& /*events*/)
{
  DEFINE_TESTS_ERROR_CONTEXT("gen_block_ts_alt_chain_equal_prev_strict::check_alt_chain");

  CHECK_EQ(14, c.get_current_blockchain_height());
  CHECK_EQ(2, c.get_alternative_blocks_count());

  return true;
}

#define STRICT_TS_TEMPLATE_TEST_CONSTRUCTOR(name) \
  name::name() \
  { \
    REGISTER_CALLBACK_METHOD(name, check_templates); \
  }

STRICT_TS_TEMPLATE_TEST_CONSTRUCTOR(gen_block_ts_template_strict)
STRICT_TS_TEMPLATE_TEST_CONSTRUCTOR(gen_block_ts_template_below_strict)
STRICT_TS_TEMPLATE_TEST_CONSTRUCTOR(gen_block_ts_template_first_strict)
STRICT_TS_TEMPLATE_TEST_CONSTRUCTOR(gen_block_ts_template_first_strict_median)
STRICT_TS_TEMPLATE_TEST_CONSTRUCTOR(gen_block_ts_template_alt_before_strict)
STRICT_TS_TEMPLATE_TEST_CONSTRUCTOR(gen_block_ts_template_tip)

bool gen_block_ts_template_strict::generate(std::vector<test_event_entry>& events) const
{
  STRICT_TS_INIT_GENERATE();

  // the newest blocks one second apart and ahead of the clock
  CHECK_AND_ASSERT_MES(make_strict_ts_base_chain(events, generator, blk_last, miner_account, strict_height, false), false, "Failed to make chain");
  CHECK_AND_ASSERT_MES(make_strict_ts_test_chain(events, generator, blk_last, miner_account, strict_height, BLOCKCHAIN_TIMESTAMP_CHECK_WINDOW,
    time(NULL) + CRYPTONOTE_BLOCK_FUTURE_TIME_LIMIT_V17 / 2, 1), false, "Failed to make chain");

  DO_CALLBACK(events, "check_templates");

  return true;
}

bool gen_block_ts_template_strict::check_templates(cryptonote::core& c, size_t ev_index, const std::vector<test_event_entry>& events)
{
  DEFINE_TESTS_ERROR_CONTEXT("gen_block_ts_template_strict::check_templates");

  const uint64_t height = c.get_current_blockchain_height();
  const block &tip = boost::get<block>(events[ev_index - 1]);
  const block &tip_parent = boost::get<block>(events[ev_index - 2]);

  block b;
  difficulty_type diffic;
  CHECK_TEST_CONDITION(get_test_block_template(c, nullptr, b, diffic));
  CHECK_EQ(b.timestamp, tip.timestamp + 1);
  CHECK_EQ(diffic, 1);
  CHECK_TEST_CONDITION(handle_test_block(c, b, median_timestamp(events, ev_index)).m_verifivation_failed);
  CHECK_TEST_CONDITION(handle_test_block(c, b, tip.timestamp).m_verifivation_failed);
  CHECK_EQ(height, c.get_current_blockchain_height());
  CHECK_TEST_CONDITION(added_to_main_chain(handle_test_block(c, b)));

  const crypto::hash alt_parent = get_block_hash(tip_parent);
  block alt;
  CHECK_TEST_CONDITION(get_test_block_template(c, &alt_parent, alt, diffic));
  CHECK_EQ(alt.timestamp, tip_parent.timestamp + 1);
  CHECK_TEST_CONDITION(added_as_alternative(handle_test_block(c, alt)));

  const crypto::hash alt_tip = get_block_hash(alt);
  block alt_child;
  CHECK_TEST_CONDITION(get_test_block_template(c, &alt_tip, alt_child, diffic));
  CHECK_EQ(alt_child.timestamp, alt.timestamp + 1);
  CHECK_TEST_CONDITION(added_as_alternative(handle_test_block(c, alt_child)));
  CHECK_EQ(2, c.get_alternative_blocks_count());

  return true;
}

bool gen_block_ts_template_below_strict::generate(std::vector<test_event_entry>& events) const
{
  STRICT_TS_INIT_GENERATE();

  // the blocks below the strict height run ahead of the clock, and so does their median; two strict blocks at the clock follow
  const uint64_t now = time(NULL);
  CHECK_AND_ASSERT_MES(make_strict_ts_test_chain(events, generator, blk_last, miner_account, strict_height, strict_height - 1, now + 6800, DIFFICULTY_TARGET_V2 + 1), false, "Failed to make chain");
  CHECK_AND_ASSERT_MES(make_strict_ts_test_chain(events, generator, blk_last, miner_account, strict_height, 2, now + 1, 1), false, "Failed to make chain");

  DO_CALLBACK(events, "check_templates");

  return true;
}

bool gen_block_ts_template_below_strict::check_templates(cryptonote::core& c, size_t /*ev_index*/, const std::vector<test_event_entry>& events)
{
  DEFINE_TESTS_ERROR_CONTEXT("gen_block_ts_template_below_strict::check_templates");

  // a template on a block below the strict height follows the rule of that block's chain, not the main chain tip's
  const size_t parent_height = strict_height - 4;
  const crypto::hash parent = get_block_hash(boost::get<block>(events[parent_height]));
  block b;
  difficulty_type diffic;
  CHECK_TEST_CONDITION(get_test_block_template(c, &parent, b, diffic));
  CHECK_TEST_CONDITION(b.major_version < HF_VERSION_STRICT_TIMESTAMPS);
  CHECK_TEST_CONDITION(b.timestamp > (uint64_t)time(NULL));
  CHECK_EQ(b.timestamp, median_timestamp(events, parent_height + 1));
  CHECK_TEST_CONDITION(added_as_alternative(handle_test_block(c, b)));
  CHECK_EQ(1, c.get_alternative_blocks_count());

  return true;
}

bool gen_block_ts_template_first_strict::generate(std::vector<test_event_entry>& events) const
{
  STRICT_TS_INIT_GENERATE();

  // the last block below the strict height is stamped beyond the new future time limit
  const uint64_t now = time(NULL);
  CHECK_AND_ASSERT_MES(make_strict_ts_test_chain(events, generator, blk_last, miner_account, strict_height, strict_height - 2, now - 2 * DIFFICULTY_TARGET_V2, 2 * DIFFICULTY_TARGET_V2), false, "Failed to make chain");
  CHECK_AND_ASSERT_MES(make_strict_ts_test_chain(events, generator, blk_last, miner_account, strict_height, 1, now + 2 * CRYPTONOTE_BLOCK_FUTURE_TIME_LIMIT_V17, 0), false, "Failed to make block");

  DO_CALLBACK(events, "check_templates");

  return true;
}

bool gen_block_ts_template_first_strict::check_templates(cryptonote::core& c, size_t ev_index, const std::vector<test_event_entry>& events)
{
  DEFINE_TESTS_ERROR_CONTEXT("gen_block_ts_template_first_strict::check_templates");

  const block &tip = boost::get<block>(events[ev_index - 1]);
  CHECK_TEST_CONDITION(tip.timestamp > (uint64_t)time(NULL) + CRYPTONOTE_BLOCK_FUTURE_TIME_LIMIT_V17);

  block first, second;
  difficulty_type diffic;
  CHECK_TEST_CONDITION(get_test_block_template(c, nullptr, first, diffic));
  CHECK_EQ(first.major_version, HF_VERSION_STRICT_TIMESTAMPS);
  CHECK_TEST_CONDITION(first.timestamp < tip.timestamp);
  CHECK_TEST_CONDITION(added_to_main_chain(handle_test_block(c, first)));

  CHECK_TEST_CONDITION(get_test_block_template(c, nullptr, second, diffic));
  CHECK_TEST_CONDITION(second.timestamp > first.timestamp);
  CHECK_TEST_CONDITION(handle_test_block(c, second, first.timestamp).m_verifivation_failed);
  CHECK_TEST_CONDITION(added_to_main_chain(handle_test_block(c, second)));

  return true;
}

bool gen_block_ts_template_first_strict_median::generate(std::vector<test_event_entry>& events) const
{
  STRICT_TS_INIT_GENERATE();

  // more than half of the last blocks below the strict height are stamped beyond the new future time limit
  const uint64_t now = time(NULL);
  CHECK_AND_ASSERT_MES(make_strict_ts_test_chain(events, generator, blk_last, miner_account, strict_height, strict_height - 32, now - 2 * DIFFICULTY_TARGET_V2, 2 * DIFFICULTY_TARGET_V2), false, "Failed to make chain");
  CHECK_AND_ASSERT_MES(make_strict_ts_test_chain(events, generator, blk_last, miner_account, strict_height, 31, now + 7000, 0), false, "Failed to make chain");

  DO_CALLBACK(events, "check_templates");

  return true;
}

bool gen_block_ts_template_first_strict_median::check_templates(cryptonote::core& c, size_t ev_index, const std::vector<test_event_entry>& events)
{
  DEFINE_TESTS_ERROR_CONTEXT("gen_block_ts_template_first_strict_median::check_templates");

  const uint64_t median = median_timestamp(events, ev_index);
  CHECK_TEST_CONDITION(median > (uint64_t)time(NULL) + CRYPTONOTE_BLOCK_FUTURE_TIME_LIMIT_V17);

  block first;
  difficulty_type diffic;
  CHECK_TEST_CONDITION(get_test_block_template(c, nullptr, first, diffic));
  CHECK_EQ(first.major_version, HF_VERSION_STRICT_TIMESTAMPS);
  CHECK_EQ(first.timestamp, median - first_strict_ts_slack);
  CHECK_TEST_CONDITION(first.timestamp > (uint64_t)time(NULL));
  CHECK_TEST_CONDITION(handle_test_block(c, first, first.timestamp - 1).m_verifivation_failed);
  CHECK_TEST_CONDITION(added_to_main_chain(handle_test_block(c, first)));

  return true;
}

bool gen_block_ts_template_alt_before_strict::generate(std::vector<test_event_entry>& events) const
{
  STRICT_TS_INIT_GENERATE();

  // an alternative chain ahead of the clock on block 50 of 100
  CHECK_AND_ASSERT_MES(make_strict_ts_test_chain(events, generator, blk_last, miner_account, strict_height, 100, blk_last.timestamp + 100 * 2 * DIFFICULTY_TARGET_V2, 2 * DIFFICULTY_TARGET_V2), false, "Failed to make chain");
  blk_last = boost::get<block>(events[50]);
  CHECK_AND_ASSERT_MES(make_strict_ts_test_chain(events, generator, blk_last, miner_account, strict_height, 35, time(NULL) + CRYPTONOTE_BLOCK_FUTURE_TIME_LIMIT / 2, 1), false, "Failed to make chain");

  DO_CALLBACK(events, "check_templates");

  return true;
}

bool gen_block_ts_template_alt_before_strict::check_templates(cryptonote::core& c, size_t ev_index, const std::vector<test_event_entry>& events)
{
  DEFINE_TESTS_ERROR_CONTEXT("gen_block_ts_template_alt_before_strict::check_templates");

  CHECK_EQ(35, c.get_alternative_blocks_count());
  const crypto::hash alt_tip = get_block_hash(boost::get<block>(events[ev_index - 1]));
  block b;
  difficulty_type diffic;
  CHECK_TEST_CONDITION(get_test_block_template(c, &alt_tip, b, diffic));
  CHECK_TEST_CONDITION(b.major_version < HF_VERSION_STRICT_TIMESTAMPS);
  CHECK_TEST_CONDITION(added_as_alternative(handle_test_block(c, b)));
  CHECK_EQ(36, c.get_alternative_blocks_count());

  return true;
}

bool gen_block_ts_template_tip::generate(std::vector<test_event_entry>& events) const
{
  STRICT_TS_INIT_GENERATE();

  // with the genesis block just enough blocks for a median, which is ahead of the clock
  CHECK_AND_ASSERT_MES(make_strict_ts_test_chain(events, generator, blk_last, miner_account, strict_height, BLOCKCHAIN_TIMESTAMP_CHECK_WINDOW - 1, time(NULL) + 7000, DIFFICULTY_TARGET_V2 + 1), false, "Failed to make chain");

  DO_CALLBACK(events, "check_templates");

  return true;
}

bool gen_block_ts_template_tip::check_templates(cryptonote::core& c, size_t ev_index, const std::vector<test_event_entry>& events)
{
  DEFINE_TESTS_ERROR_CONTEXT("gen_block_ts_template_tip::check_templates");

  // a template on the tip given by its hash is the template on the tip
  const crypto::hash tip = get_block_hash(boost::get<block>(events[ev_index - 1]));
  block plain, on_tip;
  difficulty_type diffic;
  CHECK_TEST_CONDITION(get_test_block_template(c, nullptr, plain, diffic));
  CHECK_EQ(plain.timestamp, median_timestamp(events, ev_index));
  CHECK_TEST_CONDITION(plain.timestamp > (uint64_t)time(NULL));
  CHECK_TEST_CONDITION(get_test_block_template(c, &tip, on_tip, diffic));
  CHECK_EQ(on_tip.timestamp, plain.timestamp);
  CHECK_TEST_CONDITION(added_to_main_chain(handle_test_block(c, on_tip)));

  return true;
}

template<uint64_t height, bool median_chain>
gen_block_ts_miner_data_base<height, median_chain>::gen_block_ts_miner_data_base()
{
  REGISTER_CALLBACK_METHOD(gen_block_ts_miner_data_base, check_miner_data);
}

template<uint64_t height, bool median_chain>
bool gen_block_ts_miner_data_base<height, median_chain>::generate(std::vector<test_event_entry>& events) const
{
  STRICT_TS_INIT_GENERATE();

  CHECK_AND_ASSERT_MES(median_chain ? make_strict_ts_base_chain(events, generator, blk_last, miner_account, strict_height, true)
    : make_strict_ts_test_chain(events, generator, blk_last, miner_account, strict_height, 70, blk_last.timestamp + 70 * 2 * DIFFICULTY_TARGET_V2, 2 * DIFFICULTY_TARGET_V2),
    false, "Failed to make chain");

  DO_CALLBACK(events, "check_miner_data");

  return true;
}

template<uint64_t height, bool median_chain>
bool gen_block_ts_miner_data_base<height, median_chain>::check_miner_data(cryptonote::core& c, size_t ev_index, const std::vector<test_event_entry>& events)
{
  DEFINE_TESTS_ERROR_CONTEXT("gen_block_ts_miner_data_base::check_miner_data");

  uint8_t major_version;
  uint64_t next_height, median_weight, already_generated_coins, min_timestamp;
  crypto::hash prev_id, seed_hash;
  difficulty_type diffic;
  std::vector<tx_block_template_backlog_entry> tx_backlog;
  CHECK_TEST_CONDITION(c.get_miner_data(major_version, next_height, prev_id, seed_hash, diffic, median_weight, already_generated_coins, min_timestamp, tx_backlog));
  const uint64_t median = median_timestamp(events, ev_index);
  const uint64_t parent = boost::get<block>(events[ev_index - 1]).timestamp;
  CHECK_TEST_CONDITION(major_version == (next_height >= strict_height ? HF_VERSION_STRICT_TIMESTAMPS : HF_VERSION_STRICT_TIMESTAMPS - 1));
  const uint64_t expected = next_height > strict_height ? parent + 1 : next_height == strict_height ? median - first_strict_ts_slack : median;
  CHECK_EQ(min_timestamp, expected);

  // a block is valid from min_timestamp on, and the next block's is notified
  block b;
  CHECK_TEST_CONDITION(get_test_block_template(c, nullptr, b, diffic));
  CHECK_TEST_CONDITION(handle_test_block(c, b, min_timestamp - 1).m_verifivation_failed);
  const auto notified_min_timestamp = std::make_shared<uint64_t>(0);
  c.get_blockchain_storage().add_miner_notify([notified_min_timestamp](uint8_t, uint64_t, const crypto::hash&, const crypto::hash&, difficulty_type, uint64_t, uint64_t, uint64_t notified, const std::vector<tx_block_template_backlog_entry>&)
  {
    *notified_min_timestamp = notified;
  });
  CHECK_TEST_CONDITION(added_to_main_chain(handle_test_block(c, b, min_timestamp)));
  CHECK_TEST_CONDITION(c.get_miner_data(major_version, next_height, prev_id, seed_hash, diffic, median_weight, already_generated_coins, min_timestamp, tx_backlog));
  CHECK_EQ(*notified_min_timestamp, min_timestamp);

  return true;
}

template struct gen_block_ts_miner_data_base<100, true>;
template struct gen_block_ts_miner_data_base<70, true>;
template struct gen_block_ts_miner_data_base<2, false>;

namespace
{
  static_assert(HF_VERSION_STRICT_TIMESTAMPS == HF_VERSION_DIFFICULTY_ASERT, "the test chains switch both rules at one height");

  difficulty_type expected_difficulty(const std::vector<uint64_t>& timestamps, const std::vector<difficulty_type>& cumulative_difficulties, size_t asert_height)
  {
    const size_t height = timestamps.size();
    if (height < asert_height)
      return next_difficulty(std::vector<uint64_t>(timestamps.begin() + 1, timestamps.end()),
        std::vector<difficulty_type>(cumulative_difficulties.begin() + 1, cumulative_difficulties.end()), DIFFICULTY_TARGET_V2);
    const size_t anchor = std::max<size_t>(asert_height - 1, 2);
    if (height <= anchor)
      return 1;
    const difficulty_type anchor_difficulty = cumulative_difficulties[anchor] - cumulative_difficulties[anchor - 1];
    if (height <= anchor + DIFFICULTY_ASERT_LAG)
      return anchor_difficulty;
    const size_t newest = height - 1 - DIFFICULTY_ASERT_LAG;
    return next_difficulty_asert(anchor_difficulty, timestamps[anchor - 1], timestamps[newest], newest - anchor + 1, DIFFICULTY_TARGET_V2, DIFFICULTY_ASERT_HALF_LIFE);
  }

  struct difficulty_test_chain
  {
    size_t asert_height;
    std::vector<block> blocks;
    std::vector<uint64_t> timestamps;
    std::vector<difficulty_type> cumulative_difficulties;

    explicit difficulty_test_chain(const block& genesis, size_t asert_height = difficulty_asert_test_height):
      asert_height(asert_height), blocks{genesis}, timestamps{genesis.timestamp}, cumulative_difficulties{1} {}

    size_t height() const { return blocks.size(); }
    difficulty_type next() const { return expected_difficulty(timestamps, cumulative_difficulties, asert_height); }
    difficulty_type difficulty(size_t h) const { return cumulative_difficulties[h] - cumulative_difficulties[h - 1]; }

    void append(const block& blk)
    {
      cumulative_difficulties.push_back(cumulative_difficulties.back() + next());
      timestamps.push_back(blk.timestamp);
      blocks.push_back(blk);
    }

    bool mine(std::vector<test_event_entry>& events, test_generator& generator, const account_base& miner_account, int64_t step)
    {
      block blk;
      if (!make_strict_ts_test_block(generator, blk, blocks.back(), miner_account, asert_height, blocks.back().timestamp + step, next()))
        return false;
      events.push_back(blk);
      append(blk);
      return true;
    }

    void cut(size_t new_height)
    {
      blocks.resize(new_height);
      timestamps.resize(new_height);
      cumulative_difficulties.resize(new_height);
    }
  };

  bool get_template_difficulty(cryptonote::core& c, const crypto::hash *parent, difficulty_type& diffic)
  {
    block b;
    return get_test_block_template(c, parent, b, diffic);
  }

  // Compares the stored main chain with expected_difficulty and with the template on every one of its blocks.
  bool check_main_chain_difficulties(cryptonote::core& c, difficulty_test_chain& chain)
  {
    DEFINE_TESTS_ERROR_CONTEXT("check_main_chain_difficulties");

    Blockchain& bc = c.get_blockchain_storage();
    const uint64_t height = c.get_current_blockchain_height();
    block blk;
    CHECK_TEST_CONDITION(bc.get_block_by_hash(c.get_block_id_by_height(0), blk));
    chain = difficulty_test_chain(blk, chain.asert_height);
    for (uint64_t i = 1; i <= height; ++i)
    {
      const crypto::hash parent = c.get_block_id_by_height(i - 1);
      difficulty_type diffic;
      CHECK_TEST_CONDITION(get_template_difficulty(c, &parent, diffic));
      CHECK_EQ(diffic, chain.next());
      if (i == height)
        break;
      CHECK_TEST_CONDITION(bc.get_block_by_hash(c.get_block_id_by_height(i), blk));
      chain.append(blk);
      CHECK_EQ(bc.get_db().get_block_cumulative_difficulty(i), chain.cumulative_difficulties.back());
    }
    difficulty_type diffic;
    CHECK_TEST_CONDITION(get_template_difficulty(c, nullptr, diffic));
    CHECK_EQ(diffic, chain.next());
    return true;
  }

  // Difficulties of the test chains below, from tests/difficulty/gen_asert_vectors.py core: every block from a given
  // height on, then the next block's.
  const std::vector<uint64_t> asert_model_main_1 = {1, 1, 1, 1, 1, 1, 2, 2, 3, 3, 4, 5, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 8, 13, 6, 5, 6, 5, 2, 2, 2, 2, 2, 2, 2};
  const std::vector<uint64_t> asert_model_alt_1 = {6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 8, 13, 6, 5, 6, 5, 2, 1, 1, 1};
  const std::vector<uint64_t> asert_model_main_2 = {1, 1, 1, 1, 1, 1, 2, 2, 3, 3, 4, 5, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 5, 6, 5};
  const std::vector<uint64_t> asert_model_alt_2 = {4, 4, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 4, 21, 21, 21, 21, 21};
  const std::vector<uint64_t> asert_model_early = {1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 4, 4, 5, 5, 5, 5, 5};

  bool check_model_difficulties(const difficulty_test_chain& chain, size_t first_height, const std::vector<uint64_t>& model)
  {
    DEFINE_TESTS_ERROR_CONTEXT("check_model_difficulties");

    CHECK_EQ(chain.height(), first_height + model.size() - 1);
    for (size_t i = 0; i + 1 < model.size(); ++i)
      CHECK_EQ(chain.difficulty(first_height + i), model[i]);
    CHECK_EQ(chain.next(), model.back());
    return true;
  }
}

gen_block_difficulty_asert::gen_block_difficulty_asert()
{
  REGISTER_CALLBACK_METHOD(gen_block_difficulty_asert, check_difficulties);
}

bool gen_block_difficulty_asert::generate(std::vector<test_event_entry>& events) const
{
  BLOCK_VALIDATION_INIT_GENERATE();
  generator.set_events(&events);

  // The anchor is stamped below its parent and the first block of the new rule below the anchor. The next two
  // blocks are exactly on schedule and one second behind it, then come an hour, a half-life and fast blocks.
  difficulty_test_chain chain(blk_0);
  std::vector<int64_t> steps{120, 120, 120, 120, 120, 1, 1, 1, 1, 1, 1, 1, -20000,
                             -30000, 50000 + 3 * DIFFICULTY_TARGET_V2, DIFFICULTY_TARGET_V2 + 1, 1, 3600, DIFFICULTY_ASERT_HALF_LIFE};
  steps.resize(55, 1);
  for (const int64_t step: steps)
    CHECK_AND_ASSERT_MES(chain.mine(events, generator, miner_account, step), false, "Failed to make block");

  // an alternative chain long enough to have its own timestamps taken into account
  difficulty_test_chain alt = chain;
  alt.cut(20);
  for (size_t i = 0; i < DIFFICULTY_ASERT_LAG + 3; ++i)
    CHECK_AND_ASSERT_MES(alt.mine(events, generator, miner_account, i ? 1 : DIFFICULTY_ASERT_HALF_LIFE), false, "Failed to make block");
  CHECK_AND_ASSERT_MES(alt.cumulative_difficulties.back() < chain.cumulative_difficulties.back(), false, "The alternative chain is not lighter");

  DO_CALLBACK(events, "check_difficulties");

  return true;
}

bool gen_block_difficulty_asert::check_difficulties(cryptonote::core& c, size_t ev_index, const std::vector<test_event_entry>& events)
{
  DEFINE_TESTS_ERROR_CONTEXT("gen_block_difficulty_asert::check_difficulties");

  Blockchain& bc = c.get_blockchain_storage();
  const uint64_t height = c.get_current_blockchain_height();
  CHECK_EQ(height, 56);
  CHECK_EQ(c.get_tail_id(), get_block_hash(boost::get<block>(events[55])));
  CHECK_EQ(c.get_alternative_blocks_count(), ev_index - 56);

  difficulty_test_chain chain(boost::get<block>(events[0]));
  CHECK_TEST_CONDITION(check_main_chain_difficulties(c, chain));
  CHECK_TEST_CONDITION(check_model_difficulties(chain, 1, asert_model_main_1));

  difficulty_test_chain alt = chain;
  alt.cut(20);
  for (size_t i = 56; i < ev_index; ++i)
  {
    alt.append(boost::get<block>(events[i]));
    const crypto::hash alt_id = get_block_hash(alt.blocks.back());
    difficulty_type diffic;
    CHECK_TEST_CONDITION(get_template_difficulty(c, &alt_id, diffic));
    CHECK_EQ(diffic, alt.next());
  }
  CHECK_TEST_CONDITION(check_model_difficulties(alt, 20, asert_model_alt_1));

  // a wrong anchor is recalculated before it is used; a recalculation that starts above the anchor reads it
  CHECK_EQ(bc.recalculate_difficulties(1), 0);
  for (const uint64_t wrong_from: {difficulty_asert_test_height - 1, difficulty_asert_test_height + DIFFICULTY_ASERT_LAG + 5})
  {
    std::vector<difficulty_type> wrong(chain.cumulative_difficulties.begin() + wrong_from, chain.cumulative_difficulties.end());
    for (difficulty_type &d: wrong)
      ++d;
    bc.get_db().correct_block_cumulative_difficulties(wrong_from, wrong);
    CHECK_EQ(bc.recalculate_difficulties(wrong_from < difficulty_asert_test_height ? 1 : wrong_from - 3), height - wrong_from);
    for (uint64_t i = 0; i < height; ++i)
      CHECK_EQ(bc.get_db().get_block_cumulative_difficulty(i), chain.cumulative_difficulties[i]);
  }

  return true;
}

gen_block_difficulty_asert_reorg::gen_block_difficulty_asert_reorg()
{
  REGISTER_CALLBACK_METHOD(gen_block_difficulty_asert_reorg, check_before_reorg);
  REGISTER_CALLBACK_METHOD(gen_block_difficulty_asert_reorg, check_after_reorg);
}

bool gen_block_difficulty_asert_reorg::generate(std::vector<test_event_entry>& events) const
{
  BLOCK_VALIDATION_INIT_GENERATE();
  generator.set_events(&events);

  difficulty_test_chain chain(blk_0);
  std::vector<int64_t> steps{120, 120, 120, 120, 120, 1, 1, 1, 1, 1, 1, 1, DIFFICULTY_TARGET_V2 + 1, 1, 5000, 5000};
  steps.resize(45, 1);
  for (const int64_t step: steps)
    CHECK_AND_ASSERT_MES(chain.mine(events, generator, miner_account, step), false, "Failed to make block");

  DO_CALLBACK(events, "check_before_reorg");

  // Forks three blocks below the anchor and gets its own anchor, of a lower difficulty than the main chain's. Its
  // first block of the new rule is stamped far below the anchor, which puts it ahead of schedule once the lag has
  // passed.
  difficulty_test_chain alt = chain;
  alt.cut(difficulty_asert_test_height - 3);
  const std::vector<int64_t> alt_steps{200, 1, DIFFICULTY_TARGET_V2 + 1, -90000};
  for (size_t i = 0, heavier = 0; heavier < 3; ++i)
  {
    CHECK_AND_ASSERT_MES(alt.mine(events, generator, miner_account, i < alt_steps.size() ? alt_steps[i] : 1), false, "Failed to make block");
    heavier += alt.cumulative_difficulties.back() > chain.cumulative_difficulties.back();
  }
  CHECK_AND_ASSERT_MES(alt.difficulty(difficulty_asert_test_height - 1) != chain.difficulty(difficulty_asert_test_height - 1), false, "The anchors do not differ");

  DO_CALLBACK(events, "check_after_reorg");

  return true;
}

bool gen_block_difficulty_asert_reorg::check_before_reorg(cryptonote::core& c, size_t ev_index, const std::vector<test_event_entry>& events)
{
  DEFINE_TESTS_ERROR_CONTEXT("gen_block_difficulty_asert_reorg::check_before_reorg");

  CHECK_EQ(ev_index, 46);
  CHECK_EQ(c.get_current_blockchain_height(), 46);
  CHECK_EQ(c.get_tail_id(), get_block_hash(boost::get<block>(events[45])));
  CHECK_EQ(c.get_alternative_blocks_count(), 0);

  difficulty_test_chain chain(boost::get<block>(events[0]));
  CHECK_TEST_CONDITION(check_main_chain_difficulties(c, chain));
  CHECK_TEST_CONDITION(check_model_difficulties(chain, 1, asert_model_main_2));

  return true;
}

bool gen_block_difficulty_asert_reorg::check_after_reorg(cryptonote::core& c, size_t ev_index, const std::vector<test_event_entry>& events)
{
  DEFINE_TESTS_ERROR_CONTEXT("gen_block_difficulty_asert_reorg::check_after_reorg");

  const uint64_t fork_height = difficulty_asert_test_height - 3;
  CHECK_EQ(c.get_current_blockchain_height(), fork_height + ev_index - 47);
  CHECK_EQ(c.get_tail_id(), get_block_hash(boost::get<block>(events[ev_index - 1])));
  CHECK_EQ(c.get_alternative_blocks_count(), 46 - fork_height);

  difficulty_test_chain chain(boost::get<block>(events[0]));
  CHECK_TEST_CONDITION(check_main_chain_difficulties(c, chain));
  CHECK_TEST_CONDITION(check_model_difficulties(chain, fork_height, asert_model_alt_2));

  // the replaced chain is now an alternative chain with its own anchor
  difficulty_test_chain old_chain(boost::get<block>(events[0]));
  for (size_t i = 1; i <= 45; ++i)
  {
    old_chain.append(boost::get<block>(events[i]));
    if (i < fork_height)
      continue;
    const crypto::hash id = get_block_hash(old_chain.blocks.back());
    difficulty_type diffic;
    CHECK_TEST_CONDITION(get_template_difficulty(c, &id, diffic));
    CHECK_EQ(diffic, old_chain.next());
  }

  CHECK_EQ(c.get_blockchain_storage().recalculate_difficulties(1), 0);

  return true;
}

gen_block_difficulty_asert_early::gen_block_difficulty_asert_early()
{
  REGISTER_CALLBACK_METHOD(gen_block_difficulty_asert_early, check_difficulties);
}

bool gen_block_difficulty_asert_early::generate(std::vector<test_event_entry>& events) const
{
  BLOCK_VALIDATION_INIT_GENERATE();
  generator.set_events(&events);

  // The new rule starts at height 2, so the anchor is block 2 and not block 1, whose parent is the genesis block.
  // Block 1 is stamped far above the blocks that follow, which puts them ahead of schedule.
  difficulty_test_chain chain(blk_0, asert_height);
  std::vector<int64_t> steps{100000, -99999};
  steps.resize(DIFFICULTY_ASERT_LAG + 8, 1);
  for (const int64_t step: steps)
    CHECK_AND_ASSERT_MES(chain.mine(events, generator, miner_account, step), false, "Failed to make block");

  DO_CALLBACK(events, "check_difficulties");

  return true;
}

bool gen_block_difficulty_asert_early::check_difficulties(cryptonote::core& c, size_t ev_index, const std::vector<test_event_entry>& events)
{
  DEFINE_TESTS_ERROR_CONTEXT("gen_block_difficulty_asert_early::check_difficulties");

  CHECK_EQ(c.get_current_blockchain_height(), ev_index);

  difficulty_test_chain chain(boost::get<block>(events[0]), asert_height);
  CHECK_TEST_CONDITION(check_main_chain_difficulties(c, chain));
  CHECK_TEST_CONDITION(check_model_difficulties(chain, 1, asert_model_early));

  CHECK_EQ(c.get_blockchain_storage().recalculate_difficulties(1), 0);

  return true;
}
