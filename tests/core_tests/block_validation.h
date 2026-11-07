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

#pragma once 
#include "chaingen.h"

template<size_t invalid_block_idx = 0>
class gen_block_verification_base : public test_chain_unit_base
{
public:
  gen_block_verification_base()
  {
    REGISTER_CALLBACK("check_block_purged", gen_block_verification_base<invalid_block_idx>::check_block_purged);
  }

  bool check_block_verification_context(const cryptonote::block_verification_context& bvc, size_t event_idx, const cryptonote::block& /*blk*/)
  {
    if (invalid_block_idx == event_idx)
      return bvc.m_verifivation_failed;
    else
      return !bvc.m_verifivation_failed;
  }

  bool check_block_purged(cryptonote::core& c, size_t ev_index, const std::vector<test_event_entry>& events)
  {
    DEFINE_TESTS_ERROR_CONTEXT("gen_block_verification_base::check_block_purged");

    CHECK_TEST_CONDITION(invalid_block_idx < ev_index);
    CHECK_EQ(0, c.get_pool_transactions_count());
    CHECK_EQ(invalid_block_idx, c.get_current_blockchain_height());

    return true;
  }
};

template<size_t expected_blockchain_height>
struct gen_block_accepted_base : public test_chain_unit_base
{
  gen_block_accepted_base()
  {
    REGISTER_CALLBACK("check_block_accepted", gen_block_accepted_base::check_block_accepted);
  }

  bool check_block_accepted(cryptonote::core& c, size_t /*ev_index*/, const std::vector<test_event_entry>& /*events*/)
  {
    DEFINE_TESTS_ERROR_CONTEXT("gen_block_accepted_base::check_block_accepted");

    CHECK_EQ(0, c.get_pool_transactions_count());
    CHECK_EQ(expected_blockchain_height, c.get_current_blockchain_height());

    return true;
  }
};

struct gen_block_big_major_version : public gen_block_verification_base<1>
{
  bool generate(std::vector<test_event_entry>& events) const;
};

struct gen_block_big_minor_version : public gen_block_accepted_base<2>
{
  bool generate(std::vector<test_event_entry>& events) const;
};

struct gen_block_ts_not_checked : public gen_block_accepted_base<BLOCKCHAIN_TIMESTAMP_CHECK_WINDOW>
{
  bool generate(std::vector<test_event_entry>& events) const;
};

struct gen_block_ts_in_past : public gen_block_verification_base<BLOCKCHAIN_TIMESTAMP_CHECK_WINDOW>
{
  bool generate(std::vector<test_event_entry>& events) const;
};

struct gen_block_ts_in_future : public gen_block_verification_base<1>
{
  bool generate(std::vector<test_event_entry>& events) const;
};

struct gen_block_invalid_prev_id : public gen_block_verification_base<1>
{
  bool generate(std::vector<test_event_entry>& events) const;
  bool check_block_verification_context(const cryptonote::block_verification_context& bvc, size_t event_idx, const cryptonote::block& /*blk*/);
};

struct gen_block_invalid_nonce : public gen_block_verification_base<3>
{
  bool generate(std::vector<test_event_entry>& events) const;
};

struct gen_block_no_miner_tx : public gen_block_verification_base<1>
{
  bool generate(std::vector<test_event_entry>& events) const;
};

struct gen_block_unlock_time_is_low : public gen_block_verification_base<1>
{
  bool generate(std::vector<test_event_entry>& events) const;
};

struct gen_block_unlock_time_is_high : public gen_block_verification_base<1>
{
  bool generate(std::vector<test_event_entry>& events) const;
};

struct gen_block_unlock_time_is_timestamp_in_past : public gen_block_verification_base<1>
{
  bool generate(std::vector<test_event_entry>& events) const;
};

struct gen_block_unlock_time_is_timestamp_in_future : public gen_block_verification_base<1>
{
  bool generate(std::vector<test_event_entry>& events) const;
};

struct gen_block_height_is_low : public gen_block_verification_base<1>
{
  bool generate(std::vector<test_event_entry>& events) const;
};

struct gen_block_height_is_high : public gen_block_verification_base<1>
{
  bool generate(std::vector<test_event_entry>& events) const;
};

struct gen_block_miner_tx_has_2_tx_gen_in : public gen_block_verification_base<1>
{
  bool generate(std::vector<test_event_entry>& events) const;
};

struct gen_block_miner_tx_has_2_in : public gen_block_verification_base<CRYPTONOTE_MINED_MONEY_UNLOCK_WINDOW + 1>
{
  bool generate(std::vector<test_event_entry>& events) const;
};

struct gen_block_miner_tx_with_txin_to_key : public gen_block_verification_base<CRYPTONOTE_MINED_MONEY_UNLOCK_WINDOW + 2>
{
  bool generate(std::vector<test_event_entry>& events) const;
};

struct gen_block_miner_tx_out_is_small : public gen_block_verification_base<1>
{
  bool generate(std::vector<test_event_entry>& events) const;
};

struct gen_block_miner_tx_out_is_big : public gen_block_verification_base<1>
{
  bool generate(std::vector<test_event_entry>& events) const;
};

struct gen_block_miner_tx_has_no_out : public gen_block_verification_base<1>
{
  bool generate(std::vector<test_event_entry>& events) const;
};

struct gen_block_miner_tx_has_out_to_alice : public gen_block_accepted_base<2>
{
  bool generate(std::vector<test_event_entry>& events) const;
};

struct gen_block_has_invalid_tx : public gen_block_verification_base<1>
{
  bool generate(std::vector<test_event_entry>& events) const;
};

struct gen_block_is_too_big : public gen_block_verification_base<1>
{
  bool generate(std::vector<test_event_entry>& events) const;
};

struct gen_block_invalid_binary_format : public test_chain_unit_base
{
  gen_block_invalid_binary_format();
  bool generate(std::vector<test_event_entry>& events) const;
  bool check_block_verification_context(const cryptonote::block_verification_context& bvc, size_t event_idx, const cryptonote::block& /*blk*/);
  bool check_all_blocks_purged(cryptonote::core& c, size_t ev_index, const std::vector<test_event_entry>& events);
  bool corrupt_blocks_boundary(cryptonote::core& c, size_t ev_index, const std::vector<test_event_entry>& events);

private:
  size_t m_corrupt_blocks_begin_idx;
};

struct gen_block_late_v1_coinbase_tx : public gen_block_verification_base<1>
{
  bool generate(std::vector<test_event_entry>& events) const;
};
template<>
struct get_test_options<gen_block_late_v1_coinbase_tx> {
  const std::pair<uint8_t, uint64_t> hard_forks[3] = {std::make_pair(1, 0), std::make_pair(HF_VERSION_MIN_V2_COINBASE_TX, 1), std::make_pair(0, 0)};
  const cryptonote::test_options test_options = {
    hard_forks, 0
  };
};

struct gen_block_low_coinbase : public gen_block_verification_base<1>
{
  bool generate(std::vector<test_event_entry>& events) const;
};
template<>
struct get_test_options<gen_block_low_coinbase> {
  const std::pair<uint8_t, uint64_t> hard_forks[3] = {std::make_pair(1, 0), std::make_pair(HF_VERSION_EXACT_COINBASE, 1), std::make_pair(0, 0)};
  const cryptonote::test_options test_options = {
    hard_forks, 0
  };
};

struct gen_block_miner_tx_out_has_no_view_tag_before_hf_view_tags : public gen_block_accepted_base<2>
{
  bool generate(std::vector<test_event_entry>& events) const;
};

struct gen_block_miner_tx_out_has_no_view_tag_from_hf_view_tags : public gen_block_verification_base<1>
{
  bool generate(std::vector<test_event_entry>& events) const;
};
template<>
struct get_test_options<gen_block_miner_tx_out_has_no_view_tag_from_hf_view_tags> {
  const std::pair<uint8_t, uint64_t> hard_forks[3] = {std::make_pair(1, 0), std::make_pair(HF_VERSION_VIEW_TAGS+1, 1), std::make_pair(0, 0)};
  const cryptonote::test_options test_options = {
    hard_forks, 0
  };
};

struct gen_block_miner_tx_out_has_view_tag_before_hf_view_tags : public gen_block_verification_base<1>
{
  bool generate(std::vector<test_event_entry>& events) const;
};

struct gen_block_miner_tx_out_has_view_tag_from_hf_view_tags : public gen_block_accepted_base<2>
{
  bool generate(std::vector<test_event_entry>& events) const;
};
template<>
struct get_test_options<gen_block_miner_tx_out_has_view_tag_from_hf_view_tags> {
  const std::pair<uint8_t, uint64_t> hard_forks[3] = {std::make_pair(1, 0), std::make_pair(HF_VERSION_VIEW_TAGS, 1), std::make_pair(0, 0)};
  const cryptonote::test_options test_options = {
    hard_forks, 0
  };
};

template<uint64_t strict_height>
struct get_strict_timestamps_test_options {
  const std::pair<uint8_t, uint64_t> hard_forks[4] = {std::make_pair(1, 0), std::make_pair(HF_VERSION_STRICT_TIMESTAMPS - 1, 1),
    std::make_pair(HF_VERSION_STRICT_TIMESTAMPS, strict_height), std::make_pair(0, 0)};
  const cryptonote::test_options test_options = {
    hard_forks, 0
  };
};

struct gen_block_ts_equal_prev_before_strict : public gen_block_accepted_base<12>
{
  bool generate(std::vector<test_event_entry>& events) const;
};
template<> struct get_test_options<gen_block_ts_equal_prev_before_strict>: public get_strict_timestamps_test_options<100> {};

struct gen_block_ts_equal_prev_strict : public gen_block_verification_base<11>
{
  bool generate(std::vector<test_event_entry>& events) const;
};
template<> struct get_test_options<gen_block_ts_equal_prev_strict>: public get_strict_timestamps_test_options<3> {};

struct gen_block_ts_equal_median_before_strict : public gen_block_accepted_base<71>
{
  bool generate(std::vector<test_event_entry>& events) const;
};
template<> struct get_test_options<gen_block_ts_equal_median_before_strict>: public get_strict_timestamps_test_options<100> {};

struct gen_block_ts_equal_median_strict : public gen_block_verification_base<70>
{
  bool generate(std::vector<test_event_entry>& events) const;
};
template<> struct get_test_options<gen_block_ts_equal_median_strict>: public get_strict_timestamps_test_options<70> {};

struct gen_block_ts_above_median_strict : public gen_block_accepted_base<71>
{
  bool generate(std::vector<test_event_entry>& events) const;
};
template<> struct get_test_options<gen_block_ts_above_median_strict>: public get_strict_timestamps_test_options<70> {};

struct gen_block_ts_template_strict : public test_chain_unit_base
{
  gen_block_ts_template_strict();
  bool generate(std::vector<test_event_entry>& events) const;
  bool check_templates(cryptonote::core& c, size_t ev_index, const std::vector<test_event_entry>& events);
};
template<> struct get_test_options<gen_block_ts_template_strict>: public get_strict_timestamps_test_options<2> {};

struct gen_block_ts_template_below_strict : public test_chain_unit_base
{
  gen_block_ts_template_below_strict();
  bool generate(std::vector<test_event_entry>& events) const;
  bool check_template(cryptonote::core& c, size_t ev_index, const std::vector<test_event_entry>& events);
};
template<> struct get_test_options<gen_block_ts_template_below_strict>: public get_strict_timestamps_test_options<68> {};

struct gen_block_ts_template_median_strict : public test_chain_unit_base
{
  gen_block_ts_template_median_strict();
  bool generate(std::vector<test_event_entry>& events) const;
  bool check_templates(cryptonote::core& c, size_t ev_index, const std::vector<test_event_entry>& events);
};
template<> struct get_test_options<gen_block_ts_template_median_strict>: public get_strict_timestamps_test_options<70> {};

struct gen_block_ts_template_alt_before_strict : public test_chain_unit_base
{
  gen_block_ts_template_alt_before_strict();
  bool generate(std::vector<test_event_entry>& events) const;
  bool check_template(cryptonote::core& c, size_t ev_index, const std::vector<test_event_entry>& events);
};
template<> struct get_test_options<gen_block_ts_template_alt_before_strict>: public get_strict_timestamps_test_options<100000> {};

template<size_t alt_idx, bool rejected>
struct gen_block_ts_alt_base : public test_chain_unit_base
{
  gen_block_ts_alt_base()
  {
    REGISTER_CALLBACK("check_alt", gen_block_ts_alt_base::check_alt);
  }

  bool check_block_verification_context(const cryptonote::block_verification_context& bvc, size_t event_idx, const cryptonote::block& /*blk*/)
  {
    if (event_idx == alt_idx)
      return rejected ? bvc.m_verifivation_failed : !bvc.m_verifivation_failed && !bvc.m_added_to_main_chain;
    return !bvc.m_verifivation_failed;
  }

  bool check_alt(cryptonote::core& c, size_t /*ev_index*/, const std::vector<test_event_entry>& /*events*/)
  {
    DEFINE_TESTS_ERROR_CONTEXT("gen_block_ts_alt_base::check_alt");
    CHECK_EQ(alt_idx, c.get_current_blockchain_height());
    CHECK_EQ((rejected ? 0u : 1u), c.get_alternative_blocks_count());
    return true;
  }
};

struct gen_block_ts_alt_equal_prev_before_strict : public gen_block_ts_alt_base<12, false>
{
  bool generate(std::vector<test_event_entry>& events) const;
};
template<> struct get_test_options<gen_block_ts_alt_equal_prev_before_strict>: public get_strict_timestamps_test_options<100> {};

struct gen_block_ts_alt_equal_prev_strict : public gen_block_ts_alt_base<12, true>
{
  bool generate(std::vector<test_event_entry>& events) const;
};
template<> struct get_test_options<gen_block_ts_alt_equal_prev_strict>: public get_strict_timestamps_test_options<3> {};

struct gen_block_ts_alt_equal_median_before_strict : public gen_block_ts_alt_base<71, false>
{
  bool generate(std::vector<test_event_entry>& events) const;
};
template<> struct get_test_options<gen_block_ts_alt_equal_median_before_strict>: public get_strict_timestamps_test_options<100> {};

struct gen_block_ts_alt_equal_median_strict : public gen_block_ts_alt_base<71, true>
{
  bool generate(std::vector<test_event_entry>& events) const;
};
template<> struct get_test_options<gen_block_ts_alt_equal_median_strict>: public get_strict_timestamps_test_options<70> {};

struct gen_block_ts_alt_chain_equal_prev_strict : public test_chain_unit_base
{
  gen_block_ts_alt_chain_equal_prev_strict();
  bool generate(std::vector<test_event_entry>& events) const;
  bool check_block_verification_context(const cryptonote::block_verification_context& bvc, size_t event_idx, const cryptonote::block& /*blk*/);
  bool check_alt_chain(cryptonote::core& c, size_t ev_index, const std::vector<test_event_entry>& events);
};
template<> struct get_test_options<gen_block_ts_alt_chain_equal_prev_strict>: public get_strict_timestamps_test_options<3> {};

struct gen_block_difficulty_span_floor : public test_chain_unit_base
{
  gen_block_difficulty_span_floor();
  bool generate(std::vector<test_event_entry>& events) const;
  bool check_difficulties(cryptonote::core& c, size_t ev_index, const std::vector<test_event_entry>& events);
};
template<> struct get_test_options<gen_block_difficulty_span_floor>: public get_strict_timestamps_test_options<22> {};

template<bool rejected>
struct gen_block_ts_alt_window_base : public test_chain_unit_base
{
  gen_block_ts_alt_window_base()
  {
    REGISTER_CALLBACK("check_alt_window", gen_block_ts_alt_window_base::check_alt_window);
  }

  bool check_block_verification_context(const cryptonote::block_verification_context& bvc, size_t event_idx, const cryptonote::block& /*blk*/)
  {
    if (event_idx == 126)
      return rejected ? bvc.m_verifivation_failed : !bvc.m_verifivation_failed && !bvc.m_added_to_main_chain;
    return !bvc.m_verifivation_failed && (event_idx <= 64 || !bvc.m_added_to_main_chain);
  }

  bool check_alt_window(cryptonote::core& c, size_t /*ev_index*/, const std::vector<test_event_entry>& /*events*/)
  {
    DEFINE_TESTS_ERROR_CONTEXT("gen_block_ts_alt_window_base::check_alt_window");
    CHECK_EQ(65, c.get_current_blockchain_height());
    CHECK_EQ((rejected ? 62u : 63u), c.get_alternative_blocks_count());
    return true;
  }
};

struct gen_block_ts_alt_window_before_strict : public gen_block_ts_alt_window_base<false>
{
  bool generate(std::vector<test_event_entry>& events) const;
};
template<> struct get_test_options<gen_block_ts_alt_window_before_strict>: public get_strict_timestamps_test_options<100> {};

struct gen_block_ts_alt_window_strict : public gen_block_ts_alt_window_base<true>
{
  bool generate(std::vector<test_event_entry>& events) const;
};
template<> struct get_test_options<gen_block_ts_alt_window_strict>: public get_strict_timestamps_test_options<63> {};

template<uint64_t strict_height, bool median_chain>
struct gen_block_ts_miner_data_base : public test_chain_unit_base
{
  gen_block_ts_miner_data_base();
  bool generate(std::vector<test_event_entry>& events) const;
  bool check_miner_data(cryptonote::core& c, size_t ev_index, const std::vector<test_event_entry>& events);
};

struct gen_block_ts_miner_data_before_strict : public gen_block_ts_miner_data_base<100, true> {};
template<> struct get_test_options<gen_block_ts_miner_data_before_strict>: public get_strict_timestamps_test_options<100> {};

struct gen_block_ts_miner_data_strict : public gen_block_ts_miner_data_base<70, true> {};
template<> struct get_test_options<gen_block_ts_miner_data_strict>: public get_strict_timestamps_test_options<70> {};

struct gen_block_ts_miner_data_parent_strict : public gen_block_ts_miner_data_base<2, false> {};
template<> struct get_test_options<gen_block_ts_miner_data_parent_strict>: public get_strict_timestamps_test_options<2> {};

struct gen_block_ts_future_flag : public test_chain_unit_base
{
  gen_block_ts_future_flag();
  bool generate(std::vector<test_event_entry>& events) const;
  bool check_block_verification_context(const cryptonote::block_verification_context& bvc, size_t event_idx, const cryptonote::block& /*blk*/);
  bool check_future_flags(cryptonote::core& c, size_t ev_index, const std::vector<test_event_entry>& events);
};

struct gen_block_ts_future_cache : public test_chain_unit_base
{
  gen_block_ts_future_cache();
  bool generate(std::vector<test_event_entry>& events) const;
  bool check_block_verification_context(const cryptonote::block_verification_context& bvc, size_t event_idx, const cryptonote::block& /*blk*/);
  bool wait_for_expiry(cryptonote::core& c, size_t ev_index, const std::vector<test_event_entry>& events);
  bool check_future_cache(cryptonote::core& c, size_t ev_index, const std::vector<test_event_entry>& events);
};

struct gen_block_ts_future_low_difficulty_alt : public test_chain_unit_base
{
  bool generate(std::vector<test_event_entry>& events) const;
  bool check_block_verification_context(const cryptonote::block_verification_context& bvc, size_t event_idx, const cryptonote::block& /*blk*/);
};
