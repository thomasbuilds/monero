#!/usr/bin/env python3
#
# Reference values for the ASERT difficulty tests, from exact integer arithmetic.
#
#   gen_asert_vectors.py unit    the vectors of TEST(difficulty, asert_vectors) in tests/unit_tests/difficulty.cpp
#   gen_asert_vectors.py core    the asert_model_* arrays of tests/core_tests/block_validation.cpp

import random
import sys

TARGET = 120
HALF_LIFE = 43200
LAG = 30
MAX_DIFFICULTY = (1 << 128) - 1
MAX_UINT64 = (1 << 64) - 1


def pow2_factor(frac):
    """2^(frac / 65536) * 65536 by the cubic approximation of aserti3-2d"""
    return 65536 + ((195766423245049 * frac + 971821376 * frac**2 + 5127 * frac**3 + (1 << 47)) >> 48)


def next_difficulty_asert(anchor_difficulty, anchor_time, time, blocks, target=TARGET, half_life=HALF_LIFE):
    """anchor_difficulty * 2^((target * blocks - (time - anchor_time)) / half_life) within [1, 2^128 - 1]

    The exponent has 16 fractional bits and is truncated toward zero, the result is rounded down."""
    ahead = target * blocks - (time - anchor_time)
    exponent = abs(ahead) * 65536 // half_life
    if ahead < 0:
        exponent = -exponent
    shifts, frac = exponent >> 16, exponent & 0xffff
    if shifts >= 128:
        return MAX_DIFFICULTY
    difficulty = anchor_difficulty * pow2_factor(frac)
    difficulty = difficulty << (shifts - 16) if shifts >= 16 else difficulty >> (16 - shifts)
    return min(max(difficulty, 1), MAX_DIFFICULTY)


def next_difficulty(timestamps, cumulative_difficulties, target=TARGET):
    """cryptonote::next_difficulty for a chain too short for the cut"""
    assert len(timestamps) <= 600
    if len(timestamps) <= 1:
        return 1
    time_span = max(max(timestamps) - min(timestamps), 1)
    total_work = cumulative_difficulties[-1] - cumulative_difficulties[0]
    return (total_work * target + time_span - 1) // time_span


def chain_difficulty(timestamps, cumulative_difficulties, fork_height):
    """difficulty of the next block of a chain given from the genesis block on, ASERT from fork_height"""
    height = len(timestamps)
    if height < fork_height:
        return next_difficulty(timestamps[1:], cumulative_difficulties[1:])
    anchor = max(fork_height - 1, 2)
    if height <= anchor:
        return 1
    anchor_difficulty = cumulative_difficulties[anchor] - cumulative_difficulties[anchor - 1]
    newest = height - 1 - LAG
    if newest < anchor:
        return anchor_difficulty
    return next_difficulty_asert(anchor_difficulty, timestamps[anchor - 1], timestamps[newest], newest - anchor + 1)


def unit_vectors():
    rng = random.Random(20261113)
    rows = []

    def add(target, half_life, difficulty, anchor_time, time, blocks):
        rows.append((target, half_life, difficulty, anchor_time, time, blocks,
                     next_difficulty_asert(difficulty, anchor_time, time, blocks, target, half_life)))

    base, blocks = 1700000000, 1000
    # around the schedule, the half-life and the saturation points
    for ahead in (0, 1, -1, 119, -119, HALF_LIFE // 2, -(HALF_LIFE // 2), HALF_LIFE - 1, HALF_LIFE, HALF_LIFE + 1,
                  -HALF_LIFE + 1, -HALF_LIFE, -HALF_LIFE - 1, 7200, -7200, 40 * HALF_LIFE, -40 * HALF_LIFE,
                  128 * HALF_LIFE - 1, 128 * HALF_LIFE, -128 * HALF_LIFE + 1, -128 * HALF_LIFE):
        add(TARGET, HALF_LIFE, 600000000000, base, base + TARGET * blocks - ahead, blocks)
    for half_life in (21600, 86400):
        for ahead in (1, -1, 7200, -7200):
            add(TARGET, half_life, 600000000000, base, base + TARGET * blocks - ahead, blocks)
    # the ends of the difficulty range
    for difficulty in (1, 3, (1 << 64) + 1, (1 << 127) + 5, MAX_DIFFICULTY):
        for ahead in (1, -1, HALF_LIFE // 3, -(HALF_LIFE // 3), 5 * HALF_LIFE + 17, -5 * HALF_LIFE - 17,
                      127 * HALF_LIFE, 127 * HALF_LIFE + 1, -127 * HALF_LIFE, -127 * HALF_LIFE - 1):
            add(TARGET, HALF_LIFE, difficulty, base, base + TARGET * blocks - ahead, blocks)
    # anchor_difficulty * factor just above 2^144, shifted to the top of 256 bits (with a half-life of 65536 the
    # exponent is the time ahead)
    for frac in (1, 40000, 65535):
        difficulty = -((-(1 << 144)) // pow2_factor(frac))
        for whole in (127, 128):
            add(TARGET, 65536, difficulty, 1 << 40, (1 << 40) + TARGET * 1000000 - (whole * 65536 + frac), 1000000)
    # the two fractions at which the last digit of the quadratic coefficient changes the factor
    for frac in (42375, 64937):
        add(TARGET, 65536, 600000000000, base, base + TARGET * blocks - frac, blocks)
    # the ends of the 64-bit inputs
    for anchor_time, time, count in ((0, 0, 0), (0, MAX_UINT64, 0), (MAX_UINT64, 0, 0), (MAX_UINT64, MAX_UINT64, MAX_UINT64),
                                     (0, MAX_UINT64, MAX_UINT64), (MAX_UINT64, 0, MAX_UINT64), (0, 120, 1), (1, 0, 1),
                                     (0, 1700000000, 1), (1700000000, 0, 14166667)):
        add(TARGET, HALF_LIFE, 600000000000, anchor_time, time, count)
    add(MAX_UINT64, MAX_UINT64, 12345, MAX_UINT64, MAX_UINT64, MAX_UINT64)
    add(1, 1, 12345, 5, 3, 7)
    add(60, 7, MAX_DIFFICULTY, 1000, 2000, 16)
    for _ in range(20):
        half_life = rng.choice((21600, HALF_LIFE, HALF_LIFE, HALF_LIFE, 86400))
        difficulty = int(2 ** rng.uniform(0, 127.9))
        count = rng.randrange(1, 3000000)
        anchor_time = rng.randrange(1 << 30, 1 << 31)
        add(TARGET, half_life, difficulty, anchor_time, anchor_time + TARGET * count + rng.randrange(-30 * half_life, 30 * half_life), count)
    return rows


class Chain:
    """the difficulties of a core test chain with ASERT from fork_height, from its timestamps"""

    def __init__(self, fork_height):
        self.fork_height = fork_height
        self.timestamps = [1338224400]
        self.cumulative_difficulties = [1]

    def next(self):
        return chain_difficulty(self.timestamps, self.cumulative_difficulties, self.fork_height)

    def mine(self, step):
        self.cumulative_difficulties.append(self.cumulative_difficulties[-1] + self.next())
        self.timestamps.append(self.timestamps[-1] + step)

    def cut(self, height):
        chain = Chain(self.fork_height)
        chain.timestamps = self.timestamps[:height]
        chain.cumulative_difficulties = self.cumulative_difficulties[:height]
        return chain

    def model(self, first_height):
        difficulties = [b - a for a, b in zip(self.cumulative_difficulties, self.cumulative_difficulties[1:])]
        return difficulties[first_height - 1:] + [self.next()]


def core_models():
    fork_height = 14

    # gen_block_difficulty_asert
    main_1 = Chain(fork_height)
    for step in [120] * 5 + [1] * 7 + [-20000, -30000, 50000 + 3 * TARGET, TARGET + 1, 1, 3600, HALF_LIFE] + [1] * 36:
        main_1.mine(step)
    alt_1 = main_1.cut(20)
    for step in [HALF_LIFE] + [1] * (LAG + 2):
        alt_1.mine(step)
    assert alt_1.cumulative_difficulties[-1] < main_1.cumulative_difficulties[-1]

    # gen_block_difficulty_asert_reorg
    main_2 = Chain(fork_height)
    for step in [120] * 5 + [1] * 7 + [TARGET + 1, 1, 5000, 5000] + [1] * 29:
        main_2.mine(step)
    alt_2 = main_2.cut(fork_height - 3)
    steps = [200, 1, TARGET + 1, -90000]
    heavier = 0
    while heavier < 3:
        alt_2.mine(steps.pop(0) if steps else 1)
        heavier += alt_2.cumulative_difficulties[-1] > main_2.cumulative_difficulties[-1]

    # gen_block_difficulty_asert_early
    early = Chain(2)
    for step in [100000, -99999] + [1] * (LAG + 6):
        early.mine(step)

    return (('asert_model_main_1', main_1.model(1)), ('asert_model_alt_1', alt_1.model(20)),
            ('asert_model_main_2', main_2.model(1)), ('asert_model_alt_2', alt_2.model(fork_height - 3)),
            ('asert_model_early', early.model(1)))


if len(sys.argv) == 2 and sys.argv[1] == 'unit':
    for row in unit_vectors():
        print('    {%dull, %dull, "%d", %dull, %dull, %dull, "%d"},' % row)
elif len(sys.argv) == 2 and sys.argv[1] == 'core':
    for name, model in core_models():
        print('  const std::vector<uint64_t> %s = {%s};' % (name, ', '.join(map(str, model))))
else:
    sys.exit('usage: gen_asert_vectors.py unit|core')
