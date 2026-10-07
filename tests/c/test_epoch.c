/* test_epoch.c — L0/L1/L2 for nonce lifecycle discipline (B-23.1/B-23.2).
 *
 * Storage backend is RAM hooks with fault injection (dropped writes,
 * torn commit-flag, corrupted CRC): power-loss simulation without
 * hardware. B-13.3 file/NVS hooks plug the same interface later with
 * zero logic change. White-box struct pokes (counter/epoch saturation)
 * are marked as such — those two comparisons are untestable by iteration
 * (2^64/2^32 steps) any other way.
 */
#include "unity.h"

#include <string.h>

#include "qc_epoch.h"

/* RAM slot backend + fault injection. */
static uint8_t ram_slots[2][QC_EPOCH_SLOT_LEN];
static int fail_writes = 0;   /* drop whole writes when nonzero. */
static int torn_commit = 0;   /* write all but the commit-flag byte. */

static int ram_read(int slot, uint8_t out[QC_EPOCH_SLOT_LEN]) {
    if (slot < 0 || slot > 1) {
        return -1;
    }
    memcpy(out, ram_slots[slot], QC_EPOCH_SLOT_LEN);
    return 0;
}

static int ram_write(int slot, const uint8_t in[QC_EPOCH_SLOT_LEN]) {
    size_t n = QC_EPOCH_SLOT_LEN;
    if (slot < 0 || slot > 1) {
        return -1;
    }
    if (fail_writes) {
        return -1;
    }
    if (torn_commit) {
        n = QC_EPOCH_SLOT_LEN - 1; /* commit flag never lands. */
    }
    memcpy(ram_slots[slot], in, n);
    return 0;
}

static void ram_clear(void) {
    memset(ram_slots, 0, sizeof(ram_slots));
    fail_writes = 0;
    torn_commit = 0;
}

static void mk(qc_epoch *e) {
    e->read = ram_read;
    e->write = ram_write;
    e->epoch = 0;
    e->counter = 0;
    e->loaded = 0;
}

static void test_crc_check_value(void) {
    static const uint8_t v[] = { '1', '2', '3', '4', '5',
                                 '6', '7', '8', '9' };
    TEST_ASSERT_EQUAL_UINT32(0xCBF43926u, qc_crc32(v, sizeof(v)));
    TEST_ASSERT_EQUAL_UINT32(0, qc_crc32(v, 0));
}

static void test_format_load(void) {
    qc_epoch e;

    ram_clear();
    mk(&e);
    TEST_ASSERT_EQUAL_INT(QC_EPOCH_UNINIT, qc_epoch_load(&e));
    TEST_ASSERT_EQUAL_INT(QC_EPOCH_OK, qc_epoch_format(&e, 5));
    TEST_ASSERT_EQUAL_UINT(5, e.epoch);
    /* Reload from medium: same epoch, counter reset. */
    e.loaded = 0;
    TEST_ASSERT_EQUAL_INT(QC_EPOCH_OK, qc_epoch_load(&e));
    TEST_ASSERT_EQUAL_UINT(5, e.epoch);
    TEST_ASSERT_EQUAL_UINT64(0, e.counter);
}

static void test_bump_sequence(void) {
    qc_epoch e;
    uint8_t nw[12];

    ram_clear();
    mk(&e);
    TEST_ASSERT_EQUAL_INT(QC_EPOCH_OK, qc_epoch_format(&e, 5));
    TEST_ASSERT_EQUAL_INT(QC_EPOCH_OK, qc_epoch_bump(&e));
    TEST_ASSERT_EQUAL_UINT(6, e.epoch);
    TEST_ASSERT_EQUAL_INT(QC_EPOCH_OK, qc_epoch_bump(&e));
    TEST_ASSERT_EQUAL_UINT(7, e.epoch);
    /* Nonces carry epoch-BE || counter-BE, monotonic. */
    TEST_ASSERT_EQUAL_INT(QC_EPOCH_OK, qc_epoch_next(&e, nw));
    TEST_ASSERT_EQUAL_UINT8(0, nw[0]);
    TEST_ASSERT_EQUAL_UINT8(0, nw[1]);
    TEST_ASSERT_EQUAL_UINT8(0, nw[2]);
    TEST_ASSERT_EQUAL_UINT8(7, nw[3]);
    TEST_ASSERT_EQUAL_UINT8(0, nw[11]);
    TEST_ASSERT_EQUAL_INT(QC_EPOCH_OK, qc_epoch_next(&e, nw));
    TEST_ASSERT_EQUAL_UINT8(1, nw[11]);
    /* Bump resets the send counter. */
    TEST_ASSERT_EQUAL_INT(QC_EPOCH_OK, qc_epoch_bump(&e));
    TEST_ASSERT_EQUAL_INT(QC_EPOCH_OK, qc_epoch_next(&e, nw));
    TEST_ASSERT_EQUAL_UINT8(8, nw[3]);
    TEST_ASSERT_EQUAL_UINT8(0, nw[11]);
    /* Reload picks highest committed (spare alternation proof: after
     * 5->6->7->8 the medium holds 8 somewhere committable). */
    e.loaded = 0;
    TEST_ASSERT_EQUAL_INT(QC_EPOCH_OK, qc_epoch_load(&e));
    TEST_ASSERT_EQUAL_UINT(8, e.epoch);
}

/* Power loss mid-bump: dropped write -> old slot still valid. */
static void test_powerloss_dropped_write(void) {
    qc_epoch e;

    ram_clear();
    mk(&e);
    TEST_ASSERT_EQUAL_INT(QC_EPOCH_OK, qc_epoch_format(&e, 41));
    fail_writes = 1;
    TEST_ASSERT_EQUAL_INT(QC_EPOCH_IO_FAIL, qc_epoch_bump(&e));
    fail_writes = 0;
    e.loaded = 0;
    TEST_ASSERT_EQUAL_INT(QC_EPOCH_OK, qc_epoch_load(&e));
    TEST_ASSERT_EQUAL_UINT(41, e.epoch);
}

/* Torn write (commit flag never lands): new slot invalid, old wins. */
static void test_powerloss_torn_commit(void) {
    qc_epoch e;

    ram_clear();
    mk(&e);
    TEST_ASSERT_EQUAL_INT(QC_EPOCH_OK, qc_epoch_format(&e, 41));
    torn_commit = 1;
    TEST_ASSERT_EQUAL_INT(QC_EPOCH_IO_FAIL, qc_epoch_bump(&e));
    torn_commit = 0;
    e.loaded = 0;
    TEST_ASSERT_EQUAL_INT(QC_EPOCH_OK, qc_epoch_load(&e));
    TEST_ASSERT_EQUAL_UINT(41, e.epoch);
}

/* Highest valid wins (hand-crafted out-of-band second slot), fallback
 * when newest corrupts, halt when none valid. */
static void test_corrupt_recovery(void) {
    qc_epoch e;
    uint8_t slot[QC_EPOCH_SLOT_LEN];
    uint32_t crc;

    ram_clear();
    mk(&e);
    TEST_ASSERT_EQUAL_INT(QC_EPOCH_OK, qc_epoch_format(&e, 10));
    /* Hand-craft slot 1 = valid epoch 12 (bypasses bump/retire, models
     * out-of-band medium state): load must pick highest (12, not 10). */
    slot[0] = 0;
    slot[1] = 0;
    slot[2] = 0;
    slot[3] = 12;
    crc = qc_crc32(slot, 4);
    slot[4] = (uint8_t)(crc >> 24);
    slot[5] = (uint8_t)(crc >> 16);
    slot[6] = (uint8_t)(crc >> 8);
    slot[7] = (uint8_t)crc;
    slot[8] = QC_EPOCH_COMMITTED;
    memcpy(ram_slots[1], slot, QC_EPOCH_SLOT_LEN);
    e.loaded = 0;
    TEST_ASSERT_EQUAL_INT(QC_EPOCH_OK, qc_epoch_load(&e));
    TEST_ASSERT_EQUAL_UINT(12, e.epoch);
    /* Corrupt the newest: falls back to 10 (older but valid). */
    ram_slots[1][4] ^= 0xFF;
    e.loaded = 0;
    TEST_ASSERT_EQUAL_INT(QC_EPOCH_OK, qc_epoch_load(&e));
    TEST_ASSERT_EQUAL_UINT(10, e.epoch);
    /* Corrupt both: halt, never guess. */
    ram_slots[0][4] ^= 0xFF;
    e.loaded = 0;
    TEST_ASSERT_EQUAL_INT(QC_EPOCH_UNINIT, qc_epoch_load(&e));
}

/* Saturation halts (white-box: untestable by iteration). */
static void test_saturation(void) {
    qc_epoch e;
    uint8_t nw[12];

    ram_clear();
    mk(&e);
    TEST_ASSERT_EQUAL_INT(QC_EPOCH_OK, qc_epoch_format(&e, UINT32_MAX));
    TEST_ASSERT_EQUAL_INT(QC_EPOCH_SATURATED, qc_epoch_bump(&e));
    TEST_ASSERT_EQUAL_UINT(UINT32_MAX, e.epoch);
    mk(&e);
    TEST_ASSERT_EQUAL_INT(QC_EPOCH_OK, qc_epoch_format(&e, 3));
    e.counter = UINT64_MAX;
    TEST_ASSERT_EQUAL_INT(QC_EPOCH_SATURATED, qc_epoch_next(&e, nw));
}

/* Replay window: accept/dup/advance/stale/epoch-reset/gap-clear. */
static void test_window(void) {
    qc_window w;

    memset(&w, 0, sizeof(w));
    TEST_ASSERT_EQUAL_INT(QC_ACCEPT, qc_window_check(&w, 7u, 100u));
    TEST_ASSERT_EQUAL_INT(QC_DUP, qc_window_check(&w, 7u, 100u));
    TEST_ASSERT_EQUAL_INT(QC_ACCEPT, qc_window_check(&w, 7u, 101u));
    TEST_ASSERT_EQUAL_INT(QC_DUP, qc_window_check(&w, 7u, 100u));
    TEST_ASSERT_EQUAL_INT(QC_ACCEPT, qc_window_check(&w, 7u, 99u));
    TEST_ASSERT_EQUAL_INT(QC_DUP, qc_window_check(&w, 7u, 99u));
    /* Older epoch always stale, even for unseen counters. */
    TEST_ASSERT_EQUAL_INT(QC_STALE, qc_window_check(&w, 6u, 1000u));
    /* Newer epoch resets and accepts. */
    TEST_ASSERT_EQUAL_INT(QC_ACCEPT, qc_window_check(&w, 8u, 0u));
    TEST_ASSERT_EQUAL_INT(QC_DUP, qc_window_check(&w, 8u, 0u));
    /* Jump +200: gap clears the mask; the jumped-from counter is now
     * ancient history (below window) -> stale, not dup. */
    TEST_ASSERT_EQUAL_INT(QC_ACCEPT, qc_window_check(&w, 8u, 200u));
    TEST_ASSERT_EQUAL_INT(QC_STALE, qc_window_check(&w, 8u, 0u));
    TEST_ASSERT_EQUAL_INT(QC_STALE, qc_window_check(&w, 8u, 72u));
    TEST_ASSERT_EQUAL_INT(QC_ACCEPT, qc_window_check(&w, 8u, 73u));
    TEST_ASSERT_EQUAL_INT(QC_DUP, qc_window_check(&w, 8u, 73u));
    /* NULL window. */
    TEST_ASSERT_EQUAL_INT(QC_STALE, qc_window_check(NULL, 8u, 0u));
}

static int fail_read(int slot, uint8_t out[QC_EPOCH_SLOT_LEN]) {
    (void)slot;
    (void)out;
    return -1;
}

/* Guards: NULL hooks/buffers, unloaded bump/next, failing reads. */
static void test_guards(void) {
    qc_epoch e;
    uint8_t nw[12];

    ram_clear();
    mk(&e);
    /* Total medium failure: no slot readable -> UNINIT (halt). */
    e.read = fail_read;
    TEST_ASSERT_EQUAL_INT(QC_EPOCH_UNINIT, qc_epoch_load(&e));
    mk(&e);
    TEST_ASSERT_EQUAL_INT(QC_EPOCH_BAD_ARG, qc_epoch_format(NULL, 1));
    e.write = NULL;
    TEST_ASSERT_EQUAL_INT(QC_EPOCH_BAD_ARG, qc_epoch_format(&e, 1));
    mk(&e);
    TEST_ASSERT_EQUAL_INT(QC_EPOCH_BAD_ARG, qc_epoch_bump(&e));
    TEST_ASSERT_EQUAL_INT(QC_EPOCH_BAD_ARG, qc_epoch_next(&e, nw));
    TEST_ASSERT_EQUAL_INT(QC_EPOCH_BAD_ARG, qc_epoch_next(&e, NULL));
    TEST_ASSERT_EQUAL_INT(QC_EPOCH_BAD_ARG, qc_epoch_load(NULL));
}

void setUp(void) {
    ram_clear();
}

void tearDown(void) {}

int main(void) {
    UNITY_BEGIN();
    RUN_TEST(test_crc_check_value);
    RUN_TEST(test_format_load);
    RUN_TEST(test_bump_sequence);
    RUN_TEST(test_powerloss_dropped_write);
    RUN_TEST(test_powerloss_torn_commit);
    RUN_TEST(test_corrupt_recovery);
    RUN_TEST(test_saturation);
    RUN_TEST(test_window);
    RUN_TEST(test_guards);
    return UNITY_END();
}