/* qc_replay.c — bounded server replay cache (B-22.2).
 * Array scan (cap <= 1024, handshake-rate lookups): no hash table, no
 * pointers, no alloc — the whole cache is caller-owned static storage.
 * LRU keyed on last-mutation stamp (insert/complete only; lookups and
 * duplicate inserts do NOT refresh — insertion order defines age, which
 * is exactly what a replay window wants). Expiry via caller `now`.
 */
#include "qc_replay.h"

#include <string.h>

#include "qc_sha256.h"

void qc_cache_key(const uint8_t id[16], uint32_t epoch,
                  const uint8_t nw[12],
                  const uint8_t *ct, size_t ct_len,
                  uint8_t key[QC_CACHE_KEY_LEN]) {
    uint8_t digest[32];

    /* Layout is normative (B-22.2): id || epoch-BE || N_W || H(ct_S). */
    memcpy(key, id, 16);
    key[16] = (uint8_t)(epoch >> 24);
    key[17] = (uint8_t)(epoch >> 16);
    key[18] = (uint8_t)(epoch >> 8);
    key[19] = (uint8_t)epoch;
    memcpy(key + 20, nw, 12);
    qc_sha256(ct, ct_len, digest);
    memcpy(key + 32, digest, 32);
}

qc_cache_rc qc_cache_init(qc_cache *c, size_t cap, uint64_t ttl) {
    size_t i;

    if (c == NULL) {
        return QC_CACHE_BAD_LEN;
    }
    if (cap == 0) {
        return QC_CACHE_BAD_LEN;
    }
    if (cap > QC_CACHE_MAX) {
        cap = QC_CACHE_MAX;
    }
    for (i = 0; i < QC_CACHE_MAX; i++) {
        c->slots[i].occupied = 0;
    }
    c->cap = cap;
    c->ttl = ttl;
    return QC_CACHE_OK;
}

static int key_eq(const uint8_t a[QC_CACHE_KEY_LEN],
                  const uint8_t b[QC_CACHE_KEY_LEN]) {
    return memcmp(a, b, QC_CACHE_KEY_LEN) == 0;
}

/* Expired iff ttl nonzero and now is past stamp+ttl (saturating compare:
 * now < stamp means caller clock went backwards — treat as fresh, never
 * as expired; clock discipline is the caller's, documented). Stamp+ttl
 * overflow pins the entry (fail-safe direction: keep, don't drop). */
static int is_expired(const qc_cache *c, const qc_cache_entry *e,
                      uint64_t now) {
    uint64_t end;

    if (c->ttl == 0) {
        return 0;
    }
    if (now < e->stamp) {
        return 0;
    }
    end = e->stamp + c->ttl;
    if (end < e->stamp) {
        return 0;
    }
    return now > end;
}

/* Live entry index or -1 (absent, unoccupied, or expired). */
static int find_live(qc_cache *c, const uint8_t key[QC_CACHE_KEY_LEN],
                     uint64_t now) {
    size_t i;

    for (i = 0; i < c->cap; i++) {
        if (c->slots[i].occupied && !is_expired(c, &c->slots[i], now) &&
            key_eq(c->slots[i].key, key)) {
            return (int)i;
        }
    }
    return -1;
}

/* Occupied slot index with matching key, ignoring expiry (teardown only).
 * Expired-but-present entries are dead weight the next insert reclaims. */
static int find_occupied(qc_cache *c, const uint8_t key[QC_CACHE_KEY_LEN]) {
    size_t i;

    for (i = 0; i < c->cap; i++) {
        if (c->slots[i].occupied && key_eq(c->slots[i].key, key)) {
            return (int)i;
        }
    }
    return -1;
}

static void occupy(qc_cache *c, size_t i,
                   const uint8_t key[QC_CACHE_KEY_LEN], uint64_t now) {
    memset(&c->slots[i], 0, sizeof(c->slots[i]));
    memcpy(c->slots[i].key, key, QC_CACHE_KEY_LEN);
    c->slots[i].occupied = 1;
    c->slots[i].completed = 0;
    c->slots[i].stamp = now;
}

qc_cache_rc qc_cache_insert(qc_cache *c, const uint8_t key[QC_CACHE_KEY_LEN],
                            uint64_t now) {
    size_t i, victim;
    uint64_t oldest;

    if (c == NULL || key == NULL) {
        return QC_CACHE_BAD_LEN;
    }
    if (find_live(c, key, now) >= 0) {
        /* Duplicate live key: same attempt re-announced. Idempotent —
         * disturb nothing (lifetime runs from first insert; LRU order
         * is by mutation, and a duplicate is not a mutation). */
        return QC_CACHE_OK;
    }
    /* Prefer an empty or expired slot. */
    for (i = 0; i < c->cap; i++) {
        if (!c->slots[i].occupied ||
            is_expired(c, &c->slots[i], now)) {
            occupy(c, i, key, now);
            return QC_CACHE_OK;
        }
    }
    /* LRU victim among COMPLETED only (in-flight pinned, never evicted:
     * no fresh KEM work from eviction, ever). */
    victim = c->cap;
    oldest = now;
    for (i = 0; i < c->cap; i++) {
        if (c->slots[i].completed && c->slots[i].stamp <= oldest) {
            oldest = c->slots[i].stamp;
            victim = i;
        }
    }
    if (victim >= c->cap) {
        return QC_CACHE_FULL;
    }
    occupy(c, victim, key, now);
    return QC_CACHE_OK;
}

qc_cache_rc qc_cache_complete(qc_cache *c, const uint8_t key[QC_CACHE_KEY_LEN],
                              const uint8_t *m2, size_t m2_len, uint64_t now) {
    int at;

    if (c == NULL || key == NULL) {
        return QC_CACHE_BAD_LEN;
    }
    if (m2_len > QC_CACHE_M2_MAX || (m2_len > 0 && m2 == NULL)) {
        return QC_CACHE_BAD_LEN;
    }
    at = find_live(c, key, now);
    if (at < 0) {
        return QC_CACHE_MISS;
    }
    if (m2_len > 0) {
        memcpy(c->slots[at].m2, m2, m2_len);
    }
    c->slots[at].m2_len = m2_len;
    c->slots[at].completed = 1;
    c->slots[at].stamp = now;
    return QC_CACHE_OK;
}

const qc_cache_entry *qc_cache_lookup(qc_cache *c,
                                      const uint8_t key[QC_CACHE_KEY_LEN],
                                      uint64_t now) {
    int at;

    if (c == NULL || key == NULL) {
        return NULL;
    }
    at = find_live(c, key, now);
    if (at < 0) {
        return NULL;
    }
    return &c->slots[at];
}

qc_cache_rc qc_cache_remove(qc_cache *c, const uint8_t key[QC_CACHE_KEY_LEN]) {
    int at;

    if (c == NULL || key == NULL) {
        return QC_CACHE_BAD_LEN;
    }
    at = find_occupied(c, key);
    if (at < 0) {
        return QC_CACHE_MISS;
    }
    memset(&c->slots[at], 0, sizeof(c->slots[at]));
    return QC_CACHE_OK;
}