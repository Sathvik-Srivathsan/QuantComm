/* qc_replay.h — bounded server replay cache (plan B-22.2).
 *
 * Key (64 B exact): device-id[16] || epoch u32-BE || N_W[12] ||
 *   SHA-256(ct_S)[32], concatenated in this order. Binds the ciphertext
 *   without storing it. One-byte mutation of any component misses.
 *
 * Value: full M2 bytes (for idempotent resend) + completed flag, where
 * completed means "M2 stored" and nothing more. Lifecycle: insert
 * (in-flight, pinned) -> pipeline runs KEM/derive -> complete (stores M2)
 * — or the entry stays pinned in-flight on failure paths until removed.
 * The resend-vs-drop POLICY lives in the pipeline (B-22.1), not here:
 * this unit reports the flag and the bytes; it does not decide. Current
 * pipeline policy (qc_server, documented there): a live hit resends the
 * stored M2 (covers the B-20.4 retry carve-out; byte-identical, zero new
 * KEM work, security-neutral — replayed M1s can only ever receive the
 * same M2 bytes already on the wire). The drop-on-established-session
 * rule activates with the session registry (B-40), which owns the
 * established signal this unit cannot see.
 *
 * Eviction: LRU over COMPLETED entries only; in-flight entries are pinned
 * (no fresh KEM work from eviction, ever). Expiry: entries carry the
 * caller clock `now` (u64, opaque monotonic units — the caller owns clock
 * discipline; determinism for tests); an entry older than ttl is treated
 * as absent and its slot reusable. In-flight entries expire too (timeout),
 * so a dead handshake cannot pin memory forever. Clock-backward edge: if
 * caller time runs behind all stamps, everything reads fresh and nothing
 * is evictable (FULL possible with completed entries present) — correct
 * fail-safe direction for a broken clock; the caller must not run the
 * clock backwards.
 *
 * Capacity in entries, clamped to [1, QC_CACHE_MAX]. No heap, no threads:
 * fixed array sized QC_CACHE_MAX; only the first `cap` slots used.
 * Counters/audit live in the pipeline (B-22.3), not here.
 */
#ifndef QC_REPLAY_H
#define QC_REPLAY_H

#include <stddef.h>
#include <stdint.h>

#define QC_CACHE_KEY_LEN 64
#define QC_CACHE_MAX 1024

/* Largest M2 this cache will store (version + ct_W max + N_S + MAC).
 * ct_W max 1568 B (ML-KEM-1024) -> 1+1568+32+32 = 1633; headroom to 2048.
 * Oversize M2 is a caller bug (pipeline sizes M2 from the level table). */
#define QC_CACHE_M2_MAX 2048

typedef enum {
    QC_CACHE_OK = 0,
    QC_CACHE_BAD_LEN,  /* NULL graduates, over-cap M2, zero capacity. */
    QC_CACHE_FULL,     /* no evictable slot (all pinned in-flight). */
    QC_CACHE_MISS      /* lookup: absent or expired. */
} qc_cache_rc;

typedef struct {
    uint8_t key[QC_CACHE_KEY_LEN];
    uint8_t m2[QC_CACHE_M2_MAX];
    size_t m2_len;
    uint8_t completed;  /* 0 in-flight (pinned), 1 completed. */
    uint8_t occupied;
    uint64_t stamp;     /* caller `now` at insert/complete (LRU + expiry). */
} qc_cache_entry;

typedef struct {
    qc_cache_entry slots[QC_CACHE_MAX];
    size_t cap;         /* active slots: [1, QC_CACHE_MAX]. */
    uint64_t ttl;       /* resend-window/expiry horizon, caller units. */
} qc_cache;

/* Build a cache key. ct may be any length (hashed, not stored);
 * ct NULL iff ct_len 0 (empty ciphertext hashes cleanly). id/nw/key
 * must be non-NULL (NULL key output is a caller bug; not checked —
 * the pipeline never passes NULL here and the audit pins it). */
void qc_cache_key(const uint8_t id[16], uint32_t epoch,
                  const uint8_t nw[12],
                  const uint8_t *ct, size_t ct_len,
                  uint8_t key[QC_CACHE_KEY_LEN]);

/* Init. cap 0 rejected; cap > MAX clamped; ttl 0 means never expire.
 * Clears all QC_CACHE_MAX slots (only the first `cap` are used). */
qc_cache_rc qc_cache_init(qc_cache *c, size_t cap, uint64_t ttl);

/* Insert as in-flight (pinned). Duplicate key (unexpired) -> OK without
 * disturbing the entry (idempotent; same attempt re-announced). Expired
 * slots are reused first; else LRU completed victim; else FULL. */
qc_cache_rc qc_cache_insert(qc_cache *c, const uint8_t key[QC_CACHE_KEY_LEN],
                            uint64_t now);

/* Mark completed and store M2 for resend. Missing/expired key -> MISS.
 * Re-completing overwrites (same attempt retried post-store is caller bug
 * territory; last write wins, documented). */
qc_cache_rc qc_cache_complete(qc_cache *c, const uint8_t key[QC_CACHE_KEY_LEN],
                              const uint8_t *m2, size_t m2_len, uint64_t now);

/* Lookup. Returns entry pointer (borrowed, valid until next mutating call)
 * or NULL on absent/expired. Caller branches on entry->completed. */
const qc_cache_entry *qc_cache_lookup(qc_cache *c,
                                      const uint8_t key[QC_CACHE_KEY_LEN],
                                      uint64_t now);

/* Remove (failure-path teardown). Missing -> MISS (not an error to the
 * pipeline beyond branch logic; code lets pipeline count accurately). */
qc_cache_rc qc_cache_remove(qc_cache *c, const uint8_t key[QC_CACHE_KEY_LEN]);

#endif