/* qc_store.h — secure storage: schema, monotonicity, corruption (B-13.3).
 *
 * Items (RAM image): schema_version u16 (starts 1, monotonic), Kdev
 * (32 B, NEVER bare at rest — wrapped blob in the image), manifest
 * version u32 (persisted-max wins), epoch u64 (monotonic, saturate-
 * never-wrap), replay state (48 B opaque blob), backoff counters
 * (2x u64 saturating in use; stored plain).
 *
 * At-rest format: image || HMAC-32, where image =
 *   magic "QCS1"[4] || schema u16 || kdev_wrapped_len u16 ||
 *   kdev_wrapped (nonce12 || ct32 || tag16, AES-GCM under a KDF item
 *   key) || manifest_version u32 || epoch u64 || replay[48] ||
 *   backoff[2] u64.
 * Item keys derive from the storage root via HKDF-Expand with item
 * labels ("QC-STORE-KDEV", "QC-STORE-MAC"); the root (provisioned at
 * enrollment) is used directly as PRK (already uniform — documented,
 * not Extract-ed). Kdev wrap nonce is CALLER-supplied (explicit, like
 * every other coin in this tree — never hidden randomness).
 *
 * Rules enforced here: unknown-major schema on load -> HALT_VERSION
 * (never guess, never migrate silently — no old versions exist yet, so
 * forward-migration is noted future, not dead code); MAC failure ->
 * CORRUPT (halt); missing/empty backend -> NOT_FOUND (caller halts per
 * B-13.3 loss rules); epoch decrease or manifest-version decrease ->
 * STALE (monotonicity is anti-rollback); epoch at max -> SATURATED.
 * Wear accounting/coalescing, backup export, ESP32 NVS mapping: B-60 /
 * future (host file backend has no wear; documented, not stubbed).
 *
 * Persistence MECHANISM is caller hooks (whole-blob read/write); the
 * host file backend (qc_store_file.c) implements hooks over fopen.
 * SIZE: struct ~400 B caller static; no heap, no threads.
 */
#ifndef QC_STORE_H
#define QC_STORE_H

#include <stddef.h>
#include <stdint.h>

#define QC_STORE_SCHEMA_CURRENT 1
#define QC_STORE_REPLAY_LEN 48
#define QC_STORE_KDEV_WRAP_LEN (12 + 32 + 16)
#define QC_STORE_MAC_LEN 32
/* Fixed image (146 B) + file (178 B) sizes: part of the format contract
 * (backends enforce exact size; no truncation/padding ever). */
#define QC_STORE_IMAGE_LEN 146
#define QC_STORE_FILE_LEN (146 + 32)

typedef enum {
    QC_STORE_OK = 0,
    QC_STORE_BAD_ARG,
    QC_STORE_IO_FAIL,     /* backend hook failed (non-corrupt: caller
                           * distinguishes NOT_FOUND). */
    QC_STORE_NOT_FOUND,   /* backend empty/missing (loss -> halt path). */
    QC_STORE_CORRUPT,     /* MAC failure or undecodable image (halt). */
    QC_STORE_HALT_VERSION,/* unknown major schema (halt, never migrate). */
    QC_STORE_SATURATED,   /* epoch at max (halt, never wrap). */
    QC_STORE_STALE        /* monotonicity refusal (decrease attempt). */
} qc_store_rc;

typedef struct {
    uint8_t root[32];
    uint8_t has_root;
    uint16_t schema_version;
    uint8_t kdev[32];
    uint8_t has_kdev;
    uint32_t manifest_version;
    uint8_t has_manifest_version;
    uint64_t epoch;
    uint8_t has_epoch;
    uint8_t replay[QC_STORE_REPLAY_LEN];
    uint64_t backoff[2];
} qc_store;

/* Whole-blob backend hooks (file on host, NVS later). read returns bytes
 * + length (missing/empty -> NOT_FOUND mapping by the backend contract:
 * read_fn returns nonzero with *len 0 for absent). */
typedef int (*qc_store_read_fn)(uint8_t *out, size_t cap, size_t *len_out);
typedef int (*qc_store_write_fn)(const uint8_t *in, size_t len);

/* Provision with the storage root (enrollment). Clears all state. */
qc_store_rc qc_store_open(qc_store *s, const uint8_t root[32]);
void qc_store_close(qc_store *s);

/* Item setters (monotonicity enforced; STALE on decrease). Getters on
 * unset items return NOT_FOUND (nothing stored yet — not corruption). */
qc_store_rc qc_store_set_kdev(qc_store *s, const uint8_t kdev[32]);
qc_store_rc qc_store_get_kdev(const qc_store *s, uint8_t kdev[32]);
qc_store_rc qc_store_set_manifest_version(qc_store *s, uint32_t v);
qc_store_rc qc_store_set_epoch(qc_store *s, uint64_t epoch);
qc_store_rc qc_store_set_replay(qc_store *s,
                                const uint8_t replay[QC_STORE_REPLAY_LEN]);
qc_store_rc qc_store_set_backoff(qc_store *s, int idx, uint64_t v);

/* Persist the whole image through the backend hook. wrap_nonce must be
 * fresh per save whenever a Kdev is stored (GCM nonce discipline);
 * NULL iff no Kdev stored. */
qc_store_rc qc_store_save(qc_store *s, const uint8_t *wrap_nonce,
                          qc_store_write_fn write_fn);
qc_store_rc qc_store_load(qc_store *s, qc_store_read_fn read_fn);

/* Host file backend (qc_store_file.c): path-backed one-shot save/load.
 * wrap_nonce must be fresh per save whenever a Kdev is stored (NULL iff
 * none stored). ESP32 port swaps this TU for the NVS one (same header). */
qc_store_rc qc_store_file_save(qc_store *s, const char *path,
                               const uint8_t *wrap_nonce);
qc_store_rc qc_store_file_load(qc_store *s, const char *path);

#endif