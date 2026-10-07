/* qc_server.h — server handshake pipeline, one device (plan B-20.3/B-22.1).
 *
 * Single device context (multi-device registry is B-40): provisioned
 * identity + Kdev + floor + this server's KEM level/keypair. Runs the
 * ordered pipeline per M1: parse -> HMAC-Kdev verify -> epoch check ->
 * replay-cache check -> floor check -> decaps K1 -> encaps K2 -> KDF
 * derive -> transcript + N_S + confirmation MAC -> cache store -> emit M2.
 * No step skippable or reorderable (order enforced by code sequence).
 *
 * Wire level codes (B-20 gap fill, flagged for phase gate): M1 carries L
 * as ONE byte, which cannot hold 512/768/1024. This chunk uses
 * 1->ML-KEM-512, 2->768, 3->1024 (ordinal-preserving, so floor comparison
 * is meaningful). The codepoints are NOT in B-20.1 — phase gate owns them.
 *
 * Resend policy (B-20.4 carve-out + B-22.1, documented): a live cache hit
 * (bit-identical M1) resends the stored M2 bytes with zero new KEM work.
 * Security-neutral: replays can only ever receive the same M2 already on
 * the wire (no fresh keys, no new material). The drop-on-established
 * rule needs the session registry (B-40) and activates there.
 * Equal (epoch,counter) with DIFFERENT bytes (cache miss) is a replay
 * attempt -> drop + replay-drop counter. Lower (epoch,counter) -> drop +
 * replay-drop counter (stale-epoch replays; phase gate may split this).
 *
 * Failure vocabulary: DROP = no state change except counters (parse,
 * HMAC, epoch, replay classes); ABORT = per-attempt teardown (floor,
 * decaps, encaps, RNG, KDF, emit-capacity). HMAC failures take the
 * auth-fail path, never the replay path (order enforced: HMAC before
 * cache). Backend codes surface in the abort code family.
 *
 * Epoch state is IN MEMORY (last seen per device). Persistence across
 * reboot is B-23/B-13 (NVS); this unit documents the handoff, not the
 * mechanism. Audit records are B-40 (counters here feed them).
 *
 * SIZE: struct embeds the replay cache (~2.1 MB). ALWAYS static, never
 * stack-local (same rule as the cache unit tests).
 */
#ifndef QC_SERVER_H
#define QC_SERVER_H

#include <stddef.h>
#include <stdint.h>

#include "qc_kdf.h"
#include "qc_kem.h"
#include "qc_replay.h"

/* Wire level codepoints (see header comment: B-20 gap fill). */
#define QC_WIRE_L512 1
#define QC_WIRE_L768 2
#define QC_WIRE_L1024 3

/* Largest M2 this pipeline emits (level table maximum). */
#define QC_SRV_M2_MAX (1 + 1568 + 32 + 32)

/* Largest transcript (M1 max + M2-body max): M1 at 1024 is
 * 1+16+1+1568+1568+12+32 = 4198 B; M2-body 1633 B; total 5831 B. */
#define QC_SRV_TRANSCRIPT_MAX 8192

/* Six B-22.3 counters, 64-bit saturating. */
typedef struct {
    uint64_t parse_fail;
    uint64_t auth_fail;
    uint64_t replay_drop;
    uint64_t hs_attempt;
    uint64_t floor_refusal;
    uint64_t failconf_obs; /* unwired: stays 0 until B-24 traffic confirms. */
} qc_srv_counters;

typedef struct {
    uint8_t identity[16];
    uint8_t kdev[32];
    uint8_t floor_wire;     /* floor in wire codepoints (ordinal). */
    uint8_t level_wire;     /* this server's level, wire codepoint. */
    qc_kem_level level;     /* decoded KEM level. */
    uint8_t server_pk[1568];
    uint8_t server_sk[3168];
    uint8_t has_last;       /* epoch state valid. */
    uint32_t last_epoch;
    uint64_t last_counter;
    qc_cache cache;
    qc_srv_counters cnt;
    uint64_t decaps_calls;  /* test-visibility KEM op counts (B-22.4). */
    uint64_t encaps_calls;
    /* Established session keys (single device). Set on EMIT (old keys
     * wiped first); failure paths never touch them. B-24 owns session
     * use; B-20.5/B-21 own erasure events (wiped at next handshake). */
    uint8_t session_valid;
    qc_kdf_keys session;
} qc_server;

/* Disposition (fail-closed taxonomy; tests assert exact codes). */
typedef enum {
    QC_SRV_OK_EMIT = 0, /* M2 emitted (m2_len set). */
    QC_SRV_RESEND,      /* bit-identical retry: stored M2 re-emitted. */
    QC_SRV_DROP_PARSE,
    QC_SRV_DROP_HMAC,
    QC_SRV_DROP_EPOCH,
    QC_SRV_DROP_REPLAY,
    QC_SRV_ABORT_FLOOR,
    QC_SRV_ABORT_DECAPS,
    QC_SRV_ABORT_ENCAPS,
    QC_SRV_ABORT_RNG,
    QC_SRV_ABORT_KDF,
    QC_SRV_ABORT_EMIT,  /* caller m2 buffer too small (caller bug). */
    QC_SRV_BAD_INIT     /* init: NULL, bad level/floor encoding. */
} qc_srv_rc;

/* Init. server_pk/sk sized for `level` (512/768/1024). cache_cap/ttl
 * forwarded to the replay cache. floor/level as WIRE codepoints. */
qc_srv_rc qc_server_init(qc_server *s,
                         const uint8_t identity[16],
                         const uint8_t kdev[32],
                         uint8_t floor_wire, uint8_t level_wire,
                         const uint8_t *server_pk, const uint8_t *server_sk,
                         size_t cache_cap, uint64_t cache_ttl);

/* Process one M1. m2_out must hold QC_SRV_M2_MAX (checked). now = caller
 * clock for the cache (opaque units). m2_len set on EMIT/RESEND only.
 * N_S drawn from qc_rng_generate (link-time provider: test RNG in tests,
 * B-13 provider in production). */
qc_srv_rc qc_server_m1(qc_server *s,
                       const uint8_t *m1, size_t m1_len,
                       uint8_t *m2_out, size_t m2_cap,
                       uint64_t now, size_t *m2_len);

#endif