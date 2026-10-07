/* qc_server.c — server handshake pipeline, one device (B-20.3/B-22.1).
 * Code order IS the pipeline order (B-22.1: no step skippable or
 * reorderable). Each step returns its disposition immediately; later
 * steps never run after an earlier failure (zero-KEM-work evidence for
 * structural/auth failures falls out structurally: decaps/encaps calls
 * sit strictly after the HMAC/epoch/cache/floor gates).
 */
#include "qc_server.h"

#include <string.h>

#include "qc_codec.h"
#include "qc_hmac.h"
#include "qc_kdf.h"
#include "qc_rng.h"
#include "qc_zeroize.h"

/* 64-bit saturating increment (B-22.3). Saturation emits no alarm here:
 * the alarm/audit sink is B-40; saturation without a sink would be a
 * silent stall, so this is flagged for the B-40 wiring (counter stuck
 * at UINT64_MAX is itself the observable signal). */
static uint64_t sat_inc(uint64_t *c) {
    if (*c < UINT64_MAX) {
        (*c)++;
    }
    return *c;
}

static qc_kem_level wire_to_level(uint8_t w, size_t *pk_len, size_t *ct_len) {
    switch (w) {
    case QC_WIRE_L512:
        *pk_len = QC_KEM512_PK_BYTES;
        *ct_len = QC_KEM512_CT_BYTES;
        return QC_KEM_512;
    case QC_WIRE_L768:
        *pk_len = QC_KEM768_PK_BYTES;
        *ct_len = QC_KEM768_CT_BYTES;
        return QC_KEM_768;
    case QC_WIRE_L1024:
        *pk_len = QC_KEM1024_PK_BYTES;
        *ct_len = QC_KEM1024_CT_BYTES;
        return QC_KEM_1024;
    default:
        *pk_len = 0;
        *ct_len = 0;
        return 0;
    }
}

qc_srv_rc qc_server_init(qc_server *s,
                         const uint8_t identity[16],
                         const uint8_t kdev[32],
                         uint8_t floor_wire, uint8_t level_wire,
                         const uint8_t *server_pk, const uint8_t *server_sk,
                         size_t cache_cap, uint64_t cache_ttl) {
    size_t pk_len, ct_len;
    qc_kem_level level;

    if (s == NULL || identity == NULL || kdev == NULL ||
        server_pk == NULL || server_sk == NULL) {
        return QC_SRV_BAD_INIT;
    }
    level = wire_to_level(level_wire, &pk_len, &ct_len);
    if (level == 0) {
        return QC_SRV_BAD_INIT;
    }
    if (floor_wire != QC_WIRE_L512 && floor_wire != QC_WIRE_L768 &&
        floor_wire != QC_WIRE_L1024) {
        return QC_SRV_BAD_INIT;
    }
    memset(s, 0, sizeof(*s));
    memcpy(s->identity, identity, 16);
    memcpy(s->kdev, kdev, 32);
    s->floor_wire = floor_wire;
    s->level_wire = level_wire;
    s->level = level;
    memcpy(s->server_pk, server_pk, pk_len);
    memcpy(s->server_sk, server_sk, qc_kem_sk_bytes(level));
    if (qc_cache_init(&s->cache, cache_cap, cache_ttl) != QC_CACHE_OK) {
        return QC_SRV_BAD_INIT;
    }
    return QC_SRV_OK_EMIT;
}

qc_srv_rc qc_server_m1(qc_server *s,
                       const uint8_t *m1, size_t m1_len,
                       uint8_t *m2_out, size_t m2_cap,
                       uint64_t now, size_t *m2_len) {
    /* Per-level sizes + crypto material (stack, wiped before return). */
    size_t pk_len, ct_len;
    qc_kem_level level;
    qc_m1_fields f;
    uint8_t mac[32];
    uint32_t epoch;
    uint64_t counter;
    uint8_t key[QC_CACHE_KEY_LEN];
    const qc_cache_entry *hit;
    uint8_t k1[32], k2[32];
    uint8_t ns[32];
    qc_kdf_keys keys;
    qc_m2_fields m2f;
    uint8_t m2body[QC_SRV_M2_MAX];
    size_t m2body_len, need;
    uint8_t transcript[QC_SRV_TRANSCRIPT_MAX];
    size_t transcript_len;
    int rc;

    if (s == NULL || m1 == NULL || m2_out == NULL || m2_len == NULL) {
        return QC_SRV_DROP_PARSE;
    }
    *m2_len = 0;

    /* (0) structural parse. Level-decodable first: L lives at byte 17
     * (version u8 + identity[16]); messages shorter than 18 B cannot
     * carry a level and are malformed. */
    if (m1_len < 18) {
        sat_inc(&s->cnt.parse_fail);
        return QC_SRV_DROP_PARSE;
    }
    if (m1[0] != QC_M1_VERSION) {
        sat_inc(&s->cnt.parse_fail);
        return QC_SRV_DROP_PARSE;
    }
    level = wire_to_level(m1[17], &pk_len, &ct_len);
    if (level == 0) {
        sat_inc(&s->cnt.parse_fail);
        return QC_SRV_DROP_PARSE;
    }
    if (qc_m1_len(pk_len, ct_len) == 0 ||
        m1_len != qc_m1_len(pk_len, ct_len)) {
        sat_inc(&s->cnt.parse_fail);
        return QC_SRV_DROP_PARSE;
    }
    if (qc_m1_parse(m1, m1_len, pk_len, ct_len, &f) != QC_CODEC_OK) {
        sat_inc(&s->cnt.parse_fail);
        return QC_SRV_DROP_PARSE;
    }
    /* Emit-capacity is knowable pre-KEM (level table): fail the caller's
     * undersize buffer before any crypto work, not after. Counted as
     * parse_fail (caller-side structural bug, same class as malformed
     * lengths). The resend path keeps its own check (stored M2 size is
     * only known at lookup). */
    /* Identity must match the provisioned device (single-device ctx):
     * the cache key is built from s->identity, so a mismatched id would
     * misattribute the session. (A wrong-device M1 fails HMAC anyway
     * under distinct Kdev; this gate covers shared/rotated credentials.) */
    if (memcmp(f.identity, s->identity, 16) != 0) {
        sat_inc(&s->cnt.parse_fail);
        return QC_SRV_DROP_PARSE;
    }
    if (qc_m2_len(ct_len) == 0 || qc_m2_len(ct_len) > m2_cap) {
        sat_inc(&s->cnt.parse_fail);
        return QC_SRV_ABORT_EMIT;
    }

    /* (1) HMAC-Kdev verify over all preceding bytes (before cache: bad
     * HMAC takes the auth-fail path, never the replay path). */
    qc_hmac_sha256(s->kdev, 32, m1, m1_len - 32, mac);
    {
        uint8_t diff = 0;
        size_t i;
        for (i = 0; i < 32; i++) {
            diff |= (uint8_t)(mac[i] ^ f.hmac[i]);
        }
        qc_zeroize(mac, sizeof(mac));
        if (diff != 0) {
            sat_inc(&s->cnt.auth_fail);
            return QC_SRV_DROP_HMAC;
        }
    }
    sat_inc(&s->cnt.hs_attempt);

    /* Epoch/counter from N_W (4-B epoch + 8-B counter, big-endian). */
    epoch = ((uint32_t)f.nonce[0] << 24) | ((uint32_t)f.nonce[1] << 16) |
            ((uint32_t)f.nonce[2] << 8) | (uint32_t)f.nonce[3];
    counter = ((uint64_t)f.nonce[4] << 56) | ((uint64_t)f.nonce[5] << 48) |
              ((uint64_t)f.nonce[6] << 40) | ((uint64_t)f.nonce[7] << 32) |
              ((uint64_t)f.nonce[8] << 24) | ((uint64_t)f.nonce[9] << 16) |
              ((uint64_t)f.nonce[10] << 8) | (uint64_t)f.nonce[11];

    /* Epoch gate FIRST (spec order: epoch before cache): lower than
     * last-seen is stale regardless of cache state. Equal advances to
     * the cache, which distinguishes identical-retry (hit -> resend)
     * from different-bytes (miss -> DROP_REPLAY below). Greater advances
     * to the cache normally. First handshake accepts any epoch. */
    if (s->has_last) {
        if (epoch < s->last_epoch ||
            (epoch == s->last_epoch && counter < s->last_counter)) {
            sat_inc(&s->cnt.replay_drop);
            return QC_SRV_DROP_EPOCH;
        }
    }

    /* (2) replay-cache check (key binds id/epoch/N_W/H(ct_S)).
     * Stored M2 (completed) -> RESEND identical bytes, zero new KEM work.
     * In-flight hit (no M2 stored yet — unreachable in sync flow, where
     * store precedes emit atomically; reachable only via manual poking
     * or a racing async attempt) -> DROP + replay-drop: full reprocessing
     * would risk emitting two different M2s (fresh coins) for one
     * attempt, desynchronizing device/server sessions. The device retry
     * schedule (B-20.2) re-announces; by then the entry is complete and
     * resends. Dropping is fail-closed; resending zeros would be wrong. */
    qc_cache_key(s->identity, epoch, f.nonce, f.ct_s, ct_len, key);
    hit = qc_cache_lookup(&s->cache, key, now);
    if (hit != NULL) {
        if (!hit->completed) {
            sat_inc(&s->cnt.replay_drop);
            return QC_SRV_DROP_REPLAY;
        }
        if (hit->m2_len > m2_cap) {
            return QC_SRV_ABORT_EMIT;
        }
        memcpy(m2_out, hit->m2, hit->m2_len);
        *m2_len = hit->m2_len;
        return QC_SRV_RESEND;
    }

    /* Equal (epoch,counter) with different bytes (cache miss above) is a
     * replay attempt: the retry path is identical-bytes only. */
    if (s->has_last && epoch == s->last_epoch &&
        counter == s->last_counter) {
        sat_inc(&s->cnt.replay_drop);
        return QC_SRV_DROP_REPLAY;
    }

    /* Pin in-flight BEFORE any fallible KEM work (failure paths remove;
     * success completes with M2). */
    if (qc_cache_insert(&s->cache, key, now) != QC_CACHE_OK) {
        /* Cache full of pinned entries: fail closed (drop, no KEM work).
         * Counted as replay-drop: the server cannot distinguish a
         * legitimate retry storm from attack here; phase gate may split. */
        sat_inc(&s->cnt.replay_drop);
        return QC_SRV_DROP_REPLAY;
    }

    /* (3) floor check on L (ordinal wire codepoints). */
    if (f.level < s->floor_wire) {
        qc_cache_remove(&s->cache, key);
        sat_inc(&s->cnt.floor_refusal);
        return QC_SRV_ABORT_FLOOR;
    }
    /* Single-level server: L must equal our level (multi-level registry
     * is B-40; floor step covers below-floor, this covers above/other). */
    if (f.level != s->level_wire) {
        qc_cache_remove(&s->cache, key);
        sat_inc(&s->cnt.parse_fail);
        return QC_SRV_DROP_PARSE;
    }

    /* (4) decaps K1 (backend code surfaced on abort). */
    s->decaps_calls++;
    rc = qc_kem_decaps(s->level, k1, f.ct_s, s->server_sk);
    if (rc != QC_KEM_OK) {
        qc_cache_remove(&s->cache, key);
        qc_zeroize(k1, sizeof(k1));
        return QC_SRV_ABORT_DECAPS;
    }

    /* (5) encaps to ek_W giving K2. */
    {
        uint8_t coins[32];
        if (qc_rng_generate(coins, sizeof(coins)) != 0) {
            qc_cache_remove(&s->cache, key);
            qc_zeroize(k1, sizeof(k1));
            return QC_SRV_ABORT_RNG;
        }
        s->encaps_calls++;
        rc = qc_kem_encaps(s->level, m2body, k2, f.ek, coins);
        qc_zeroize(coins, sizeof(coins));
        if (rc != QC_KEM_OK) {
            qc_cache_remove(&s->cache, key);
            qc_zeroize(k1, sizeof(k1));
            qc_zeroize(k2, sizeof(k2));
            return QC_SRV_ABORT_ENCAPS;
        }
    }

    /* (5b) derive PRK/keys (B-21). N_S drawn here (caller RNG above drew
     * encaps coins; N_S needs its own fresh 32 B). */
    if (qc_rng_generate(ns, sizeof(ns)) != 0) {
        qc_cache_remove(&s->cache, key);
        qc_zeroize(k1, sizeof(k1));
        qc_zeroize(k2, sizeof(k2));
        return QC_SRV_ABORT_RNG;
    }
    /* Transcript needs M2-body first: encode with zero confirm, hash,
     * derive, then MAC. m2body currently holds ct_W at [0..ct_len). */
    m2f.version = f.version;
    m2f.ct_w = m2body;
    m2f.ct_len = ct_len;
    memcpy(m2f.nonce_s, ns, 32);
    memset(m2f.confirm, 0, 32);
    /* M2-body = version || ct_W || N_S (confirm EXCLUDED — a tag cannot
     * cover itself). No zero placeholder: the transcript simply ends. */
    m2body_len = 1 + ct_len + 32;
    transcript_len = m1_len + m2body_len;
    if (transcript_len > sizeof(transcript)) {
        qc_cache_remove(&s->cache, key);
        goto wipe_abort_kdf;
    }
    memcpy(transcript, m1, m1_len);
    {
        /* M2-body bytes: version || ct_W || N_S (confirm excluded). */
        uint8_t *p = transcript + m1_len;
        p[0] = m2f.version;
        memcpy(p + 1, m2body, ct_len);
        memcpy(p + 1 + ct_len, ns, 32);
    }
    if (qc_kdf_derive(f.nonce, ns, k1, 32, k2, 32, s->kdev,
                      transcript, transcript_len, &keys) != 0) {
        qc_cache_remove(&s->cache, key);
        goto wipe_abort_kdf;
    }
    qc_zeroize(k1, sizeof(k1));
    qc_zeroize(k2, sizeof(k2));
    /* N_S consumed by the KDF (copied into salt): wipe the frame copy on
     * every path from here on (success + MAC + store + emit). */
    qc_zeroize(ns, sizeof(ns));

    /* (6) confirmation MAC over transcript, emit M2, store cache.
     * k_conf lives in `keys` until the session store below copies it;
     * no early field wipe (it would only destroy the retained copy). */
    qc_hmac_sha256(keys.k_conf, 32, transcript, transcript_len, m2f.confirm);
    need = qc_m2_len(ct_len);
    if (need == 0 || need > m2_cap) {
        qc_cache_remove(&s->cache, key);
        return QC_SRV_ABORT_EMIT;
    }
    m2f.ct_w = m2body; /* ct_W bytes already at m2body[0..ct_len). */
    if (qc_m2_encode(&m2f, m2_out, need) != QC_CODEC_OK) {
        qc_cache_remove(&s->cache, key);
        return QC_SRV_ABORT_EMIT;
    }
    *m2_len = need;
    if (qc_cache_complete(&s->cache, key, m2_out, need, now) != QC_CACHE_OK) {
        /* Unreachable in practice (entry was just inserted; need fits
         * QC_CACHE_M2_MAX by construction) — remove defensively so no
         * pinned in-flight entry leaks its slot. */
        qc_cache_remove(&s->cache, key);
        *m2_len = 0;
        return QC_SRV_ABORT_EMIT;
    }

    /* Advance epoch state + establish session (old keys wiped first;
     * erasure events owned by B-20.5/B-21, session use by B-24). */
    s->has_last = 1;
    s->last_epoch = epoch;
    s->last_counter = counter;
    qc_zeroize(&s->session, sizeof(s->session));
    memcpy(&s->session, &keys, sizeof(keys));
    qc_zeroize(&keys, sizeof(keys));
    s->session_valid = 1;
    qc_zeroize(ns, sizeof(ns));
    qc_zeroize(transcript, sizeof(transcript));
    return QC_SRV_OK_EMIT;

wipe_abort_kdf:
    qc_zeroize(k1, sizeof(k1));
    qc_zeroize(k2, sizeof(k2));
    return QC_SRV_ABORT_KDF;
}