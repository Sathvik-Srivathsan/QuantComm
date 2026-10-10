/* qc_drbg.c — HMAC-DRBG-SHA-256 (SP 800-90A §10.1.2).
 * Update(data): K = HMAC(K, V||0x00||data); V = HMAC(K, V);
 *               if data: K = HMAC(K, V||0x01||data); V = HMAC(K, V).
 * Instantiate (K=0,V=1) + Update(seed); Reseed = Update(seed); Generate:
 * optional reseed-check, temp loop V=HMAC(K,V), then Update(additional).
 */
#include "qc_drbg.h"

#include <string.h>
#include <unistd.h>

#include "qc_entropy.h"
#include "qc_hmac.h"
#include "qc_zeroize.h"

/* HMAC with explicit key/data (one-shot helper over streaming init). */
static void hmac2(const uint8_t *key, size_t klen,
                  const uint8_t *a, size_t alen,
                  const uint8_t *b, size_t blen,
                  const uint8_t *c, size_t clen,
                  uint8_t out[32]) {
    /* Our one-shot takes (key,key_len,msg,msg_len): concatenate small
     * parts on the stack. Audit F8: the workspace is an EXACT fit
     * (32+1+256 = 289 for V||0x01||seed) and stays safe ONLY because
     * both entry points gate inputs at QC_DRBG_MAX_SEED (reseed caps
     * entropy_len, generate caps add_len) — never silently truncated.
     * Any future caller passing longer material must add its own gate. */
    uint8_t msg[1 + 32 + QC_DRBG_MAX_SEED];
    size_t n = 0;

    if (alen > 0) {
        memcpy(msg + n, a, alen);
        n += alen;
    }
    if (blen > 0) {
        memcpy(msg + n, b, blen);
        n += blen;
    }
    if (clen > 0) {
        memcpy(msg + n, c, clen);
        n += clen;
    }
    qc_hmac_sha256(key, klen, msg, n, out);
    qc_zeroize(msg, sizeof(msg));
}

static void drbg_update(qc_drbg *d, const uint8_t *seed, size_t seed_len) {
    static const uint8_t zero[1] = { 0 };
    static const uint8_t one[1] = { 1 };

    hmac2(d->k, 32, d->v, 32, zero, 1, seed, seed_len, d->k);
    hmac2(d->k, 32, d->v, 32, NULL, 0, NULL, 0, d->v);
    if (seed_len > 0) {
        hmac2(d->k, 32, d->v, 32, one, 1, seed, seed_len, d->k);
        hmac2(d->k, 32, d->v, 32, NULL, 0, NULL, 0, d->v);
    }
}

int qc_drbg_init(qc_drbg *d) {
    if (d == NULL) {
        return -1;
    }
    memset(d, 0, sizeof(*d));
    return 0;
}

void qc_drbg_free(qc_drbg *d) {
    if (d == NULL) {
        return;
    }
    qc_zeroize(d, sizeof(*d));
}

int qc_drbg_reseed(qc_drbg *d, const uint8_t *entropy, size_t entropy_len) {
    /* Empty reseed is legal (still performs the mandatory 0x00 Update
     * round — this is exactly what NIST CAVS vectors exercise); only
     * the cap and NULL discipline are enforced here. Fresh-entropy
     * policy belongs to callers (auto-reseed always carries 32 B). */
    if (d == NULL || (entropy_len > 0 && entropy == NULL) ||
        entropy_len > QC_DRBG_MAX_SEED) {
        return -1;
    }
    if (!d->seeded) {
        memset(d->k, 0x00, 32);
        memset(d->v, 0x01, 32);
        d->seeded = 1;
    }
    /* SP 800-90A reseed_counter resets to 1 on every reseed (not
     * incremented: the counter bounds generates-per-seed, and a fresh
     * seed restarts the count). Record owner pid here too: otherwise the
     * next generate() sees pid-mismatch (fresh struct has pid 0) and
     * wrongly takes the fork path, discarding this seed. reseed_at is
     * left for reseed_from_provider (explicit reseed carries no clock;
     * first generate() with now >= T will auto-reseed once — harmless
     * and deterministic under the same provider). */
    d->reseed_ctr = 1;
    drbg_update(d, entropy, entropy_len);
    d->out_total = 0;
    d->pid = getpid();
    return 0;
}

int qc_drbg_reseed_from_provider(qc_drbg *d, uint64_t now) {
    uint8_t entropy[32];
    char audit[QC_ENTROPY_AUDIT_LEN];
    int rc;

    if (d == NULL) {
        return -1;
    }
    if (qc_entropy_poll(entropy, sizeof(entropy), audit) != 0) {
        qc_zeroize(entropy, sizeof(entropy));
        return -1;
    }
    rc = qc_drbg_reseed(d, entropy, sizeof(entropy));
    qc_zeroize(entropy, sizeof(entropy));
    if (rc != 0) {
        return -1;
    }
    d->reseed_at = now;
    return 0;
}

int qc_drbg_generate(qc_drbg *d, uint8_t *out, size_t len,
                     const uint8_t *add, size_t add_len, uint64_t now) {
    size_t done = 0;

    if (d == NULL || (len > 0 && out == NULL)) {
        return -1;
    }
    if (add_len > 0 && add == NULL) {
        return -1;
    }
    /* Additional input shares the stack-concat bound (hmac2 workspace);
     * KAT and production uses are far below it. */
    if (add_len > QC_DRBG_MAX_SEED) {
        return -1;
    }
    if (len > QC_DRBG_MAX_GEN) {
        return -1;
    }
    if (len == 0) {
        return 0;
    }
    /* Fork check FIRST: child pid differs -> zeroize + fresh reseed
     * (never continue the parent stream, never fail silently). */
    if (!d->seeded || getpid() != d->pid) {
        qc_zeroize(d, sizeof(*d));
        if (qc_drbg_reseed_from_provider(d, now) != 0) {
            return -1;
        }
    }
    /* R/T reseed policy before producing (reseed_at maintained inside
     * reseed_from_provider). */
    if (d->out_total + len > QC_DRBG_RESEED_BYTES ||
        (now >= d->reseed_at &&
         now - d->reseed_at >= QC_DRBG_RESEED_SECS)) {
        if (qc_drbg_reseed_from_provider(d, now) != 0) {
            return -1;
        }
    }
    if (d->reseed_ctr >= ((uint64_t)1 << 48)) {
        return -1;
    }
    /* SP 800-90A Generate step 2 (+ step 6 below): non-empty additional
     * input stirs state BEFORE producing output. Conditional (like the
     * reference): empty additional skips the pre-stir (its 0x00-only
     * round would otherwise perturb empty-add vectors, which must match
     * exactly). Omitting the conditional pre-stir breaks CAVS vectors
     * with additional input (found via cross-check). */
    if (add_len > 0) {
        drbg_update(d, add, add_len);
    }
    while (done < len) {
        size_t take;
        hmac2(d->k, 32, d->v, 32, NULL, 0, NULL, 0, d->v);
        take = len - done;
        if (take > 32) {
            take = 32;
        }
        memcpy(out + done, d->v, take);
        done += take;
    }
    drbg_update(d, add, add_len);
    d->out_total += len;
    d->reseed_ctr++;
    return 0;
}

int qc_drbg_selftest_stats(const uint8_t *buf, size_t len) {
    size_t i, ones = 0, total;

    if (buf == NULL || len == 0) {
        return -1;
    }
    for (i = 0; i < len; i++) {
        uint8_t b = buf[i];
        while (b != 0) {
            ones += (size_t)(b & 1u);
            b >>= 1;
        }
    }
    total = len * 8;
    /* |ones/total - 1/2| < 0.02  <=>  |2*ones - total| < total/25.
     * Integer-only (no float in crypto-adjacent code). */
    {
        uint64_t diff = ones * 2 > total ? (uint64_t)(ones * 2 - total)
                                         : (uint64_t)(total - ones * 2);
        if (diff * 25u >= total) {
            return -1;
        }
    }
    return 0;
}
