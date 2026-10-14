/* srv_crypto.c — crypto servant for the Python service (B-40 bridge).
 *
 * HOST-ONLY (Linux): exposes the audited C adapters over argv/stdout so
 * the Python server/sim use the IDENTICAL implementations (no crypto
 * fork: same TUs, different calling convention — the E0 story). Static
 * linkage against qc_kem/qc_dsa/qc_aead (+ sha/hmac/hkdf/drbg/entropy
 * sources); no shared libs needed.
 *
 * Protocol: srv_crypto <cmd> <hex...> prints hex result lines, exit 0.
 * Failures exit with the ADAPTER rc value (0..5: OK/BAD_* — the enums
 * are smallints by audit); usage errors exit 2 with stderr text.
 * Secrets traverse stdout (piped, never logged — the no-plaintext test
 * enforces the caller's discipline, not this TU's). All key material
 * handled here is zeroized after use (qc_zeroize); output copies are
 * the caller's responsibility once printed.
 *
 * Determinism: every randomized input arrives as explicit caller coins
 * (derand APIs only) — same coins give byte-identical output, which is
 * what makes the service tests deterministic. The `rng` command is the
 * SOLE live-entropy path (prod server randomness); tests must never
 * call it (fixed coins instead — asserted by review, not by code).
 *
 * Input caps (per hex arg): 65536 bytes (argv MAX_ARG_STRLEN bound,
 * documented, not silently raised).
 */
#include <stdio.h>
#include <string.h>

#include "qc_aead.h"
#include "qc_dsa.h"
#include "qc_hkdf.h"
#include "qc_hmac.h"
#include "qc_kem.h"
#include "qc_rng.h"
#include "qc_sha256.h"
#include "qc_zeroize.h"
#include "srv_ctl.h" /* controller verbs (own audit surface in srv_ctl.c) */

#define ARG_CAP 65536

static uint8_t buf_a[ARG_CAP];
static uint8_t buf_b[ARG_CAP];
static uint8_t buf_c[ARG_CAP];
static uint8_t buf_o1[ARG_CAP];
static uint8_t buf_o2[ARG_CAP];

static int hexval(char c) {
    if (c >= '0' && c <= '9') {
        return c - '0';
    }
    if (c >= 'a' && c <= 'f') {
        return c - 'a' + 10;
    }
    if (c >= 'A' && c <= 'F') {
        return c - 'A' + 10;
    }
    return -1;
}

/* Decode hex s into out (cap); returns byte length or (size_t)-1. */
static size_t unhex(const char *s, uint8_t *out, size_t cap) {
    size_t sl, n, i;
    int hi, lo;

    if (s == NULL) {
        return (size_t)-1;
    }
    sl = strlen(s);
    if (sl % 2 != 0) {
        return (size_t)-1;
    }
    n = sl / 2;
    if (n > cap) {
        return (size_t)-1;
    }
    for (i = 0; i < n; i++) {
        hi = hexval(s[2 * i]);
        lo = hexval(s[2 * i + 1]);
        if (hi < 0 || lo < 0) {
            return (size_t)-1;
        }
        out[i] = (uint8_t)((hi << 4) | lo);
    }
    return n;
}

static void hexprint(const uint8_t *b, size_t n) {
    size_t i;
    for (i = 0; i < n; i++) {
        printf("%02x", b[i]);
    }
    printf("\n");
}

static int usage(const char *msg) {
    fprintf(stderr, "usage-error: %s\n", msg);
    return 2;
}

static qc_kem_level kem_level(const char *s, int *ok) {
    long v = 0;
    size_t i;
    if (s == NULL) {
        *ok = 0;
        return QC_KEM_512;
    }
    for (i = 0; s[i] != '\0'; i++) {
        if (s[i] < '0' || s[i] > '9' || i > 4) {
            *ok = 0;
            return QC_KEM_512;
        }
        v = v * 10 + (s[i] - '0');
    }
    *ok = (v == 512 || v == 768 || v == 1024);
    return (qc_kem_level)v;
}

static qc_dsa_level dsa_level(const char *s, int *ok) {
    long v = 0;
    size_t i;
    if (s == NULL) {
        *ok = 0;
        return QC_DSA_44;
    }
    for (i = 0; s[i] != '\0'; i++) {
        if (s[i] < '0' || s[i] > '9' || i > 3) {
            *ok = 0;
            return QC_DSA_44;
        }
        v = v * 10 + (s[i] - '0');
    }
    *ok = (v == 44 || v == 65 || v == 87);
    return (qc_dsa_level)v;
}

/* Wipe helper for secret buffers (sizes known at call sites). */
static void wipe(void *p, size_t n) {
    qc_zeroize(p, n);
}

int main(int argc, char **argv) {
    if (argc < 2) {
        return usage("need subcommand");
    }

#define NEED(n)                                      \
    do {                                             \
        if (argc != (n)) {                           \
            return usage("wrong arg count");         \
        }                                            \
    } while (0)

    /* ---- controller verbs (delegated; frozen crypto below) ---- */
    if (argc >= 2 && argv[1][0] == 'c' && argv[1][1] == 't' &&
        argv[1][2] == 'l' && argv[1][3] == '-') {
        int ctl_rc = srv_ctl_main(argc, argv);
        if (ctl_rc >= 0) {
            return ctl_rc;
        }
    }

    /* ---- hashes ---- */
    if (strcmp(argv[1], "sha256") == 0) {
        size_t ml;
        uint8_t d[32];
        NEED(3);
        ml = unhex(argv[2], buf_a, sizeof(buf_a));
        if (ml == (size_t)-1) {
            return usage("bad hex");
        }
        qc_sha256(buf_a, ml, d);
        hexprint(d, 32);
        wipe(buf_a, sizeof(buf_a));
        wipe(d, sizeof(d));
        return 0;
    }
    if (strcmp(argv[1], "hmac") == 0) {
        size_t kl, ml;
        uint8_t d[32];
        NEED(4);
        kl = unhex(argv[2], buf_a, sizeof(buf_a));
        ml = unhex(argv[3], buf_b, sizeof(buf_b));
        if (kl == (size_t)-1 || ml == (size_t)-1) {
            return usage("bad hex");
        }
        /* One-shot has no rc (empty key/msg are legal HMAC inputs). */
        qc_hmac_sha256(buf_a, kl, buf_b, ml, d);
        hexprint(d, 32);
        wipe(buf_a, sizeof(buf_a));
        wipe(buf_b, sizeof(buf_b));
        wipe(d, sizeof(d));
        return 0;
    }
    if (strcmp(argv[1], "hkdf-extract") == 0) {
        size_t sl, il;
        uint8_t prk[32];
        int rc;
        NEED(4);
        sl = unhex(argv[2], buf_a, sizeof(buf_a));
        il = unhex(argv[3], buf_b, sizeof(buf_b));
        if (sl == (size_t)-1 || il == (size_t)-1) {
            return usage("bad hex");
        }
        rc = qc_hkdf_extract(buf_a, sl, buf_b, il, prk);
        if (rc != 0) {
            wipe(buf_a, sizeof(buf_a));
            wipe(buf_b, sizeof(buf_b));
            return rc;
        }
        hexprint(prk, 32);
        wipe(buf_a, sizeof(buf_a));
        wipe(buf_b, sizeof(buf_b));
        wipe(prk, sizeof(prk));
        return 0;
    }
    if (strcmp(argv[1], "hkdf-expand") == 0) {
        size_t pl, il, want;
        int rc;
        NEED(5);
        pl = unhex(argv[2], buf_a, sizeof(buf_a));
        il = unhex(argv[3], buf_b, sizeof(buf_b));
        if (pl == (size_t)-1 || il == (size_t)-1 || pl != 32) {
            return usage("bad hex (prk must be 32 B)");
        }
        want = 0;
        {
            size_t i;
            for (i = 0; argv[4][i] != '\0'; i++) {
                if (argv[4][i] < '0' || argv[4][i] > '9' || i > 5) {
                    return usage("bad length");
                }
                want = want * 10 + (size_t)(argv[4][i] - '0');
            }
        }
        if (want == 0 || want > sizeof(buf_o1)) {
            return usage("length out of range");
        }
        rc = qc_hkdf_expand(buf_a, buf_b, il, buf_o1, want);
        if (rc != 0) {
            wipe(buf_a, sizeof(buf_a));
            wipe(buf_b, sizeof(buf_b));
            return rc;
        }
        hexprint(buf_o1, want);
        wipe(buf_a, sizeof(buf_a));
        wipe(buf_b, sizeof(buf_b));
        wipe(buf_o1, sizeof(buf_o1));
        return 0;
    }

    /* ---- AEAD (ct||tag concatenated out for enc; split args for dec) */
    if (strcmp(argv[1], "aead-enc") == 0) {
        size_t kl, nl, al, pl;
        uint8_t tag[QC_AEAD_TAG_LEN];
        int rc;
        NEED(6);
        kl = unhex(argv[2], buf_a, sizeof(buf_a));
        nl = unhex(argv[3], buf_b, sizeof(buf_b));
        al = unhex(argv[4], buf_c, sizeof(buf_c));
        pl = unhex(argv[5], buf_o1, sizeof(buf_o1) - 16);
        if (kl == (size_t)-1 || nl == (size_t)-1 ||
            al == (size_t)-1 || pl == (size_t)-1) {
            return usage("bad hex");
        }
        rc = qc_aead_encrypt(buf_a, kl, buf_b, nl, buf_c, al, buf_o1,
                             pl, buf_o2, tag);
        if (rc != 0) {
            wipe(buf_a, sizeof(buf_a));
            wipe(buf_o1, sizeof(buf_o1));
            return rc;
        }
        /* Ciphertext bytes live in buf_o2 per the adapter contract
         * (ct buffer distinct from pt staging in buf_o1). */
        hexprint(buf_o2, pl);
        hexprint(tag, QC_AEAD_TAG_LEN);
        wipe(buf_a, sizeof(buf_a));
        wipe(buf_o1, sizeof(buf_o1));
        wipe(buf_o2, sizeof(buf_o2));
        wipe(tag, sizeof(tag));
        return 0;
    }
    if (strcmp(argv[1], "aead-dec") == 0) {
        size_t kl, nl, al, cl, tl;
        int rc;
        NEED(7);
        kl = unhex(argv[2], buf_a, sizeof(buf_a));
        nl = unhex(argv[3], buf_b, sizeof(buf_b));
        al = unhex(argv[4], buf_c, sizeof(buf_c));
        cl = unhex(argv[5], buf_o1, sizeof(buf_o1));
        tl = unhex(argv[6], buf_o2, QC_AEAD_TAG_LEN + 64);
        if (kl == (size_t)-1 || nl == (size_t)-1 ||
            al == (size_t)-1 || cl == (size_t)-1 ||
            tl == (size_t)-1 || tl != QC_AEAD_TAG_LEN) {
            return usage("bad hex (tag must be 16 B)");
        }
        rc = qc_aead_decrypt(buf_a, kl, buf_b, nl, buf_c, al, buf_o1,
                             cl, buf_o2, buf_o1);
        /* In-place decrypt into the ct staging (adapter wipes on
         * AUTH_FAIL per the B-12 contract — nothing extra here). */
        if (rc != 0) {
            wipe(buf_a, sizeof(buf_a));
            return rc;
        }
        hexprint(buf_o1, cl);
        wipe(buf_a, sizeof(buf_a));
        wipe(buf_o1, sizeof(buf_o1));
        wipe(buf_o2, sizeof(buf_o2));
        return 0;
    }

    /* ---- KEM ---- */
    if (strcmp(argv[1], "kem-keypair") == 0) {
        qc_kem_level lv;
        size_t cl;
        size_t pk, sk;
        int ok, rc;
        NEED(4);
        lv = kem_level(argv[2], &ok);
        if (!ok) {
            return usage("bad level (512/768/1024)");
        }
        cl = unhex(argv[3], buf_c, sizeof(buf_c));
        if (cl == (size_t)-1 || cl != QC_KEM_KEYGEN_COINS_BYTES) {
            return usage("bad coins (64 B)");
        }
        pk = qc_kem_pk_bytes(lv);
        sk = qc_kem_sk_bytes(lv);
        if (pk == 0 || sk == 0 || pk > sizeof(buf_o1) ||
            sk > sizeof(buf_o2)) {
            return usage("level sizing failed");
        }
        rc = qc_kem_keypair(lv, buf_o1, buf_o2, buf_c);
        if (rc != 0) {
            wipe(buf_c, sizeof(buf_c));
            return rc;
        }
        hexprint(buf_o1, pk);
        hexprint(buf_o2, sk);
        wipe(buf_c, sizeof(buf_c));
        return 0;
    }
    if (strcmp(argv[1], "kem-encaps") == 0) {
        qc_kem_level lv;
        size_t pl, cl;
        size_t ct;
        int ok, rc;
        NEED(5);
        lv = kem_level(argv[2], &ok);
        if (!ok) {
            return usage("bad level (512/768/1024)");
        }
        pl = unhex(argv[3], buf_a, sizeof(buf_a));
        cl = unhex(argv[4], buf_c, sizeof(buf_c));
        if (pl == (size_t)-1 || cl == (size_t)-1 ||
            cl != QC_KEM_ENCAPS_COINS_BYTES ||
            pl != qc_kem_pk_bytes(lv)) {
            return usage("bad pk/coins");
        }
        ct = qc_kem_ct_bytes(lv);
        if (ct == 0 || ct > sizeof(buf_o1)) {
            return usage("level sizing failed");
        }
        rc = qc_kem_encaps(lv, buf_o1, buf_o2, buf_a, buf_c);
        if (rc != 0) {
            wipe(buf_c, sizeof(buf_c));
            wipe(buf_o2, sizeof(buf_o2));
            return rc;
        }
        hexprint(buf_o1, ct);
        hexprint(buf_o2, QC_KEM_SS_BYTES);
        wipe(buf_c, sizeof(buf_c));
        wipe(buf_o2, sizeof(buf_o2));
        return 0;
    }
    if (strcmp(argv[1], "kem-decaps") == 0) {
        qc_kem_level lv;
        size_t cl, sl;
        int ok, rc;
        NEED(5);
        lv = kem_level(argv[2], &ok);
        if (!ok) {
            return usage("bad level (512/768/1024)");
        }
        cl = unhex(argv[3], buf_a, sizeof(buf_a));
        sl = unhex(argv[4], buf_b, sizeof(buf_b));
        if (cl == (size_t)-1 || sl == (size_t)-1 ||
            cl != qc_kem_ct_bytes(lv) || sl != qc_kem_sk_bytes(lv)) {
            return usage("bad ct/sk");
        }
        rc = qc_kem_decaps(lv, buf_o1, buf_a, buf_b);
        if (rc != 0) {
            return rc;
        }
        hexprint(buf_o1, QC_KEM_SS_BYTES);
        wipe(buf_o1, sizeof(buf_o1));
        return 0;
    }

    /* ---- DSA ---- */
    if (strcmp(argv[1], "dsa-keypair") == 0) {
        qc_dsa_level lv;
        size_t sl;
        size_t pk, sk;
        int ok, rc;
        NEED(4);
        lv = dsa_level(argv[2], &ok);
        if (!ok) {
            return usage("bad level (44/65/87)");
        }
        sl = unhex(argv[3], buf_c, sizeof(buf_c));
        if (sl == (size_t)-1 || sl != QC_DSA_SEED_BYTES) {
            return usage("bad seed (32 B)");
        }
        pk = qc_dsa_pk_bytes(lv);
        sk = qc_dsa_sk_bytes(lv);
        if (pk == 0 || sk == 0 || pk > sizeof(buf_o1) ||
            sk > sizeof(buf_o2)) {
            return usage("level sizing failed");
        }
        rc = qc_dsa_keypair(lv, buf_o1, buf_o2, buf_c);
        if (rc != 0) {
            wipe(buf_c, sizeof(buf_c));
            return rc;
        }
        hexprint(buf_o1, pk);
        hexprint(buf_o2, sk);
        wipe(buf_c, sizeof(buf_c));
        return 0;
    }
    if (strcmp(argv[1], "dsa-sign") == 0) {
        qc_dsa_level lv;
        size_t ml, cl, rl, sl;
        int ok, rc;
        /* sign <level> <sk> <msg> <rnd> [ctx] */
        if (argc != 6 && argc != 7) {
            return usage("sign <level> <sk> <msg> <rnd> [ctx]");
        }
        lv = dsa_level(argv[2], &ok);
        if (!ok) {
            return usage("bad level (44/65/87)");
        }
        sl = unhex(argv[3], buf_a, sizeof(buf_a));
        ml = unhex(argv[4], buf_b, sizeof(buf_b));
        rl = unhex(argv[5], buf_c, sizeof(buf_c));
        if (sl == (size_t)-1 || ml == (size_t)-1 || rl == (size_t)-1 ||
            sl != qc_dsa_sk_bytes(lv) || rl != QC_DSA_RND_BYTES) {
            return usage("bad sk/msg/rnd");
        }
        cl = 0;
        if (argc == 7) {
            cl = unhex(argv[6], buf_o2, QC_DSA_CTX_MAX_BYTES);
            if (cl == (size_t)-1) {
                return usage("bad ctx");
            }
        }
        sl = qc_dsa_sig_bytes(lv);
        if (sl == 0 || sl > sizeof(buf_o1)) {
            return usage("level sizing failed");
        }
        rc = qc_dsa_sign(lv, buf_o1, buf_b, ml,
                         argc == 7 ? buf_o2 : NULL, cl, buf_c, buf_a);
        wipe(buf_c, sizeof(buf_c));
        if (rc != 0) {
            return rc;
        }
        hexprint(buf_o1, sl);
        return 0;
    }
    if (strcmp(argv[1], "dsa-verify") == 0) {
        qc_dsa_level lv;
        size_t ml, cl, sl, pl;
        int ok, rc;
        /* verify <level> <pk> <msg> <sig> [ctx] */
        if (argc != 6 && argc != 7) {
            return usage("verify <level> <pk> <msg> <sig> [ctx]");
        }
        lv = dsa_level(argv[2], &ok);
        if (!ok) {
            return usage("bad level (44/65/87)");
        }
        pl = unhex(argv[3], buf_a, sizeof(buf_a));
        ml = unhex(argv[4], buf_b, sizeof(buf_b));
        sl = unhex(argv[5], buf_o1, sizeof(buf_o1));
        if (pl == (size_t)-1 || ml == (size_t)-1 || sl == (size_t)-1 ||
            pl != qc_dsa_pk_bytes(lv) || sl != qc_dsa_sig_bytes(lv)) {
            return usage("bad pk/msg/sig");
        }
        cl = 0;
        if (argc == 7) {
            cl = unhex(argv[6], buf_o2, QC_DSA_CTX_MAX_BYTES);
            if (cl == (size_t)-1) {
                return usage("bad ctx");
            }
        }
        rc = qc_dsa_verify(lv, buf_b, ml, argc == 7 ? buf_o2 : NULL,
                           cl, buf_o1, buf_a);
        return rc;
    }

    /* ---- sizes (level table live from the adapters — callers never
     * hardcode sizes; B-42/B-43 use this too) ---- */
    if (strcmp(argv[1], "sizes") == 0) {
        int ok;
        NEED(4);
        if (strcmp(argv[2], "kem") == 0) {
            qc_kem_level lv = kem_level(argv[3], &ok);
            if (!ok) {
                return usage("bad level (512/768/1024)");
            }
            /* Three values like dsa (ss is FIPS-fixed 32, carried
             * by the KDF layout, not the level table). %lu with casts:
             * MSVCRT printf never learned %zu (audit: MinGW -Werror
             * flags it); values are bytes counts, never wide. */
            printf("%lu %lu %lu\n",
                   (unsigned long)qc_kem_pk_bytes(lv),
                   (unsigned long)qc_kem_sk_bytes(lv),
                   (unsigned long)qc_kem_ct_bytes(lv));
            return 0;
        }
        if (strcmp(argv[2], "dsa") == 0) {
            qc_dsa_level lv = dsa_level(argv[3], &ok);
            if (!ok) {
                return usage("bad level (44/65/87)");
            }
            printf("%zu %zu %zu\n", qc_dsa_pk_bytes(lv),
                   qc_dsa_sk_bytes(lv), qc_dsa_sig_bytes(lv));
            return 0;
        }
        return usage("sizes kem|dsa <level>");
    }

    /* ---- live entropy (prod path only; tests use fixed coins) ---- */
    if (strcmp(argv[1], "rng") == 0) {
        size_t want = 0;
        size_t i;
        int rc = 0;
        NEED(3);
        for (i = 0; argv[2][i] != '\0'; i++) {
            if (argv[2][i] < '0' || argv[2][i] > '9' || i > 5) {
                return usage("bad length");
            }
            want = want * 10 + (size_t)(argv[2][i] - '0');
        }
        if (want == 0 || want > sizeof(buf_o1)) {
            return usage("length out of range");
        }
        rc = qc_rng_generate(buf_o1, want);
        if (rc != 0) {
            memset(buf_o1, 0, sizeof(buf_o1));
            return 1;
        }
        hexprint(buf_o1, want);
        memset(buf_o1, 0, sizeof(buf_o1));
        return 0;
    }

    return usage("unknown subcommand");
}
