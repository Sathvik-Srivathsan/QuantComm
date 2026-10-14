/* srv_sim.c — sim servant verbs for Chunk 3 (B-24 batch/Merkle, B-25 manifest).
 *
 * Same conventions as srv_crypto.c/srv_ctl.c: C89 decls first, NEED-style
 * argc guards, static buffers (no heap), hex in/out, stateful verbs print
 * rc + new blob and exit 0 (blobs mutate even on failure paths: batch
 * counters, manifest rate windows), pure verbs print values, usage exits 2.
 *
 * State crosses as RAW STRUCT BYTES (hex): qc_batch (~5 KB) and
 * qc_manifest_store (~7 KB) contain no pointers (arrays + scalars only),
 * and both ends live in THIS binary — no cross-ABI ferry, exact-size
 * checked on decode. Merkle is pure (no state): leaves in, root/proof
 * out. Manifest verify needs DSA (linked via qc_dsa lib) + enrolled key
 * carried in the store blob (no-secret rule holds: bodies carry no keys
 * except public next_server_key by B-25 design).
 *
 * Prefix: sim- (dispatched from srv_crypto.c main alongside ctl-).
 */
#include <stdio.h>
#include <string.h>

#include "qc_batch.h"
#include "qc_dsa.h"
#include "qc_manifest.h"
#include "qc_merkle.h"
#include "qc_zeroize.h"

#define SIM_ARG_CAP 65536

static uint8_t s_a[SIM_ARG_CAP];
static uint8_t s_b[SIM_ARG_CAP];
static uint8_t s_state[16384];
static uint8_t s_out[SIM_ARG_CAP];
static uint8_t s_scratch[32768];
static uint8_t s_proof[4096];

static int sim_hexval(char c) {
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

static size_t sim_unhex(const char *s, uint8_t *out, size_t cap) {
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
        hi = sim_hexval(s[2 * i]);
        lo = sim_hexval(s[2 * i + 1]);
        if (hi < 0 || lo < 0) {
            return (size_t)-1;
        }
        out[i] = (uint8_t)((hi << 4) | lo);
    }
    return n;
}

static void sim_hexprint(const uint8_t *b, size_t n) {
    size_t i;
    for (i = 0; i < n; i++) {
        printf("%02x", b[i]);
    }
    printf("\n");
}

static int sim_usage(const char *msg) {
    fprintf(stderr, "usage-error: %s\n", msg);
    return 2;
}

static int sim_u32(const char *s, uint32_t *out) {
    size_t i;
    uint32_t v;
    if (s == NULL || s[0] == '\0') {
        return -1;
    }
    v = 0;
    for (i = 0; s[i] != '\0'; i++) {
        if (s[i] < '0' || s[i] > '9' || i > 9) {
            return -1;
        }
        v = v * 10 + (uint32_t)(s[i] - '0');
    }
    *out = v;
    return 0;
}

static int sim_u64(const char *s, uint64_t *out) {
    size_t i;
    uint64_t v;
    if (s == NULL || s[0] == '\0') {
        return -1;
    }
    v = 0;
    for (i = 0; s[i] != '\0'; i++) {
        if (s[i] < '0' || s[i] > '9' || i > 19) {
            return -1;
        }
        v = v * 10 + (uint64_t)(s[i] - '0');
    }
    *out = v;
    return 0;
}

static int sim_u8(const char *s, uint8_t *out) {
    uint32_t v;
    if (sim_u32(s, &v) != 0 || v > 255) {
        return -1;
    }
    *out = (uint8_t)v;
    return 0;
}

/* Decode a raw-struct blob (exact sizeof match, fail-closed). */
static int sim_dec_blob(const char *hex, void *st, size_t want) {
    size_t n;
    if (want > sizeof(s_state)) {
        return -1;
    }
    n = sim_unhex(hex, s_state, sizeof(s_state));
    if (n != want) {
        return -1;
    }
    memcpy(st, s_state, want);
    return 0;
}

static void sim_enc_blob(const void *st, size_t want) {
    memcpy(s_state, st, want);
    sim_hexprint(s_state, want);
}

/* ---- batch (stateful) ---- */

static int sim_batch_new(void) {
    qc_batch b;
    if (sizeof(b) > sizeof(s_state)) {
        return sim_usage("batch state too large");
    }
    qc_batch_init(&b);
    printf("0\n");
    sim_enc_blob(&b, sizeof(b));
    return 0;
}

static int sim_batch_insert(int argc, char **argv) {
    qc_batch b;
    size_t rl;
    uint8_t cls;
    uint64_t now;
    qc_batch_rc rc;
    if (argc != 6) {
        return sim_usage("batch-insert blob reading cls now");
    }
    if (sim_dec_blob(argv[2], &b, sizeof(b)) != 0) {
        return sim_usage("bad batch blob");
    }
    rl = sim_unhex(argv[3], s_a, sizeof(s_a));
    if (rl == (size_t)-1 || rl == 0) {
        return sim_usage("bad reading (nonempty hex)");
    }
    if (sim_u8(argv[4], &cls) != 0 || sim_u64(argv[5], &now) != 0) {
        return sim_usage("bad cls/now");
    }
    rc = qc_batch_insert(&b, s_a, rl, cls, now);
    printf("%d\n", (int)rc);
    sim_enc_blob(&b, sizeof(b));
    return 0;
}

static int sim_batch_ready(int argc, char **argv) {
    qc_batch b;
    uint32_t nb, tc0, tc1;
    uint64_t now;
    qc_batch_close reason;
    int r;
    if (argc != 7) {
        return sim_usage("batch-ready blob nb tc0 tc1 now");
    }
    if (sim_dec_blob(argv[2], &b, sizeof(b)) != 0) {
        return sim_usage("bad batch blob");
    }
    if (sim_u32(argv[3], &nb) != 0 ||
        sim_u32(argv[4], &tc0) != 0 ||
        sim_u32(argv[5], &tc1) != 0 || sim_u64(argv[6], &now) != 0) {
        return sim_usage("bad nb/tc0/tc1/now");
    }
    if (nb < 1 || nb > 32) {
        /* Pre-truncation guard: (uint8_t)288 == 32 would alias valid. */
        return sim_usage("bad nb (1..32)");
    }
    r = qc_batch_ready(&b, (uint8_t)nb, (uint64_t)tc0, (uint64_t)tc1,
                       now, &reason);
    /* Contract: -1 misuse, 0 OPEN, 1 CLOSED (COUNT|LATENCY in reason).
     * Only the negative is an error — a close is the normal answer. */
    if (r < 0) {
        /* Decisive diagnostic: state as the core saw it. */
        fprintf(stderr, "usage-error: ready failed (nb=%lu init=%u "
                "count=%lu r=%d tc0=%lu tc1=%lu now=%lu)\n",
                (unsigned long)nb, (unsigned)b.init,
                (unsigned long)qc_batch_count(&b), r,
                (unsigned long)tc0, (unsigned long)tc1,
                (unsigned long)now);
        return 2;
    }
    printf("%d\n", (int)reason);
    return 0;
}

static int sim_batch_pop(int argc, char **argv) {
    qc_batch b;
    uint32_t cap;
    uint64_t now, age;
    size_t len;
    uint8_t cls;
    qc_batch_rc rc;
    if (argc != 5) {
        return sim_usage("batch-pop blob cap now");
    }
    if (sim_dec_blob(argv[2], &b, sizeof(b)) != 0) {
        return sim_usage("bad batch blob");
    }
    if (sim_u32(argv[3], &cap) != 0 || cap == 0 ||
        cap > sizeof(s_out) || sim_u64(argv[4], &now) != 0) {
        return sim_usage("bad cap/now");
    }
    rc = qc_batch_pop(&b, s_out, (size_t)cap, &len, &cls, &age, now);
    printf("%d\n", (int)rc);
    sim_enc_blob(&b, sizeof(b));
    if (rc == QC_BATCH_OK) {
        sim_hexprint(s_out, len);
        printf("%u\n%lu\n", (unsigned)cls, (unsigned long)age);
    }
    return 0;
}

static int sim_batch_count(int argc, char **argv) {
    qc_batch b;
    if (argc != 3) {
        return sim_usage("batch-count blob");
    }
    if (sim_dec_blob(argv[2], &b, sizeof(b)) != 0) {
        return sim_usage("bad batch blob");
    }
    printf("%lu\n", (unsigned long)qc_batch_count(&b));
    return 0;
}

/* ---- merkle (pure) ---- */

static int sim_merkle_leaf(int argc, char **argv) {
    uint8_t cls;
    uint64_t counter;
    size_t rl;
    uint8_t leaf[32];
    if (argc != 5) {
        return sim_usage("merkle-leaf cls counter reading");
    }
    if (sim_u8(argv[2], &cls) != 0 || sim_u64(argv[3], &counter) != 0) {
        return sim_usage("bad cls/counter");
    }
    rl = sim_unhex(argv[4], s_a, sizeof(s_a));
    if (rl == (size_t)-1) {
        return sim_usage("bad reading hex");
    }
    if (qc_merkle_leaf(cls, counter, s_a, rl, leaf) != QC_MERKLE_OK) {
        return sim_usage("leaf failed");
    }
    sim_hexprint(leaf, 32);
    return 0;
}

static int sim_merkle_root(int argc, char **argv) {
    size_t ll;
    size_t n;
    uint8_t root[32];
    if (argc != 3) {
        return sim_usage("merkle-root leaves");
    }
    ll = sim_unhex(argv[2], s_a, sizeof(s_a));
    if (ll == (size_t)-1 || ll == 0 || ll % 32 != 0) {
        return sim_usage("bad leaves (n*32 hex)");
    }
    n = ll / 32;
    if (ll > sizeof(s_scratch)) {
        return sim_usage("too many leaves");
    }
    if (qc_merkle_root(s_a, n, s_scratch, sizeof(s_scratch),
                       root) != QC_MERKLE_OK) {
        return sim_usage("root failed");
    }
    sim_hexprint(root, 32);
    return 0;
}

static int sim_merkle_prove(int argc, char **argv) {
    size_t ll, idx, depth, cap;
    uint32_t idx32;
    if (argc != 4) {
        return sim_usage("merkle-prove leaves index");
    }
    ll = sim_unhex(argv[2], s_a, sizeof(s_a));
    if (ll == (size_t)-1 || ll == 0 || ll % 32 != 0) {
        return sim_usage("bad leaves (n*32 hex)");
    }
    if (sim_u32(argv[3], &idx32) != 0) {
        return sim_usage("bad index");
    }
    idx = (size_t)idx32;
    if (ll > sizeof(s_scratch)) {
        return sim_usage("too many leaves");
    }
    cap = sizeof(s_proof) / 32;
    depth = 0;
    if (qc_merkle_proof(s_a, ll / 32, idx, s_scratch,
                        sizeof(s_scratch), s_proof, cap,
                        &depth) != QC_MERKLE_OK) {
        return sim_usage("prove failed (index<n, cap)");
    }
    printf("%lu\n", (unsigned long)depth);
    sim_hexprint(s_proof, depth * 32);
    return 0;
}

static int sim_merkle_verify(int argc, char **argv) {
    size_t pl, rl;
    uint32_t n, idx;
    uint8_t leaf[32], root[32];
    if (argc != 7) {
        return sim_usage("merkle-verify leaf n index proof root");
    }
    if (sim_unhex(argv[2], leaf, 32) != 32) {
        return sim_usage("bad leaf (32 B)");
    }
    if (sim_u32(argv[3], &n) != 0 || sim_u32(argv[4], &idx) != 0) {
        return sim_usage("bad n/index");
    }
    pl = sim_unhex(argv[5], s_proof, sizeof(s_proof));
    if (pl == (size_t)-1 || pl % 32 != 0) {
        return sim_usage("bad proof (d*32 hex)");
    }
    rl = sim_unhex(argv[6], root, 32);
    if (rl != 32) {
        return sim_usage("bad root (32 B)");
    }
    return (int)qc_merkle_verify(leaf, (size_t)n, (size_t)idx, s_proof,
                                 pl / 32, root);
}

/* ---- manifest ---- */

static int sim_mft_init(int argc, char **argv) {
    qc_manifest_store st;
    qc_dsa_level lv;
    size_t pl;
    long v;
    size_t i;
    if (argc != 4) {
        return sim_usage("mft-init level pk");
    }
    v = 0;
    for (i = 0; argv[2][i] != '\0'; i++) {
        if (argv[2][i] < '0' || argv[2][i] > '9' || i > 3) {
            return sim_usage("bad level (44/65/87)");
        }
        v = v * 10 + (argv[2][i] - '0');
    }
    if (v != 44 && v != 65 && v != 87) {
        return sim_usage("bad level (44/65/87)");
    }
    lv = (qc_dsa_level)v;
    pl = sim_unhex(argv[3], s_a, sizeof(s_a));
    if (pl == (size_t)-1) {
        return sim_usage("bad pk hex");
    }
    if (sizeof(st) > sizeof(s_state)) {
        return sim_usage("manifest store too large");
    }
    if (qc_manifest_init(&st, lv, s_a) != QC_MFT_OK) {
        printf("%d\n", (int)QC_MFT_MALFORMED);
        memset(&st, 0, sizeof(st));
        return 0;
    }
    printf("0\n");
    sim_enc_blob(&st, sizeof(st));
    qc_zeroize(&st, sizeof(st));
    qc_zeroize(s_a, sizeof(s_a));
    return 0;
}

static int sim_mft_make(int argc, char **argv) {
    qc_manifest_fields f;
    qc_floor_entry floors[32];
    uint8_t profiles[32];
    uint8_t nextkey[2592];
    size_t fl, pl, kl, need;
    uint32_t ver, hmax, tcool;
    uint32_t c2th;
    size_t i;
    if (argc != 9) {
        return sim_usage("mft-make version floors profiles hmax tcool "
                         "c2th nextkey");
    }
    if (sim_u32(argv[2], &ver) != 0) {
        return sim_usage("bad version");
    }
    fl = sim_unhex(argv[3], s_a, sizeof(s_a));
    if (fl == (size_t)-1 || fl == 0 || fl % 2 != 0 ||
        fl / 2 > sizeof(floors) / sizeof(floors[0])) {
        return sim_usage("bad floors (cls,min pairs)");
    }
    for (i = 0; i < fl / 2; i++) {
        floors[i].cls = s_a[2 * i];
        floors[i].min_level = s_a[2 * i + 1];
    }
    pl = sim_unhex(argv[4], s_b, sizeof(s_b));
    if (pl == (size_t)-1 || pl > sizeof(profiles)) {
        return sim_usage("bad profiles");
    }
    memcpy(profiles, s_b, pl);
    if (sim_u32(argv[5], &hmax) != 0 || sim_u32(argv[6], &tcool) != 0 ||
        sim_u32(argv[7], &c2th) != 0 || c2th > 65535) {
        return sim_usage("bad hmax/tcool/c2th");
    }
    kl = 0;
    if (strcmp(argv[8], "none") != 0) {
        kl = sim_unhex(argv[8], nextkey, sizeof(nextkey));
        if (kl == (size_t)-1) {
            return sim_usage("bad nextkey");
        }
    }
    memset(&f, 0, sizeof(f));
    f.version = ver;
    f.floors = floors;
    f.n_floors = fl / 2;
    f.profiles = profiles;
    f.n_profiles = pl;
    f.hmax = hmax;
    f.t_cool = tcool;
    f.c2_threshold = (uint16_t)c2th;
    f.next_key = kl == 0 ? NULL : nextkey;
    f.next_key_len = kl;
    need = qc_manifest_encode_len(&f);
    if (need == 0 || need > sizeof(s_out)) {
        /* Decisive diagnostic (fail loud): which entry/value the core
         * rejected is otherwise invisible from outside. */
        fprintf(stderr, "usage-error: encode sizing failed "
                "(floors=%lu profiles=%lu keylen=%lu need=%lu "
                "entry_size=%lu)\n",
                (unsigned long)f.n_floors, (unsigned long)f.n_profiles,
                (unsigned long)f.next_key_len, (unsigned long)need,
                (unsigned long)sizeof(qc_floor_entry));
        for (i = 0; i < f.n_floors; i++) {
            fprintf(stderr, "  entry[%lu] cls=%u min=%u\n",
                    (unsigned long)i, (unsigned)f.floors[i].cls,
                    (unsigned)f.floors[i].min_level);
        }
        return 2;
    }
    if (qc_manifest_encode(&f, s_out, need) != QC_MFT_OK) {
        return sim_usage("encode failed");
    }
    sim_hexprint(s_out, need);
    qc_zeroize(nextkey, sizeof(nextkey));
    return 0;
}

static int sim_mft_parse(int argc, char **argv) {
    size_t bl;
    qc_manifest_parsed p;
    size_t i;
    if (argc != 3) {
        return sim_usage("mft-parse body");
    }
    bl = sim_unhex(argv[2], s_a, sizeof(s_a));
    if (bl == (size_t)-1) {
        return sim_usage("bad body hex");
    }
    if (qc_manifest_parse(s_a, bl, &p) != QC_MFT_OK) {
        return sim_usage("parse failed (prints nothing)");
    }
    printf("%lu\n", (unsigned long)p.version);
    for (i = 0; i < p.n_floors; i++) {
        printf("%02x%02x", p.floors[i].cls, p.floors[i].min_level);
    }
    printf("\n");
    sim_hexprint(p.profiles, p.n_profiles);
    printf("%lu\n%lu\n%u\n", (unsigned long)p.hmax,
           (unsigned long)p.t_cool, (unsigned)p.c2_threshold);
    if (p.next_key_len == 0) {
        printf("none\n");
    } else {
        sim_hexprint(p.next_key, p.next_key_len);
    }
    return 0;
}

static int sim_mft_verify(int argc, char **argv) {
    qc_manifest_store st;
    size_t bl, sl;
    uint64_t now;
    qc_mft_rc rc;
    if (argc != 6) {
        return sim_usage("mft-verify storeblob body sig now");
    }
    if (sim_dec_blob(argv[2], &st, sizeof(st)) != 0) {
        return sim_usage("bad store blob");
    }
    bl = sim_unhex(argv[3], s_a, sizeof(s_a));
    sl = sim_unhex(argv[4], s_b, sizeof(s_b));
    if (bl == (size_t)-1 || sl == (size_t)-1 ||
        sim_u64(argv[5], &now) != 0) {
        return sim_usage("bad body/sig/now");
    }
    rc = qc_manifest_verify_apply(&st, s_a, bl, s_b, sl, now);
    printf("%d\n", (int)rc);
    sim_enc_blob(&st, sizeof(st));
    qc_zeroize(&st, sizeof(st));
    return 0;
}

int srv_sim_main(int argc, char **argv) {
    if (argc < 2 || strncmp(argv[1], "sim-", 4) != 0) {
        return -1;
    }
    if (strcmp(argv[1], "sim-batch-new") == 0) {
        if (argc != 2) {
            return sim_usage("batch-new takes no args");
        }
        return sim_batch_new();
    }
    if (strcmp(argv[1], "sim-batch-insert") == 0) {
        return sim_batch_insert(argc, argv);
    }
    if (strcmp(argv[1], "sim-batch-ready") == 0) {
        return sim_batch_ready(argc, argv);
    }
    if (strcmp(argv[1], "sim-batch-pop") == 0) {
        return sim_batch_pop(argc, argv);
    }
    if (strcmp(argv[1], "sim-batch-count") == 0) {
        return sim_batch_count(argc, argv);
    }
    if (strcmp(argv[1], "sim-merkle-leaf") == 0) {
        return sim_merkle_leaf(argc, argv);
    }
    if (strcmp(argv[1], "sim-merkle-root") == 0) {
        return sim_merkle_root(argc, argv);
    }
    if (strcmp(argv[1], "sim-merkle-prove") == 0) {
        return sim_merkle_prove(argc, argv);
    }
    if (strcmp(argv[1], "sim-merkle-verify") == 0) {
        return sim_merkle_verify(argc, argv);
    }
    if (strcmp(argv[1], "sim-mft-init") == 0) {
        return sim_mft_init(argc, argv);
    }
    if (strcmp(argv[1], "sim-mft-make") == 0) {
        return sim_mft_make(argc, argv);
    }
    if (strcmp(argv[1], "sim-mft-parse") == 0) {
        return sim_mft_parse(argc, argv);
    }
    if (strcmp(argv[1], "sim-mft-verify") == 0) {
        return sim_mft_verify(argc, argv);
    }
    return sim_usage("unknown sim subcommand");
}
