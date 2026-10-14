/* srv_ctl.c — controller verbs for the servant (B-43 sim bridge).
 *
 * Extends srv_crypto with the frozen controller units (core/qc_state,
 * qc_floor, qc_risk, qc_energy, qc_opt, qc_gov) WITHOUT modifying them:
 * this TU owns only the argv/stdout calling convention plus ONE
 * canonical state codec. Frozen TUs are called, never patched.
 *
 * WHY A SEPARATE TU: srv_crypto.c's audit story covers crypto verbs;
 * controller verbs get their own audit surface here. The only touch
 * in srv_crypto.c is the ctl- prefix dispatch to srv_ctl_main().
 *
 * DESIGN RULES (iron — violations are audit findings):
 * 1. NO policy beyond C: the servant adds no validation the C unit
 *    lacks (argv shape/length checks are transport, not policy).
 *    Usage errors (bad argc/hex/lengths) exit 2 with stderr text.
 * 2. Controller rc values routinely occupy 2..7 (INVALID/HOLD/SHED/
 *    FAILSECURE...), colliding with the crypto convention's usage
 *    code — so ctl-* verbs ALWAYS exit 0 on successful invocation
 *    and print rc as an explicit stdout line. Crypto verbs untouched.
 * 3. Every verb prints rc FIRST (signed decimal), then payload:
 *    blob hex for mutating verbs, values otherwise. Uniform parsing
 *    beats eyeball order; usage/transport errors (never rc values)
 *    exit 2 with stderr text and no stdout. Sole exception: failed
 *    init prints rc only (no valid state exists to encode).
 * 4. State crosses as ONE canonical blob (magic QCTL + u16 ver +
 *    sections, exact-size-checked). Hooks (opt tau_spend) and the
 *    feasible callback are wired INLINE per call — neither crosses
 *    the blob (function pointers can't, and mustn't). After every
 *    decode the servant rewires opt hooks to the in-call gov state;
 *    commit additionally requires dt > 0 (div-by-zero guard — the
 *    only servant-level input check, justified: prevents FPE).
 * 5. The blob is UNMAC'd: tamper-evidence is a firmware-reboot
 *    property; sim inputs are test fixtures. MAC'd export/import
 *    paths stay firmware-only and are NOT exposed here — so NO key
 *    material crosses this surface, and nothing here needs wiping.
 *    (Risk's 64-ring transition log is dropped from the blob: the
 *    header documents reboot drops it; it stages B-40 output and
 *    never feeds a decision.)
 * 6. Floats cross as big-endian bit-copy hex (f32 = 8 chars, f64 =
 *    16); integers as strict decimal; byte fields as exact-length
 *    hex. NaN/Inf survive bit-exact (edge tests depend on it).
 * 7. decide() evaluates Ehat per candidate over the EXPLICIT window
 *    dt_w (argv): ranking is NOT t-invariant once the sigma term
 *    enters (energy differences scale with t, sigma doesn't), so the
 *    horizon is an input, never a hidden 3600. Per-candidate profile
 *    overrides the window workload's profile/tpq/tr/ta (each action
 *    carries its own cadence).
 *
 * BLOB LAYOUT (all integers big-endian; floats bit-copy):
 *   magic "QCTL"(4) ver u16(2)                                   = 6
 *   state: b_j f32 b_soc u8 b_at u64 r f32 r_at u64 s u8 s_at u64
 *     s_imm u8 c f32 c_at u64 m u32 m_at u64 l_rssi i16
 *     l_retries u16 l_at u64 q f32 q_at u64 q_counters u64
 *     risk[6] u32 risk_at u64 mask u16 init u8                   = 126
 *   riskcfg: w[6] f32 cmax[6] f32 hi f32 lo f32 ne u16 nx u16
 *     dwell u16 w u8 hint f32                                    = 67
 *   risk: init/state/emitted u8 n_enter/n_exit/dwell u16 r/hsum
 *     f32 hist[16][6] u32 hist_r[16] f32 hidx/hcount u8          = 467
 *   ftable: min[3] u8 has[3] u8                                  = 6
 *   fcfg: lmax[3] u32 nbmax u8                                   = 13
 *   res: base u32 stack[3] u32 perbyte/msg/latbase/latmsg u32    = 32
 *   opt: init u8 aprev(14) staged(14) staged_valid u8
 *     buckets[60] u16 base u64 set u8 lastsw u64 hmax u32 tcool
 *     u32 queue(14) qvalid u8 incap u8 lastalarm u64 cnt[7] u32
 *     pending u8                                                 = 228
 *   gov: init u8 tau/tmax f32 rho f64 frac f32 dwell u16 lastshed
 *     u64 hasshed u8 cnt[3] u32                                  = 44
 *   TOTAL = 989 bytes (1978 hex). Action rec = profile u8 tpq u32
 *   tr u32 ta i32 nb u8 = 14. Cand rec = action + ehat f64 +
 *   ehat_sec f64 = 30.
 * COEFF blob "QCEC"+ver: ekem[3][3]/sign[3]/verify[3]/aes/hkdfx2/
 *   sha/eb/ev/ebase[4] f64 + assumed u32 = 204 -> 210 total.
 * FOOT blob "QCFT"+ver: 9xu32 fields = 36 -> 42 total.
 * COUNTS blob "QCCN"+ver: kem72/sign24/verify24 + 7xf64 singles
 *   (aes_enc/dec, hkdf ext/exp, sha, bytes, events) = 176 -> 182.
 */
#include <stdio.h>
#include <string.h>

#include "qc_energy.h"
#include "qc_floor.h"
#include "qc_gov.h"
#include "qc_opt.h"
#include "qc_risk.h"
#include "qc_state.h"

#include "srv_ctl.h"

#define CTL_BLOB_LEN 989
#define CTL_COEFF_LEN 210
#define CTL_FOOT_LEN 42
#define CTL_COUNTS_LEN 182
#define CTL_FEAS_CAP 360

static int ctl_usage(const char *msg) {
    fprintf(stderr, "ctl-usage-error: %s\n", msg);
    return 2;
}

#define CTL_NEED(n)                                    \
    do {                                               \
        if (argc != (n)) {                             \
            return ctl_usage("wrong arg count");       \
        }                                              \
    } while (0)

/* ---- local hex (TU-private by necessity: srv_crypto.c statics are
 * file-local, and touching the frozen TU beyond dispatch is banned)
 * ---- */
static int ctl_hexval(char c) {
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

static size_t ctl_unhex(const char *s, uint8_t *out, size_t cap) {
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
        hi = ctl_hexval(s[2 * i]);
        lo = ctl_hexval(s[2 * i + 1]);
        if (hi < 0 || lo < 0) {
            return (size_t)-1;
        }
        out[i] = (uint8_t)((hi << 4) | lo);
    }
    return n;
}

static void ctl_hexprint(const uint8_t *b, size_t n) {
    size_t i;
    for (i = 0; i < n; i++) {
        printf("%02x", b[i]);
    }
    printf("\n");
}

/* ---- strict scalar parsers (transport checks, never policy) ---- */
static int ctl_u64(const char *s, uint64_t *out) {
    uint64_t v = 0;
    size_t i;
    if (s == NULL || s[0] == '\0') {
        return -1;
    }
    for (i = 0; s[i] != '\0'; i++) {
        unsigned d;
        if (s[i] < '0' || s[i] > '9' || i >= 20) {
            return -1;
        }
        d = (unsigned)(s[i] - '0');
        if (v > (UINT64_MAX - d) / 10u) {
            return -1;
        }
        v = v * 10u + d;
    }
    *out = v;
    return 0;
}

static int ctl_u32(const char *s, uint32_t *out) {
    uint64_t v = 0;
    if (ctl_u64(s, &v) != 0 || v > 0xFFFFFFFFu) {
        return -1;
    }
    *out = (uint32_t)v;
    return 0;
}

static int ctl_u16(const char *s, uint16_t *out) {
    uint64_t v = 0;
    if (ctl_u64(s, &v) != 0 || v > 0xFFFFu) {
        return -1;
    }
    *out = (uint16_t)v;
    return 0;
}

static int ctl_u8(const char *s, uint8_t *out) {
    uint64_t v = 0;
    if (ctl_u64(s, &v) != 0 || v > 0xFFu) {
        return -1;
    }
    *out = (uint8_t)v;
    return 0;
}

static int ctl_i32(const char *s, int32_t *out) {
    const char *p = s;
    uint64_t v = 0;
    int neg = 0;
    size_t i;
    if (p == NULL || p[0] == '\0') {
        return -1;
    }
    if (p[0] == '-') {
        neg = 1;
        p++;
        if (p[0] == '\0') {
            return -1;
        }
    }
    for (i = 0; p[i] != '\0'; i++) {
        unsigned d;
        if (p[i] < '0' || p[i] > '9' || i >= 10) {
            return -1;
        }
        d = (unsigned)(p[i] - '0');
        if (v > (uint64_t)2147483648u) {
            return -1;
        }
        v = v * 10u + d;
    }
    if (!neg && v > 2147483647u) {
        return -1;
    }
    if (neg && v > 2147483648u) {
        return -1;
    }
    *out = neg ? -(int32_t)v : (int32_t)v;
    return 0;
}

static int ctl_i16(const char *s, int16_t *out) {
    int32_t v = 0;
    if (ctl_i32(s, &v) != 0 || v < -32768 || v > 32767) {
        return -1;
    }
    *out = (int16_t)v;
    return 0;
}

static int ctl_f32hex(const char *s, float *out) {
    uint8_t b[4];
    if (ctl_unhex(s, b, sizeof(b)) != 4 || strlen(s) != 8) {
        return -1;
    }
    memcpy(out, b, 4);
    {
        /* Normalize host order: wire is big-endian. */
        uint8_t *p = (uint8_t *)out;
        uint8_t t0 = p[0], t1 = p[1];
        p[0] = p[3];
        p[1] = p[2];
        p[2] = t1;
        p[3] = t0;
    }
    return 0;
}

static int ctl_f64hex(const char *s, double *out) {
    uint8_t b[8];
    size_t i;
    if (ctl_unhex(s, b, sizeof(b)) != 8 || strlen(s) != 16) {
        return -1;
    }
    {
        uint8_t *p = (uint8_t *)out;
        for (i = 0; i < 8; i++) {
            p[i] = b[7 - i];
        }
    }
    return 0;
}

/* ---- cursor codec (bounds-checked; -1 = short) ---- */
typedef struct {
    uint8_t *p;
    size_t n;
} ctl_cur;

static void ctl_put_u8(ctl_cur *c, uint8_t v) {
    c->p[0] = v;
    c->p += 1;
    c->n -= 1;
}

static void ctl_put_u16(ctl_cur *c, uint16_t v) {
    c->p[0] = (uint8_t)(v >> 8);
    c->p[1] = (uint8_t)v;
    c->p += 2;
    c->n -= 2;
}

static void ctl_put_u32(ctl_cur *c, uint32_t v) {
    c->p[0] = (uint8_t)(v >> 24);
    c->p[1] = (uint8_t)(v >> 16);
    c->p[2] = (uint8_t)(v >> 8);
    c->p[3] = (uint8_t)v;
    c->p += 4;
    c->n -= 4;
}

static void ctl_put_u64(ctl_cur *c, uint64_t v) {
    ctl_put_u32(c, (uint32_t)(v >> 32));
    ctl_put_u32(c, (uint32_t)v);
}

static void ctl_put_f32(ctl_cur *c, float v) {
    uint8_t b[4];
    uint8_t *p = (uint8_t *)&v;
    b[0] = p[3];
    b[1] = p[2];
    b[2] = p[1];
    b[3] = p[0];
    memcpy(c->p, b, 4);
    c->p += 4;
    c->n -= 4;
}

static void ctl_put_f64(ctl_cur *c, double v) {
    uint8_t *p = (uint8_t *)&v;
    size_t i;
    for (i = 0; i < 8; i++) {
        c->p[i] = p[7 - i];
    }
    c->p += 8;
    c->n -= 8;
}

typedef struct {
    const uint8_t *p;
    size_t n;
} ctl_rcur;

static int ctl_get(ctl_rcur *c, uint8_t *out, size_t k) {
    if (c->n < k) {
        return -1;
    }
    memcpy(out, c->p, k);
    c->p += k;
    c->n -= k;
    return 0;
}

static int ctl_get_u8(ctl_rcur *c, uint8_t *v) {
    return ctl_get(c, v, 1);
}

static int ctl_get_u16(ctl_rcur *c, uint16_t *v) {
    uint8_t b[2];
    if (ctl_get(c, b, 2) != 0) {
        return -1;
    }
    *v = (uint16_t)(((uint16_t)b[0] << 8) | b[1]);
    return 0;
}

static int ctl_get_u32(ctl_rcur *c, uint32_t *v) {
    uint8_t b[4];
    if (ctl_get(c, b, 4) != 0) {
        return -1;
    }
    *v = ((uint32_t)b[0] << 24) | ((uint32_t)b[1] << 16) |
         ((uint32_t)b[2] << 8) | b[3];
    return 0;
}

static int ctl_get_u64(ctl_rcur *c, uint64_t *v) {
    uint32_t hi, lo;
    if (ctl_get_u32(c, &hi) != 0 || ctl_get_u32(c, &lo) != 0) {
        return -1;
    }
    *v = ((uint64_t)hi << 32) | lo;
    return 0;
}

static int ctl_get_f32(ctl_rcur *c, float *v) {
    uint8_t b[4];
    uint8_t *p;
    if (ctl_get(c, b, 4) != 0) {
        return -1;
    }
    p = (uint8_t *)v;
    p[0] = b[3];
    p[1] = b[2];
    p[2] = b[1];
    p[3] = b[0];
    return 0;
}

static int ctl_get_f64(ctl_rcur *c, double *v) {
    uint8_t b[8];
    uint8_t *p;
    size_t i;
    if (ctl_get(c, b, 8) != 0) {
        return -1;
    }
    p = (uint8_t *)v;
    for (i = 0; i < 8; i++) {
        p[i] = b[7 - i];
    }
    return 0;
}

/* ---- action codec (14 B) ---- */
static void ctl_enc_action(ctl_cur *c, const qc_action *a) {
    ctl_put_u8(c, a->profile);
    ctl_put_u32(c, a->tpq_s);
    ctl_put_u32(c, a->tr_s);
    ctl_put_u32(c, (uint32_t)a->ta_s);
    ctl_put_u8(c, a->nb);
}

static int ctl_dec_action(ctl_rcur *c, qc_action *a) {
    uint32_t ta;
    if (ctl_get_u8(c, &a->profile) != 0 ||
        ctl_get_u32(c, &a->tpq_s) != 0 ||
        ctl_get_u32(c, &a->tr_s) != 0 || ctl_get_u32(c, &ta) != 0 ||
        ctl_get_u8(c, &a->nb) != 0) {
        return -1;
    }
    a->ta_s = (int32_t)ta;
    return 0;
}

/* ---- section codecs (encode order == decode order, fixed above) ---- */
static void ctl_enc_state(ctl_cur *c, const qc_state *s) {
    size_t i;
    ctl_put_f32(c, s->b_j);
    ctl_put_u8(c, s->b_soc);
    ctl_put_u64(c, s->b_at);
    ctl_put_f32(c, s->r);
    ctl_put_u64(c, s->r_at);
    ctl_put_u8(c, s->s);
    ctl_put_u64(c, s->s_at);
    ctl_put_u8(c, s->s_immediate);
    ctl_put_f32(c, s->c);
    ctl_put_u64(c, s->c_at);
    ctl_put_u32(c, s->m);
    ctl_put_u64(c, s->m_at);
    ctl_put_u16(c, (uint16_t)s->l_rssi);
    ctl_put_u16(c, s->l_retries);
    ctl_put_u64(c, s->l_at);
    ctl_put_f32(c, s->q);
    ctl_put_u64(c, s->q_at);
    ctl_put_u64(c, s->q_counters);
    for (i = 0; i < 6; i++) {
        ctl_put_u32(c, s->risk[i]);
    }
    ctl_put_u64(c, s->risk_at);
    ctl_put_u16(c, s->mask);
    ctl_put_u8(c, s->init);
}

static int ctl_dec_state(ctl_rcur *c, qc_state *s) {
    size_t i;
    uint16_t rssi;
    if (ctl_get_f32(c, &s->b_j) != 0 ||
        ctl_get_u8(c, &s->b_soc) != 0 ||
        ctl_get_u64(c, &s->b_at) != 0 ||
        ctl_get_f32(c, &s->r) != 0 || ctl_get_u64(c, &s->r_at) != 0 ||
        ctl_get_u8(c, &s->s) != 0 || ctl_get_u64(c, &s->s_at) != 0 ||
        ctl_get_u8(c, &s->s_immediate) != 0 ||
        ctl_get_f32(c, &s->c) != 0 || ctl_get_u64(c, &s->c_at) != 0 ||
        ctl_get_u32(c, &s->m) != 0 || ctl_get_u64(c, &s->m_at) != 0 ||
        ctl_get_u16(c, &rssi) != 0 ||
        ctl_get_u16(c, &s->l_retries) != 0 ||
        ctl_get_u64(c, &s->l_at) != 0 ||
        ctl_get_f32(c, &s->q) != 0 || ctl_get_u64(c, &s->q_at) != 0 ||
        ctl_get_u64(c, &s->q_counters) != 0) {
        return -1;
    }
    s->l_rssi = (int16_t)rssi;
    for (i = 0; i < 6; i++) {
        if (ctl_get_u32(c, &s->risk[i]) != 0) {
            return -1;
        }
    }
    if (ctl_get_u64(c, &s->risk_at) != 0 ||
        ctl_get_u16(c, &s->mask) != 0 || ctl_get_u8(c, &s->init) != 0) {
        return -1;
    }
    return 0;
}

static void ctl_enc_riskcfg(ctl_cur *c, const qc_risk_cfg *k) {
    size_t i;
    for (i = 0; i < 6; i++) {
        ctl_put_f32(c, k->w[i]);
    }
    for (i = 0; i < 6; i++) {
        ctl_put_f32(c, k->cmax[i]);
    }
    ctl_put_f32(c, k->theta_hi);
    ctl_put_f32(c, k->theta_lo);
    ctl_put_u16(c, k->n_e);
    ctl_put_u16(c, k->n_x);
    ctl_put_u16(c, k->t_dwell);
    ctl_put_u8(c, k->window_w);
    ctl_put_f32(c, k->h_hint);
}

static int ctl_dec_riskcfg(ctl_rcur *c, qc_risk_cfg *k) {
    size_t i;
    for (i = 0; i < 6; i++) {
        if (ctl_get_f32(c, &k->w[i]) != 0) {
            return -1;
        }
    }
    for (i = 0; i < 6; i++) {
        if (ctl_get_f32(c, &k->cmax[i]) != 0) {
            return -1;
        }
    }
    if (ctl_get_f32(c, &k->theta_hi) != 0 ||
        ctl_get_f32(c, &k->theta_lo) != 0 ||
        ctl_get_u16(c, &k->n_e) != 0 || ctl_get_u16(c, &k->n_x) != 0 ||
        ctl_get_u16(c, &k->t_dwell) != 0 ||
        ctl_get_u8(c, &k->window_w) != 0 ||
        ctl_get_f32(c, &k->h_hint) != 0) {
        return -1;
    }
    return 0;
}

static void ctl_enc_risk(ctl_cur *c, const qc_risk *r) {
    size_t i, j;
    ctl_put_u8(c, r->init);
    ctl_put_u8(c, r->state);
    ctl_put_u8(c, r->emitted);
    ctl_put_u16(c, r->n_enter);
    ctl_put_u16(c, r->n_exit);
    ctl_put_u16(c, r->dwell);
    ctl_put_f32(c, r->r);
    ctl_put_f32(c, r->h_sum);
    for (i = 0; i < 16; i++) {
        for (j = 0; j < 6; j++) {
            ctl_put_u32(c, r->hist[i][j]);
        }
    }
    for (i = 0; i < 16; i++) {
        ctl_put_f32(c, r->hist_r[i]);
    }
    ctl_put_u8(c, r->hidx);
    ctl_put_u8(c, r->hcount);
}

static int ctl_dec_risk(ctl_rcur *c, qc_risk *r) {
    size_t i, j;
    memset(r, 0, sizeof(*r));
    if (ctl_get_u8(c, &r->init) != 0 || ctl_get_u8(c, &r->state) != 0 ||
        ctl_get_u8(c, &r->emitted) != 0 ||
        ctl_get_u16(c, &r->n_enter) != 0 ||
        ctl_get_u16(c, &r->n_exit) != 0 ||
        ctl_get_u16(c, &r->dwell) != 0 ||
        ctl_get_f32(c, &r->r) != 0 || ctl_get_f32(c, &r->h_sum) != 0) {
        return -1;
    }
    for (i = 0; i < 16; i++) {
        for (j = 0; j < 6; j++) {
            if (ctl_get_u32(c, &r->hist[i][j]) != 0) {
                return -1;
            }
        }
    }
    for (i = 0; i < 16; i++) {
        if (ctl_get_f32(c, &r->hist_r[i]) != 0) {
            return -1;
        }
    }
    if (ctl_get_u8(c, &r->hidx) != 0 ||
        ctl_get_u8(c, &r->hcount) != 0) {
        return -1;
    }
    return 0;
}

static void ctl_enc_ftable(ctl_cur *c, const qc_floor_table *t) {
    size_t i;
    for (i = 0; i < 3; i++) {
        ctl_put_u8(c, t->min_level[i]);
    }
    for (i = 0; i < 3; i++) {
        ctl_put_u8(c, t->has[i]);
    }
}

static int ctl_dec_ftable(ctl_rcur *c, qc_floor_table *t) {
    size_t i;
    for (i = 0; i < 3; i++) {
        if (ctl_get_u8(c, &t->min_level[i]) != 0) {
            return -1;
        }
    }
    for (i = 0; i < 3; i++) {
        if (ctl_get_u8(c, &t->has[i]) != 0) {
            return -1;
        }
    }
    return 0;
}

static void ctl_enc_fcfg(ctl_cur *c, const qc_floor_cfg *k) {
    size_t i;
    for (i = 0; i < 3; i++) {
        ctl_put_u32(c, k->lmax_s[i]);
    }
    ctl_put_u8(c, k->nb_max);
}

static int ctl_dec_fcfg(ctl_rcur *c, qc_floor_cfg *k) {
    size_t i;
    for (i = 0; i < 3; i++) {
        if (ctl_get_u32(c, &k->lmax_s[i]) != 0) {
            return -1;
        }
    }
    if (ctl_get_u8(c, &k->nb_max) != 0) {
        return -1;
    }
    return 0;
}

static void ctl_enc_res(ctl_cur *c, const qc_res_tables *t) {
    size_t i;
    ctl_put_u32(c, t->base_ram);
    for (i = 0; i < 3; i++) {
        ctl_put_u32(c, t->stack_ram[i]);
    }
    ctl_put_u32(c, t->ram_per_byte);
    ctl_put_u32(c, t->msg_bytes);
    ctl_put_u32(c, t->lat_base_ms);
    ctl_put_u32(c, t->lat_per_msg_ms);
}

static int ctl_dec_res(ctl_rcur *c, qc_res_tables *t) {
    size_t i;
    if (ctl_get_u32(c, &t->base_ram) != 0) {
        return -1;
    }
    for (i = 0; i < 3; i++) {
        if (ctl_get_u32(c, &t->stack_ram[i]) != 0) {
            return -1;
        }
    }
    if (ctl_get_u32(c, &t->ram_per_byte) != 0 ||
        ctl_get_u32(c, &t->msg_bytes) != 0 ||
        ctl_get_u32(c, &t->lat_base_ms) != 0 ||
        ctl_get_u32(c, &t->lat_per_msg_ms) != 0) {
        return -1;
    }
    return 0;
}

static void ctl_enc_opt(ctl_cur *c, const qc_opt *o) {
    size_t i;
    ctl_put_u8(c, o->init);
    ctl_enc_action(c, &o->a_prev);
    ctl_enc_action(c, &o->staged);
    ctl_put_u8(c, o->staged_valid);
    for (i = 0; i < 60; i++) {
        ctl_put_u16(c, o->buckets[i]);
    }
    ctl_put_u64(c, o->bucket_base);
    ctl_put_u8(c, o->buckets_set);
    ctl_put_u64(c, o->last_switch);
    ctl_put_u32(c, o->hmax);
    ctl_put_u32(c, o->t_cool_s);
    ctl_enc_action(c, &o->queue);
    ctl_put_u8(c, o->queue_valid);
    ctl_put_u8(c, o->in_cap);
    ctl_put_u64(c, o->last_cap_alarm);
    ctl_put_u32(c, o->c.holds);
    ctl_put_u32(c, o->c.sheds);
    ctl_put_u32(c, o->c.queued);
    ctl_put_u32(c, o->c.superseded);
    ctl_put_u32(c, o->c.stale_dropped);
    ctl_put_u32(c, o->c.failsecures);
    ctl_put_u32(c, o->c.apply_fails);
    ctl_put_u8(c, o->pending_alarms);
}

static int ctl_dec_opt(ctl_rcur *c, qc_opt *o) {
    size_t i;
    memset(o, 0, sizeof(*o));
    if (ctl_get_u8(c, &o->init) != 0 ||
        ctl_dec_action(c, (qc_action *)&o->a_prev) != 0 ||
        ctl_dec_action(c, (qc_action *)&o->staged) != 0 ||
        ctl_get_u8(c, &o->staged_valid) != 0) {
        return -1;
    }
    for (i = 0; i < 60; i++) {
        if (ctl_get_u16(c, &o->buckets[i]) != 0) {
            return -1;
        }
    }
    if (ctl_get_u64(c, &o->bucket_base) != 0 ||
        ctl_get_u8(c, &o->buckets_set) != 0 ||
        ctl_get_u64(c, &o->last_switch) != 0 ||
        ctl_get_u32(c, &o->hmax) != 0 ||
        ctl_get_u32(c, &o->t_cool_s) != 0 ||
        ctl_dec_action(c, (qc_action *)&o->queue) != 0 ||
        ctl_get_u8(c, &o->queue_valid) != 0 ||
        ctl_get_u8(c, &o->in_cap) != 0 ||
        ctl_get_u64(c, &o->last_cap_alarm) != 0 ||
        ctl_get_u32(c, &o->c.holds) != 0 ||
        ctl_get_u32(c, &o->c.sheds) != 0 ||
        ctl_get_u32(c, &o->c.queued) != 0 ||
        ctl_get_u32(c, &o->c.superseded) != 0 ||
        ctl_get_u32(c, &o->c.stale_dropped) != 0 ||
        ctl_get_u32(c, &o->c.failsecures) != 0 ||
        ctl_get_u32(c, &o->c.apply_fails) != 0 ||
        ctl_get_u8(c, &o->pending_alarms) != 0) {
        return -1;
    }
    return 0;
}

static void ctl_enc_gov(ctl_cur *c, const qc_gov *g) {
    ctl_put_u8(c, g->init);
    ctl_put_f32(c, g->tau);
    ctl_put_f32(c, g->tau_max);
    ctl_put_f64(c, g->rho);
    ctl_put_f32(c, g->restore_frac);
    ctl_put_u16(c, g->restore_dwell);
    ctl_put_u64(c, g->last_shed);
    ctl_put_u8(c, g->has_shed);
    ctl_put_u32(c, g->c.sheds);
    ctl_put_u32(c, g->c.exhaustions);
    ctl_put_u32(c, g->c.charges);
}

static int ctl_dec_gov(ctl_rcur *c, qc_gov *g) {
    memset(g, 0, sizeof(*g));
    if (ctl_get_u8(c, &g->init) != 0 ||
        ctl_get_f32(c, &g->tau) != 0 ||
        ctl_get_f32(c, &g->tau_max) != 0 ||
        ctl_get_f64(c, &g->rho) != 0 ||
        ctl_get_f32(c, &g->restore_frac) != 0 ||
        ctl_get_u16(c, &g->restore_dwell) != 0 ||
        ctl_get_u64(c, &g->last_shed) != 0 ||
        ctl_get_u8(c, &g->has_shed) != 0 ||
        ctl_get_u32(c, &g->c.sheds) != 0 ||
        ctl_get_u32(c, &g->c.exhaustions) != 0 ||
        ctl_get_u32(c, &g->c.charges) != 0) {
        return -1;
    }
    return 0;
}

/* Full controller state: decode validates magic+ver+exact length. */
typedef struct {
    qc_state st;
    qc_risk_cfg rkcfg;
    qc_risk rk;
    qc_floor_table ft;
    qc_floor_cfg fcfg;
    qc_res_tables res;
    qc_opt opt;
    qc_gov gov;
} ctl_all;

static uint8_t ctl_blob[CTL_BLOB_LEN];

static int ctl_decode(const char *hex, ctl_all *a) {
    ctl_rcur c;
    uint8_t m[4];
    uint16_t ver;
    memset(a, 0, sizeof(*a));
    if (ctl_unhex(hex, ctl_blob, sizeof(ctl_blob)) != CTL_BLOB_LEN) {
        return -1;
    }
    c.p = ctl_blob;
    c.n = sizeof(ctl_blob);
    if (ctl_get(&c, m, 4) != 0 || m[0] != 'Q' || m[1] != 'C' ||
        m[2] != 'T' || m[3] != 'L' || ctl_get_u16(&c, &ver) != 0 ||
        ver != 1) {
        return -1;
    }
    if (ctl_dec_state(&c, &a->st) != 0 ||
        ctl_dec_riskcfg(&c, &a->rkcfg) != 0 ||
        ctl_dec_risk(&c, &a->rk) != 0 ||
        ctl_dec_ftable(&c, &a->ft) != 0 ||
        ctl_dec_fcfg(&c, &a->fcfg) != 0 ||
        ctl_dec_res(&c, &a->res) != 0 ||
        ctl_dec_opt(&c, &a->opt) != 0 ||
        ctl_dec_gov(&c, &a->gov) != 0 || c.n != 0) {
        return -1;
    }
    /* Risk state carries no cfg (stored once as rkcfg); relink it —
     * without this every risk verb runs on zeroed cfg (window_w 0 →
     * SIGFPE on modulo). */
    a->rk.cfg = a->rkcfg;
    return 0;
}

static void ctl_encode(const ctl_all *a) {
    ctl_cur c;
    c.p = ctl_blob;
    c.n = sizeof(ctl_blob);
    ctl_put_u8(&c, (uint8_t)'Q');
    ctl_put_u8(&c, (uint8_t)'C');
    ctl_put_u8(&c, (uint8_t)'T');
    ctl_put_u8(&c, (uint8_t)'L');
    ctl_put_u16(&c, 1);
    ctl_enc_state(&c, &a->st);
    ctl_enc_riskcfg(&c, &a->rkcfg);
    ctl_enc_risk(&c, &a->rk);
    ctl_enc_ftable(&c, &a->ft);
    ctl_enc_fcfg(&c, &a->fcfg);
    ctl_enc_res(&c, &a->res);
    ctl_enc_opt(&c, &a->opt);
    ctl_enc_gov(&c, &a->gov);
    ctl_hexprint(ctl_blob, sizeof(ctl_blob));
}

/* opt hook adapter: charges the in-call gov (wired per call — hooks
 * never cross the blob; see design rule 4). */
struct ctl_hook_ctx {
    qc_gov *g;
    double dt;
};

static void ctl_tau_hook(void *ctx, double joules) {
    struct ctl_hook_ctx *h = (struct ctl_hook_ctx *)ctx;
    if (h == NULL || h->g == NULL || h->dt <= 0.0) {
        return;
    }
    (void)qc_gov_charge(h->g, joules / h->dt, h->dt);
}

static void ctl_wire_hooks(qc_opt *o, struct ctl_hook_ctx *h, qc_gov *g,
                           double dt) {
    static qc_opt_hooks hk;
    h->g = g;
    h->dt = dt;
    hk.ctx = h;
    hk.tau_spend = ctl_tau_hook;
    o->hooks = hk;
    o->has_hooks = 1;
}

static void ctl_print_rc(long rc) {
    printf("%ld\n", rc);
}

static void ctl_print_u32(uint32_t v) {
    printf("%lu\n", (unsigned long)v);
}

static void ctl_print_f64(double v) {
    uint8_t *p = (uint8_t *)&v;
    size_t i;
    for (i = 0; i < 8; i++) {
        printf("%02x", p[7 - i]);
    }
    printf("\n");
}

static void ctl_print_f32(float v) {
    uint8_t *p = (uint8_t *)&v;
    printf("%02x%02x%02x%02x\n", p[3], p[2], p[1], p[0]);
}

/* ---- verb handlers: each returns process exit (0 ok, 2 usage) ---- */

static int verb_init(int argc, char **argv) {
    /* ctl-init ft fcfg res riskcfg taumax rho frac dwell hmax tcool
     *   aprev lastswitch (argc 14) -> blob */
    ctl_all a;
    qc_opt_hooks hk;
    uint8_t tmp[128];
    struct ctl_hook_ctx hctx;
    qc_risk_cfg rkc;
    qc_floor_table ft;
    qc_floor_cfg fcfg;
    qc_res_tables res;
    qc_action aprev;
    float taumax, frac;
    double rho;
    uint16_t dwell;
    uint32_t hmax, tcool;
    uint64_t lastsw;
    ctl_rcur c;
    int rc;
    (void)tmp;
    CTL_NEED(14);
    memset(&a, 0, sizeof(a));
    if (ctl_unhex(argv[2], tmp, 6) != 6) {
        return ctl_usage("bad ftable");
    }
    c.p = tmp;
    c.n = 6;
    if (ctl_dec_ftable(&c, &ft) != 0) {
        return ctl_usage("bad ftable");
    }
    if (ctl_unhex(argv[3], tmp, 13) != 13) {
        return ctl_usage("bad fcfg");
    }
    c.p = tmp;
    c.n = 13;
    if (ctl_dec_fcfg(&c, &fcfg) != 0) {
        return ctl_usage("bad fcfg");
    }
    if (ctl_unhex(argv[4], tmp, 32) != 32) {
        return ctl_usage("bad res");
    }
    c.p = tmp;
    c.n = 32;
    if (ctl_dec_res(&c, &res) != 0) {
        return ctl_usage("bad res");
    }
    if (ctl_unhex(argv[5], tmp, 67) != 67) {
        return ctl_usage("bad riskcfg");
    }
    c.p = tmp;
    c.n = 67;
    if (ctl_dec_riskcfg(&c, &rkc) != 0) {
        return ctl_usage("bad riskcfg");
    }
    if (ctl_f32hex(argv[6], &taumax) != 0 ||
        ctl_f64hex(argv[7], &rho) != 0 ||
        ctl_f32hex(argv[8], &frac) != 0 ||
        ctl_u16(argv[9], &dwell) != 0 ||
        ctl_u32(argv[10], &hmax) != 0 ||
        ctl_u32(argv[11], &tcool) != 0) {
        return ctl_usage("bad gov/init scalars");
    }
    if (ctl_unhex(argv[12], tmp, 14) != 14) {
        return ctl_usage("bad aprev");
    }
    c.p = tmp;
    c.n = 14;
    if (ctl_dec_action(&c, &aprev) != 0) {
        return ctl_usage("bad aprev");
    }
    if (ctl_u64(argv[13], &lastsw) != 0) {
        return ctl_usage("bad lastswitch");
    }
    a.ft = ft;
    a.fcfg = fcfg;
    a.res = res;
    a.rkcfg = rkc;
    qc_state_init(&a.st);
    rc = qc_risk_init(&a.rk, &a.rkcfg);
    if (rc != 0) {
        ctl_print_rc((long)rc);
        return 0;
    }
    hctx.g = &a.gov;
    hctx.dt = 1.0;
    hk.ctx = &hctx;
    hk.tau_spend = ctl_tau_hook;
    rc = qc_opt_init(&a.opt, &aprev, hmax, tcool, lastsw, &hk);
    if (rc != 0) {
        ctl_print_rc((long)rc);
        return 0;
    }
    {
        qc_gov_rc grc = qc_gov_init(&a.gov, taumax, rho, frac, dwell);
        if (grc != QC_GOV_OK) {
            ctl_print_rc((long)grc);
            return 0;
        }
    }
    ctl_print_rc(0);
    ctl_encode(&a);
    return 0;
}

/* ---- state samplers/check (comp-indexed payloads, documented) ----
 * ctl-state-sample blob comp v0 v1 now -> rc blob
 *   comp: 0 B(joules-f32hex, soc-dec) 1 R(risk-f32hex) 2 S(cls-dec)
 *   3 C(load-f32hex) 4 M(bytes-dec) 5 L(rssi-dec,retries-dec)
 *   6 Q(rate-f32hex,counters-dec) 7 risk-snapshot(counts6-hex)
 *   unused payload args ignored (documented, never validated). */
static int verb_state_sample(int argc, char **argv) {
    ctl_all a;
    uint8_t comp;
    uint64_t now;
    qc_state_rc rc;
    CTL_NEED(7);
    if (ctl_decode(argv[2], &a) != 0) {
        return ctl_usage("bad blob");
    }
    if (ctl_u8(argv[3], &comp) != 0 || comp > 7) {
        return ctl_usage("bad comp (0..7)");
    }
    if (ctl_u64(argv[6], &now) != 0) {
        return ctl_usage("bad now");
    }
    rc = QC_STATE_BAD_ARG;
    if (comp == 0) {
        float j;
        uint8_t soc;
        if (ctl_f32hex(argv[4], &j) != 0 || ctl_u8(argv[5], &soc) != 0) {
            return ctl_usage("bad B payload");
        }
        rc = qc_state_sample_b(&a.st, j, soc, now);
    } else if (comp == 1) {
        float r;
        if (ctl_f32hex(argv[4], &r) != 0) {
            return ctl_usage("bad R payload");
        }
        rc = qc_state_sample_r(&a.st, r, now);
    } else if (comp == 2) {
        uint8_t cls;
        if (ctl_u8(argv[4], &cls) != 0) {
            return ctl_usage("bad S payload");
        }
        rc = qc_state_sample_s(&a.st, cls, now);
    } else if (comp == 3) {
        float l;
        if (ctl_f32hex(argv[4], &l) != 0) {
            return ctl_usage("bad C payload");
        }
        rc = qc_state_sample_c(&a.st, l, now);
    } else if (comp == 4) {
        uint32_t m;
        if (ctl_u32(argv[4], &m) != 0) {
            return ctl_usage("bad M payload");
        }
        rc = qc_state_sample_m(&a.st, m, now);
    } else if (comp == 5) {
        int16_t rssi;
        uint16_t ret;
        if (ctl_i16(argv[4], &rssi) != 0 || ctl_u16(argv[5], &ret) != 0) {
            return ctl_usage("bad L payload");
        }
        rc = qc_state_sample_l(&a.st, rssi, ret, now);
    } else if (comp == 6) {
        float q;
        uint64_t ctr;
        if (ctl_f32hex(argv[4], &q) != 0 || ctl_u64(argv[5], &ctr) != 0) {
            return ctl_usage("bad Q payload");
        }
        rc = qc_state_sample_q(&a.st, q, ctr, now);
    } else {
        uint8_t cnt[24];
        uint32_t c6[6];
        size_t i;
        if (ctl_unhex(argv[4], cnt, sizeof(cnt)) != 24) {
            return ctl_usage("bad snapshot payload (24 B)");
        }
        for (i = 0; i < 6; i++) {
            c6[i] = ((uint32_t)cnt[4 * i] << 24) |
                    ((uint32_t)cnt[4 * i + 1] << 16) |
                    ((uint32_t)cnt[4 * i + 2] << 8) | cnt[4 * i + 3];
        }
        rc = qc_state_snapshot_risk(&a.st, c6, now);
    }
    ctl_print_rc((long)rc);
    ctl_encode(&a);
    return 0;
}

/* ctl-state-check blob now dmax memmin counters qeps -> rc mask */
static int verb_state_check(int argc, char **argv) {
    ctl_all a;
    uint64_t now, dmax, ctrs;
    uint32_t memmin;
    float qeps;
    uint16_t mask;
    CTL_NEED(8);
    if (ctl_decode(argv[2], &a) != 0) {
        return ctl_usage("bad blob");
    }
    if (ctl_u64(argv[3], &now) != 0 || ctl_u64(argv[4], &dmax) != 0 ||
        ctl_u32(argv[5], &memmin) != 0 ||
        ctl_u64(argv[6], &ctrs) != 0 ||
        ctl_f32hex(argv[7], &qeps) != 0) {
        return ctl_usage("bad check scalars");
    }
    mask = qc_state_check(&a.st, now, dmax, memmin, ctrs, qeps);
    ctl_print_rc(0);
    ctl_print_u32((uint32_t)mask);
    ctl_encode(&a);
    return 0;
}

/* ctl-state-take-immediate blob -> rc flag (clears on read). */
static int verb_state_take(int argc, char **argv) {
    ctl_all a;
    int f;
    CTL_NEED(3);
    if (ctl_decode(argv[2], &a) != 0) {
        return ctl_usage("bad blob");
    }
    f = qc_state_take_s_immediate(&a.st);
    ctl_print_rc(0);
    ctl_print_u32((uint32_t)f);
    ctl_encode(&a);
    return 0;
}

/* ctl-risk-window blob inc24hex -> rc blob R band */
static int verb_risk_window(int argc, char **argv) {
    ctl_all a;
    uint8_t ib[24];
    uint32_t inc[6];
    size_t i;
    qc_risk_rc rc;
    CTL_NEED(4);
    if (ctl_decode(argv[2], &a) != 0) {
        return ctl_usage("bad blob");
    }
    if (ctl_unhex(argv[3], ib, sizeof(ib)) != 24) {
        return ctl_usage("bad inc (24 B)");
    }
    for (i = 0; i < 6; i++) {
        inc[i] = ((uint32_t)ib[4 * i] << 24) |
                 ((uint32_t)ib[4 * i + 1] << 16) |
                 ((uint32_t)ib[4 * i + 2] << 8) | ib[4 * i + 3];
    }
    rc = qc_risk_window(&a.rk, inc);
    ctl_print_rc((long)rc);
    ctl_encode(&a);
    ctl_print_f32(qc_risk_r(&a.rk));
    ctl_print_u32((uint32_t)qc_risk_high(&a.rk));
    return 0;
}

/* ctl-risk-hint blob -> rc blob R band */
static int verb_risk_hint(int argc, char **argv) {
    ctl_all a;
    qc_risk_rc rc;
    CTL_NEED(3);
    if (ctl_decode(argv[2], &a) != 0) {
        return ctl_usage("bad blob");
    }
    rc = qc_risk_hint(&a.rk);
    ctl_print_rc((long)rc);
    ctl_encode(&a);
    ctl_print_f32(qc_risk_r(&a.rk));
    ctl_print_u32((uint32_t)qc_risk_high(&a.rk));
    return 0;
}

/* ctl-risk-miss blob -> rc blob R band */
static int verb_risk_miss(int argc, char **argv) {
    ctl_all a;
    qc_risk_rc rc;
    CTL_NEED(3);
    if (ctl_decode(argv[2], &a) != 0) {
        return ctl_usage("bad blob");
    }
    rc = qc_risk_miss(&a.rk);
    ctl_print_rc((long)rc);
    ctl_encode(&a);
    ctl_print_f32(qc_risk_r(&a.rk));
    ctl_print_u32((uint32_t)qc_risk_high(&a.rk));
    return 0;
}

/* Pure floor verbs take minimal explicit encodings (no blob — const
 * proof by construction). State section = 126 B hex. */

/* ctl-floor-select state126 rhigh -> rc seff rhigh_out */
static int verb_floor_select(int argc, char **argv) {
    uint8_t sb[126];
    qc_state s;
    ctl_rcur c;
    uint8_t rh;
    qc_floor_basis out;
    qc_floor_rc rc;
    CTL_NEED(4);
    if (ctl_unhex(argv[2], sb, sizeof(sb)) != 126) {
        return ctl_usage("bad state (126 B)");
    }
    c.p = sb;
    c.n = sizeof(sb);
    memset(&s, 0, sizeof(s));
    if (ctl_dec_state(&c, &s) != 0) {
        return ctl_usage("bad state");
    }
    if (ctl_u8(argv[3], &rh) != 0 || rh > 1) {
        return ctl_usage("bad r_high (0/1)");
    }
    memset(&out, 0, sizeof(out));
    rc = qc_floor_select(&s, (int)rh, &out);
    ctl_print_rc((long)rc);
    ctl_print_u32((uint32_t)out.s_eff);
    ctl_print_u32((uint32_t)out.r_high);
    return 0;
}

/* ctl-floor-c1 profile table6 seff -> 0/1 */
static int verb_floor_c1(int argc, char **argv) {
    uint8_t tb[6];
    qc_floor_table t;
    ctl_rcur c;
    uint8_t prof, seff;
    CTL_NEED(5);
    if (ctl_u8(argv[2], &prof) != 0 ||
        ctl_u8(argv[4], &seff) != 0) {
        return ctl_usage("bad profile/seff");
    }
    if (ctl_unhex(argv[3], tb, sizeof(tb)) != 6) {
        return ctl_usage("bad table (6 B)");
    }
    c.p = tb;
    c.n = sizeof(tb);
    if (ctl_dec_ftable(&c, &t) != 0) {
        return ctl_usage("bad table");
    }
    ctl_print_rc(0);
    ctl_print_u32((uint32_t)qc_floor_c1(prof, &t, seff));
    return 0;
}

/* ctl-floor-c2 tpq seff -> 0/1 */
static int verb_floor_c2(int argc, char **argv) {
    uint32_t tpq;
    uint8_t seff;
    CTL_NEED(4);
    if (ctl_u32(argv[2], &tpq) != 0 || ctl_u8(argv[3], &seff) != 0) {
        return ctl_usage("bad tpq/seff");
    }
    ctl_print_rc(0);
    ctl_print_u32((uint32_t)qc_floor_c2(tpq, seff));
    return 0;
}

/* ctl-floor-c3 ta seff -> 0/1 (ta signed: sentinels negative). */
static int verb_floor_c3(int argc, char **argv) {
    int32_t ta;
    uint8_t seff;
    CTL_NEED(4);
    if (ctl_i32(argv[2], &ta) != 0 || ctl_u8(argv[3], &seff) != 0) {
        return ctl_usage("bad ta/seff");
    }
    ctl_print_rc(0);
    ctl_print_u32((uint32_t)qc_floor_c3(ta, seff));
    return 0;
}

/* ctl-floor-c4 action14 res32 mfree -> 0/1 ram */
static int verb_floor_c4(int argc, char **argv) {
    uint8_t ab[14], rb[32];
    qc_action a;
    qc_res_tables rt;
    ctl_rcur c;
    uint32_t mfree, ram = 0;
    int v;
    CTL_NEED(5);
    if (ctl_unhex(argv[2], ab, sizeof(ab)) != 14) {
        return ctl_usage("bad action (14 B)");
    }
    if (ctl_unhex(argv[3], rb, sizeof(rb)) != 32) {
        return ctl_usage("bad res (32 B)");
    }
    if (ctl_u32(argv[4], &mfree) != 0) {
        return ctl_usage("bad mfree");
    }
    c.p = ab;
    c.n = sizeof(ab);
    memset(&a, 0, sizeof(a));
    if (ctl_dec_action(&c, &a) != 0) {
        return ctl_usage("bad action");
    }
    c.p = rb;
    c.n = sizeof(rb);
    memset(&rt, 0, sizeof(rt));
    if (ctl_dec_res(&c, &rt) != 0) {
        return ctl_usage("bad res");
    }
    v = qc_floor_c4(&a, &rt, mfree, &ram);
    ctl_print_rc(0);
    ctl_print_u32((uint32_t)v);
    ctl_print_u32(ram);
    return 0;
}

/* ctl-floor-c5 action14 res32 cfg13 seff -> 0/1 latms */
static int verb_floor_c5(int argc, char **argv) {
    uint8_t ab[14], rb[32], cb[13];
    qc_action a;
    qc_res_tables rt;
    qc_floor_cfg fc;
    ctl_rcur c;
    uint8_t seff;
    uint32_t lat = 0;
    int v;
    CTL_NEED(6);
    if (ctl_unhex(argv[2], ab, sizeof(ab)) != 14) {
        return ctl_usage("bad action (14 B)");
    }
    if (ctl_unhex(argv[3], rb, sizeof(rb)) != 32) {
        return ctl_usage("bad res (32 B)");
    }
    if (ctl_unhex(argv[4], cb, sizeof(cb)) != 13) {
        return ctl_usage("bad cfg (13 B)");
    }
    if (ctl_u8(argv[5], &seff) != 0) {
        return ctl_usage("bad seff");
    }
    c.p = ab;
    c.n = sizeof(ab);
    memset(&a, 0, sizeof(a));
    if (ctl_dec_action(&c, &a) != 0) {
        return ctl_usage("bad action");
    }
    c.p = rb;
    c.n = sizeof(rb);
    memset(&rt, 0, sizeof(rt));
    if (ctl_dec_res(&c, &rt) != 0) {
        return ctl_usage("bad res");
    }
    c.p = cb;
    c.n = sizeof(cb);
    memset(&fc, 0, sizeof(fc));
    if (ctl_dec_fcfg(&c, &fc) != 0) {
        return ctl_usage("bad cfg");
    }
    v = qc_floor_c5(&a, &rt, &fc, seff, &lat);
    ctl_print_rc(0);
    ctl_print_u32((uint32_t)v);
    ctl_print_u32(lat);
    return 0;
}

static qc_action feas_buf[CTL_FEAS_CAP];
static size_t feas_n;

static void feas_cb(const qc_action *a, void *ctx) {
    (void)ctx;
    if (feas_n < CTL_FEAS_CAP) {
        feas_buf[feas_n] = *a;
        feas_n++;
    }
}

/* ctl-floor-feasible admitted3 table6 seff res32 cfg13 mfree
 *   -> count + action lines (lattice bounded by construction). */
static int verb_floor_feasible(int argc, char **argv) {
    uint8_t ab[3], tb[6], rb[32], cb[13];
    uint8_t admitted[3];
    qc_floor_table t;
    qc_res_tables rt;
    qc_floor_cfg fc;
    ctl_rcur c;
    uint8_t seff;
    uint32_t mfree;
    size_t i, n;
    CTL_NEED(8);
    if (ctl_unhex(argv[2], ab, sizeof(ab)) != 3) {
        return ctl_usage("bad admitted (3 B)");
    }
    if (ctl_unhex(argv[3], tb, sizeof(tb)) != 6) {
        return ctl_usage("bad table (6 B)");
    }
    if (ctl_u8(argv[4], &seff) != 0) {
        return ctl_usage("bad seff");
    }
    if (ctl_unhex(argv[5], rb, sizeof(rb)) != 32) {
        return ctl_usage("bad res (32 B)");
    }
    if (ctl_unhex(argv[6], cb, sizeof(cb)) != 13) {
        return ctl_usage("bad cfg (13 B)");
    }
    if (ctl_u32(argv[7], &mfree) != 0) {
        return ctl_usage("bad mfree");
    }
    for (i = 0; i < 3; i++) {
        admitted[i] = ab[i];
    }
    c.p = tb;
    c.n = sizeof(tb);
    memset(&t, 0, sizeof(t));
    if (ctl_dec_ftable(&c, &t) != 0) {
        return ctl_usage("bad table");
    }
    c.p = rb;
    c.n = sizeof(rb);
    memset(&rt, 0, sizeof(rt));
    if (ctl_dec_res(&c, &rt) != 0) {
        return ctl_usage("bad res");
    }
    c.p = cb;
    c.n = sizeof(cb);
    memset(&fc, 0, sizeof(fc));
    if (ctl_dec_fcfg(&c, &fc) != 0) {
        return ctl_usage("bad cfg");
    }
    feas_n = 0;
    n = qc_floor_feasible(admitted, &t, seff, &rt, &fc, mfree, feas_cb,
                          NULL);
    ctl_print_rc(0);
    ctl_print_u32((uint32_t)n);
    for (i = 0; i < feas_n; i++) {
        ctl_cur o;
        uint8_t ob[14];
        o.p = ob;
        o.n = sizeof(ob);
        ctl_enc_action(&o, &feas_buf[i]);
        ctl_hexprint(ob, sizeof(ob));
    }
    return 0;
}

/* ---- energy coeff/foot/counts blobs (magic'd like the state blob) ---- */
static uint8_t ctl_cblob[CTL_COEFF_LEN];
static uint8_t ctl_fblob[CTL_FOOT_LEN];
static uint8_t ctl_nblob[CTL_COUNTS_LEN];

static void ctl_enc_coeff(ctl_cur *c, const qc_e_coeff *k) {
    size_t i, j;
    for (i = 0; i < 3; i++) {
        for (j = 0; j < 3; j++) {
            ctl_put_f64(c, k->e_kem[i][j]);
        }
    }
    for (i = 0; i < 3; i++) {
        ctl_put_f64(c, k->e_dsa_sign[i]);
    }
    for (i = 0; i < 3; i++) {
        ctl_put_f64(c, k->e_dsa_verify[i]);
    }
    ctl_put_f64(c, k->e_aes_b);
    ctl_put_f64(c, k->e_hkdf_ext);
    ctl_put_f64(c, k->e_hkdf_exp);
    ctl_put_f64(c, k->e_sha_b);
    ctl_put_f64(c, k->eB);
    ctl_put_f64(c, k->e_ev);
    for (i = 0; i < 4; i++) {
        ctl_put_f64(c, k->ebase_jps[i]);
    }
    ctl_put_u32(c, k->assumed);
}

static int ctl_dec_coeff(ctl_rcur *c, qc_e_coeff *k) {
    size_t i, j;
    memset(k, 0, sizeof(*k));
    for (i = 0; i < 3; i++) {
        for (j = 0; j < 3; j++) {
            if (ctl_get_f64(c, &k->e_kem[i][j]) != 0) {
                return -1;
            }
        }
    }
    for (i = 0; i < 3; i++) {
        if (ctl_get_f64(c, &k->e_dsa_sign[i]) != 0) {
            return -1;
        }
    }
    for (i = 0; i < 3; i++) {
        if (ctl_get_f64(c, &k->e_dsa_verify[i]) != 0) {
            return -1;
        }
    }
    if (ctl_get_f64(c, &k->e_aes_b) != 0 ||
        ctl_get_f64(c, &k->e_hkdf_ext) != 0 ||
        ctl_get_f64(c, &k->e_hkdf_exp) != 0 ||
        ctl_get_f64(c, &k->e_sha_b) != 0 ||
        ctl_get_f64(c, &k->eB) != 0 || ctl_get_f64(c, &k->e_ev) != 0) {
        return -1;
    }
    for (i = 0; i < 4; i++) {
        if (ctl_get_f64(c, &k->ebase_jps[i]) != 0) {
            return -1;
        }
    }
    if (ctl_get_u32(c, &k->assumed) != 0) {
        return -1;
    }
    return 0;
}

static int ctl_coeff_in(const char *hex, qc_e_coeff *k) {
    ctl_rcur c;
    uint8_t m[4];
    uint16_t ver;
    if (ctl_unhex(hex, ctl_cblob, sizeof(ctl_cblob)) != CTL_COEFF_LEN) {
        return -1;
    }
    c.p = ctl_cblob;
    c.n = sizeof(ctl_cblob);
    if (ctl_get(&c, m, 4) != 0 || m[0] != 'Q' || m[1] != 'C' ||
        m[2] != 'E' || m[3] != 'C' || ctl_get_u16(&c, &ver) != 0 ||
        ver != 1 || ctl_dec_coeff(&c, k) != 0 || c.n != 0) {
        return -1;
    }
    return 0;
}

static void ctl_coeff_out(const qc_e_coeff *k) {
    ctl_cur c;
    c.p = ctl_cblob;
    c.n = sizeof(ctl_cblob);
    ctl_put_u8(&c, (uint8_t)'Q');
    ctl_put_u8(&c, (uint8_t)'C');
    ctl_put_u8(&c, (uint8_t)'E');
    ctl_put_u8(&c, (uint8_t)'C');
    ctl_put_u16(&c, 1);
    ctl_enc_coeff(&c, k);
    ctl_hexprint(ctl_cblob, sizeof(ctl_cblob));
}

static void ctl_enc_foot(ctl_cur *c, const qc_foot_tables *t) {
    size_t i;
    ctl_put_u32(c, t->base_ram);
    for (i = 0; i < 3; i++) {
        ctl_put_u32(c, t->stack_ram[i]);
    }
    ctl_put_u32(c, t->ram_per_byte);
    ctl_put_u32(c, t->msg_bytes);
    ctl_put_u32(c, t->lat_base_ms);
    ctl_put_u32(c, t->lat_per_msg_ms);
    ctl_put_u32(c, t->assumed);
}

static int ctl_dec_foot(ctl_rcur *c, qc_foot_tables *t) {
    size_t i;
    memset(t, 0, sizeof(*t));
    if (ctl_get_u32(c, &t->base_ram) != 0) {
        return -1;
    }
    for (i = 0; i < 3; i++) {
        if (ctl_get_u32(c, &t->stack_ram[i]) != 0) {
            return -1;
        }
    }
    if (ctl_get_u32(c, &t->ram_per_byte) != 0 ||
        ctl_get_u32(c, &t->msg_bytes) != 0 ||
        ctl_get_u32(c, &t->lat_base_ms) != 0 ||
        ctl_get_u32(c, &t->lat_per_msg_ms) != 0 ||
        ctl_get_u32(c, &t->assumed) != 0) {
        return -1;
    }
    return 0;
}

static int ctl_foot_in(const char *hex, qc_foot_tables *t) {
    ctl_rcur c;
    uint8_t m[4];
    uint16_t ver;
    if (ctl_unhex(hex, ctl_fblob, sizeof(ctl_fblob)) != CTL_FOOT_LEN) {
        return -1;
    }
    c.p = ctl_fblob;
    c.n = sizeof(ctl_fblob);
    if (ctl_get(&c, m, 4) != 0 || m[0] != 'Q' || m[1] != 'C' ||
        m[2] != 'F' || m[3] != 'T' || ctl_get_u16(&c, &ver) != 0 ||
        ver != 1 || ctl_dec_foot(&c, t) != 0 || c.n != 0) {
        return -1;
    }
    return 0;
}

static void ctl_foot_out(const qc_foot_tables *t) {
    ctl_cur c;
    c.p = ctl_fblob;
    c.n = sizeof(ctl_fblob);
    ctl_put_u8(&c, (uint8_t)'Q');
    ctl_put_u8(&c, (uint8_t)'C');
    ctl_put_u8(&c, (uint8_t)'F');
    ctl_put_u8(&c, (uint8_t)'T');
    ctl_put_u16(&c, 1);
    ctl_enc_foot(&c, t);
    ctl_hexprint(ctl_fblob, sizeof(ctl_fblob));
}

static void ctl_enc_counts(ctl_cur *c, const qc_e_counts *n) {
    size_t i, j;
    for (i = 0; i < 3; i++) {
        for (j = 0; j < 3; j++) {
            ctl_put_f64(c, n->kem[i][j]);
        }
    }
    for (i = 0; i < 3; i++) {
        ctl_put_f64(c, n->dsa_sign[i]);
    }
    for (i = 0; i < 3; i++) {
        ctl_put_f64(c, n->dsa_verify[i]);
    }
    ctl_put_f64(c, n->aes_enc_b);
    ctl_put_f64(c, n->aes_dec_b);
    ctl_put_f64(c, n->hkdf_ext);
    ctl_put_f64(c, n->hkdf_exp);
    ctl_put_f64(c, n->sha_b);
    ctl_put_f64(c, n->bytes);
    ctl_put_f64(c, n->events);
}

static int ctl_dec_counts(ctl_rcur *c, qc_e_counts *n) {
    size_t i, j;
    memset(n, 0, sizeof(*n));
    for (i = 0; i < 3; i++) {
        for (j = 0; j < 3; j++) {
            if (ctl_get_f64(c, &n->kem[i][j]) != 0) {
                return -1;
            }
        }
    }
    for (i = 0; i < 3; i++) {
        if (ctl_get_f64(c, &n->dsa_sign[i]) != 0) {
            return -1;
        }
    }
    for (i = 0; i < 3; i++) {
        if (ctl_get_f64(c, &n->dsa_verify[i]) != 0) {
            return -1;
        }
    }
    if (ctl_get_f64(c, &n->aes_enc_b) != 0 ||
        ctl_get_f64(c, &n->aes_dec_b) != 0 ||
        ctl_get_f64(c, &n->hkdf_ext) != 0 ||
        ctl_get_f64(c, &n->hkdf_exp) != 0 ||
        ctl_get_f64(c, &n->sha_b) != 0 ||
        ctl_get_f64(c, &n->bytes) != 0 ||
        ctl_get_f64(c, &n->events) != 0) {
        return -1;
    }
    return 0;
}

static int ctl_counts_in(const char *hex, qc_e_counts *n) {
    ctl_rcur c;
    uint8_t m[4];
    uint16_t ver;
    if (ctl_unhex(hex, ctl_nblob, sizeof(ctl_nblob)) != CTL_COUNTS_LEN) {
        return -1;
    }
    c.p = ctl_nblob;
    c.n = sizeof(ctl_nblob);
    if (ctl_get(&c, m, 4) != 0 || m[0] != 'Q' || m[1] != 'C' ||
        m[2] != 'C' || m[3] != 'N' || ctl_get_u16(&c, &ver) != 0 ||
        ver != 1 || ctl_dec_counts(&c, n) != 0 || c.n != 0) {
        return -1;
    }
    return 0;
}

static void ctl_counts_out(const qc_e_counts *n) {
    ctl_cur c;
    c.p = ctl_nblob;
    c.n = sizeof(ctl_nblob);
    ctl_put_u8(&c, (uint8_t)'Q');
    ctl_put_u8(&c, (uint8_t)'C');
    ctl_put_u8(&c, (uint8_t)'C');
    ctl_put_u8(&c, (uint8_t)'N');
    ctl_put_u16(&c, 1);
    ctl_enc_counts(&c, n);
    ctl_hexprint(ctl_nblob, sizeof(ctl_nblob));
}

/* ctl-energy-priors -> coeff */
static int verb_energy_priors(int argc, char **argv) {
    qc_e_coeff k;
    (void)argv;
    CTL_NEED(2);
    memset(&k, 0, sizeof(k));
    qc_energy_priors(&k);
    ctl_print_rc(0);
    ctl_coeff_out(&k);
    return 0;
}

/* ctl-energy-foot-priors -> foot */
static int verb_energy_foot_priors(int argc, char **argv) {
    qc_foot_tables t;
    (void)argv;
    CTL_NEED(2);
    memset(&t, 0, sizeof(t));
    qc_foot_priors(&t);
    ctl_print_rc(0);
    ctl_foot_out(&t);
    return 0;
}

/* ctl-energy-calibrate coeff field idx sub value -> rc coeff */
static int verb_energy_calibrate(int argc, char **argv) {
    qc_e_coeff k;
    int32_t field, idx, sub;
    double v;
    int rc;
    CTL_NEED(7);
    if (ctl_coeff_in(argv[2], &k) != 0) {
        return ctl_usage("bad coeff");
    }
    if (ctl_i32(argv[3], &field) != 0 ||
        ctl_i32(argv[4], &idx) != 0 ||
        ctl_i32(argv[5], &sub) != 0 ||
        ctl_f64hex(argv[6], &v) != 0) {
        return ctl_usage("bad field/idx/sub/value");
    }
    rc = qc_energy_calibrate(&k, (int)field, (int)idx, (int)sub, v);
    ctl_print_rc((long)rc);
    ctl_coeff_out(&k);
    return 0;
}

/* ctl-energy-foot-calibrate foot field idx value -> rc foot */
static int verb_energy_foot_calibrate(int argc, char **argv) {
    qc_foot_tables t;
    int32_t field, idx;
    uint32_t v;
    int rc;
    CTL_NEED(6);
    if (ctl_foot_in(argv[2], &t) != 0) {
        return ctl_usage("bad foot");
    }
    if (ctl_i32(argv[3], &field) != 0 ||
        ctl_i32(argv[4], &idx) != 0 ||
        ctl_u32(argv[5], &v) != 0) {
        return ctl_usage("bad field/idx/value");
    }
    rc = qc_foot_calibrate(&t, (int)field, (int)idx, v);
    ctl_print_rc((long)rc);
    ctl_foot_out(&t);
    return 0;
}

/* ctl-energy-foot-to-res foot -> res32hex */
static int verb_energy_foot_to_res(int argc, char **argv) {
    qc_foot_tables t;
    qc_res_tables rt;
    ctl_cur c;
    uint8_t ob[32];
    CTL_NEED(3);
    if (ctl_foot_in(argv[2], &t) != 0) {
        return ctl_usage("bad foot");
    }
    memset(&rt, 0, sizeof(rt));
    qc_foot_to_res(&t, &rt);
    c.p = ob;
    c.n = sizeof(ob);
    ctl_enc_res(&c, &rt);
    ctl_print_rc(0);
    ctl_hexprint(ob, sizeof(ob));
    return 0;
}

/* ctl-energy-eval coeff counts ebase ectrl t -> base crypto comm adapt
 *   total (f64hex lines). */
static int verb_energy_eval(int argc, char **argv) {
    qc_e_coeff k;
    qc_e_counts n;
    double ebase, ectrl, t;
    qc_e_groups g;
    CTL_NEED(7);
    if (ctl_coeff_in(argv[2], &k) != 0) {
        return ctl_usage("bad coeff");
    }
    if (ctl_counts_in(argv[3], &n) != 0) {
        return ctl_usage("bad counts");
    }
    if (ctl_f64hex(argv[4], &ebase) != 0 ||
        ctl_f64hex(argv[5], &ectrl) != 0 ||
        ctl_f64hex(argv[6], &t) != 0) {
        return ctl_usage("bad ebase/ectrl/t");
    }
    memset(&g, 0, sizeof(g));
    qc_energy_eval(&n, &k, ebase, ectrl, t, &g);
    ctl_print_rc(0);
    ctl_print_f64(g.base);
    ctl_print_f64(g.crypto);
    ctl_print_f64(g.comm);
    ctl_print_f64(g.adapt);
    ctl_print_f64(g.total);
    return 0;
}

/* ctl-energy-ehat coeff counts -> f64hex */
static int verb_energy_ehat(int argc, char **argv) {
    qc_e_coeff k;
    qc_e_counts n;
    CTL_NEED(4);
    if (ctl_coeff_in(argv[2], &k) != 0) {
        return ctl_usage("bad coeff");
    }
    if (ctl_counts_in(argv[3], &n) != 0) {
        return ctl_usage("bad counts");
    }
    ctl_print_rc(0);
    ctl_print_f64(qc_ehat_sec(&n, &k));
    return 0;
}

/* ctl-energy-ehs coeff profile nev -> f64hex */
static int verb_energy_ehs(int argc, char **argv) {
    qc_e_coeff k;
    uint8_t prof;
    double nev;
    CTL_NEED(5);
    if (ctl_coeff_in(argv[2], &k) != 0) {
        return ctl_usage("bad coeff");
    }
    if (ctl_u8(argv[3], &prof) != 0 || prof < 1 || prof > 3) {
        return ctl_usage("bad profile (1..3)");
    }
    if (ctl_f64hex(argv[4], &nev) != 0) {
        return ctl_usage("bad nev");
    }
    ctl_print_rc(0);
    ctl_print_f64(qc_energy_ehs(&k, (int)prof, nev));
    return 0;
}

/* ctl-energy-hmax-rate ehs rekeys -> f64hex (pure caller arithmetic,
 * exposed so sim and C share one spelling). */
static int verb_energy_hmax_rate(int argc, char **argv) {
    double ehs, rk;
    CTL_NEED(4);
    if (ctl_f64hex(argv[2], &ehs) != 0 ||
        ctl_f64hex(argv[3], &rk) != 0) {
        return ctl_usage("bad ehs/rekeys");
    }
    ctl_print_rc(0);
    ctl_print_f64(qc_energy_hmax_rate(ehs, rk));
    return 0;
}

/* ctl-energy-derive profile msgph resend msgb tpq tr ta taev c2
 *   readings transcript dsa_verify -> counts (12 workload args). */
static int verb_energy_derive(int argc, char **argv) {
    qc_workload w;
    qc_e_counts n;
    uint8_t prof;
    int32_t ta;
    uint32_t tpq, tr;
    memset(&w, 0, sizeof(w));
    memset(&n, 0, sizeof(n));
    CTL_NEED(14);
    if (ctl_u8(argv[2], &prof) != 0 || prof < 1 || prof > 3) {
        return ctl_usage("bad profile (1..3)");
    }
    if (ctl_f64hex(argv[3], &w.msg_per_h) != 0 ||
        ctl_f64hex(argv[4], &w.resend) != 0 ||
        ctl_f64hex(argv[5], &w.msg_bytes) != 0 ||
        ctl_u32(argv[6], &tpq) != 0 || ctl_u32(argv[7], &tr) != 0 ||
        ctl_i32(argv[8], &ta) != 0 ||
        ctl_f64hex(argv[9], &w.ta_event_per_h) != 0 ||
        ctl_f64hex(argv[10], &w.c2_per_h) != 0 ||
        ctl_f64hex(argv[11], &w.readings_per_h) != 0 ||
        ctl_f64hex(argv[12], &w.transcript_b) != 0 ||
        ctl_f64hex(argv[13], &w.dsa_verify_per_h) != 0) {
        return ctl_usage("bad workload");
    }
    w.profile = (int)prof;
    w.tpq_s = tpq;
    w.tr_s = tr;
    w.ta_s = ta;
    qc_derive_counts(&w, &n);
    ctl_print_rc(0);
    ctl_counts_out(&n);
    return 0;
}

/* ctl-opt-reconfigure blob hmax tcool -> rc blob */
static int verb_opt_reconfigure(int argc, char **argv) {
    ctl_all a;
    uint32_t hmax, tcool;
    int rc;
    CTL_NEED(5);
    if (ctl_decode(argv[2], &a) != 0) {
        return ctl_usage("bad blob");
    }
    if (ctl_u32(argv[3], &hmax) != 0 || ctl_u32(argv[4], &tcool) != 0) {
        return ctl_usage("bad hmax/tcool");
    }
    rc = qc_opt_reconfigure(&a.opt, hmax, tcool);
    ctl_print_rc((long)rc);
    ctl_encode(&a);
    return 0;
}

/* ctl-opt-decide blob ncands candshex lambda tau margin now
 *   -> rc blob staged [action] */
static int verb_opt_decide(int argc, char **argv) {
    ctl_all a;
    uint32_t n;
    size_t clen, i;
    static uint8_t cands_raw[CTL_FEAS_CAP * 30];
    qc_cand cands[CTL_FEAS_CAP];
    qc_action staged_out;
    double lambda, tau, margin;
    uint64_t now;
    struct ctl_hook_ctx hctx;
    qc_opt_rc rc;
    int staged;
    CTL_NEED(9);
    if (ctl_decode(argv[2], &a) != 0) {
        return ctl_usage("bad blob");
    }
    if (ctl_u32(argv[3], &n) != 0 || n > CTL_FEAS_CAP) {
        return ctl_usage("bad ncands");
    }
    if (n == 0) {
        if (strcmp(argv[4], "none") != 0) {
            return ctl_usage("empty cands must be \"none\"");
        }
    } else {
        clen = strlen(argv[4]);
        if (clen != (size_t)n * 60u) {
            return ctl_usage("bad cands length");
        }
        if (ctl_unhex(argv[4], cands_raw, sizeof(cands_raw)) !=
            (size_t)n * 30u) {
            return ctl_usage("bad cands hex");
        }
        for (i = 0; i < n; i++) {
            ctl_rcur cc;
            uint8_t *p = cands_raw + i * 30u;
            cc.p = p;
            cc.n = 30;
            if (ctl_dec_action(&cc, &cands[i].action) != 0 ||
                ctl_get_f64(&cc, &cands[i].ehat_j) != 0 ||
                ctl_get_f64(&cc, &cands[i].ehat_sec) != 0) {
                return ctl_usage("bad cand record");
            }
        }
    }
    if (ctl_f64hex(argv[5], &lambda) != 0 ||
        ctl_f64hex(argv[6], &tau) != 0 ||
        ctl_f64hex(argv[7], &margin) != 0 ||
        ctl_u64(argv[8], &now) != 0) {
        return ctl_usage("bad lambda/tau/margin/now");
    }
    ctl_wire_hooks(&a.opt, &hctx, &a.gov, 1.0);
    memset(&staged_out, 0, sizeof(staged_out));
    rc = qc_opt_decide(&a.opt, cands, (size_t)n, lambda,
                       tau, margin, now);
    staged = qc_opt_staged(&a.opt, &staged_out);
    ctl_print_rc((long)rc);
    ctl_encode(&a);
    ctl_print_u32((uint32_t)staged);
    if (staged) {
        ctl_cur o;
        uint8_t ob[14];
        o.p = ob;
        o.n = sizeof(ob);
        ctl_enc_action(&o, &staged_out);
        ctl_hexprint(ob, sizeof(ob));
    }
    return 0;
}

/* ctl-opt-staged blob -> flag [action] (pure read, no blob out). */
static int verb_opt_staged(int argc, char **argv) {
    ctl_all a;
    qc_action act;
    int staged;
    CTL_NEED(3);
    if (ctl_decode(argv[2], &a) != 0) {
        return ctl_usage("bad blob");
    }
    memset(&act, 0, sizeof(act));
    staged = qc_opt_staged(&a.opt, &act);
    ctl_print_rc(0);
    ctl_print_u32((uint32_t)staged);
    if (staged) {
        ctl_cur o;
        uint8_t ob[14];
        o.p = ob;
        o.n = sizeof(ob);
        ctl_enc_action(&o, &act);
        ctl_hexprint(ob, sizeof(ob));
    }
    return 0;
}

/* ctl-opt-commit blob ok now spend applied|none dt -> rc blob.
 * applied "none" decodes to NULL (staged). dt must be > 0 (hook
 * adapter divides by it — the one servant input guard beyond C). */
static int verb_opt_commit(int argc, char **argv) {
    ctl_all a;
    uint8_t ok;
    uint64_t now;
    double spend, dt;
    qc_action applied;
    const qc_action *pap;
    struct ctl_hook_ctx hctx;
    qc_opt_rc rc;
    CTL_NEED(8);
    if (ctl_decode(argv[2], &a) != 0) {
        return ctl_usage("bad blob");
    }
    if (ctl_u8(argv[3], &ok) != 0 || ok > 1) {
        return ctl_usage("bad ok (0/1)");
    }
    if (ctl_u64(argv[4], &now) != 0 ||
        ctl_f64hex(argv[5], &spend) != 0) {
        return ctl_usage("bad now/spend");
    }
    if (strcmp(argv[6], "none") == 0) {
        pap = NULL;
    } else {
        uint8_t ab[14];
        ctl_rcur c;
        if (ctl_unhex(argv[6], ab, sizeof(ab)) != 14) {
            return ctl_usage("bad applied (14 B or \"none\")");
        }
        c.p = ab;
        c.n = sizeof(ab);
        memset(&applied, 0, sizeof(applied));
        if (ctl_dec_action(&c, &applied) != 0) {
            return ctl_usage("bad applied");
        }
        pap = &applied;
    }
    if (ctl_f64hex(argv[7], &dt) != 0 || dt <= 0.0) {
        return ctl_usage("bad dt (must be > 0)");
    }
    ctl_wire_hooks(&a.opt, &hctx, &a.gov, dt);
    rc = qc_opt_commit(&a.opt, (int)ok, now, spend, pap);
    ctl_print_rc((long)rc);
    ctl_encode(&a);
    return 0;
}

/* ctl-opt-note-handshake blob now -> rc blob */
static int verb_opt_note(int argc, char **argv) {
    ctl_all a;
    uint64_t now;
    int rc;
    CTL_NEED(4);
    if (ctl_decode(argv[2], &a) != 0) {
        return ctl_usage("bad blob");
    }
    if (ctl_u64(argv[3], &now) != 0) {
        return ctl_usage("bad now");
    }
    rc = qc_opt_note_handshake(&a.opt, now);
    ctl_print_rc((long)rc);
    ctl_encode(&a);
    return 0;
}

/* ctl-opt-cap-count blob now -> count blob (read rolls window). */
static int verb_opt_capcount(int argc, char **argv) {
    ctl_all a;
    uint64_t now;
    uint32_t c;
    CTL_NEED(4);
    if (ctl_decode(argv[2], &a) != 0) {
        return ctl_usage("bad blob");
    }
    if (ctl_u64(argv[3], &now) != 0) {
        return ctl_usage("bad now");
    }
    c = qc_opt_cap_count(&a.opt, now);
    ctl_print_rc(0);
    ctl_print_u32(c);
    ctl_encode(&a);
    return 0;
}

/* ctl-opt-take-alarms blob -> blob bits (drains on read; blob second
 * per the multi-output convention). */
static int verb_opt_alarms(int argc, char **argv) {
    ctl_all a;
    uint8_t b;
    CTL_NEED(3);
    if (ctl_decode(argv[2], &a) != 0) {
        return ctl_usage("bad blob");
    }
    b = qc_opt_take_alarms(&a.opt);
    ctl_print_rc(0);
    ctl_encode(&a);
    ctl_print_u32((uint32_t)b);
    return 0;
}

/* ctl-opt-counts blob -> 7 counter lines (pure read, no blob). */
static int verb_opt_counts(int argc, char **argv) {
    ctl_all a;
    qc_opt_counters c;
    CTL_NEED(3);
    if (ctl_decode(argv[2], &a) != 0) {
        return ctl_usage("bad blob");
    }
    memset(&c, 0, sizeof(c));
    qc_opt_counts(&a.opt, &c);
    ctl_print_rc(0);
    ctl_print_u32(c.holds);
    ctl_print_u32(c.sheds);
    ctl_print_u32(c.queued);
    ctl_print_u32(c.superseded);
    ctl_print_u32(c.stale_dropped);
    ctl_print_u32(c.failsecures);
    ctl_print_u32(c.apply_fails);
    return 0;
}

/* ctl-gov-charge blob ehat dt -> rc blob tau */
static int verb_gov_charge(int argc, char **argv) {
    ctl_all a;
    double ehat, dt;
    qc_gov_rc rc;
    CTL_NEED(5);
    if (ctl_decode(argv[2], &a) != 0) {
        return ctl_usage("bad blob");
    }
    if (ctl_f64hex(argv[3], &ehat) != 0 ||
        ctl_f64hex(argv[4], &dt) != 0) {
        return ctl_usage("bad ehat/dt");
    }
    rc = qc_gov_charge(&a.gov, ehat, dt);
    ctl_print_rc((long)rc);
    ctl_encode(&a);
    ctl_print_f32(qc_gov_tau(&a.gov));
    return 0;
}

/* ctl-gov-tau blob -> tau (pure read, no blob). */
static int verb_gov_tau(int argc, char **argv) {
    ctl_all a;
    CTL_NEED(3);
    if (ctl_decode(argv[2], &a) != 0) {
        return ctl_usage("bad blob");
    }
    ctl_print_rc(0);
    ctl_print_f32(qc_gov_tau(&a.gov));
    return 0;
}

/* ctl-gov-shed blob c0rate action c0min tacap now
 *   -> rc blob c0directive exhausted action */
static int verb_gov_shed(int argc, char **argv) {
    ctl_all a;
    double rate, c0min;
    qc_action act;
    qc_shed_in in;
    qc_shed_floors fl;
    qc_shed_out out;
    uint8_t ab[14];
    ctl_rcur c;
    int32_t tacap;
    uint64_t now;
    qc_gov_rc rc;
    CTL_NEED(8);
    if (ctl_decode(argv[2], &a) != 0) {
        return ctl_usage("bad blob");
    }
    if (ctl_f64hex(argv[3], &rate) != 0) {
        return ctl_usage("bad c0rate");
    }
    if (ctl_unhex(argv[4], ab, sizeof(ab)) != 14) {
        return ctl_usage("bad action (14 B)");
    }
    c.p = ab;
    c.n = sizeof(ab);
    memset(&act, 0, sizeof(act));
    if (ctl_dec_action(&c, &act) != 0) {
        return ctl_usage("bad action");
    }
    if (ctl_f64hex(argv[5], &c0min) != 0 ||
        ctl_i32(argv[6], &tacap) != 0 ||
        ctl_u64(argv[7], &now) != 0) {
        return ctl_usage("bad c0min/tacap/now");
    }
    memset(&in, 0, sizeof(in));
    memset(&fl, 0, sizeof(fl));
    memset(&out, 0, sizeof(out));
    in.c0_rate = rate;
    in.action = act;
    fl.c0_min = c0min;
    fl.ta_cap_s = tacap;
    rc = qc_gov_shed(&a.gov, &in, &fl, &out, now);
    ctl_print_rc((long)rc);
    ctl_encode(&a);
    ctl_print_f64(out.c0_directive);
    ctl_print_u32((uint32_t)out.exhausted);
    {
        ctl_cur o;
        uint8_t ob[14];
        o.p = ob;
        o.n = sizeof(ob);
        ctl_enc_action(&o, &out.a_shed);
        ctl_hexprint(ob, sizeof(ob));
    }
    return 0;
}

/* ctl-gov-restore-ready blob now delta -> 0/1 (pure read). */
static int verb_gov_ready(int argc, char **argv) {
    ctl_all a;
    uint64_t now, delta;
    CTL_NEED(5);
    if (ctl_decode(argv[2], &a) != 0) {
        return ctl_usage("bad blob");
    }
    if (ctl_u64(argv[3], &now) != 0 || ctl_u64(argv[4], &delta) != 0) {
        return ctl_usage("bad now/delta");
    }
    ctl_print_rc(0);
    ctl_print_u32((uint32_t)qc_gov_restore_ready(&a.gov, now, delta));
    return 0;
}

/* ctl-gov-restore-step currate curaction desrate desaction
 *   -> leg outrate outaction (pure, no blob at all). */
static int verb_gov_step(int argc, char **argv) {
    double crate, drate;
    qc_action ca, da;
    qc_shed_in cur, des;
    uint8_t cb[14], db[14];
    ctl_rcur c;
    int leg;
    CTL_NEED(6);
    if (ctl_f64hex(argv[2], &crate) != 0) {
        return ctl_usage("bad currate");
    }
    if (ctl_unhex(argv[3], cb, sizeof(cb)) != 14) {
        return ctl_usage("bad curaction (14 B)");
    }
    if (ctl_f64hex(argv[4], &drate) != 0) {
        return ctl_usage("bad desrate");
    }
    if (ctl_unhex(argv[5], db, sizeof(db)) != 14) {
        return ctl_usage("bad desaction (14 B)");
    }
    c.p = cb;
    c.n = sizeof(cb);
    memset(&ca, 0, sizeof(ca));
    if (ctl_dec_action(&c, &ca) != 0) {
        return ctl_usage("bad curaction");
    }
    c.p = db;
    c.n = sizeof(db);
    memset(&da, 0, sizeof(da));
    if (ctl_dec_action(&c, &da) != 0) {
        return ctl_usage("bad desaction");
    }
    memset(&cur, 0, sizeof(cur));
    memset(&des, 0, sizeof(des));
    cur.c0_rate = crate;
    cur.action = ca;
    des.c0_rate = drate;
    des.action = da;
    {
        qc_shed_in out;
        memset(&out, 0, sizeof(out));
        leg = qc_gov_restore_step(&cur, &des, &out);
        ctl_print_rc(0);
        ctl_print_u32((uint32_t)leg);
        ctl_print_f64(out.c0_rate);
        {
            ctl_cur o;
            uint8_t ob[14];
            o.p = ob;
            o.n = sizeof(ob);
            ctl_enc_action(&o, &out.action);
            ctl_hexprint(ob, sizeof(ob));
        }
    }
    return 0;
}

/* ctl-gov-counts blob -> sheds exhaustions charges (pure read). */
static int verb_gov_counts(int argc, char **argv) {
    ctl_all a;
    qc_gov_counters c;
    CTL_NEED(3);
    if (ctl_decode(argv[2], &a) != 0) {
        return ctl_usage("bad blob");
    }
    memset(&c, 0, sizeof(c));
    qc_gov_counts(&a.gov, &c);
    ctl_print_rc(0);
    ctl_print_u32(c.sheds);
    ctl_print_u32(c.exhaustions);
    ctl_print_u32(c.charges);
    return 0;
}

/* Composite decide (hot path): risk close -> floor basis -> feasible
 * -> per-candidate Ehat over dt_w -> opt decide -> drain alarms.
 * Charging/commit stay caller-side (decide never commits — staged or
 * SHED/HOLD/FAILSECURE outcomes need caller action first, per B-34
 * order). Alarms drain here so one call = one window, fully observed.
 * Energy coeff/ebase/ectrl and the admitted mask arrive EXPLICITLY
 * (never hidden inside the blob): ebase/ectrl are caller-lumped per
 * B-33 single-counting, and hiding them as 0.0 would silently fix the
 * absolute Ehat scale (ranking-neutral across candidates, but the
 * printed values must mean what they say).
 * ctl-decide blob inc24 hint profile msgph resend msgb tpq tr ta
 *   taev c2 readings transcript dsaverify lambda margin now dtw
 *   admitted3 coeff210 ebase ectrl (argc 25)
 *   -> rc blob staged [action] alarms. */
static int verb_decide(int argc, char **argv) {
    ctl_all a;
    uint8_t ib[24];
    uint32_t inc[6];
    size_t i;
    uint8_t hint, prof;
    uint8_t adm[3];
    uint8_t admitted[3];
    qc_workload wbase;
    qc_e_coeff ecoeff;
    double lambda, margin, dtw, ebase, ectrl;
    uint64_t now;
    uint32_t tpq, tr;
    int32_t ta;
    qc_floor_basis basis;
    qc_cand cands[CTL_FEAS_CAP];
    qc_action staged_out;
    struct ctl_hook_ctx hctx;
    qc_opt_rc rc;
    int staged;
    uint8_t alarms;
    CTL_NEED(25);
    if (ctl_decode(argv[2], &a) != 0) {
        return ctl_usage("bad blob");
    }
    if (ctl_unhex(argv[3], ib, sizeof(ib)) != 24) {
        return ctl_usage("bad inc (24 B)");
    }
    for (i = 0; i < 6; i++) {
        inc[i] = ((uint32_t)ib[4 * i] << 24) |
                 ((uint32_t)ib[4 * i + 1] << 16) |
                 ((uint32_t)ib[4 * i + 2] << 8) | ib[4 * i + 3];
    }
    if (ctl_u8(argv[4], &hint) != 0 || hint > 1) {
        return ctl_usage("bad hint (0/1)");
    }
    memset(&wbase, 0, sizeof(wbase));
    if (ctl_u8(argv[5], &prof) != 0 || prof < 1 || prof > 3) {
        return ctl_usage("bad profile (1..3)");
    }
    if (ctl_f64hex(argv[6], &wbase.msg_per_h) != 0 ||
        ctl_f64hex(argv[7], &wbase.resend) != 0 ||
        ctl_f64hex(argv[8], &wbase.msg_bytes) != 0 ||
        ctl_u32(argv[9], &tpq) != 0 || ctl_u32(argv[10], &tr) != 0 ||
        ctl_i32(argv[11], &ta) != 0 ||
        ctl_f64hex(argv[12], &wbase.ta_event_per_h) != 0 ||
        ctl_f64hex(argv[13], &wbase.c2_per_h) != 0 ||
        ctl_f64hex(argv[14], &wbase.readings_per_h) != 0 ||
        ctl_f64hex(argv[15], &wbase.transcript_b) != 0 ||
        ctl_f64hex(argv[16], &wbase.dsa_verify_per_h) != 0 ||
        ctl_f64hex(argv[17], &lambda) != 0 ||
        ctl_f64hex(argv[18], &margin) != 0 ||
        ctl_u64(argv[19], &now) != 0) {
        return ctl_usage("bad window scalars");
    }
    if (ctl_f64hex(argv[20], &dtw) != 0) {
        return ctl_usage("bad dtw");
    }
    if (ctl_unhex(argv[21], adm, sizeof(adm)) != 3) {
        return ctl_usage("bad admitted (3 B)");
    }
    if (ctl_coeff_in(argv[22], &ecoeff) != 0) {
        return ctl_usage("bad coeff");
    }
    if (ctl_f64hex(argv[23], &ebase) != 0 ||
        ctl_f64hex(argv[24], &ectrl) != 0) {
        return ctl_usage("bad ebase/ectrl");
    }
    for (i = 0; i < 3; i++) {
        admitted[i] = adm[i];
    }
    wbase.profile = (int)prof;
    wbase.tpq_s = tpq;
    wbase.tr_s = tr;
    wbase.ta_s = ta;
    if (hint) {
        (void)qc_risk_hint(&a.rk);
    }
    (void)qc_risk_window(&a.rk, inc);
    memset(&basis, 0, sizeof(basis));
    rc = QC_OPT_OK_STAGED;
    {
        qc_floor_rc frc = qc_floor_select(&a.st, qc_risk_high(&a.rk),
                                         &basis);
        if (frc != QC_FLOOR_OK) {
            alarms = qc_opt_take_alarms(&a.opt);
            ctl_print_rc((long)frc);
            ctl_encode(&a);
            ctl_print_u32(0);
            ctl_print_u32((uint32_t)alarms);
            return 0;
        }
    }
    feas_n = 0;
    {
        size_t n;
        n = qc_floor_feasible(admitted, &a.ft, basis.s_eff, &a.res,
                              &a.fcfg, a.st.m, feas_cb, NULL);
        (void)n;
    }
    for (i = 0; i < feas_n; i++) {
        qc_workload w;
        qc_e_counts n;
        qc_e_groups g;
        w = wbase;
        w.profile = (int)feas_buf[i].profile;
        w.tpq_s = feas_buf[i].tpq_s;
        w.tr_s = feas_buf[i].tr_s;
        w.ta_s = feas_buf[i].ta_s;
        memset(&n, 0, sizeof(n));
        memset(&g, 0, sizeof(g));
        qc_derive_counts(&w, &n);
        qc_energy_eval(&n, &ecoeff, ebase, ectrl, dtw, &g);
        cands[i].action = feas_buf[i];
        cands[i].ehat_j = g.total;
        cands[i].ehat_sec = qc_ehat_sec(&n, &ecoeff);
    }
    ctl_wire_hooks(&a.opt, &hctx, &a.gov, dtw);
    rc = qc_opt_decide(&a.opt, feas_n == 0 ? NULL : cands, feas_n,
                       lambda, (double)qc_gov_tau(&a.gov), margin, now);
    memset(&staged_out, 0, sizeof(staged_out));
    staged = qc_opt_staged(&a.opt, &staged_out);
    alarms = qc_opt_take_alarms(&a.opt);
    ctl_print_rc((long)rc);
    ctl_encode(&a);
    ctl_print_u32((uint32_t)staged);
    if (staged) {
        ctl_cur o;
        uint8_t ob[14];
        o.p = ob;
        o.n = sizeof(ob);
        ctl_enc_action(&o, &staged_out);
        ctl_hexprint(ob, sizeof(ob));
    }
    ctl_print_u32((uint32_t)alarms);
    return 0;
}

/* ---- dispatch: exact names, prefix-guarded by the caller ---- */
int srv_ctl_main(int argc, char **argv) {
    const char *c;
    if (argc < 2 || argv[1] == NULL) {
        return -1;
    }
    c = argv[1];
    if (c[0] != 'c' || c[1] != 't' || c[2] != 'l' || c[3] != '-') {
        return -1;
    }
    if (strcmp(c, "ctl-init") == 0) {
        return verb_init(argc, argv);
    }
    if (strcmp(c, "ctl-state-sample") == 0) {
        return verb_state_sample(argc, argv);
    }
    if (strcmp(c, "ctl-state-check") == 0) {
        return verb_state_check(argc, argv);
    }
    if (strcmp(c, "ctl-state-take-immediate") == 0) {
        return verb_state_take(argc, argv);
    }
    if (strcmp(c, "ctl-risk-window") == 0) {
        return verb_risk_window(argc, argv);
    }
    if (strcmp(c, "ctl-risk-hint") == 0) {
        return verb_risk_hint(argc, argv);
    }
    if (strcmp(c, "ctl-risk-miss") == 0) {
        return verb_risk_miss(argc, argv);
    }
    if (strcmp(c, "ctl-floor-select") == 0) {
        return verb_floor_select(argc, argv);
    }
    if (strcmp(c, "ctl-floor-c1") == 0) {
        return verb_floor_c1(argc, argv);
    }
    if (strcmp(c, "ctl-floor-c2") == 0) {
        return verb_floor_c2(argc, argv);
    }
    if (strcmp(c, "ctl-floor-c3") == 0) {
        return verb_floor_c3(argc, argv);
    }
    if (strcmp(c, "ctl-floor-c4") == 0) {
        return verb_floor_c4(argc, argv);
    }
    if (strcmp(c, "ctl-floor-c5") == 0) {
        return verb_floor_c5(argc, argv);
    }
    if (strcmp(c, "ctl-floor-feasible") == 0) {
        return verb_floor_feasible(argc, argv);
    }
    if (strcmp(c, "ctl-energy-priors") == 0) {
        return verb_energy_priors(argc, argv);
    }
    if (strcmp(c, "ctl-energy-foot-priors") == 0) {
        return verb_energy_foot_priors(argc, argv);
    }
    if (strcmp(c, "ctl-energy-calibrate") == 0) {
        return verb_energy_calibrate(argc, argv);
    }
    if (strcmp(c, "ctl-energy-foot-calibrate") == 0) {
        return verb_energy_foot_calibrate(argc, argv);
    }
    if (strcmp(c, "ctl-energy-foot-to-res") == 0) {
        return verb_energy_foot_to_res(argc, argv);
    }
    if (strcmp(c, "ctl-energy-eval") == 0) {
        return verb_energy_eval(argc, argv);
    }
    if (strcmp(c, "ctl-energy-ehat") == 0) {
        return verb_energy_ehat(argc, argv);
    }
    if (strcmp(c, "ctl-energy-ehs") == 0) {
        return verb_energy_ehs(argc, argv);
    }
    if (strcmp(c, "ctl-energy-hmax-rate") == 0) {
        return verb_energy_hmax_rate(argc, argv);
    }
    if (strcmp(c, "ctl-energy-derive") == 0) {
        return verb_energy_derive(argc, argv);
    }
    if (strcmp(c, "ctl-opt-reconfigure") == 0) {
        return verb_opt_reconfigure(argc, argv);
    }
    if (strcmp(c, "ctl-opt-decide") == 0) {
        return verb_opt_decide(argc, argv);
    }
    if (strcmp(c, "ctl-opt-staged") == 0) {
        return verb_opt_staged(argc, argv);
    }
    if (strcmp(c, "ctl-opt-commit") == 0) {
        return verb_opt_commit(argc, argv);
    }
    if (strcmp(c, "ctl-opt-note-handshake") == 0) {
        return verb_opt_note(argc, argv);
    }
    if (strcmp(c, "ctl-opt-cap-count") == 0) {
        return verb_opt_capcount(argc, argv);
    }
    if (strcmp(c, "ctl-opt-take-alarms") == 0) {
        return verb_opt_alarms(argc, argv);
    }
    if (strcmp(c, "ctl-opt-counts") == 0) {
        return verb_opt_counts(argc, argv);
    }
    if (strcmp(c, "ctl-gov-charge") == 0) {
        return verb_gov_charge(argc, argv);
    }
    if (strcmp(c, "ctl-gov-tau") == 0) {
        return verb_gov_tau(argc, argv);
    }
    if (strcmp(c, "ctl-gov-shed") == 0) {
        return verb_gov_shed(argc, argv);
    }
    if (strcmp(c, "ctl-gov-restore-ready") == 0) {
        return verb_gov_ready(argc, argv);
    }
    if (strcmp(c, "ctl-gov-restore-step") == 0) {
        return verb_gov_step(argc, argv);
    }
    if (strcmp(c, "ctl-gov-counts") == 0) {
        return verb_gov_counts(argc, argv);
    }
    if (strcmp(c, "ctl-decide") == 0) {
        return verb_decide(argc, argv);
    }
    return ctl_usage("unknown ctl subcommand");
}
