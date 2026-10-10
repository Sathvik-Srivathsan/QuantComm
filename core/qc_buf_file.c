/* qc_buf_file.c — HOST file mirror for C2 buffer entries (B-24.5).
 * Write-through on every C2 insert (caller invokes after OK); temp+rename
 * (write-then-use, no torn mirror); load repopulates after reboot with
 * ORIGINAL enqueue times (stale age survives reboot). C0/C1 never touch
 * this file (RAM-only by design). Oversize remainder stays RAM-only
 * (bounded mirror, documented). Corrupt mirror -> BAD_ARG (durability,
 * not trust: caller treats as empty and re-mirrors; never halts).
 * ESP32 port swaps this TU for NVS (same header).
 */
#include "qc_buf.h"

#include <stdio.h>
#include <string.h>

/* Entry header: len u16 || cls u8 || score u8 || epoch u32 ||
 * counter u64 || at u64 (2+1+1+4+8+8 = 24 B) + bytes. Audit fix: was
 * 20, overlapping `at` with entry bytes (caught by mirror age test). */
#define QC_BUF_MHDR 24

static void put_u16(uint8_t *p, uint16_t v) {
    p[0] = (uint8_t)(v >> 8);
    p[1] = (uint8_t)v;
}

static void put_u32(uint8_t *p, uint32_t v) {
    p[0] = (uint8_t)(v >> 24);
    p[1] = (uint8_t)(v >> 16);
    p[2] = (uint8_t)(v >> 8);
    p[3] = (uint8_t)v;
}

static void put_u64(uint8_t *p, uint64_t v) {
    int i;
    for (i = 0; i < 8; i++) {
        p[i] = (uint8_t)(v >> (8 * (7 - i)));
    }
}

static uint16_t get_u16(const uint8_t *p) {
    return (uint16_t)(((uint16_t)p[0] << 8) | p[1]);
}

static uint32_t get_u32(const uint8_t *p) {
    return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) |
           ((uint32_t)p[2] << 8) | (uint32_t)p[3];
}

static uint64_t get_u64(const uint8_t *p) {
    uint64_t v = 0;
    int i;
    for (i = 0; i < 8; i++) {
        v = (v << 8) | p[i];
    }
    return v;
}

qc_buf_rc qc_buf_mirror_save(qc_buf *b, const char *path) {
    /* Serialize C2 entries (slot order; drain re-sorts on load). */
    static uint8_t img[QC_BUF_MIRROR_CAP];
    char tmp[512];
    size_t n = 6; /* magic[4] + count[2] */
    uint16_t cnt = 0;
    FILE *f;

    if (b == NULL || path == NULL) {
        return QC_BUF_BAD_ARG;
    }
    if (strlen(path) + 4 >= sizeof(tmp)) {
        return QC_BUF_BAD_ARG;
    }
    img[0] = 'Q';
    img[1] = 'C';
    img[2] = 'B';
    img[3] = '1';
    for (int i = 0; i < QC_BUF_SLOTS; i++) {
        const uint16_t L = b->slot[i].len;
        if (!b->slot[i].valid || b->slot[i].cls != 2) {
            continue;
        }
        /* slot.len <= QC_BUF_CAP < 65536: no truncation (checked). */
        if (n + QC_BUF_MHDR + L > QC_BUF_MIRROR_CAP) {
            break; /* remainder stays RAM-only (bounded mirror). */
        }
        put_u16(img + n, L);
        img[n + 2] = b->slot[i].cls;
        img[n + 3] = b->slot[i].score;
        put_u32(img + n + 4, b->slot[i].epoch);
        put_u64(img + n + 8, b->slot[i].counter);
        put_u64(img + n + 16, b->slot[i].at);
        /* Entry bytes live in b->arena at slot off (valid slot). */
        memcpy(img + n + QC_BUF_MHDR, b->arena + b->slot[i].off, L);
        n += QC_BUF_MHDR + L;
        cnt++;
    }
    put_u16(img + 4, cnt);
    memcpy(tmp, path, strlen(path) + 1);
    memcpy(tmp + strlen(path), ".tmp", 5);
    f = fopen(tmp, "wb");
    if (f == NULL) {
        return QC_BUF_BAD_ARG;
    }
    /* Audit: no double-fclose (short fwrite closes once here). */
    if (fwrite(img, 1, n, f) != n) {
        fclose(f);
        remove(tmp);
        return QC_BUF_BAD_ARG;
    }
    if (fclose(f) != 0) {
        remove(tmp);
        return QC_BUF_BAD_ARG;
    }
    if (rename(tmp, path) != 0) {
        /* Windows rename refuses overwrite (POSIX path above stays
         * atomic): one remove+retry covers native-Windows hosts. */
        remove(path);
        if (rename(tmp, path) != 0) {
            remove(tmp);
            return QC_BUF_BAD_ARG;
        }
    }
    b->c.mirror_writes++;
    return QC_BUF_OK;
}

qc_buf_rc qc_buf_mirror_load(qc_buf *b, const char *path, uint64_t now) {
    static uint8_t img[QC_BUF_MIRROR_CAP + 64];
    FILE *f;
    size_t n, off;
    uint16_t cnt;

    if (b == NULL || !b->init || path == NULL) {
        return QC_BUF_BAD_ARG;
    }
    f = fopen(path, "rb");
    if (f == NULL) {
        return QC_BUF_OK; /* absent mirror: nothing to repopulate. */
    }
    n = fread(img, 1, sizeof(img), f);
    fclose(f);
    if (n == 0) {
        return QC_BUF_OK; /* empty mirror: same as absent. */
    }
    if (n < 6 || img[0] != 'Q' || img[1] != 'C' || img[2] != 'B' ||
        img[3] != '1') {
        return QC_BUF_BAD_ARG; /* corrupt: caller treats as empty. */
    }
    cnt = get_u16(img + 4);
    off = 6;
    for (uint16_t k = 0; k < cnt; k++) {
        uint16_t L;
        uint8_t cls;
        uint64_t at;

        if (off + QC_BUF_MHDR > n) {
            return QC_BUF_BAD_ARG;
        }
        L = get_u16(img + off);
        cls = img[off + 2];
        if (cls != 2 || off + QC_BUF_MHDR + L > n) {
            return QC_BUF_BAD_ARG; /* mirror holds C2 only; exact fit. */
        }
        at = get_u64(img + off + 16);
        /* Boot path: fresh buffer expected (load-into-live merges in
         * drain order anyway — reinsert is order-agnostic). Original `at`
         * preserved, so stale age survives reboot; pre-expired entries
         * are refused counted (EXPIRED), never kept. */
        {
            qc_buf_rc rc = qc_buf_reinsert(b, img + off + QC_BUF_MHDR, L,
                                           cls, img[off + 3],
                                           get_u32(img + off + 4),
                                           get_u64(img + off + 8), at, now);
            if (rc == QC_BUF_EXPIRED) {
                /* counted inside reinsert; next entry. */
            } else if (rc != QC_BUF_OK) {
                return rc;
            }
        }
        off += QC_BUF_MHDR + L;
    }
    return QC_BUF_OK;
}
