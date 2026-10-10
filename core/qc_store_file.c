/* qc_store_file.c — HOST file backend for qc_store (B-13.3).
 * Whole-blob read/write over fopen. Missing/empty file reads as absent
 * (NOT_FOUND mapping); short reads, oversize files, and all write errors
 * are I/O faults. Hook adapters use static captures (C has no closures;
 * single in-flight save/load, single-threaded callers only — same
 * assumption as everywhere else in this tree).
 * ESP32 port swaps this TU for the encrypted-NVS one (same header).
 */
#include "qc_store.h"

#include <stdio.h>
#include <string.h>

static const char *s_path;
static const uint8_t *s_nonce;

static int save_hook(const uint8_t *in, size_t len) {
    FILE *f;

    if (in == NULL && len > 0) {
        return -1;
    }
    f = fopen(s_path, "wb");
    if (f == NULL) {
        return -1;
    }
    if (len > 0 && fwrite(in, 1, len, f) != len) {
        fclose(f);
        return -1;
    }
    if (fclose(f) != 0) {
        return -1;
    }
    return 0;
}

qc_store_rc qc_store_file_save(qc_store *s, const char *path,
                               const uint8_t *wrap_nonce) {
    qc_store_rc rc;

    if (s == NULL || path == NULL) {
        return QC_STORE_BAD_ARG;
    }
    s_path = path;
    s_nonce = wrap_nonce;
    rc = qc_store_save(s, s_nonce, save_hook);
    s_path = NULL;
    s_nonce = NULL;
    return rc;
}

static int load_hook(uint8_t *out, size_t cap, size_t *len_out) {
    FILE *f;
    size_t n = 0;
    int c;

    if (out == NULL || len_out == NULL) {
        return -1;
    }
    *len_out = 0;
    f = fopen(s_path, "rb");
    if (f == NULL) {
        return -1;
    }
    while (n < cap) {
        c = fgetc(f);
        if (c == EOF) {
            break;
        }
        out[n++] = (uint8_t)c;
    }
    /* Larger than cap: corrupt/unexpected for our fixed-size store
     * (never truncate silently). */
    if (n == cap && fgetc(f) != EOF) {
        fclose(f);
        return -1;
    }
    fclose(f);
    *len_out = n;
    return 0;
}

qc_store_rc qc_store_file_load(qc_store *s, const char *path) {
    FILE *f;
    long sz;
    qc_store_rc rc;

    if (s == NULL || path == NULL) {
        return QC_STORE_BAD_ARG;
    }
    /* Fixed-size store: size itself is structural. Missing -> NOT_FOUND;
     * any other size -> CORRUPT (never truncate/pad silently). */
    f = fopen(path, "rb");
    if (f == NULL) {
        return QC_STORE_NOT_FOUND;
    }
    if (fseek(f, 0, SEEK_END) != 0) {
        fclose(f);
        return QC_STORE_IO_FAIL;
    }
    sz = ftell(f);
    fclose(f);
    if (sz < 0) {
        return QC_STORE_IO_FAIL;
    }
    if (sz == 0) {
        return QC_STORE_NOT_FOUND;
    }
    if (sz != QC_STORE_FILE_LEN) {
        return QC_STORE_CORRUPT;
    }
    s_path = path;
    rc = qc_store_load(s, load_hook);
    s_path = NULL;
    return rc;
}
