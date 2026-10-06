/* qc_zeroize.h — elision-resistant memory wipe for key material.
 *
 * Plain memset-on-a-dead-buffer may be optimized away (the compiler can
 * prove the bytes are never read again), silently deleting a security
 * wipe. This helper writes through a volatile pointer (observable
 * behavior the compiler must preserve on all toolchains) plus a compiler
 * barrier where supported (GCC/Clang), and is a safe no-op for NULL /
 * zero length.
 *
 * Semantics match the B-10.4/B-11.4 `qc_zeroize` specified there
 * (volatile write + barrier, NULL/len-0 safe); adapter release wrappers
 * should adopt this helper rather than reimplementing it.
 */
#ifndef QC_ZEROIZE_H
#define QC_ZEROIZE_H

#include <stddef.h>

static inline void qc_zeroize(void *buf, size_t len) {
    volatile unsigned char *p = (volatile unsigned char *)buf;

    if (buf == NULL || len == 0) {
        return;
    }
    while (len > 0) {
        *p++ = 0;
        len--;
    }
#if defined(__GNUC__)
    __asm__ __volatile__("" : : : "memory");
#endif
}

#endif