/* qc_rng_prod.c — production entropy source (Linux/WSL: getrandom).
 * ESP-IDF port will swap this TU for the HW-RNG one (same header).
 */
#include "qc_rng.h"

#include <sys/random.h>

int qc_rng_generate(uint8_t *out, size_t len) {
    size_t done = 0;
    while (done < len) {
        ssize_t n = getrandom(out + done, len - done, 0);
        if (n <= 0) {
            return -1;
        }
        done += (size_t)n;
    }
    return 0;
}
