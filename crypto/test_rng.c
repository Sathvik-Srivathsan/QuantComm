/* test_rng.c — TEST-ONLY deterministic RNG (SplitMix64, Steele et al.).
 * NEVER linked into production. Presence in a production link closure
 * is a build failure (CI scans TU list for `test_rng`).
 * Same seed -> identical stream, forever. That is the entire point:
 * every L1 trace replays bit-identically.
 */
#include "qc_rng.h"

static uint64_t s_state = 0x9e3779b97f4a7c15ull; /* overwritten by seed fn */

void test_rng_seed(uint64_t seed) { s_state = seed; }

int qc_rng_generate(uint8_t *out, size_t len) {
    size_t i = 0;
    while (i < len) {
        uint64_t z;
        s_state += 0x9e3779b97f4a7c15ull;
        z = s_state;
        z = (z ^ (z >> 30)) * 0xbf58476d1ce4e5b9ull;
        z = (z ^ (z >> 27)) * 0x94d049bb133111ebull;
        z = z ^ (z >> 31);
        for (unsigned k = 0; k < 8 && i < len; k++, i++) {
            out[i] = (uint8_t)(z >> (8 * k));
        }
    }
    return 0;
}
