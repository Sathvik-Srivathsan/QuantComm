/* qc_trace.h — synthetic-trace + policy-log record schema (plan B-30.3).
 *
 * Tooling-side codec (B-43 generates/consumes; device never parses —
 * stated in spec, enforced by absence: no device TU includes this).
 * All integers big-endian; floats via bit-copy (deterministic bytes).
 *
 * Vector record (38 B): ver u16 (major hi, minor lo) || ts u64 ||
 *   B f32 || soc u8 || R f32 || S u8 || C f32 || M u32 ||
 *   L_rssi i16 || L_retries u16 || Q f32 || mask u16.
 * Event record (27 B): ver u16 || ts u64 || type u8 || a u64 || b u64.
 *   Types: 0 risk-transition (a=old band, b=new band), 1 battery-segment
 *   (a=soc pct, b=mV), 2 load-step (a=msg/s x1000, b=class mix bits),
 *   3 link-loss (a=duration s, b=dropped count). Encode validates ≤3;
 *   decode tolerates unknown types (forward-compat within a major).
 * Policy record (46 B): vector(38) || action u32 || energy f32.
 *   action is an OPAQUE B-34 cookie (B-30 never interprets it).
 *
 * Version gate: major mismatch -> BAD_VERSION (unknown major rejected);
 * higher minor accepted with trailing bytes ignored; same-minor
 * trailing garbage -> MALFORMED (strict within a version).
 * Coverage/S0-S6/30-trace rules are B-43 tooling duty (not codec).
 */
#ifndef QC_TRACE_H
#define QC_TRACE_H

#include <stddef.h>
#include <stdint.h>

#include "qc_state.h"

#define QC_TRACE_MAJOR 1u
#define QC_TRACE_MINOR 0u

#define QC_TRACE_VEC_LEN 38u
#define QC_TRACE_EVT_LEN 27u
#define QC_TRACE_POL_LEN (38u + 4u + 4u)

enum {
    QC_TRACE_RISK = 0,
    QC_TRACE_BATTERY = 1,
    QC_TRACE_LOAD = 2,
    QC_TRACE_LINK = 3
};

typedef enum {
    QC_TRACE_OK = 0,
    QC_TRACE_BAD_ARG,   /* NULLs, short buffers, bad event type. */
    QC_TRACE_BAD_VERSION, /* unknown major. */
    QC_TRACE_MALFORMED  /* short record, same-minor trailing garbage. */
} qc_trace_rc;

qc_trace_rc qc_trace_vec_encode(const qc_state *s, uint64_t ts,
                                uint8_t *out, size_t cap);
qc_trace_rc qc_trace_vec_decode(const uint8_t *in, size_t len,
                                qc_state *s, uint64_t *ts_out);
qc_trace_rc qc_trace_evt_encode(uint64_t ts, uint8_t type, uint64_t a,
                                uint64_t b, uint8_t *out, size_t cap);
qc_trace_rc qc_trace_evt_decode(const uint8_t *in, size_t len,
                                uint64_t *ts_out, uint8_t *type_out,
                                uint64_t *a_out, uint64_t *b_out);
qc_trace_rc qc_trace_pol_encode(const qc_state *s, uint64_t ts,
                                uint32_t action, float energy_j,
                                uint8_t *out, size_t cap);
qc_trace_rc qc_trace_pol_decode(const uint8_t *in, size_t len,
                                qc_state *s, uint64_t *ts_out,
                                uint32_t *action_out, float *energy_out);

#endif
