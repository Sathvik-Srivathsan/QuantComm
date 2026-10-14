/* srv_ctl.h — controller-verb entry for the servant (B-43 bridge).
 *
 * Chunk 1 (servant verbs only; sim wiring is a later chunk). Frozen
 * controller units (core/qc_state, qc_floor, qc_risk, qc_energy,
 * qc_opt, qc_gov) are CALLED, never modified — this TU owns only the
 * argv/stdout calling convention plus ONE canonical state codec.
 */
#ifndef SRV_CTL_H
#define SRV_CTL_H

/* Dispatch: returns -1 if argv[1] is not a ctl-* command (caller
 * falls through to the crypto verbs); otherwise runs the verb and
 * returns the process exit code. */
int srv_ctl_main(int argc, char **argv);

#endif
