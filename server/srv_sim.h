#ifndef SRV_SIM_H
#define SRV_SIM_H

/* Sim verbs (Chunk 3): batch/Merkle/manifest over explicit state blobs.
 * Returns >= 0 (verb rc / usage 2) or -1 when argv[1] is not sim-. */
int srv_sim_main(int argc, char **argv);

#endif
