/**
    Need to define larger data structure to pass the verifier.

    ./falco/modern_bpf/shared_definitions/struct_definitions.h:16
 */


/* The auxiliary map can contain events of at most 64 KB.
 * Here we have 128 KB as dimension to guarantee the verifier
 * that there are always at least 64 KB free.
 */
#define AUXILIARY_MAP_SIZE 128 * 1024