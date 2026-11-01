#ifndef CRYPTO_POLICY_H
#define CRYPTO_POLICY_H

#include <stddef.h>
#include <stdint.h>

typedef enum
{
    PHASE6_OBJECTIVE_LATENCY = 0,
    PHASE6_OBJECTIVE_BANDWIDTH = 1
} Phase6Objective;

typedef struct
{
    uint8_t minimum_profile_id;
    uint32_t bandwidth_kbps; /* 0 means unconstrained / unknown */
    double maximum_handshake_ms; /* 0 means no latency ceiling */
    Phase6Objective objective;
} Phase6PolicyInput;

typedef struct
{
    uint8_t profile_id;
    const char *name;
    uint32_t client_hello_bytes;
    uint32_t server_hello_bytes;
    uint32_t total_hello_wire_bytes;
    double measured_handshake_median_ms;
} Phase6Profile;

typedef struct
{
    Phase6Profile profile;
    double estimated_transfer_ms;
    double estimated_handshake_ms;
} Phase6PolicyChoice;

/* Returns 0 when a profile meets the security floor and constraints. */
int phase6_policy_select(
    const Phase6PolicyInput *input,
    Phase6PolicyChoice *choice);

const Phase6Profile *phase6_profiles(size_t *count);

#endif
