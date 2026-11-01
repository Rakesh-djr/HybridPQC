#include "crypto_policy.h"

#include <math.h>

/*
 * Pilot measurements from results/phase6/handshake_profile_summary.csv.
 * These values are environment-specific and are intended as policy inputs
 * for the experiment, not universal performance constants.
 */
static const Phase6Profile profiles[] = {
    { 1, "ML-KEM-512", 833, 4113, 4958, 6.267 },
    { 2, "ML-KEM-768", 1217, 4433, 5662, 5.726 },
    { 3, "ML-KEM-1024", 1601, 4913, 6526, 6.931 }
};

const Phase6Profile *phase6_profiles(size_t *count)
{
    if (count != NULL)
    {
        *count = sizeof(profiles) / sizeof(profiles[0]);
    }
    return profiles;
}

int phase6_policy_select(
    const Phase6PolicyInput *input,
    Phase6PolicyChoice *choice)
{
    size_t i;
    const Phase6Profile *best = NULL;
    double best_transfer_ms = 0.0;
    double best_total_ms = 0.0;

    if (input == NULL || choice == NULL ||
        input->minimum_profile_id < 1 ||
        input->minimum_profile_id > 3 ||
        (input->objective != PHASE6_OBJECTIVE_LATENCY &&
         input->objective != PHASE6_OBJECTIVE_BANDWIDTH) ||
        input->maximum_handshake_ms < 0.0 ||
        !isfinite(input->maximum_handshake_ms))
    {
        return -1;
    }

    for (i = 0; i < sizeof(profiles) / sizeof(profiles[0]); i++)
    {
        const Phase6Profile *candidate = &profiles[i];
        double transfer_ms = 0.0;
        double total_ms;
        int is_better;

        /* Profile IDs are ordered policy tiers; a stronger minimum excludes
         * every lower tier before performance is considered. */
        if (candidate->profile_id < input->minimum_profile_id)
        {
            continue;
        }

        if (input->bandwidth_kbps > 0)
        {
            transfer_ms =
                (double)candidate->total_hello_wire_bytes * 8.0 /
                (double)input->bandwidth_kbps;
        }

        total_ms = candidate->measured_handshake_median_ms + transfer_ms;
        if (input->maximum_handshake_ms > 0.0 &&
            total_ms > input->maximum_handshake_ms)
        {
            continue;
        }

        if (best == NULL)
        {
            is_better = 1;
        }
        else if (input->objective == PHASE6_OBJECTIVE_BANDWIDTH)
        {
            is_better = candidate->total_hello_wire_bytes <
                            best->total_hello_wire_bytes ||
                (candidate->total_hello_wire_bytes ==
                     best->total_hello_wire_bytes && total_ms < best_total_ms);
        }
        else
        {
            is_better = total_ms < best_total_ms ||
                (total_ms == best_total_ms &&
                 candidate->total_hello_wire_bytes <
                     best->total_hello_wire_bytes);
        }

        if (is_better)
        {
            best = candidate;
            best_transfer_ms = transfer_ms;
            best_total_ms = total_ms;
        }
    }

    if (best == NULL)
    {
        return -1;
    }

    choice->profile = *best;
    choice->estimated_transfer_ms = best_transfer_ms;
    choice->estimated_handshake_ms = best_total_ms;
    return 0;
}
