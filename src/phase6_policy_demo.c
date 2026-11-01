#define _CRT_SECURE_NO_WARNINGS

#include "crypto_policy.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static void usage(const char *program)
{
    fprintf(stderr,
        "Usage: %s [--minimum 512|768|1024] [--bandwidth-kbps N] "
        "[--max-handshake-ms N] [--objective latency|bandwidth]\n",
        program);
}

static int parse_profile(const char *value, uint8_t *profile_id)
{
    if (strcmp(value, "512") == 0) *profile_id = 1;
    else if (strcmp(value, "768") == 0) *profile_id = 2;
    else if (strcmp(value, "1024") == 0) *profile_id = 3;
    else return -1;
    return 0;
}

static int parse_uint32(const char *value, uint32_t *number)
{
    char *end = NULL;
    unsigned long parsed;

    errno = 0;
    parsed = strtoul(value, &end, 10);
    if (errno != 0 || end == value || *end != '\0' || parsed == 0 ||
        parsed > UINT32_MAX)
    {
        return -1;
    }
    *number = (uint32_t)parsed;
    return 0;
}

static int parse_positive_double(const char *value, double *number)
{
    char *end = NULL;
    double parsed;

    errno = 0;
    parsed = strtod(value, &end);
    if (errno != 0 || end == value || *end != '\0' ||
        parsed <= 0.0 || parsed > 1000000.0)
    {
        return -1;
    }
    *number = parsed;
    return 0;
}

int main(int argc, char **argv)
{
    Phase6PolicyInput input = { 2, 0, 0.0, PHASE6_OBJECTIVE_LATENCY };
    Phase6PolicyChoice choice;
    size_t profile_count = 0;
    const Phase6Profile *profiles = phase6_profiles(&profile_count);
    int i;

    for (i = 1; i < argc; i++)
    {
        if (i + 1 >= argc)
        {
            usage(argv[0]);
            return EXIT_FAILURE;
        }

        if (strcmp(argv[i], "--minimum") == 0)
        {
            if (parse_profile(argv[++i], &input.minimum_profile_id) != 0)
            {
                fprintf(stderr, "Invalid minimum profile.\n");
                usage(argv[0]);
                return EXIT_FAILURE;
            }
        }
        else if (strcmp(argv[i], "--bandwidth-kbps") == 0)
        {
            if (parse_uint32(argv[++i], &input.bandwidth_kbps) != 0)
            {
                fprintf(stderr, "Bandwidth must be a positive integer.\n");
                return EXIT_FAILURE;
            }
        }
        else if (strcmp(argv[i], "--max-handshake-ms") == 0)
        {
            if (parse_positive_double(argv[++i],
                                      &input.maximum_handshake_ms) != 0)
            {
                fprintf(stderr, "Handshake limit must be positive.\n");
                return EXIT_FAILURE;
            }
        }
        else if (strcmp(argv[i], "--objective") == 0)
        {
            if (strcmp(argv[++i], "latency") == 0)
                input.objective = PHASE6_OBJECTIVE_LATENCY;
            else if (strcmp(argv[i], "bandwidth") == 0)
                input.objective = PHASE6_OBJECTIVE_BANDWIDTH;
            else
            {
                fprintf(stderr, "Objective must be latency or bandwidth.\n");
                return EXIT_FAILURE;
            }
        }
        else
        {
            usage(argv[0]);
            return EXIT_FAILURE;
        }
    }

    printf("Candidate profiles (measured median + estimated hello transfer):\n");
    for (i = 0; i < (int)profile_count; i++)
    {
        double transfer_ms = input.bandwidth_kbps > 0
            ? (double)profiles[i].total_hello_wire_bytes * 8.0 /
                (double)input.bandwidth_kbps
            : 0.0;
        double total_ms = profiles[i].measured_handshake_median_ms + transfer_ms;
        const char *status = profiles[i].profile_id < input.minimum_profile_id
            ? "below minimum profile"
            : (input.maximum_handshake_ms > 0.0 &&
               total_ms > input.maximum_handshake_ms
                   ? "over latency limit" : "eligible");

        printf("  %-11s %4u B, measured %.3f ms, transfer %.3f ms, %s\n",
               profiles[i].name,
               profiles[i].total_hello_wire_bytes,
               profiles[i].measured_handshake_median_ms,
               transfer_ms,
               status);
    }

    if (phase6_policy_select(&input, &choice) != 0)
    {
        fprintf(stderr,
            "Policy has no eligible profile. Relax a performance constraint "
            "or lower the configured minimum profile.\n");
        return EXIT_FAILURE;
    }

    printf("Selected: %s (profile ID %u)\n",
           choice.profile.name, choice.profile.profile_id);
    printf("Reason: objective=%s, minimum-profile-ID=%u, "
           "estimated-handshake=%.3f ms\n",
           input.objective == PHASE6_OBJECTIVE_LATENCY
               ? "latency" : "bandwidth",
           input.minimum_profile_id,
           choice.estimated_handshake_ms);
    return EXIT_SUCCESS;
}
