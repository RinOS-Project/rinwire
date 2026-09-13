/* SPDX-License-Identifier: MIT */
#ifndef RINWIRE_CAPABILITY_H
#define RINWIRE_CAPABILITY_H

#include <stddef.h>
#include <stdint.h>

#include "validation.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Capability payloads are opaque to this helper.  Service schemas choose the
 * exact payload, while the common boundary enforces a bounded envelope. */
#define RIN_WIRE_CAPABILITY_MAX_TOKEN_BYTES ((size_t)4096u)

typedef enum RinWireCapabilityStatus {
    RIN_WIRE_CAPABILITY_OK = 0,
    RIN_WIRE_CAPABILITY_INVALID_ARGUMENT = -1,
    RIN_WIRE_CAPABILITY_BAD_LENGTH = -2,
    RIN_WIRE_CAPABILITY_GENERATION_MISMATCH = -3,
    RIN_WIRE_CAPABILITY_NOT_YET_VALID = -4,
    RIN_WIRE_CAPABILITY_EXPIRED = -5,
    RIN_WIRE_CAPABILITY_REVOKED = -6,
    RIN_WIRE_CAPABILITY_CONSUMED = -7,
    RIN_WIRE_CAPABILITY_STALE_RESPONSE = -8
} RinWireCapabilityStatus;

static inline RinWireCapabilityStatus rin_wire_capability_token_size_valid(
    const void* token, size_t token_size, size_t minimum_size,
    size_t maximum_size)
{
    if ((token == NULL && token_size != 0u) || minimum_size == 0u ||
        minimum_size > maximum_size ||
        maximum_size > RIN_WIRE_CAPABILITY_MAX_TOKEN_BYTES)
        return RIN_WIRE_CAPABILITY_INVALID_ARGUMENT;
    if (token_size < minimum_size || token_size > maximum_size)
        return RIN_WIRE_CAPABILITY_BAD_LENGTH;
    return RIN_WIRE_CAPABILITY_OK;
}

/* A fixed-size capability field must carry material as well as fit the
 * bounded envelope.  This keeps consumers from duplicating an aggregate loop
 * and makes an all-zero token unambiguously invalid. */
static inline RinWireCapabilityStatus rin_wire_capability_token_valid(
    const void* token, size_t token_size, size_t minimum_size,
    size_t maximum_size)
{
    RinWireCapabilityStatus status = rin_wire_capability_token_size_valid(
        token, token_size, minimum_size, maximum_size);
    if (status != RIN_WIRE_CAPABILITY_OK) return status;
    return rin_wire_nonzero_bytes_valid(token, token_size)
        ? RIN_WIRE_CAPABILITY_OK
        : RIN_WIRE_CAPABILITY_BAD_LENGTH;
}

static inline RinWireCapabilityStatus rin_wire_capability_generation_valid(
    uint64_t generation)
{
    return generation != 0u ? RIN_WIRE_CAPABILITY_OK
                            : RIN_WIRE_CAPABILITY_INVALID_ARGUMENT;
}

static inline RinWireCapabilityStatus rin_wire_capability_generation_matches(
    uint64_t expected_generation, uint64_t actual_generation)
{
    if (expected_generation == 0u || actual_generation == 0u)
        return RIN_WIRE_CAPABILITY_INVALID_ARGUMENT;
    return expected_generation == actual_generation
        ? RIN_WIRE_CAPABILITY_OK
        : RIN_WIRE_CAPABILITY_GENERATION_MISMATCH;
}

static inline RinWireCapabilityStatus rin_wire_capability_expiry_valid(
    uint64_t not_before_epoch, uint64_t expires_at_epoch,
    uint64_t current_epoch)
{
    if (not_before_epoch == 0u || expires_at_epoch < not_before_epoch ||
        current_epoch == 0u)
        return RIN_WIRE_CAPABILITY_INVALID_ARGUMENT;
    if (current_epoch < not_before_epoch)
        return RIN_WIRE_CAPABILITY_NOT_YET_VALID;
    if (current_epoch > expires_at_epoch)
        return RIN_WIRE_CAPABILITY_EXPIRED;
    return RIN_WIRE_CAPABILITY_OK;
}

/* Validate the ordering without pretending that a structural validator owns
 * the service's clock.  Callers that have a trusted current epoch should use
 * rin_wire_capability_expiry_valid as the second step. */
static inline RinWireCapabilityStatus rin_wire_capability_expiry_shape_valid(
    uint64_t not_before_epoch, uint64_t expires_at_epoch)
{
    return not_before_epoch != 0u && expires_at_epoch > not_before_epoch
        ? RIN_WIRE_CAPABILITY_OK
        : RIN_WIRE_CAPABILITY_INVALID_ARGUMENT;
}

static inline RinWireCapabilityStatus rin_wire_capability_not_revoked(
    uint64_t policy_generation, uint64_t minimum_policy_generation)
{
    if (policy_generation == 0u || minimum_policy_generation == 0u)
        return RIN_WIRE_CAPABILITY_INVALID_ARGUMENT;
    return policy_generation >= minimum_policy_generation
        ? RIN_WIRE_CAPABILITY_OK
        : RIN_WIRE_CAPABILITY_REVOKED;
}

/* Atomically consume a one-shot capability state owned by the caller.  The
 * state is deliberately only a bit of lifecycle, never token material. */
static inline RinWireCapabilityStatus rin_wire_capability_consume(
    uint32_t* consumed)
{
    uint32_t expected = 0u;
    if (consumed == NULL) return RIN_WIRE_CAPABILITY_INVALID_ARGUMENT;
    return __atomic_compare_exchange_n(
               consumed, &expected, 1u, 0, __ATOMIC_ACQ_REL,
               __ATOMIC_ACQUIRE)
        ? RIN_WIRE_CAPABILITY_OK
        : RIN_WIRE_CAPABILITY_CONSUMED;
}

static inline RinWireCapabilityStatus rin_wire_capability_session_valid(
    uint64_t client_generation, uint64_t service_generation)
{
    return rin_wire_capability_generation_matches(
        client_generation, service_generation);
}

static inline RinWireCapabilityStatus rin_wire_capability_response_valid(
    uint64_t request_id, uint64_t request_generation,
    uint64_t response_id, uint64_t response_generation)
{
    if (request_id == 0u || request_generation == 0u ||
        response_id == 0u || response_generation == 0u)
        return RIN_WIRE_CAPABILITY_INVALID_ARGUMENT;
    return request_id == response_id && request_generation == response_generation
        ? RIN_WIRE_CAPABILITY_OK
        : RIN_WIRE_CAPABILITY_STALE_RESPONSE;
}

#ifdef __cplusplus
}
#endif

#endif /* RINWIRE_CAPABILITY_H */
