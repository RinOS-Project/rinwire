/* SPDX-License-Identifier: MIT */
#ifndef RINWIRE_RECONNECT_H
#define RINWIRE_RECONNECT_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Transport reconnect policy is deliberately service-agnostic.  It owns only
 * bounded retry lifecycle and monotonic deadlines; credentials, sockets,
 * replay safety, and service-specific state remain with the caller. */
typedef enum RinWireReconnectState {
    RIN_WIRE_RECONNECT_DISCONNECTED = 0,
    RIN_WIRE_RECONNECT_CONNECTING = 1,
    RIN_WIRE_RECONNECT_AUTHENTICATED = 2,
    RIN_WIRE_RECONNECT_WAITING = 3,
    RIN_WIRE_RECONNECT_FAILED = 4
} RinWireReconnectState;

typedef struct RinWireReconnectPolicy {
    uint32_t max_attempts;
    uint64_t initial_backoff_ms;
    uint64_t max_backoff_ms;
    RinWireReconnectState state;
    uint32_t attempts;
    uint64_t retry_at_ms;
    uint64_t last_now_ms;
    uint8_t has_clock_sample;
} RinWireReconnectPolicy;

/* Returns zero for an unusable policy configuration. */
static inline int rin_wire_reconnect_init(
    RinWireReconnectPolicy* policy, uint32_t max_attempts,
    uint64_t initial_backoff_ms, uint64_t max_backoff_ms)
{
    if (policy == NULL || max_attempts == 0u || initial_backoff_ms == 0u ||
        initial_backoff_ms > max_backoff_ms)
        return 0;
    policy->max_attempts = max_attempts;
    policy->initial_backoff_ms = initial_backoff_ms;
    policy->max_backoff_ms = max_backoff_ms;
    policy->state = RIN_WIRE_RECONNECT_DISCONNECTED;
    policy->attempts = 0u;
    policy->retry_at_ms = 0u;
    policy->last_now_ms = 0u;
    policy->has_clock_sample = 0u;
    return 1;
}

static inline void rin_wire_reconnect_observe_clock(
    RinWireReconnectPolicy* policy, uint64_t now_ms)
{
    if (policy == NULL) return;
    if (policy->has_clock_sample && now_ms < policy->last_now_ms)
        policy->retry_at_ms = now_ms;
    policy->last_now_ms = now_ms;
    policy->has_clock_sample = 1u;
}

static inline int rin_wire_reconnect_begin(
    RinWireReconnectPolicy* policy, uint64_t now_ms)
{
    if (policy == NULL) return 0;
    rin_wire_reconnect_observe_clock(policy, now_ms);
    if (policy->state == RIN_WIRE_RECONNECT_FAILED ||
        (policy->state == RIN_WIRE_RECONNECT_WAITING &&
         now_ms < policy->retry_at_ms) ||
        (policy->state != RIN_WIRE_RECONNECT_DISCONNECTED &&
         policy->state != RIN_WIRE_RECONNECT_WAITING))
        return 0;
    if (policy->attempts >= policy->max_attempts) {
        policy->state = RIN_WIRE_RECONNECT_FAILED;
        return 0;
    }
    ++policy->attempts;
    policy->state = RIN_WIRE_RECONNECT_CONNECTING;
    return 1;
}

static inline int rin_wire_reconnect_authenticated(
    RinWireReconnectPolicy* policy)
{
    if (policy == NULL || policy->state != RIN_WIRE_RECONNECT_CONNECTING)
        return 0;
    policy->state = RIN_WIRE_RECONNECT_AUTHENTICATED;
    return 1;
}

/* Compute a bounded exponential delay without iterating over an untrusted
 * attempt count.  At most 64 doublings can affect a uint64_t deadline. */
static inline uint64_t rin_wire_reconnect_backoff_ms(
    const RinWireReconnectPolicy* policy)
{
    uint64_t delay;
    uint32_t remaining;
    if (policy == NULL || policy->attempts == 0u) return 0u;
    delay = policy->initial_backoff_ms;
    remaining = policy->attempts - 1u;
    while (remaining != 0u && delay < policy->max_backoff_ms) {
        if (delay > policy->max_backoff_ms / 2u) {
            delay = policy->max_backoff_ms;
            break;
        }
        delay *= 2u;
        --remaining;
    }
    return delay > policy->max_backoff_ms ? policy->max_backoff_ms : delay;
}

/* Advance a caller-owned reconnect delay without overflowing while doubling.
 * A current delay below the configured floor is repaired to that floor; an
 * invalid range returns zero so callers cannot silently busy-loop. */
static inline uint64_t rin_wire_reconnect_next_delay_ms(
    uint64_t current_delay_ms, uint64_t minimum_delay_ms,
    uint64_t maximum_delay_ms)
{
    uint64_t doubled;
    if (minimum_delay_ms == 0u || minimum_delay_ms > maximum_delay_ms)
        return 0u;
    if (current_delay_ms < minimum_delay_ms) return minimum_delay_ms;
    if (current_delay_ms >= maximum_delay_ms) return maximum_delay_ms;
    if (current_delay_ms > UINT64_MAX / 2u) return maximum_delay_ms;
    doubled = current_delay_ms * 2u;
    return doubled > maximum_delay_ms ? maximum_delay_ms : doubled;
}

/* Schedules a retry only from a connection/authentication phase.  A false
 * return means either a terminal failure or an invalid state transition. */
static inline int rin_wire_reconnect_failure(
    RinWireReconnectPolicy* policy, uint64_t now_ms, int retryable)
{
    uint64_t delay;
    if (policy == NULL) return 0;
    rin_wire_reconnect_observe_clock(policy, now_ms);
    if (policy->state != RIN_WIRE_RECONNECT_CONNECTING &&
        policy->state != RIN_WIRE_RECONNECT_AUTHENTICATED)
        return 0;
    if (!retryable || policy->attempts >= policy->max_attempts) {
        policy->state = RIN_WIRE_RECONNECT_FAILED;
        return 0;
    }
    delay = rin_wire_reconnect_backoff_ms(policy);
    policy->retry_at_ms = now_ms > UINT64_MAX - delay
        ? UINT64_MAX : now_ms + delay;
    policy->state = RIN_WIRE_RECONNECT_WAITING;
    return 1;
}

static inline RinWireReconnectState rin_wire_reconnect_state(
    const RinWireReconnectPolicy* policy)
{
    return policy == NULL ? RIN_WIRE_RECONNECT_FAILED : policy->state;
}

static inline uint32_t rin_wire_reconnect_attempts(
    const RinWireReconnectPolicy* policy)
{
    return policy == NULL ? 0u : policy->attempts;
}

static inline uint64_t rin_wire_reconnect_retry_at_ms(
    const RinWireReconnectPolicy* policy)
{
    return policy == NULL ? UINT64_MAX : policy->retry_at_ms;
}

#ifdef __cplusplus
}
#endif

#endif /* RINWIRE_RECONNECT_H */
