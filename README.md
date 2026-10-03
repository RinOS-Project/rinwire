# RinWire

RinWire provides small inline validators for common IPC wire-record, capability-lifetime, and reconnect-policy invariants.

Reconnect policy admission validates the complete enum range, including the
lower bound. A caller-corrupted negative `RinWireReconnectState` therefore
fails closed instead of being accepted by an upper-bound-only check and
driving another retry transition.

Terminal retry exhaustion also publishes `UINT64_MAX` as the retry deadline,
including the normal max-attempt and non-retryable failure paths. Callers do
not receive a stale finite deadline together with the `FAILED` state.

## Public API contract

| Requirement | Contract |
| --- | --- |
| Purpose | RinWire provides small inline validators for common IPC wire-record, capability-lifetime, and reconnect-policy invariants. |
| Supported API | Public headers are `rinwire/capability.h`, `rinwire/reconnect.h`, and `rinwire/validation.h`. They validate bounded token envelopes, generations, expiry/revocation/consumption state, request and response fields, and reconnect timing. |
| Unsupported API | These helpers do not authenticate peers, verify token cryptography, authorize a service operation, validate service-specific schemas, or define a complete wire protocol. |
| ownership | Records, token bytes, strings, and reconnect state are caller-owned. The helpers do not retain passed pointers; callers remain responsible for lifetimes and schema storage. |
| thread-safety | Pure validation calls are reentrant. The one-shot capability consume helper uses an atomic compare-and-exchange on caller-owned state; concurrent mutation of other state requires caller synchronization. |
| limits | Capability token material is bounded to 4096 bytes. Other limits are supplied by each call's capacities and service schema. |
| errors | Validation functions return explicit status values or booleans for invalid shape, mismatched generation, expiry, revocation, consumption, stale responses, invalid arguments, and corrupted reconnect policy state. Reconnect transitions fail closed instead of treating malformed caller-owned state as a retry authorization. |
| ABI stability | These are inline C headers; there is no separately versioned binary ABI. Struct layout and compiler settings must match between producer and consumer. |
| security | Structural checks are only one layer. Callers must separately authenticate the peer, verify token authenticity, enforce service authorization, and validate service-specific contents. |
| build | Header-only integration; include the public headers from a RinOS consumer. No separate build/install command is documented. |
| test | No standalone test target or command is documented for this header-only repository. Validate the owning IPC service contract in RinOS. |
