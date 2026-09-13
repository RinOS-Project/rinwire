/* SPDX-License-Identifier: MIT */
#ifndef RINWIRE_VALIDATION_H
#define RINWIRE_VALIDATION_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Common envelope checks deliberately do not know any service schema. */
static inline int rin_wire_struct_version_valid(
    const void* record, size_t expected_size, uint32_t struct_size,
    uint16_t version, uint16_t expected_version)
{
    return record != NULL && expected_size != 0u &&
           struct_size == expected_size && version == expected_version;
}

static inline int rin_wire_request_id_valid(uint64_t request_id)
{
    return request_id != 0u;
}

static inline int rin_wire_generation_valid(uint64_t generation)
{
    return generation != 0u;
}

static inline int rin_wire_monotonic_sequence_valid(
    uint64_t sequence, uint64_t previous_sequence)
{
    return sequence != 0u &&
           (previous_sequence == 0u || sequence > previous_sequence);
}

static inline int rin_wire_bounded_string_valid(
    const char* value, size_t capacity, size_t max_bytes, size_t* size_out)
{
    size_t index;
    if (size_out != NULL) *size_out = 0u;
    if (value == NULL || capacity == 0u || max_bytes >= capacity) return 0;
    for (index = 0u; index < capacity; ++index) {
        if (value[index] == '\0') {
            if (index > max_bytes) return 0;
            if (size_out != NULL) *size_out = index;
            return 1;
        }
    }
    return 0;
}

static inline int rin_wire_bounded_bytes_valid(
    const void* value, size_t size, size_t capacity)
{
    return size <= capacity && (size == 0u || value != NULL);
}

/* Validate opaque identity/token material without letting an all-zero value
 * masquerade as a granted identity.  Callers still own schema-specific size
 * checks; this helper only covers the common non-zero invariant. */
static inline int rin_wire_nonzero_bytes_valid(const void* value, size_t size)
{
    const unsigned char* bytes = (const unsigned char*)value;
    unsigned char aggregate = 0u;
    size_t index;
    if (size != 0u && bytes == NULL) return 0;
    for (index = 0u; index < size; ++index) aggregate |= bytes[index];
    return size != 0u && aggregate != 0u;
}

static inline int rin_wire_flags_valid(uint32_t flags, uint32_t known_flags)
{
    return (flags & ~known_flags) == 0u;
}

static inline int rin_wire_enum_u32_valid(
    uint32_t value, uint32_t minimum, uint32_t maximum)
{
    return minimum <= maximum && value >= minimum && value <= maximum;
}

static inline int rin_wire_enum_u16_valid(
    uint16_t value, uint16_t minimum, uint16_t maximum)
{
    return minimum <= maximum && value >= minimum && value <= maximum;
}

static inline int rin_wire_reserved_zero(const void* value, size_t size)
{
    const unsigned char* bytes = (const unsigned char*)value;
    unsigned char aggregate = 0u;
    size_t index;
    if (size != 0u && bytes == NULL) return 0;
    for (index = 0u; index < size; ++index) aggregate |= bytes[index];
    return aggregate == 0u;
}

static inline int rin_wire_u64_range_valid(
    uint64_t value, uint64_t minimum, uint64_t maximum)
{
    return minimum <= maximum && value >= minimum && value <= maximum;
}

static inline int rin_wire_i64_range_valid(
    int64_t value, int64_t minimum, int64_t maximum)
{
    return minimum <= maximum && value >= minimum && value <= maximum;
}

static inline int rin_wire_request_id_echo_valid(
    uint64_t request_id, uint64_t response_request_id)
{
    return rin_wire_request_id_valid(request_id) &&
           response_request_id == request_id;
}

static inline int rin_wire_generation_echo_valid(
    uint64_t generation, uint64_t response_generation)
{
    return rin_wire_generation_valid(generation) &&
           response_generation == generation;
}

#ifdef __cplusplus
}
#endif

#endif /* RINWIRE_VALIDATION_H */
