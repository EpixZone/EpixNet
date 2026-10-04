/* Experimental transport only. This is not an EVX execution backend. */
#ifndef EVX_XPC_PROTOCOL_H
#define EVX_XPC_PROTOCOL_H

#include <stdbool.h>
#include <stdint.h>
#include <string.h>
#include <xpc/xpc.h>

#define EVX_XPC_FRAME_LIMIT (128u * 1024u)
#define EVX_XPC_TOTAL_LIMIT (256u * 1024u)
#define EVX_XPC_FRAME_COUNT 130u

/* Exact dictionaries avoid unrestricted object decoding and capability
 * smuggling. In particular, endpoints, descriptors and caller paths are not
 * accepted by guest or compiler transports. Bytes remain uninterpreted. */
static inline bool evx_xpc_frame(xpc_object_t frame, const char *role,
                                 uint64_t sequence, size_t *length) {
    if (xpc_get_type(frame) != XPC_TYPE_DICTIONARY ||
        xpc_dictionary_get_count(frame) != 4) return false;
    xpc_object_t version = xpc_dictionary_get_value(frame, "version");
    xpc_object_t number = xpc_dictionary_get_value(frame, "sequence");
    xpc_object_t role_value = xpc_dictionary_get_value(frame, "role");
    xpc_object_t body = xpc_dictionary_get_value(frame, "body");
    if (!version || !number || !role_value || !body ||
        xpc_get_type(version) != XPC_TYPE_UINT64 ||
        xpc_get_type(number) != XPC_TYPE_UINT64 ||
        xpc_get_type(role_value) != XPC_TYPE_STRING ||
        xpc_get_type(body) != XPC_TYPE_DATA ||
        xpc_uint64_get_value(version) != 1 ||
        xpc_uint64_get_value(number) != sequence ||
        strcmp(xpc_string_get_string_ptr(role_value), role) != 0) return false;
    *length = xpc_data_get_length(body);
    return *length <= EVX_XPC_FRAME_LIMIT;
}

static inline void evx_xpc_put_frame(xpc_object_t frame, const char *role,
                                     uint64_t sequence, const void *body,
                                     size_t length) {
    xpc_dictionary_set_uint64(frame, "version", 1);
    xpc_dictionary_set_uint64(frame, "sequence", sequence);
    xpc_dictionary_set_string(frame, "role", role);
    xpc_dictionary_set_data(frame, "body", body, length);
}

#endif
