#ifndef STDK_ABI_CONTRACT_H
#define STDK_ABI_CONTRACT_H

#include <stdk.h>

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
    #include <cstddef>
using stdk_call_signature = uint32_t (*)(stdk_call_envelope*);
    #define STDK_NULLPTR_T std::nullptr_t
#else
typedef uint32_t (*stdk_call_signature)(stdk_call_envelope*);
    #define STDK_NULLPTR_T nullptr_t
#endif

#define STDK_ABI_CONTRACT(CHECK)                                                                                       \
    CHECK(TYPE, ((stdk_id*) 0)->low, uint64_t);                                                                        \
    CHECK(TYPE, ((stdk_id*) 0)->high, uint64_t);                                                                       \
    CHECK(TYPE, ((stdk_node*) 0)->structure_size, uint32_t);                                                           \
    CHECK(TYPE, ((stdk_node*) 0)->flags, uint32_t);                                                                    \
    CHECK(TYPE, ((stdk_node*) 0)->id, stdk_id);                                                                        \
    CHECK(TYPE, ((stdk_node*) 0)->value_low, uint64_t);                                                                \
    CHECK(TYPE, ((stdk_node*) 0)->value_high, uint64_t);                                                               \
    CHECK(TYPE, ((stdk_node*) 0)->bytes, uint8_t*);                                                                    \
    CHECK(TYPE, ((stdk_node*) 0)->byte_capacity, uint64_t);                                                            \
    CHECK(TYPE, ((stdk_node*) 0)->byte_length, uint64_t);                                                              \
    CHECK(TYPE, ((stdk_node*) 0)->child, stdk_node*);                                                                  \
    CHECK(TYPE, ((stdk_node*) 0)->next, stdk_node*);                                                                   \
    CHECK(TYPE, ((stdk_call_envelope*) 0)->structure_size, uint32_t);                                                  \
    CHECK(TYPE, ((stdk_call_envelope*) 0)->flags, uint32_t);                                                           \
    CHECK(TYPE, ((stdk_call_envelope*) 0)->operation, stdk_id);                                                        \
    CHECK(TYPE, ((stdk_call_envelope*) 0)->request, stdk_node*);                                                       \
    CHECK(TYPE, ((stdk_call_envelope*) 0)->response, stdk_node*);                                                      \
    CHECK(TYPE, ((stdk_call_envelope*) 0)->diagnostic, stdk_node*);                                                    \
    CHECK(TYPE, ((stdk_call_envelope*) 0)->workspace, uint8_t*);                                                       \
    CHECK(TYPE, ((stdk_call_envelope*) 0)->workspace_capacity, uint64_t);                                              \
    CHECK(TYPE, ((stdk_call_envelope*) 0)->callback, stdk_callback);                                                   \
    CHECK(TYPE, ((stdk_call_envelope*) 0)->callback_context, void*);                                                   \
    CHECK(TYPE, nullptr, STDK_NULLPTR_T);                                                                              \
    CHECK(TYPE, &stdk_call, stdk_call_signature);                                                                      \
    CHECK(SIZE, stdk_id, STDK_SIZEOF_ID);                                                                              \
    CHECK(SIZE, stdk_node, STDK_SIZEOF_NODE);                                                                          \
    CHECK(SIZE, stdk_call_envelope, STDK_SIZEOF_CALL);                                                                 \
    CHECK(OFFSET, stdk_id, low, 0);                                                                                    \
    CHECK(OFFSET, stdk_id, high, 8);                                                                                   \
    CHECK(OFFSET, stdk_node, structure_size, 0);                                                                       \
    CHECK(OFFSET, stdk_node, flags, 4);                                                                                \
    CHECK(OFFSET, stdk_node, id, 8);                                                                                   \
    CHECK(OFFSET, stdk_node, value_low, 24);                                                                           \
    CHECK(OFFSET, stdk_node, value_high, 32);                                                                          \
    CHECK(OFFSET, stdk_node, bytes, 40);                                                                               \
    CHECK(OFFSET, stdk_node, byte_capacity, 48);                                                                       \
    CHECK(OFFSET, stdk_node, byte_length, 56);                                                                         \
    CHECK(OFFSET, stdk_node, child, 64);                                                                               \
    CHECK(OFFSET, stdk_node, next, 72);                                                                                \
    CHECK(OFFSET, stdk_node, reserved, 80);                                                                            \
    CHECK(OFFSET, stdk_call_envelope, structure_size, 0);                                                              \
    CHECK(OFFSET, stdk_call_envelope, flags, 4);                                                                       \
    CHECK(OFFSET, stdk_call_envelope, operation, 8);                                                                   \
    CHECK(OFFSET, stdk_call_envelope, request, 24);                                                                    \
    CHECK(OFFSET, stdk_call_envelope, response, 32);                                                                   \
    CHECK(OFFSET, stdk_call_envelope, diagnostic, 40);                                                                 \
    CHECK(OFFSET, stdk_call_envelope, workspace, 48);                                                                  \
    CHECK(OFFSET, stdk_call_envelope, workspace_capacity, 56);                                                         \
    CHECK(OFFSET, stdk_call_envelope, callback, 64);                                                                   \
    CHECK(OFFSET, stdk_call_envelope, callback_context, 72);                                                           \
    CHECK(OFFSET, stdk_call_envelope, reserved, 80);                                                                   \
    CHECK(VALUE, STDK_ABI_EPOCH, 3);                                                                                   \
    CHECK(VALUE, STDK_STATUS_OK, 0);                                                                                   \
    CHECK(VALUE, STDK_STATUS_INVALID_CALL, 1);                                                                         \
    CHECK(VALUE, STDK_STATUS_UNSUPPORTED, 2);                                                                          \
    CHECK(VALUE, STDK_STATUS_INSUFFICIENT_CAPACITY, 3);                                                                \
    CHECK(VALUE, STDK_STATUS_INVALID_DATA, 4);                                                                         \
    CHECK(VALUE, STDK_STATUS_INTEGRITY_FAILURE, 5);                                                                    \
    CHECK(VALUE, STDK_STATUS_IO_FAILURE, 6);                                                                           \
    CHECK(VALUE, STDK_STATUS_RESOURCE_LIMIT, 7);                                                                       \
    CHECK(VALUE, STDK_STATUS_INTERNAL_FAILURE, 8);

#endif
