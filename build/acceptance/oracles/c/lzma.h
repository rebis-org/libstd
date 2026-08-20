#ifndef LIBSTD_ORACLE_LZMA_H
#define LIBSTD_ORACLE_LZMA_H

#include <stddef.h>
#include <stdint.h>

typedef uint64_t lzma_vli;
typedef uint64_t lzma_check;
typedef int lzma_ret;
typedef int lzma_action;

typedef struct lzma_internal lzma_internal;

typedef struct lzma_allocator {
    void* (*alloc)(void* opaque, size_t nmemb, size_t size);
    void (*free)(void* opaque, void* ptr);
    void* opaque;
} lzma_allocator;

typedef struct lzma_stream {
    const uint8_t* next_in;
    size_t avail_in;
    uint64_t total_in;
    uint8_t* next_out;
    size_t avail_out;
    uint64_t total_out;
    const lzma_allocator* allocator;
    lzma_internal* internal;
    void* reserved_ptr1;
    void* reserved_ptr2;
    void* reserved_ptr3;
    void* reserved_ptr4;
    uint64_t reserved_int1;
    uint64_t reserved_int2;
    size_t reserved_int3;
    size_t reserved_int4;
    lzma_vli reserved_int5;
} lzma_stream;

typedef struct lzma_filter {
    lzma_vli id;
    void* options;
} lzma_filter;

typedef struct lzma_options_lzma {
    uint32_t dict_size;
    const uint8_t* preset_dict;
    uint32_t preset_dict_size;
    uint32_t lc;
    uint32_t lp;
    uint32_t pb;
    uint32_t mode;
    uint32_t nice_len;
    uint32_t mf;
    uint32_t depth;
    uint64_t ext_flags;
    uint64_t reserved_int1;
    uint32_t reserved_int2;
    uint32_t reserved_int3;
    uint32_t reserved_int4;
} lzma_options_lzma;

typedef struct lzma_options_delta {
    uint32_t type;
    uint32_t dist;
} lzma_options_delta;

#define LZMA_OK 0
#define LZMA_STREAM_END 1
#define LZMA_FINISH 3

#define LZMA_FILTER_DELTA 0x03
#define LZMA_FILTER_LZMA1 0x4000000000000001ULL
#define LZMA_FILTER_LZMA2 0x21
#define LZMA_VLI_UNKNOWN UINT64_MAX

#define LZMA_DELTA_TYPE_BYTE 0

extern lzma_ret lzma_stream_buffer_decode(uint64_t* memlimit,
                                          uint32_t flags,
                                          const lzma_allocator* allocator,
                                          const uint8_t* in,
                                          size_t* in_pos,
                                          size_t in_size,
                                          uint8_t* out,
                                          size_t* out_pos,
                                          size_t out_size);
extern lzma_ret lzma_stream_encoder(lzma_stream* strm, const lzma_filter* filters, lzma_check check);
extern lzma_ret lzma_alone_decoder(lzma_stream* strm, uint64_t memlimit);
extern lzma_ret lzma_raw_encoder(lzma_stream* strm, const lzma_filter* filters);
extern lzma_ret lzma_code(lzma_stream* strm, lzma_action action);
extern void lzma_end(lzma_stream* strm);
extern lzma_ret lzma_lzma_preset(lzma_options_lzma* options, uint32_t preset);

#endif
