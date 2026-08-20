#ifndef REF_H
#define REF_H

#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>

// NOLINTNEXTLINE(performance-enum-size)
enum {
    REF_OK = 0,
    REF_FAIL = 1,
    REF_OVERFLOW = 2,
};

typedef struct {
    unsigned char* out;
    size_t cap;
    size_t len;
    int overflow;
} ref_sink;

static inline int ref_sink_write(ref_sink* sink, const void* data, size_t size) {
    if (sink->overflow != 0) {
        return REF_OVERFLOW;
    }
    if (sink->len > sink->cap || size > sink->cap - sink->len) {
        sink->overflow = 1;
        return REF_OVERFLOW;
    }
    if (size != 0) {
        memcpy(sink->out + sink->len, data, size);
    }
    sink->len += size;
    return REF_OK;
}

static inline int ref_emit(const void* data, size_t size, unsigned char* out, size_t cap, size_t* out_size) {
    ref_sink sink = {out, cap, 0, 0};
    const int status = ref_sink_write(&sink, data, size);
    *out_size = status == REF_OVERFLOW ? size : sink.len;
    return status;
}

static inline int ref_file_write(const char* path, const void* data, size_t size) {
    FILE* file = fopen(path, "wb");
    if (file == NULL) {
        return REF_FAIL;
    }
    const bool ok = fwrite(data, 1, size, file) == size;
    fclose(file);
    if (ok) {
        return REF_OK;
    }
    return REF_FAIL;
}

static inline int ref_file_read(const char* path, unsigned char* out, size_t cap, size_t* out_size) {
    FILE* file = fopen(path, "rb");
    if (file == NULL) {
        return REF_FAIL;
    }
    if (fseek(file, 0, SEEK_END) != 0) {
        fclose(file);
        return REF_FAIL;
    }
    const long total = ftell(file);
    if (total < 0) {
        fclose(file);
        return REF_FAIL;
    }
    if ((size_t) total > cap) {
        fclose(file);
        *out_size = (size_t) total;
        return REF_OVERFLOW;
    }
    if (fseek(file, 0, SEEK_SET) != 0) {
        fclose(file);
        return REF_FAIL;
    }
    if (fread(out, 1, (size_t) total, file) != (size_t) total) {
        fclose(file);
        return REF_FAIL;
    }
    fclose(file);
    *out_size = (size_t) total;
    return REF_OK;
}

#endif
