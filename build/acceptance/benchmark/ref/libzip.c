#include <string.h>

#include "ref.h"
#include "zip.h"

int ref_zip_create(const unsigned char* data,
                   size_t size,
                   const char* name,
                   int store,
                   const char* temp_path,
                   unsigned char* output,
                   size_t capacity,
                   size_t* output_size) {
    *output_size = 0;
    int open_error = 0;
    zip_t* za = zip_open(temp_path, (int) ((unsigned int) ZIP_CREATE | (unsigned int) ZIP_TRUNCATE), &open_error);
    if (za == NULL) {
        return REF_FAIL;
    }
    zip_error_t source_error;
    zip_error_init(&source_error);
    zip_source_t* file = zip_source_buffer_create(data, size, 0, &source_error);
    if (file == NULL) {
        zip_close(za);
        return REF_FAIL;
    }
    const zip_int64_t index = zip_file_add(za, name, file, ZIP_FL_ENC_UTF_8);
    if (index < 0) {
        zip_source_free(file);
        zip_close(za);
        return REF_FAIL;
    }
    if (store != 0 && zip_set_file_compression(za, index, ZIP_CM_STORE, 0) != 0) {
        zip_close(za);
        return REF_FAIL;
    }
    if (zip_close(za) != 0) {
        return REF_FAIL;
    }
    const int status = ref_file_read(temp_path, output, capacity, output_size);
    remove(temp_path);
    return status;
}

int ref_zip_extract(const unsigned char* data,
                    size_t size,
                    unsigned char* output,
                    size_t capacity,
                    size_t* output_size) {
    *output_size = 0;
    zip_error_t archive_error;
    zip_error_init(&archive_error);
    zip_source_t* source = zip_source_buffer_create(data, size, 0, &archive_error);
    if (source == NULL) {
        return REF_FAIL;
    }
    zip_t* za = zip_open_from_source(source, 0, &archive_error);
    if (za == NULL) {
        zip_source_free(source);
        return REF_FAIL;
    }
    zip_stat_t st;
    const zip_int64_t count = zip_get_num_entries(za, 0);
    zip_int64_t index = -1;
    for (zip_int64_t i = 0; i < count; i++) {
        zip_stat_init(&st);
        if (zip_stat_index(za, i, 0, &st) != 0) {
            continue;
        }
        const size_t name_len = st.valid & ZIP_STAT_NAME ? strlen(st.name) : 0;
        if (name_len == 0 || st.name[name_len - 1] != '/') {
            index = i;
            break;
        }
    }
    if (index < 0) {
        zip_close(za);
        return REF_FAIL;
    }
    zip_stat_init(&st);
    if (zip_stat_index(za, index, 0, &st) != 0 || !(st.valid & ZIP_STAT_SIZE)) {
        zip_close(za);
        return REF_FAIL;
    }
    if (st.size > capacity) {
        zip_close(za);
        *output_size = (size_t) st.size;
        return REF_OVERFLOW;
    }
    zip_file_t* zf = zip_fopen_index(za, index, 0);
    if (zf == NULL) {
        zip_close(za);
        return REF_FAIL;
    }
    size_t done = 0;
    while (done < (size_t) st.size) {
        const zip_int64_t n = zip_fread(zf, output + done, (zip_uint64_t) ((size_t) st.size - done));
        if (n <= 0) {
            break;
        }
        done += (size_t) n;
    }
    zip_fclose(zf);
    zip_close(za);
    if (done != (size_t) st.size) {
        return REF_FAIL;
    }
    *output_size = done;
    return REF_OK;
}
