#include <stddef.h>
#include <string.h>

// NOLINTNEXTLINE(bugprone-reserved-identifier,cert-dcl37-c,cert-dcl51-cpp)
#define _UNIX
#include "dll.hpp"

#include "ref.h"

// NOLINTBEGIN
static int CALLBACK unrar_callback(UINT msg, LPARAM user, LPARAM p1, LPARAM p2) {
    if (msg != UCM_PROCESSDATA) {
        return 0;
    }
    ref_sink* sink = (ref_sink*) user;
    return ref_sink_write(sink, (const void*) p1, (size_t) p2) == REF_OK ? 0 : -1;
}
// NOLINTEND

int ref_unrar_extract(const unsigned char* data,
                      size_t size,
                      const char* tmp_path,
                      const char* dest_dir,
                      unsigned char* out,
                      size_t cap,
                      size_t* out_size) {
    *out_size = 0;
    if (ref_file_write(tmp_path, data, size) != REF_OK) {
        return REF_FAIL;
    }
    struct RAROpenArchiveDataEx arc;
    memset(&arc, 0, sizeof(arc));
    arc.ArcName = (char*) tmp_path;
    arc.OpenMode = RAR_OM_EXTRACT;
    HANDLE handle = RAROpenArchiveEx(&arc);
    if (handle == NULL || arc.OpenResult != ERAR_SUCCESS) {
        if (handle != NULL) {
            RARCloseArchive(handle);
        }
        remove(tmp_path);
        return REF_FAIL;
    }
    ref_sink sink = {out, cap, 0, 0};
    RARSetCallback(handle, unrar_callback, (LPARAM) &sink);

    int result = ERAR_SUCCESS;
    char extracted[1024];
    extracted[0] = '\0';
    struct RARHeaderDataEx header;
    for (;;) {
        memset(&header, 0, sizeof(header));
        const int status = RARReadHeaderEx(handle, &header);
        if (status == ERAR_END_ARCHIVE) {
            break;
        }
        if (status != ERAR_SUCCESS) {
            result = status;
            break;
        }
        const int operation = (header.Flags & RHDF_DIRECTORY) ? RAR_OM_LIST : RAR_OM_EXTRACT;
        result = RARProcessFile(handle, operation, (char*) dest_dir, NULL);
        if (result != ERAR_SUCCESS) {
            break;
        }
        if (operation == RAR_OM_EXTRACT && extracted[0] == '\0') {
            snprintf(extracted, sizeof(extracted), "%s/%s", dest_dir, header.FileName);
        }
    }
    RARCloseArchive(handle);
    remove(tmp_path);
    if (extracted[0] != '\0') {
        remove(extracted);
    }
    if (result != ERAR_SUCCESS) {
        return REF_FAIL;
    }
    if (sink.overflow) {
        *out_size = sink.len;
        return REF_OVERFLOW;
    }
    *out_size = sink.len;
    return REF_OK;
}
