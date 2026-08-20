#ifndef LIBSTD_ORACLE_ARCHIVE_H
#define LIBSTD_ORACLE_ARCHIVE_H

#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>

typedef struct archive archive;
typedef struct archive_entry archive_entry;
typedef long la_ssize_t;
typedef int64_t la_int64_t;

#define ARCHIVE_OK 0
#define ARCHIVE_EOF 1

extern archive* archive_write_new(void);
extern int archive_write_free(archive* a);
extern int archive_write_set_format_7zip(archive* a);
extern int archive_write_set_format_zip(archive* a);
extern int archive_write_set_format_pax_restricted(archive* a);
extern int archive_write_set_format_option(archive* a, const char* module, const char* option, const char* value);
extern int archive_write_open_filename(archive* a, const char* filename);
extern int archive_write_close(archive* a);
extern int archive_write_header(archive* a, archive_entry* entry);
extern la_ssize_t archive_write_data(archive* a, const void* buff, size_t size);
extern int archive_write_finish_entry(archive* a);

extern archive_entry* archive_entry_new(void);
extern void archive_entry_free(archive_entry* entry);
extern void archive_entry_set_pathname(archive_entry* entry, const char* pathname);
extern void archive_entry_set_size(archive_entry* entry, la_int64_t size);
extern void archive_entry_set_filetype(archive_entry* entry, unsigned int type);
extern void archive_entry_set_perm(archive_entry* entry, mode_t perm);
extern void archive_entry_set_mtime(archive_entry* entry, time_t sec, long nsec);
extern void archive_entry_set_symlink(archive_entry* entry, const char* linkname);
extern void archive_entry_set_uid(archive_entry* entry, la_int64_t uid);

extern archive* archive_read_new(void);
extern int archive_read_free(archive* a);
extern int archive_read_support_format_all(archive* a);
extern int archive_read_support_filter_all(archive* a);
extern int archive_read_open_filename(archive* a, const char* filename, size_t block_size);
extern int archive_read_next_header(archive* a, archive_entry** entry);
extern la_ssize_t archive_read_data(archive* a, void* buff, size_t size);

extern const char* archive_entry_pathname(archive_entry* entry);
extern unsigned int archive_entry_filetype(archive_entry* entry);
extern la_int64_t archive_entry_uid(archive_entry* entry);
extern const char* archive_entry_symlink(archive_entry* entry);
extern const char* archive_entry_hardlink(archive_entry* entry);

#endif
