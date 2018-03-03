#pragma once

#include "dr_api.h"
#include "bbtrace_data.h"

#define BUF_TOTAL 1024*1024
#define MAX_TRACE_LOG 4294967295

#ifdef __cplusplus
extern "C" {
#endif

char * bbtrace_append_string(char *, const char *, bool);
char * bbtrace_append_integer(char *, uint, bool);
char * bbtrace_append_hex(char *, uint, bool);
size_t bbtrace_escape_string(const char *, char *, size_t);
const char *bbtrace_log_filename(uint);
      char *bbtrace_formatinfo_module2(char *,const module_data_t*);
      char *bbtrace_formatinfo_symbol2(char *, dr_symbol_export_t *, app_pc, app_pc);
      char *bbtrace_formatinfo_symbol_import2(char *, dr_symbol_import_t *);
      char *bbtrace_formatinfo_block2(char *, app_pc, app_pc, app_pc, app_pc, const char *);
      char *bbtrace_formatinfo_exception2(char *, dr_exception_t *);
size_t bbtrace_dump_thread_data(per_thread_t*);
uint instrlist_app_length(void*, instrlist_t*);
uint instrlist_length(void*, instrlist_t*);
per_thread_t* create_bbtrace_thread_data(void *);
void bbtrace_init();
void bbtrace_shutdown();
#ifdef __cplusplus
}
#endif
