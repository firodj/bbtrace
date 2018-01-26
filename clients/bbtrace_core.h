#pragma once

#include "dr_api.h"

typedef enum {
	PKT_CODE_TRACE = 1
} pkt_code_t;

#pragma pack(1)
typedef struct {
	pkt_code_t code;
    uint64 ts;
    uint thread;
} pkt_header_t;

typedef struct {
    pkt_header_t header;
    uint size;
} pkt_trace_t;
#pragma pack()

#define BUF_TOTAL 1024*1024
#define MAX_TRACE_LOG 4294967295

typedef struct {
    uint pos;
    uint64 ts;
    thread_id_t thread;
} per_thread_t;

#ifdef __cplusplus
extern "C" {
#endif

size_t bbtrace_escape_string(const char *, char *, size_t);
const char *bbtrace_log_filename(uint);
const char *bbtrace_formatinfo_module(const module_data_t*);
const char *bbtrace_formatinfo_symbol(dr_symbol_export_t*, app_pc, app_pc);
const char *bbtrace_formatinfo_symbol_import(dr_symbol_import_t *, const char *);
int bbtrace_formatinfo_block(char *, size_t, app_pc, app_pc, app_pc, app_pc, const char *);
const char *bbtrace_formatinfo_exception(dr_exception_t *);
size_t bbtrace_dump_thread_data(per_thread_t*);
uint instrlist_app_length(void*, instrlist_t*);
uint instrlist_length(void*, instrlist_t*);
per_thread_t* create_bbtrace_thread_data(void *);
void bbtrace_init();
void bbtrace_shutdown();
#ifdef __cplusplus
}
#endif
