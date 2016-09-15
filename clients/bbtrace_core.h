#pragma once

#include "dr_api.h"

typedef enum {
	PKT_CODE_TRACE
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

const char *bbtrace_log_filename(uint);
const char *bbtrace_formatinfo_module(module_data_t*);
const char *bbtrace_formatinfo_symbol(dr_symbol_export_t*, app_pc, app_pc);
const char *bbtrace_formatinfo_block(app_pc, app_pc, uint);
uint instrlist_app_length(void*, instrlist_t*);
uint instrlist_length(void*, instrlist_t*);
#ifdef __cplusplus
}
#endif