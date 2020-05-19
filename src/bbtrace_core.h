#ifndef _BBTRACE_CORE_H_
#define _BBTRACE_CORE_H_

#include "bbtrace.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
    char   *buf_ptr;
    char   *buf_base;
    /* buf_end holds the negative value of real address of buffer end. */
    ptr_int_t buf_end;
    file_t dump_f;
    uint loop_xcx;
    app_pc loop_pc;
    bool dump_mcontext;
} per_thread_t;

void dump_symbol_data(buf_symbol_t *buf_item);
void dump_event_data(buf_event_t *buf_item);
void add_dynamic_codes(void* start, void *end);
void lib_entry(void *wrapcxt, INOUT void **user_data);
void lib_exit(void *wrapcxt, INOUT void *user_data);
void WndProc_entry(void *wrapcxt, INOUT void **user_data);

char* set_dump_path(client_id_t id, dr_time_t* start_time);
bool is_from_exe(app_pc pc, bool lookup);
void dump_data(void *drcontext);

extern bbtrace_options_t g_opts;
extern module_data_t *app_exe;
extern int tls_index;

#ifdef __cplusplus
}
#endif

#endif
