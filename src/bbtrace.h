#ifndef _BBTRACE_H_
#define _BBTRACE_H_

#ifdef __cplusplus
extern "C" {
#endif

typedef struct _bbtrace_options_tag {
    bool enable_memtrace;
    unsigned int  libcall_mode;
} bbtrace_options_t;

void bbtrace_init(client_id_t id, bbtrace_options_t opts);
void bbtrace_exit(void);
file_t get_info_file();

#ifdef __cplusplus
}
#endif

#endif
