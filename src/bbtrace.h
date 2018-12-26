#ifndef _BBTRACE_H_
#define _BBTRACE_H_

#ifdef __cplusplus
extern "C" {
#endif

void bbtrace_init(client_id_t id, bool is_enable_memtrace);
void bbtrace_exit(void);
file_t get_info_file();

#ifdef __cplusplus
}
#endif

#endif
