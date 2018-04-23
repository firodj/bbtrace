#ifndef _BBTRACE_H_
#define _BBTRACE_H_

#ifdef __cplusplus
extern "C" {
#endif

void bbtrace_init(client_id_t id);
void bbtrace_exit(void);

#ifdef __cplusplus
}
#endif

#endif
