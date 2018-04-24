#pragma once

#include "dr_api.h"

#ifdef __cplusplus
extern "C" {
#endif

void synchro_init(void);
void synchro_exit(void);
uint synchro_inc_cs(void *cs);
uint synchro_inc_hmutex(void *hmutex, uint kind);
uint synchro_kind_hmutex(void *hmutex);

#ifdef __cplusplus
}
#endif
