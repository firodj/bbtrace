#pragma once

#include "dr_defines.h"

#ifdef __cplusplus
extern "C" {
#endif

void codecache_init(void* clean_call, reg_t back);
void codecache_exit(void);
app_pc codecache_get(void);

#ifdef __cplusplus
}
#endif
