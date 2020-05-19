#pragma once

#include "drwrap.h"

#ifdef __cplusplus
extern "C" {
#endif

void event_module_load(void *drcontext, const module_data_t *mod, bool loaded);
void event_module_unload(void *drcontext, const module_data_t *mod);

#ifdef __cplusplus
}
#endif