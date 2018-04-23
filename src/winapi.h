#pragma once

#include "dr_api.h"

enum _shared_dll_t {
  NO_DLL,
  D3D9_DLL,
  DSOUND_DLL,
  DINPUT8_DLL,
  DDRAW_DLL,
  KERNEL32_DLL,
  NTDLL_DLL,
  WINMM_DLL,
  WS2_32_DLL,
};

enum _winapi_arg_t {
  A_LPVOID,
  A_VOID,
  A_HANDLE,
  A_LPDWORD,
  A_DWORD,
  A_BOOL,
  A_LPSTR,
  A_HRESULT,
  A_LPPVOID,
};

static const char * const shared_dll_names[] = {
  "",
  "d3d9.dll",
  "dsound.dll",
  "dinput8.dll",
  "ddraw.dll",
  "kernel32.dll",
  "ntdll.dll",
  "winmm.dll",
  "ws2_32.dll"
};

typedef struct _winapi_info_t {
    uint shared_dll;
    const char *sym_name;
    uint nargs;
    uint targs[10];
    uint tret;
    void (*pre_hook)(void *wrapcxt, void *user_data);
    void (*post_hook)(void *wrapcxt, void *user_data);
} winapi_info_t;

typedef struct _sym_info_item_t {
  dr_symbol_export_t sym;
  uint shared_dll;
  winapi_info_t *winapi_info;
} sym_info_item_t;

typedef struct _wrap_lib_user_t {
    sym_info_item_t sym_info;
    bool verbose;
    void *args[10];
    void *retval;
    // void (*pre_func_cb)(void *wrapcxt, OUT void **user_data);
    // void (*post_func_cb)(void *wrapcxt, void *user_data);
} wrap_lib_user_t;

#ifdef __cplusplus
extern "C" {
#endif

void winapi_init(void);
void winapi_exit(void);
winapi_info_t *winapi_get(const char *sym_name);
bool syminfo_add(app_pc func, sym_info_item_t *sym_info);
bool syminfo_remove(app_pc func);
sym_info_item_t* syminfo_get(app_pc func);

#ifdef __cplusplus
}
#endif
