#include "dr_api.h"
#include <stdio.h>
#include "drmgr.h"
#include "drutil.h"
#include "drwrap.h"
#include "hashtable.h"
#include "drvector.h"
#include <intrin.h>
#include <windows.h>
#include <mmsystem.h>
#include <d3d9.h>
#include <dsound.h>
#include <dinput.h>
#include "codecache.h"
#include "winapi.h"
#include "datatypes.h"
#include "synchro.h"
#include "bbtrace_core.h"
#include "wrapping.h"

#pragma intrinsic(__rdtsc)
#pragma intrinsic (_InterlockedExchangeAdd)

static app_pc g_func_CreateThread = 0;

typedef volatile unsigned char atomic8_t;
atomic8_t g_memcounter = 0;
static wrap_lib_user_t g_wrap_userdatas[256];

/* ------------------------------------------------------------------------- */
void
lib_entry(void *wrapcxt, INOUT void **user_data)
{
    void         *drcontext;
    app_pc       func, ret_addr;
    per_thread_t *thd_data;

    drcontext = drwrap_get_drcontext(wrapcxt);
    func      = drwrap_get_func(wrapcxt);
#if 1
    ret_addr  = drwrap_get_retaddr(wrapcxt);
#else
    DR_TRY_EXCEPT(drcontext, {
        ret_addr = drwrap_get_retaddr(wrapcxt);
    }, { /* EXCEPT */
        ret_addr = NULL;
    });
#endif

    sym_info_item_t *sym_info = syminfo_get(func);
    if (!sym_info) return;

    if (func != g_func_CreateThread) {
        //if (!sym_info->winapi_info) {
        if (!is_from_exe(ret_addr, false)) return;
        //}
    }

    wrap_lib_user_t data = {0};
    data.verbose  = true;
    data.sym_info = *sym_info;
    if (!data.verbose) return;

    buf_string_t buf_str = {0};
    buf_lib_call_t buf_item = {0};
    buf_item.kind     = KIND_LIB_CALL;
    buf_item.func     = func;
    buf_item.ret_addr = ret_addr;
    DR_ASSERT(sizeof(mem_ref_t) == sizeof(buf_lib_call_t));
    DR_ASSERT(6 * sizeof(mem_ref_t) == sizeof(buf_string_t));

    // DEBUG: dr_printf("lib_entry: %s\n", sym_info->sym.name);

    unsigned char memcounter = _InterlockedExchangeAdd8(&g_memcounter, 1);
    wrap_lib_user_t *p_data = &g_wrap_userdatas[memcounter];

    if (sym_info->winapi_info) {
        *user_data = p_data;
        // dr_printf("sizeof(wrap_lib_user_t) = %d\n", sizeof(wrap_lib_user_t));
        //dr_printf("g_memcounter = %d\n", g_memcounter);
        //p_data = dr_global_alloc(sizeof(wrap_lib_user_t));
        // DEBUG: dr_printf("allocate %s at: %X\n", sym_info->sym.name, (uint)p_data);
        //if (p_data) {
        //    *p_data = data;
        //    *user_data = p_data;
        //}
    }

    // WINAPI: save args and strings
    uint nargs = 0;
    if (sym_info->winapi_info) {
        nargs = sym_info->winapi_info->nargs;
        for (uint a = 0; a < nargs; a++) {
            p_data->args[a] = drwrap_get_arg(wrapcxt, a);
            // Capture only arg-0
            if (a == 0) {
                buf_item.arg = (uint)p_data->args[a];
                if (sym_info->winapi_info->targs[a] == A_LPSTR) {
                    buf_str.kind = KIND_STRING;
                    strncpy(buf_str.value, (char*)p_data->args[a], sizeof(buf_str.value));
                }
            }
        }
    }

    // trace lib call
    thd_data = drmgr_get_tls_field(drcontext, tls_index);
    if ((ptr_int_t)(thd_data->buf_ptr + sizeof(buf_lib_call_t)) >= -thd_data->buf_end)
        dump_data(drcontext);
    *(buf_lib_call_t*)thd_data->buf_ptr = buf_item;
    thd_data->buf_ptr += sizeof(buf_lib_call_t);

    // WINAPI: pre hook
    bool have_hooks = false;
    if (sym_info->winapi_info) {
        have_hooks = sym_info->winapi_info->pre_hook || sym_info->winapi_info->post_hook;

        if (sym_info->winapi_info->pre_hook) {
            sym_info->winapi_info->pre_hook(wrapcxt, &data);
        }
    }

    // WINAPI: trace strings
    if (sym_info->winapi_info) {
        if (buf_str.kind == KIND_STRING) {
            if ((ptr_int_t)(thd_data->buf_ptr + sizeof(buf_string_t)) >= -thd_data->buf_end)
                dump_data(drcontext);
            *(buf_string_t*)thd_data->buf_ptr = buf_str;
            thd_data->buf_ptr += sizeof(buf_string_t);
        }

        // NOTE: hooks usually already saved the args
        if (! have_hooks) {
            for (uint a = 1; a < nargs;) {
                buf_event_t buf_args = {0};
                buf_args.kind = KIND_ARGS;
                for (uint b = 0; b < 3 && a < nargs; b++, a++) {
                    buf_args.params[b] = (uint)p_data->args[a];
                }

                if ((ptr_int_t)(thd_data->buf_ptr + sizeof(buf_event_t)) >= -thd_data->buf_end)
                    dump_data(drcontext);
                *(buf_event_t*)thd_data->buf_ptr = buf_args;
                thd_data->buf_ptr += sizeof(buf_event_t);
            }
        }
    }
}

void
lib_exit(void *wrapcxt, INOUT void *user_data)
{
    wrap_lib_user_t  *p_data = user_data;
    app_pc           func, ret_addr;
    per_thread_t     *thd_data;
    void             *drcontext;
    sym_info_item_t  *sym_info = 0;

    drcontext = drwrap_get_drcontext(wrapcxt);
    func      = drwrap_get_func(wrapcxt);
#if 1
    ret_addr  = drwrap_get_retaddr(wrapcxt);
#else
    DR_TRY_EXCEPT(drcontext, {
        ret_addr = drwrap_get_retaddr(wrapcxt);
    }, { /* EXCEPT */
        ret_addr = NULL;
    });
#endif

    buf_lib_ret_t buf_item = {0};
    buf_item.kind          = KIND_LIB_RET;
    buf_item.func          = func;
    buf_item.ret_addr      = ret_addr;
    DR_ASSERT(sizeof(mem_ref_t) == sizeof(buf_lib_ret_t));

    if (p_data) {
        sym_info = &p_data->sym_info;
    } else if (!is_from_exe(ret_addr, false)) return;

    // WINAPI: get retval
    if (sym_info && sym_info->winapi_info) {
      // switch (sym_info->shared_dll) {}
        if (sym_info->winapi_info->tret != A_VOID) {
            p_data->retval = drwrap_get_retval(wrapcxt);
        }
        buf_item.retval = (uint)p_data->retval;
    }

#if 0
    thd_data = drmgr_get_tls_field(drcontext, tls_index);
    if ((ptr_int_t)(thd_data->buf_ptr + sizeof(buf_lib_ret_t)) >= -thd_data->buf_end)
        dump_data(drcontext);
    *(buf_lib_ret_t*)thd_data->buf_ptr = buf_item;
    thd_data->buf_ptr += sizeof(buf_lib_ret_t);
#else
    // thread_id_t thread_id = dr_get_thread_id(drcontext);
#endif

    // WINAPI: post hook
    if (sym_info && sym_info->winapi_info) {
        if (sym_info->winapi_info->post_hook) {
            sym_info->winapi_info->post_hook(wrapcxt, p_data);
        }
    }
}

/* ------------------------------------------------------------------------- */
static bool
is_wrapping_symbol(sym_info_item_t *sym_info) {
    if (g_opts.libcall_mode == 0) return false;
    if (g_opts.libcall_mode == 2 && !sym_info->winapi_info) return false;

    switch (sym_info->shared_dll) {
    case D3D9_DLL:
        if (_stricmp(sym_info->sym.name, "DebugSetMute") == 0) {
            return false;
        }
        break;
    case KERNEL32_DLL:
        if (_stricmp(sym_info->sym.name, "QueryPerformanceCounter") == 0) {
            return false;
        } else if (_stricmp(sym_info->sym.name, "CreateThread") == 0) {
            g_func_CreateThread = sym_info->sym.addr;
            dr_printf("Fun CreateThread: %X\n", g_func_CreateThread);
            return true;
        }
        break;
    case NTDLL_DLL:
        if (_stricmp(sym_info->sym.name, "RtlQueryPerformanceCounter") == 0) {
            return false;
        }
        // FAIL: RtlActivateActivationContextUnsafeFast
        // FAIL: RtlDeactivateActivationContextUnsafeFast
        break;
    }
    return true;
}

static void
iterate_exports(void * drcontext, const module_data_t *mod, bool add)
{
    int shared_dll = NO_DLL;
    buf_module_t buf_item = {0};
    per_thread_t *thd_data;
    const char *mod_name = dr_module_preferred_name(mod);

    for (int i = 1; i < (sizeof(shared_dll_names)/sizeof(*shared_dll_names)); i++) {
        if (_stricmp(mod_name, shared_dll_names[i]) == 0) {
            shared_dll = i; break;
        }
    }

    if (shared_dll == NO_DLL) return;

    buf_item.kind = KIND_MODULE;
    buf_item.entry_point = mod->entry_point;
    buf_item.start = (uint) mod->start;
    buf_item.end = (uint) mod->end;
    buf_item.shared_dll = shared_dll;
    strncpy(buf_item.name, mod_name, sizeof(buf_item.name));

    DR_ASSERT(2 * sizeof(mem_ref_t) == sizeof(buf_module_t));
    thd_data = drmgr_get_tls_field(drcontext, tls_index);
    if ((ptr_int_t)(thd_data->buf_ptr + sizeof(buf_module_t)) >= -thd_data->buf_end)
        dump_data(drcontext);
    *(buf_module_t*)thd_data->buf_ptr = buf_item;
    thd_data->buf_ptr += sizeof(buf_module_t);

    dr_symbol_export_iterator_t *exp_iter =
        dr_symbol_export_iterator_start(mod->handle);

    while (dr_symbol_export_iterator_hasnext(exp_iter)) {
        dr_symbol_export_t *sym = dr_symbol_export_iterator_next(exp_iter);
        app_pc func = sym->addr;

        if (sym->is_code && func) {
            winapi_info_t *winapi_info = winapi_get(sym->name);

            if (add) {
                sym_info_item_t *sym_info = dr_global_alloc(sizeof(sym_info_item_t));
                sym_info->sym.name = sym->name;
                sym_info->sym.addr = sym->addr;
                sym_info->sym.ordinal = sym->ordinal;
                sym_info->shared_dll = shared_dll;
                sym_info->winapi_info = winapi_info;

                syminfo_add(func, sym_info);
                if (is_wrapping_symbol(sym_info)) {
                    drwrap_wrap(func, lib_entry, lib_exit);
                }
            } else {
                drwrap_unwrap(func, lib_entry, lib_exit);

                syminfo_remove(func);
            }
        }
    }
    dr_symbol_export_iterator_stop(exp_iter);
}

void
event_module_load(void *drcontext, const module_data_t *mod, bool loaded)
{
    if (mod->start != app_exe->start)
        iterate_exports(drcontext, mod, true/*add*/);
}

void
event_module_unload(void *drcontext, const module_data_t *mod)
{
    if (mod->start != app_exe->start)
        iterate_exports(drcontext, mod, false/*remove*/);
}

/* ------------------------------------------------------------------------- */

void
WndProc_entry(void *wrapcxt, INOUT void **user_data)
{
    void *drcontext = drwrap_get_drcontext(wrapcxt);
    per_thread_t *thd_data = drmgr_get_tls_field(drcontext, tls_index);

    buf_event_t buf_item = {0};
    buf_item.kind = KIND_WNDPROC;
    for (int a=0; a<3; a++) buf_item.params[a] = (uint)drwrap_get_arg(wrapcxt, a+1);
    DR_ASSERT(sizeof(buf_event_t) % sizeof(mem_ref_t) == 0);

    if ((ptr_int_t)(thd_data->buf_ptr + sizeof(buf_event_t)) >= -thd_data->buf_end) dump_data(drcontext);
    *(buf_event_t*)thd_data->buf_ptr = buf_item;
    thd_data->buf_ptr += sizeof(buf_event_t);
}
