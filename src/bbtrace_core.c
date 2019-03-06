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

#pragma intrinsic(__rdtsc)

static bool enable_memtrace = false;
#define WITH_BBTRACE 1
#define WITH_APPCALL 0
#define WITH_LIBCALL 1
#define ONLY_WINAPI 1

static file_t info_file;
static drvector_t vec_dynamic_codes;
static range_t rng_dynamic_codes;

static module_data_t *app_exe = 0;
static thread_id_t main_thread_id = 0;
static bool enter_main = false;
static int tls_index;
static char dump_path[MAXIMUM_PATH];

static void event_exit(void);
static bool event_exception(void *drcontext, dr_exception_t *excpt);
static void event_thread_init(void *drcontext);
static void event_thread_exit(void *drcontext);
static bool is_from_exe(app_pc pc, bool lookup);
static bool is_dynamic_code(app_pc pc);
static void dump_data(void *drcontext);
static void dump_thread_mcontext(void *drcontext);

static app_pc g_funCreateThread = 0;

/* thread private log file and counter */
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

typedef struct {
    instr_t *first_instr;
    app_pc loop_stop_pc;
} user_data_t;

// Hack
static void
nop_delay(uint rep)
{
  for (uint a = 0; a < rep; a++) {
    for (uint b = 0; b < 0x1000; b++) {
      _asm nop;
    }
  }
}

/* ------------------------------------------------------------------------- */
void
lib_entry(void *wrapcxt, INOUT void **user_data)
{
    void *drcontext;
    app_pc func, ret_addr;
    per_thread_t *thd_data;

    drcontext = drwrap_get_drcontext(wrapcxt);
    func = drwrap_get_func(wrapcxt);
#if 1
    ret_addr = drwrap_get_retaddr(wrapcxt);
#else
    DR_TRY_EXCEPT(drcontext, {
        ret_addr = drwrap_get_retaddr(wrapcxt);
    }, { /* EXCEPT */
        ret_addr = NULL;
    });
#endif

    sym_info_item_t *sym_info = syminfo_get(func);
    if (!sym_info) return;

    if (func != g_funCreateThread) {
        //if (!sym_info->winapi_info) {
        if (!is_from_exe(ret_addr, false)) return;
        //}
    }

    wrap_lib_user_t data = {0};
    data.verbose = true;
    data.sym_info = *sym_info;
    if (!data.verbose) return;

    buf_string_t buf_str = {0};
    buf_lib_call_t buf_item = {0};
    buf_item.kind = KIND_LIB_CALL;
    buf_item.func = func;
    buf_item.ret_addr = ret_addr;
    DR_ASSERT(sizeof(mem_ref_t) == sizeof(buf_lib_call_t));
    DR_ASSERT(6 * sizeof(mem_ref_t) == sizeof(buf_string_t));

    wrap_lib_user_t *p_data;
    if (sym_info->winapi_info) {
        p_data = dr_global_alloc(sizeof(wrap_lib_user_t));
        *p_data = data;
        *user_data = p_data;
    } else {
        p_data = &data;
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
            sym_info->winapi_info->pre_hook(wrapcxt, (void*)p_data);
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
    wrap_lib_user_t *p_data = user_data;
    app_pc func, ret_addr;
    per_thread_t *thd_data;
    void *drcontext;
    sym_info_item_t *sym_info = 0;

    drcontext = drwrap_get_drcontext(wrapcxt);
    func = drwrap_get_func(wrapcxt);
#if 1
    ret_addr = drwrap_get_retaddr(wrapcxt);
#else
    DR_TRY_EXCEPT(drcontext, {
        ret_addr = drwrap_get_retaddr(wrapcxt);
    }, { /* EXCEPT */
        ret_addr = NULL;
    });
#endif

    buf_lib_ret_t buf_item = {0};
    buf_item.kind = KIND_LIB_RET;
    buf_item.func = func;
    buf_item.ret_addr = ret_addr;
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

    thd_data = drmgr_get_tls_field(drcontext, tls_index);
    if ((ptr_int_t)(thd_data->buf_ptr + sizeof(buf_lib_ret_t)) >= -thd_data->buf_end)
        dump_data(drcontext);
    *(buf_lib_ret_t*)thd_data->buf_ptr = buf_item;
    thd_data->buf_ptr += sizeof(buf_lib_ret_t);

    // WINAPI: post hook
    if (sym_info && sym_info->winapi_info) {
        if (sym_info->winapi_info->post_hook) {
            sym_info->winapi_info->post_hook(wrapcxt, (void*)p_data);
        }
    }

    if (p_data) {
        dr_global_free(p_data, sizeof(wrap_lib_user_t));
    }
}

/* ------------------------------------------------------------------------- */
static bool
is_wrapping_symbol(sym_info_item_t *sym_info) {
#if !WITH_LIBCALL
    return false;
#endif
#if ONLY_WINAPI
    if (!sym_info->winapi_info) return false;
#endif

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
            g_funCreateThread = sym_info->sym.addr;
            dr_printf("Fun CreateThread: %X\n", g_funCreateThread);
        }
        break;
    case NTDLL_DLL:
        if (_stricmp(sym_info->sym.name, "RtlQueryPerformanceCounter") == 0) {
            return false;
        }
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

static void
event_module_load(void *drcontext, const module_data_t *mod, bool loaded)
{
    if (mod->start != app_exe->start)
        iterate_exports(drcontext, mod, true/*add*/);
}

static void
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

static void
dump_thread_mcontext(void *drcontext)
{
    dr_mcontext_t mcontext = {
        sizeof(mcontext),
        DR_MC_ALL,
    };
    thread_id_t thread_id = dr_get_thread_id(drcontext);
    per_thread_t *thd_data = drmgr_get_tls_field(drcontext, tls_index);

    if (! dr_get_mcontext(drcontext, &mcontext)) return;

    buf_event_t buf_item = {0};
    buf_item.kind = KIND_THREAD;
    buf_item.params[0] = thread_id;
    buf_item.params[1] = mcontext.xsp;
    buf_item.params[2] = mcontext.xflags;
    DR_ASSERT(sizeof(mem_ref_t) == sizeof(buf_event_t));

    if ((ptr_int_t)(thd_data->buf_ptr + sizeof(buf_event_t)) >= -thd_data->buf_end)
        dump_data(drcontext);
    *(buf_event_t*)thd_data->buf_ptr = buf_item;
    thd_data->buf_ptr += sizeof(buf_event_t);

    thd_data->dump_mcontext = true;

    dr_fprintf(info_file, "%d] SP:0x%x, FLAGS:0x%x\n", thread_id, mcontext.xsp, mcontext.xflags);
    dr_printf("%d] SP:0x%x, FLAGS:0x%x\n", thread_id, mcontext.xsp, mcontext.xflags);
}

static void
event_thread_init(void *drcontext)
{
    char path[MAXIMUM_PATH];
    per_thread_t *thd_data;
    thread_id_t thread_id = dr_get_thread_id(drcontext);

    if (main_thread_id == 0) {
        main_thread_id = thread_id;
        dr_snprintf(path, sizeof(path), "%s.bin", dump_path);
        dr_fprintf(info_file, "Main thread: #%d\n", thread_id);
    } else {
        dr_snprintf(path, sizeof(path), "%s.bin.%d", dump_path, thread_id);
    }

    /* allocate thread private data */
    thd_data = dr_thread_alloc(drcontext, sizeof(per_thread_t));
    drmgr_set_tls_field(drcontext, tls_index, thd_data);
    thd_data->buf_base = dr_thread_alloc(drcontext, MEM_BUF_SIZE);
    thd_data->buf_ptr  = thd_data->buf_base;
    /* set buf_end to be negative of address of buffer end for the lea later */
    thd_data->buf_end  = -(ptr_int_t)(thd_data->buf_base + MEM_BUF_SIZE);

    thd_data->dump_f = dr_open_file(path, DR_FILE_WRITE_OVERWRITE | DR_FILE_ALLOW_LARGE);
    thd_data->loop_xcx = 0;
    thd_data->dump_mcontext = false;

    dr_fprintf(info_file, "%d] Open dump file: %s\n", thread_id, path);
    dr_printf("%d] Open dump file: %s\n", thread_id, path);
}

static void
event_thread_exit(void *drcontext)
{
    per_thread_t *thd_data;

    dump_data(drcontext);
    thd_data = drmgr_get_tls_field(drcontext, tls_index);
    thd_data->dump_f;

    dr_close_file(thd_data->dump_f);

    dr_thread_free(drcontext, thd_data->buf_base, MEM_BUF_SIZE);
    dr_thread_free(drcontext, thd_data, sizeof(per_thread_t));
}

static bool
event_exception(void *drcontext, dr_exception_t *excpt)
{
    per_thread_t *thd_data;
    buf_exception_t buf_item = {0};

    buf_item.kind = KIND_EXCEPTION;
    buf_item.fault_address = excpt->record->ExceptionInformation[1];
    buf_item.code = excpt->record->ExceptionCode;
    buf_item.pc = excpt->record->ExceptionAddress;
    DR_ASSERT(sizeof(mem_ref_t) == sizeof(buf_exception_t));

    thd_data = drmgr_get_tls_field(drcontext, tls_index);
    if ((ptr_int_t)(thd_data->buf_ptr + sizeof(buf_exception_t)) >= -thd_data->buf_end)
        dump_data(drcontext);
    *(buf_exception_t*)thd_data->buf_ptr = buf_item;
    thd_data->buf_ptr += sizeof(buf_exception_t);

    dr_fprintf(info_file, "Exception %X at %X\n", buf_item.code, buf_item.pc);

    return true;
}

#if 0
static void
at_call(app_pc instr_addr, app_pc target_addr)
{
    void *drcontext = dr_get_current_drcontext();
    thread_id_t thread_id = dr_get_thread_id(drcontext);
    per_thread_t *thd_data = drmgr_get_tls_field(drcontext, tls_index);
    dr_mcontext_t mc = {sizeof(mc),DR_MC_CONTROL/*only need xsp*/};
    dr_get_mcontext(drcontext, &mc);

    buf_app_call_t buf_item;
    buf_item.kind = KIND_APP_CALL;
    buf_item.instr_addr = instr_addr;
    buf_item.target_addr = target_addr;
    buf_item.tos = mc.xsp;
    DR_ASSERT(sizeof(mem_ref_t) == sizeof(buf_app_call_t));

    thd_data = drmgr_get_tls_field(drcontext, tls_index);
    if ((ptr_int_t)(thd_data->buf_ptr + sizeof(buf_app_call_t)) >= -thd_data->buf_end)
        dump_data(drcontext);
    *(buf_app_call_t*)thd_data->buf_ptr = buf_item;
    thd_data->buf_ptr += sizeof(buf_app_call_t);
}
#endif

static void
at_call_ind(app_pc instr_addr, app_pc target_addr)
{
    void *drcontext = dr_get_current_drcontext();
    thread_id_t thread_id = dr_get_thread_id(drcontext);
    per_thread_t *thd_data = drmgr_get_tls_field(drcontext, tls_index);
    dr_mcontext_t mc = {sizeof(mc),DR_MC_CONTROL/*only need xsp*/};
    dr_get_mcontext(drcontext, &mc);

    buf_app_call_t buf_item;
    buf_item.kind = KIND_APP_CALL;
    buf_item.instr_addr = instr_addr;
    buf_item.target_addr = target_addr;
    buf_item.tos = mc.xsp;
    DR_ASSERT(sizeof(mem_ref_t) == sizeof(buf_app_call_t));

    thd_data = drmgr_get_tls_field(drcontext, tls_index);
    if ((ptr_int_t)(thd_data->buf_ptr + sizeof(buf_app_call_t)) >= -thd_data->buf_end)
        dump_data(drcontext);
    *(buf_app_call_t*)thd_data->buf_ptr = buf_item;
    thd_data->buf_ptr += sizeof(buf_app_call_t);
}

#if 0
static void
at_return(app_pc instr_addr, app_pc target_addr)
{
    void *drcontext = dr_get_current_drcontext();
    thread_id_t thread_id = dr_get_thread_id(drcontext);
    per_thread_t *thd_data = drmgr_get_tls_field(drcontext, tls_index);

    buf_app_ret_t buf_item;
    buf_item.kind = KIND_APP_RET;
    buf_item.instr_addr = instr_addr;
    buf_item.target_addr = target_addr;
    DR_ASSERT(sizeof(mem_ref_t) == sizeof(buf_app_ret_t));

    thd_data = drmgr_get_tls_field(drcontext, tls_index);
    if ((ptr_int_t)(thd_data->buf_ptr + sizeof(buf_app_ret_t)) >= -thd_data->buf_end)
        dump_data(drcontext);
    *(buf_app_ret_t*)thd_data->buf_ptr = buf_item;
    thd_data->buf_ptr += sizeof(buf_app_ret_t);
}
#endif

static bool
is_dynamic_code(app_pc pc) {
  if (rng_dynamic_codes.start != 0 &&
    pc >= (app_pc)rng_dynamic_codes.start &&
    pc < (app_pc)rng_dynamic_codes.end) {
  for (size_t i = 0; i < vec_dynamic_codes.entries; ++i) {
    range_t *range = drvector_get_entry(&vec_dynamic_codes, i);
    if (pc >= (app_pc)range->start && pc < (app_pc)range->end) {
      return true;
    }
  }
  }
  return false;
}

static bool
is_from_exe(app_pc pc, bool lookup)
{
    bool from_exe = false;
    module_data_t *mod;

    if (pc) {
        if (pc >= app_exe->start && pc < app_exe->end) {
            from_exe = true;
        } else if (lookup) {
            mod = dr_lookup_module(pc);   // FIXME: Time consuming!
            if (mod) {
                from_exe = mod->start == app_exe->start;
                dr_free_module_data(mod);
            }
        }
    }

    return from_exe;
}

static void
instrument_mem(void *drcontext, instrlist_t *ilist, instr_t *where,
               opnd_t ref, bool write)
{
    instr_t *instr, *call, *restore;
    opnd_t opnd1, opnd2;
    app_pc pc;
    reg_t reg2 = DR_REG_XCX, reg1 = DR_REG_NULL;
    static const reg_id_t allowed[5] = { DR_REG_XDX, DR_REG_XBX, DR_REG_XAX, DR_REG_XSI, DR_REG_XDI };
    app_pc code_cache;

    code_cache = codecache_get();

    /* Store pc in memory ref */
    pc = instr_get_app_pc(where);

    for (int i = 0; i < 5; i++) {
        if (!opnd_uses_reg(ref, allowed[i])) {
            reg1 = allowed[i];
            break;
        }
    }

    DR_ASSERT(reg1 != DR_REG_NULL);

    call  = INSTR_CREATE_label(drcontext);
    restore = INSTR_CREATE_label(drcontext);

    dr_save_reg(drcontext, ilist, where, reg1, SPILL_SLOT_2);
    dr_save_reg(drcontext, ilist, where, reg2, SPILL_SLOT_3);

    /* use drutil to get mem address */
    drutil_insert_get_mem_addr(drcontext, ilist, where, ref, reg1, reg2);

#if 0
    /* Load g_memtrace_active into ecx */
    opnd1 = opnd_create_reg(reg2);
    opnd2 = OPND_CREATE_MEMPTR(DR_REG_NULL, &g_memtrace_active);
    instr = INSTR_CREATE_mov_ld(drcontext, opnd1, opnd2);
    instrlist_meta_preinsert(ilist, where, instr);

    /* jecxz restore */
    opnd1 = opnd_create_instr(restore);
    instr = INSTR_CREATE_jecxz(drcontext, opnd1);
    instrlist_meta_preinsert(ilist, where, instr);
#endif

    /* The following assembly performs the following instructions
     * buf_ptr->code = write;
     * buf_ptr->addr  = addr;
     * buf_ptr->size  = size;
     * buf_ptr->pc    = pc;
     * buf_ptr++;
     * if (buf_ptr >= buf_end_ptr)
     *    clean_call();
     */

    drmgr_insert_read_tls_field(drcontext, tls_index, ilist, where, reg2);

    /* Load data->buf_ptr into reg2 */
    opnd1 = opnd_create_reg(reg2);
    opnd2 = OPND_CREATE_MEMPTR(reg2, offsetof(per_thread_t, buf_ptr));
    instr = INSTR_CREATE_mov_ld(drcontext, opnd1, opnd2);
    instrlist_meta_preinsert(ilist, where, instr);

    /* Move write/read to write field */
    opnd1 = OPND_CREATE_MEM32(reg2, offsetof(mem_ref_t, kind));
    opnd2 = OPND_CREATE_INT32(write ? KIND_WRITE : KIND_READ);
    instr = INSTR_CREATE_mov_imm(drcontext, opnd1, opnd2);
    instrlist_meta_preinsert(ilist, where, instr);

    /* Store address in memory ref */
    opnd1 = OPND_CREATE_MEMPTR(reg2, offsetof(mem_ref_t, addr));
    opnd2 = opnd_create_reg(reg1);
    instr = INSTR_CREATE_mov_st(drcontext, opnd1, opnd2);
    instrlist_meta_preinsert(ilist, where, instr);

    /* Store size in memory ref */
    opnd1 = OPND_CREATE_MEMPTR(reg2, offsetof(mem_ref_t, size));
    /* drutil_opnd_mem_size_in_bytes handles OP_enter */
    opnd2 = OPND_CREATE_INT32(drutil_opnd_mem_size_in_bytes(ref, where));
    instr = INSTR_CREATE_mov_st(drcontext, opnd1, opnd2);
    instrlist_meta_preinsert(ilist, where, instr);

    /* For 64-bit, we can't use a 64-bit immediate so we split pc into two halves.
     * We could alternatively load it into reg1 and then store reg1.
     * We use a convenience routine that does the two-step store for us.
     */
    opnd1 = OPND_CREATE_MEMPTR(reg2, offsetof(mem_ref_t, pc));
    instrlist_insert_mov_immed_ptrsz(drcontext, (ptr_int_t) pc, opnd1,
                                     ilist, where, NULL, NULL);

    /* Increment reg value by pointer size using lea instr */
    opnd1 = opnd_create_reg(reg2);
    opnd2 = opnd_create_base_disp(reg2, DR_REG_NULL, 0,
                                  sizeof(mem_ref_t),
                                  OPSZ_lea);
    instr = INSTR_CREATE_lea(drcontext, opnd1, opnd2);
    instrlist_meta_preinsert(ilist, where, instr);

    /* Update the data->buf_ptr */
    drmgr_insert_read_tls_field(drcontext, tls_index, ilist, where, reg1);
    opnd1 = OPND_CREATE_MEMPTR(reg1, offsetof(per_thread_t, buf_ptr));
    opnd2 = opnd_create_reg(reg2);
    instr = INSTR_CREATE_mov_st(drcontext, opnd1, opnd2);
    instrlist_meta_preinsert(ilist, where, instr);

    /* we use lea + jecxz trick for better performance
     * lea and jecxz won't disturb the eflags, so we won't insert
     * code to save and restore application's eflags.
     */
    /* lea [reg2 + -buf_end] => reg2 */
    opnd1 = opnd_create_reg(reg1);
    opnd2 = OPND_CREATE_MEMPTR(reg1, offsetof(per_thread_t, buf_end));
    instr = INSTR_CREATE_mov_ld(drcontext, opnd1, opnd2);
    instrlist_meta_preinsert(ilist, where, instr);
    opnd1 = opnd_create_reg(reg2);
    opnd2 = opnd_create_base_disp(reg1, reg2, 1, 0, OPSZ_lea);
    instr = INSTR_CREATE_lea(drcontext, opnd1, opnd2);
    instrlist_meta_preinsert(ilist, where, instr);

    /* jecxz call */
    opnd1 = opnd_create_instr(call);
    instr = INSTR_CREATE_jecxz(drcontext, opnd1);
    instrlist_meta_preinsert(ilist, where, instr);

    /* jump restore to skip clean call */
    opnd1 = opnd_create_instr(restore);
    instr = INSTR_CREATE_jmp(drcontext, opnd1);
    instrlist_meta_preinsert(ilist, where, instr);

    /* clean call */
    /* We jump to lean procedure which performs full context switch and
     * clean call invocation. This is to reduce the code cache size.
     */
    instrlist_meta_preinsert(ilist, where, call);

    /* mov restore DR_REG_XCX */
    opnd1 = opnd_create_reg(reg2);
    /* this is the return address for jumping back from lean procedure */
    opnd2 = opnd_create_instr(restore);
    /* We could use instrlist_insert_mov_instr_addr(), but with a register
     * destination we know we can use a 64-bit immediate.
     */
    instr = INSTR_CREATE_mov_imm(drcontext, opnd1, opnd2);
    instrlist_meta_preinsert(ilist, where, instr);

    /* jmp code_cache */
    opnd1 = opnd_create_pc(code_cache);
    instr = INSTR_CREATE_jmp(drcontext, opnd1);
    instrlist_meta_preinsert(ilist, where, instr);

    /* Restore scratch registers */
    instrlist_meta_preinsert(ilist, where, restore);

    dr_restore_reg(drcontext, ilist, where, reg2, SPILL_SLOT_3);
    dr_restore_reg(drcontext, ilist, where, reg1, SPILL_SLOT_2);
}

static void
instrument_bb(void *drcontext, instrlist_t *ilist, instr_t *where, user_data_t *ud)
{
    instr_t *instr, *call, *restore;
    opnd_t opnd1, opnd2;
    app_pc pc;
    reg_t reg2 = DR_REG_XCX, reg1 = DR_REG_XBX;
    app_pc code_cache;

    if (where != ud->first_instr) return;

    instr_t* last_instr = instrlist_last_app(ilist);
    app_pc last_pc = instr_get_app_pc(last_instr);
    uint len_last_instr = instr_length(drcontext, last_instr);

    /* https://github.com/DynamoRIO/dynamorio/blob/release_6_2_0/core/arch/x86/instr.c#L292 */
    switch (instr_get_opcode(last_instr)) {
        case OP_call:
        case OP_call_ind:
        case OP_call_far:
        case OP_call_far_ind:
            len_last_instr |= (LINK_CALL << LINK_SHIFT_FIELD);
            break;
        case OP_ret:
        case OP_ret_far:
        case OP_iret:
            len_last_instr |= (LINK_RETURN << LINK_SHIFT_FIELD);
            break;
        case OP_int:
        case OP_int3:
        case OP_into:
        default:
            len_last_instr |= (LINK_JMP << LINK_SHIFT_FIELD);
    }

    code_cache = codecache_get();
    pc = instr_get_app_pc(where);

    call  = INSTR_CREATE_label(drcontext);
    restore = INSTR_CREATE_label(drcontext);

    dr_save_reg(drcontext, ilist, where, reg1, SPILL_SLOT_2);
    dr_save_reg(drcontext, ilist, where, reg2, SPILL_SLOT_3);

    drmgr_insert_read_tls_field(drcontext, tls_index, ilist, where, reg2);

    /* Load data->buf_ptr into reg2 */
    opnd1 = opnd_create_reg(reg2);
    opnd2 = OPND_CREATE_MEMPTR(reg2, offsetof(per_thread_t, buf_ptr));
    instr = INSTR_CREATE_mov_ld(drcontext, opnd1, opnd2);
    instrlist_meta_preinsert(ilist, where, instr);

    /* Store kind */
    opnd1 = OPND_CREATE_MEM32(reg2, offsetof(mem_ref_t, kind));
    opnd2 = OPND_CREATE_INT32(KIND_BB);
    instr = INSTR_CREATE_mov_imm(drcontext, opnd1, opnd2);
    instrlist_meta_preinsert(ilist, where, instr);

    /* Store last pc */
    opnd1 = OPND_CREATE_MEMPTR(reg2, offsetof(mem_ref_t, addr));
    opnd2 = OPND_CREATE_INT32(last_pc);
    instr = INSTR_CREATE_mov_st(drcontext, opnd1, opnd2);
    instrlist_meta_preinsert(ilist, where, instr);

    /* Store about last instr */
    opnd1 = OPND_CREATE_MEMPTR(reg2, offsetof(mem_ref_t, size));
    opnd2 = OPND_CREATE_INT32(len_last_instr);
    instr = INSTR_CREATE_mov_st(drcontext, opnd1, opnd2);
    instrlist_meta_preinsert(ilist, where, instr);

    /* For 64-bit, we can't use a 64-bit immediate so we split pc into two halves.
     * We could alternatively load it into reg1 and then store reg1.
     * We use a convenience routine that does the two-step store for us.
     */
    opnd1 = OPND_CREATE_MEMPTR(reg2, offsetof(mem_ref_t, pc));
    instrlist_insert_mov_immed_ptrsz(drcontext, (ptr_int_t) pc, opnd1,
                                     ilist, where, NULL, NULL);

    /* Increment reg value by pointer size using lea instr */
    opnd1 = opnd_create_reg(reg2);
    opnd2 = opnd_create_base_disp(reg2, DR_REG_NULL, 0,
                                  sizeof(mem_ref_t),
                                  OPSZ_lea);
    instr = INSTR_CREATE_lea(drcontext, opnd1, opnd2);
    instrlist_meta_preinsert(ilist, where, instr);

    /* Update the data->buf_ptr */
    drmgr_insert_read_tls_field(drcontext, tls_index, ilist, where, reg1);
    opnd1 = OPND_CREATE_MEMPTR(reg1, offsetof(per_thread_t, buf_ptr));
    opnd2 = opnd_create_reg(reg2);
    instr = INSTR_CREATE_mov_st(drcontext, opnd1, opnd2);
    instrlist_meta_preinsert(ilist, where, instr);

    /* we use lea + jecxz trick for better performance
     * lea and jecxz won't disturb the eflags, so we won't insert
     * code to save and restore application's eflags.
     */
    /* lea [reg2 + -buf_end] => reg2 */
    opnd1 = opnd_create_reg(reg1);
    opnd2 = OPND_CREATE_MEMPTR(reg1, offsetof(per_thread_t, buf_end));
    instr = INSTR_CREATE_mov_ld(drcontext, opnd1, opnd2);
    instrlist_meta_preinsert(ilist, where, instr);
    opnd1 = opnd_create_reg(reg2);
    opnd2 = opnd_create_base_disp(reg1, reg2, 1, 0, OPSZ_lea);
    instr = INSTR_CREATE_lea(drcontext, opnd1, opnd2);
    instrlist_meta_preinsert(ilist, where, instr);

    /* jecxz call */
    opnd1 = opnd_create_instr(call);
    instr = INSTR_CREATE_jecxz(drcontext, opnd1);
    instrlist_meta_preinsert(ilist, where, instr);

    /* jump restore to skip clean call */
    opnd1 = opnd_create_instr(restore);
    instr = INSTR_CREATE_jmp(drcontext, opnd1);
    instrlist_meta_preinsert(ilist, where, instr);

    /* clean call */
    /* We jump to lean procedure which performs full context switch and
     * clean call invocation. This is to reduce the code cache size.
     */
    instrlist_meta_preinsert(ilist, where, call);

    /* mov restore DR_REG_XCX */
    opnd1 = opnd_create_reg(reg2);
    /* this is the return address for jumping back from lean procedure */
    opnd2 = opnd_create_instr(restore);
    /* We could use instrlist_insert_mov_instr_addr(), but with a register
     * destination we know we can use a 64-bit immediate.
     */
    instr = INSTR_CREATE_mov_imm(drcontext, opnd1, opnd2);
    instrlist_meta_preinsert(ilist, where, instr);

    /* jmp code_cache */
    opnd1 = opnd_create_pc(code_cache);
    instr = INSTR_CREATE_jmp(drcontext, opnd1);
    instrlist_meta_preinsert(ilist, where, instr);

    /* Restore scratch registers */
    instrlist_meta_preinsert(ilist, where, restore);

    dr_restore_reg(drcontext, ilist, where, reg2, SPILL_SLOT_3);
    dr_restore_reg(drcontext, ilist, where, reg1, SPILL_SLOT_2);

    // instrlist_disassemble(drcontext, tag, bb, STDERR);
}

static bool
opc_is_stringop_loop(uint opc)
{
    return (opc == OP_rep_ins || opc == OP_rep_outs || opc == OP_rep_movs ||
            opc == OP_rep_stos || opc == OP_rep_lods || opc == OP_rep_cmps ||
            opc == OP_repne_cmps || opc == OP_rep_scas || opc == OP_repne_scas);
}

static void
instrument_stringop_loop(void *drcontext, instrlist_t *ilist, instr_t *where)
{
    instr_t *instr;
    opnd_t opnd1, opnd2;
    app_pc pc;
    reg_t reg2 = DR_REG_XCX, reg1 = DR_REG_XBX;
    pc = instr_get_app_pc(where);

    dr_save_reg(drcontext, ilist, where, reg1, SPILL_SLOT_2);

    /* read *data ptr into reg1 xbx */
    drmgr_insert_read_tls_field(drcontext, tls_index, ilist, where, reg1);

    /* Store reg2 xcx into data->loop_xcx into reg2 */
    opnd1 = OPND_CREATE_MEMPTR(reg1, offsetof(per_thread_t, loop_xcx));
    opnd2 = opnd_create_reg(reg2);
    instr = INSTR_CREATE_mov_st(drcontext, opnd1, opnd2);
    instrlist_meta_preinsert(ilist, where, instr);

    /* For 64-bit, we can't use a 64-bit immediate so we split pc into two halves.
     * We could alternatively load it into reg1 and then store reg1.
     * We use a convenience routine that does the two-step store for us.
     */
    opnd1 = OPND_CREATE_MEMPTR(reg1, offsetof(per_thread_t, loop_pc));
    instrlist_insert_mov_immed_ptrsz(drcontext, (ptr_int_t) pc, opnd1,
                                     ilist, where, NULL, NULL);

    /* Restore scratch registers */
    dr_restore_reg(drcontext, ilist, where, reg1, SPILL_SLOT_2);

    // instrlist_disassemble(drcontext, tag, bb, STDERR);
}

static void
instrument_stringop_loop_stop(void *drcontext, instrlist_t *ilist, instr_t *where)
{
    instr_t *instr, *call, *restore;
    opnd_t opnd1, opnd2;
    reg_t reg2 = DR_REG_XCX, reg1 = DR_REG_XBX, reg3 = DR_REG_XDX;
    app_pc code_cache;

    code_cache = codecache_get();
    call  = INSTR_CREATE_label(drcontext);
    restore = INSTR_CREATE_label(drcontext);

    dr_save_reg(drcontext, ilist, where, reg1, SPILL_SLOT_2);
    dr_save_reg(drcontext, ilist, where, reg2, SPILL_SLOT_3);
    dr_save_reg(drcontext, ilist, where, reg3, SPILL_SLOT_4);

    /* Save ecx register to ebx */
    opnd1 = opnd_create_reg(reg1);
    opnd2 = opnd_create_reg(reg2);
    instr = XINST_CREATE_move(drcontext, opnd1, opnd2);
    instrlist_meta_preinsert(ilist, where, instr);

    /* Load per_thread into reg2 ecx */
    drmgr_insert_read_tls_field(drcontext, tls_index, ilist, where, reg2);

    /* Save reg2 ecx register into reg3 edx */
    opnd1 = opnd_create_reg(reg3);
    opnd2 = opnd_create_reg(reg2);
    instr = XINST_CREATE_move(drcontext, opnd1, opnd2);
    instrlist_meta_preinsert(ilist, where, instr);

    /* Load data->buf_ptr into reg2 */
    opnd1 = opnd_create_reg(reg2);
    opnd2 = OPND_CREATE_MEMPTR(reg2, offsetof(per_thread_t, buf_ptr));
    instr = INSTR_CREATE_mov_ld(drcontext, opnd1, opnd2);
    instrlist_meta_preinsert(ilist, where, instr);

    /* Set kind */
    opnd1 = OPND_CREATE_MEM32(reg2, offsetof(mem_ref_t, kind));
    opnd2 = OPND_CREATE_INT32(KIND_LOOP);
    instr = INSTR_CREATE_mov_imm(drcontext, opnd1, opnd2);
    instrlist_meta_preinsert(ilist, where, instr);

    /* Store counter reg 1 xbx in memory ref's size */
    opnd1 = OPND_CREATE_MEMPTR(reg2, offsetof(mem_ref_t, size));
    opnd2 = opnd_create_reg(reg1);
    instr = INSTR_CREATE_mov_st(drcontext, opnd1, opnd2);
    instrlist_meta_preinsert(ilist, where, instr);

    /* Load loop_xcx into reg 1 xbx */
    opnd1 = opnd_create_reg(reg1);
    opnd2 = OPND_CREATE_MEMPTR(reg3, offsetof(per_thread_t, loop_xcx));
    instr = INSTR_CREATE_mov_ld(drcontext, opnd1, opnd2);
    instrlist_meta_preinsert(ilist, where, instr);

    /* Store latest xcx value into memory ref's address */
    opnd1 = OPND_CREATE_MEMPTR(reg2, offsetof(mem_ref_t, addr));
    opnd2 = opnd_create_reg(reg1);
    instr = INSTR_CREATE_mov_st(drcontext, opnd1, opnd2);
    instrlist_meta_preinsert(ilist, where, instr);

    /* Load loop_pc into reg 1 xbx */
    opnd1 = opnd_create_reg(reg1);
    opnd2 = OPND_CREATE_MEMPTR(reg3, offsetof(per_thread_t, loop_pc));
    instr = INSTR_CREATE_mov_ld(drcontext, opnd1, opnd2);
    instrlist_meta_preinsert(ilist, where, instr);

    /* Store loop pc into memory ref's pc */
    opnd1 = OPND_CREATE_MEMPTR(reg2, offsetof(mem_ref_t, pc));
    opnd2 = opnd_create_reg(reg1);
    instr = INSTR_CREATE_mov_st(drcontext, opnd1, opnd2);
    instrlist_meta_preinsert(ilist, where, instr);

    /* Increment reg value by pointer size using lea instr */
    opnd1 = opnd_create_reg(reg2);
    opnd2 = opnd_create_base_disp(reg2, DR_REG_NULL, 0,
                                  sizeof(mem_ref_t),
                                  OPSZ_lea);
    instr = INSTR_CREATE_lea(drcontext, opnd1, opnd2);
    instrlist_meta_preinsert(ilist, where, instr);

    /* Update the data->buf_ptr */
    drmgr_insert_read_tls_field(drcontext, tls_index, ilist, where, reg1);

    opnd1 = OPND_CREATE_MEMPTR(reg1, offsetof(per_thread_t, buf_ptr));
    opnd2 = opnd_create_reg(reg2);
    instr = INSTR_CREATE_mov_st(drcontext, opnd1, opnd2);
    instrlist_meta_preinsert(ilist, where, instr);

    /* we use lea + jecxz trick for better performance
     * lea and jecxz won't disturb the eflags, so we won't insert
     * code to save and restore application's eflags.
     */
    /* lea [reg2 + -buf_end] => reg2 */
    opnd1 = opnd_create_reg(reg1);
    opnd2 = OPND_CREATE_MEMPTR(reg1, offsetof(per_thread_t, buf_end));
    instr = INSTR_CREATE_mov_ld(drcontext, opnd1, opnd2);
    instrlist_meta_preinsert(ilist, where, instr);
    opnd1 = opnd_create_reg(reg2);
    opnd2 = opnd_create_base_disp(reg1, reg2, 1, 0, OPSZ_lea);
    instr = INSTR_CREATE_lea(drcontext, opnd1, opnd2);
    instrlist_meta_preinsert(ilist, where, instr);

    /* jecxz call */
    opnd1 = opnd_create_instr(call);
    instr = INSTR_CREATE_jecxz(drcontext, opnd1);
    instrlist_meta_preinsert(ilist, where, instr);

    /* jump restore to skip clean call */
    opnd1 = opnd_create_instr(restore);
    instr = INSTR_CREATE_jmp(drcontext, opnd1);
    instrlist_meta_preinsert(ilist, where, instr);

    /* clean call */
    /* We jump to lean procedure which performs full context switch and
     * clean call invocation. This is to reduce the code cache size.
     */
    instrlist_meta_preinsert(ilist, where, call);

    /* mov restore DR_REG_XCX */
    opnd1 = opnd_create_reg(reg2);
    /* this is the return address for jumping back from lean procedure */
    opnd2 = opnd_create_instr(restore);
    /* We could use instrlist_insert_mov_instr_addr(), but with a register
     * destination we know we can use a 64-bit immediate.
     */
    instr = INSTR_CREATE_mov_imm(drcontext, opnd1, opnd2);
    instrlist_meta_preinsert(ilist, where, instr);

    /* jmp code_cache */
    opnd1 = opnd_create_pc(code_cache);
    instr = INSTR_CREATE_jmp(drcontext, opnd1);
    instrlist_meta_preinsert(ilist, where, instr);

    /* Restore scratch registers */
    instrlist_meta_preinsert(ilist, where, restore);

    dr_restore_reg(drcontext, ilist, where, reg3, SPILL_SLOT_4);
    dr_restore_reg(drcontext, ilist, where, reg2, SPILL_SLOT_3);
    dr_restore_reg(drcontext, ilist, where, reg1, SPILL_SLOT_2);

    // instrlist_disassemble(drcontext, tag, bb, STDERR);
}

static dr_emit_flags_t
event_bb_app2app(void *drcontext, void *tag, instrlist_t *bb,
                 bool for_trace, bool translating, OUT void **user_data)
{
    per_thread_t *thd_data = drmgr_get_tls_field(drcontext, tls_index);
    user_data_t *ud = (user_data_t *)dr_thread_alloc(drcontext, sizeof(user_data_t));

    instr_t *first_instr = instrlist_first(bb);
    app_pc pc = instr_get_app_pc(first_instr);
    module_data_t* mod = dr_lookup_module(pc);

    ud->first_instr = NULL;
    if (is_from_exe(pc, true) || is_dynamic_code(pc)) {
        ud->first_instr = first_instr;
    }
    ud->loop_stop_pc = (app_pc)0;

    *user_data = (void *)ud;

#if 0
    if (!drutil_expand_rep_string(drcontext, bb)) {
        DR_ASSERT(false);
        /* in release build, carry on: we'll just miss per-iter refs */
    }
#endif

    return DR_EMIT_DEFAULT;
}

static dr_emit_flags_t
event_bb_instru2instru(void *drcontext, void *tag, instrlist_t *bb, bool for_trace,
                       bool translating, void *user_data)
{
    dr_thread_free(drcontext, user_data, sizeof(user_data_t));
    return DR_EMIT_DEFAULT;
}

static dr_emit_flags_t
event_bb_analysis(void *drcontext,
    void *tag, instrlist_t *bb, bool for_trace, bool translating, void *user_data)
{
    per_thread_t *thd_data = drmgr_get_tls_field(drcontext, tls_index);
    // user_data_t *ud = (user_data_t *)user_data;

    if (!for_trace && !translating && !thd_data->dump_mcontext)
        dump_thread_mcontext(drcontext);

#if 0
    instr_t *first_instr = instrlist_first(bb);
    app_pc pc = instr_get_app_pc(first_instr);
    module_data_t* mod = dr_lookup_module(pc);

    *user_data = NULL;

    if (is_from_exe(pc, true)) {
        *user_data = first_instr;
    } else if (is_dynamic_code(pc)) {
        *user_data = first_instr;
    }
#endif
    return DR_EMIT_DEFAULT;
}

static dr_emit_flags_t
event_bb_insert(void *drcontext, void *tag, instrlist_t *bb, instr_t *instr,
                      bool for_trace, bool translating, void *user_data)
{
    user_data_t *ud = (user_data_t *)user_data;

    if (ud->first_instr) {
        uint opc = instr_get_opcode(instr);
        app_pc pc = instr_get_app_pc(instr);

#if WITH_BBTRACE
        instrument_bb(drcontext, bb, instr, ud);
#endif

        if (enable_memtrace) {
            if (ud->loop_stop_pc == pc) {
                instrument_stringop_loop_stop(drcontext, bb, instr);
                ud->loop_stop_pc = (app_pc)0;
            }
            if (opc_is_stringop_loop(opc)) {
                instr_t *next = instr_get_next_app(instr);
                ud->loop_stop_pc = instr_get_app_pc(next);
                instrument_stringop_loop(drcontext, bb, instr);
            }

            opnd_t ref;
            int i;

            if (instr_reads_memory(instr)) {
                for (i = 0; i < instr_num_srcs(instr); i++) {
                    ref = instr_get_src(instr, i);
                    if (opnd_is_memory_reference(ref)) {
                        instrument_mem(drcontext, bb, instr, ref, false);
                    }
                }
            }
            if (instr_writes_memory(instr)) {
                for (i = 0; i < instr_num_dsts(instr); i++) {
                    ref = instr_get_dst(instr, i);
                    if (opnd_is_memory_reference(ref)) {
                        instrument_mem(drcontext, bb, instr, ref, true);
                    }
                }
            }
        }

#if WITH_APPCALL
        /* instrument calls and returns -- ignore far calls/rets */
#if 0
        if (instr_is_call_direct(instr)) {
            if (is_from_exe(instr_get_app_pc(instr), false)) {
                dr_insert_call_instrumentation(drcontext, bb, instr, (app_pc)at_call);
            }
        }
        else
#endif
          // TODO: check only when there is base/index regs
        if (instr_is_call_indirect(instr)) {
            dr_insert_mbr_instrumentation(drcontext, bb, instr, (app_pc)at_call_ind,
                                   SPILL_SLOT_1);
        }
#if 0
        else
        if (instr_is_return(instr)) {
            if (is_from_exe(instr_get_app_pc(instr), false)) {
                dr_insert_mbr_instrumentation(drcontext, bb, instr, (app_pc)at_return,
                                          SPILL_SLOT_1);
            }
        }
#endif
#endif
    }

    return DR_EMIT_DEFAULT;
}


/* clean_call dumps the memory reference info to the log file */
static void
clean_call(void)
{
    void *drcontext = dr_get_current_drcontext();
    dump_data(drcontext);
}

void
dump_data(void *drcontext)
{
    per_thread_t *thd_data = drmgr_get_tls_field(drcontext, tls_index);
    size_t count = (size_t)(thd_data->buf_ptr - thd_data->buf_base);

    if (thd_data->dump_f != INVALID_FILE) {
        dr_write_file(thd_data->dump_f, thd_data->buf_base, count);
    }

    thd_data->buf_ptr = thd_data->buf_base;
}

void
dump_symbol_data(buf_symbol_t *p_buf_item)
{
    void *drcontext = dr_get_current_drcontext();
    thread_id_t thread_id = dr_get_thread_id(drcontext);
    per_thread_t *thd_data = drmgr_get_tls_field(drcontext, tls_index);

    DR_ASSERT(6 * sizeof(mem_ref_t) == sizeof(buf_symbol_t));

    if ((ptr_int_t)(thd_data->buf_ptr + sizeof(buf_symbol_t)) >= -thd_data->buf_end)
        dump_data(drcontext);
    *(buf_symbol_t*)thd_data->buf_ptr = *p_buf_item;
    thd_data->buf_ptr += sizeof(buf_symbol_t);
}

void
dump_event_data(buf_event_t *p_buf_item)
{
    void *drcontext = dr_get_current_drcontext();
    thread_id_t thread_id = dr_get_thread_id(drcontext);
    per_thread_t *thd_data = drmgr_get_tls_field(drcontext, tls_index);

    DR_ASSERT(sizeof(mem_ref_t) == sizeof(buf_event_t));

    if ((ptr_int_t)(thd_data->buf_ptr + sizeof(buf_event_t)) >= -thd_data->buf_end)
        dump_data(drcontext);
    *(buf_event_t*)thd_data->buf_ptr = *p_buf_item;
    thd_data->buf_ptr += sizeof(buf_event_t);
}

void
add_dynamic_codes(void* start, void *end)
{
    range_t *range = dr_global_alloc(sizeof(range_t));
    range->start = start;
    range->end = end;
    drvector_append(&vec_dynamic_codes, range);

    if (rng_dynamic_codes.start == 0 || range->start < rng_dynamic_codes.start)
      rng_dynamic_codes.start = range->start;
    if (rng_dynamic_codes.end == 0 || range->end > rng_dynamic_codes.end)
      rng_dynamic_codes.end = range->end;
}

static void
free_range(void* range)
{
    dr_global_free(range, sizeof(range_t));
}

file_t
get_info_file() {
  return info_file;
}

char* set_dump_path(client_id_t id, dr_time_t* start_time)
{
    const char *app_name = dr_get_application_name();
    dr_snprintf(dump_path, sizeof(dump_path),
        "%s.%s.%04d%02d%02d-%02d%02d%02d",
        dr_get_client_path(id), app_name,
        start_time->year, start_time->month, start_time->day,
        start_time->hour, start_time->minute, start_time->second
        );
    return dump_path;
}

void
bbtrace_init(client_id_t id, bool is_enable_memtrace)
{
    char path[MAXIMUM_PATH];
    dr_time_t start_time;
    dr_get_time(&start_time);

    enable_memtrace = is_enable_memtrace;

    const char *app_name = dr_get_application_name();

    dr_snprintf(dump_path, sizeof(dump_path),
        "%s.%s.%04d%02d%02d-%02d%02d%02d",
        dr_get_client_path(id), app_name,
        start_time.year, start_time.month, start_time.day,
        start_time.hour, start_time.minute, start_time.second
        );

    dr_snprintf(path, sizeof(path), "%s.txt", dump_path);

    info_file = dr_open_file(path, DR_FILE_WRITE_OVERWRITE | DR_FILE_ALLOW_LARGE);

    drmgr_init();
    drutil_init();
    drwrap_init();
    drwrap_set_global_flags(DRWRAP_NO_FRILLS | DRWRAP_FAST_CLEANCALLS);

    winapi_init();
    synchro_init();

    tls_index = drmgr_register_tls_field();
    DR_ASSERT(tls_index != -1);

    codecache_init(clean_call, DR_REG_XCX);
    drvector_init(&vec_dynamic_codes, 10, false, free_range);
    memset(&rng_dynamic_codes, 0, sizeof(range_t));

    drmgr_register_thread_init_event(event_thread_init);
    drmgr_register_thread_exit_event(event_thread_exit);
    drmgr_register_bb_instrumentation_ex_event(event_bb_app2app,
        event_bb_analysis, event_bb_insert, event_bb_instru2instru, NULL);
    drmgr_register_module_load_event(event_module_load);
    drmgr_register_module_unload_event(event_module_unload);
    drmgr_register_exception_event(event_exception);

    app_exe = dr_get_main_module();
}

void
bbtrace_exit(void)
{
    dr_free_module_data(app_exe);

    drmgr_unregister_exception_event(event_exception);
    drmgr_unregister_module_unload_event(event_module_unload);
    drmgr_unregister_module_load_event(event_module_load);
    drmgr_unregister_bb_instrumentation_ex_event(
                event_bb_app2app, event_bb_analysis, event_bb_insert,
                event_bb_instru2instru);
    drmgr_unregister_thread_exit_event(event_thread_exit);
    drmgr_unregister_thread_init_event(event_thread_init);

    drvector_delete(&vec_dynamic_codes);
    codecache_exit();

    drmgr_unregister_tls_field(tls_index);

    synchro_exit();
    winapi_exit();

    drwrap_exit();
    drutil_exit();
    drmgr_exit();

    if (info_file != INVALID_FILE) {
        dr_close_file(info_file);
    }
}
