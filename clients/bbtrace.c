#include "dr_api.h"
#include <stddef.h>
#include "drmgr.h"
#include "drwrap.h"
#include "hashtable.h"
#include <intrin.h>
#include "bbtrace_core.h"

static app_pc exe_start;
static thread_id_t main_thread = 0;
static int tls_idx;
static file_t info_file;

static hashtable_t sym_info_table;

static void lib_entry(void *wrapcxt, INOUT void **user_data)
{
    dr_symbol_export_t *sym = NULL;
    const char *mod_name = NULL;
    app_pc func = drwrap_get_func(wrapcxt);
    module_data_t *mod;
    app_pc ret_addr = NULL;
    void *drcontext = drwrap_get_drcontext(wrapcxt);

    per_thread_t *tls_field = (per_thread_t *) drmgr_get_tls_field(drcontext, tls_idx);
    bool from_exe = false;
    byte *data = (byte*)tls_field + sizeof(per_thread_t);
    app_pc *pc_data = (app_pc*)data;
    bool res = false;

    DR_TRY_EXCEPT(drcontext, {
        ret_addr = drwrap_get_retaddr(wrapcxt);
    }, { /* EXCEPT */
        ret_addr = NULL;
    });

    if (ret_addr) {
        mod = dr_lookup_module(ret_addr);
        if (mod) {
            from_exe = mod->start == exe_start;
            dr_free_module_data(mod);
        }
    }

    if (!from_exe) return;

    pc_data[tls_field->pos++] = func;
    if (tls_field->pos >= BUF_TOTAL) {
        bbtrace_dump_thread_data(tls_field);
    }

    sym = hashtable_lookup(&sym_info_table, func);
    if (sym) {
        mod = dr_lookup_module(func);
        if (mod) {
#ifdef XXX
            const char *info = bbtrace_formatinfo_symbol(sym, mod->start, func);
            dr_fprintf(info_file, info);
#else
            char info[256];
            char *info_end = bbtrace_formatinfo_symbol2(info, sym, mod->start, func);
            dr_write_file(info_file, info, info_end - info);
#endif
            dr_free_module_data(mod);
        }
        res = hashtable_remove(&sym_info_table, func);
    }
}

static void iterate_exports(const module_data_t *mod, bool add)
{
    const char *mod_name = dr_module_preferred_name(mod);
#ifdef XXX
    const char *info = bbtrace_formatinfo_module(mod);
    dr_fprintf(info_file, info);
#else
    char info[512];
    char *info_end = bbtrace_formatinfo_module2(info, mod);
    dr_write_file(info_file, info, info_end - info);
#endif

    dr_symbol_export_iterator_t *exp_iter =
        dr_symbol_export_iterator_start(mod->handle);

    while (dr_symbol_export_iterator_hasnext(exp_iter)) {
        dr_symbol_export_t *sym = dr_symbol_export_iterator_next(exp_iter);
        app_pc func = NULL;
        if (sym->is_code)
            func = sym->addr;
        if (func) {
            if (add) {
                dr_symbol_export_t *sym_entry = dr_global_alloc(sizeof(dr_symbol_export_t));
                sym_entry->name = sym->name;
                sym_entry->addr = sym->addr;
                sym_entry->ordinal = sym->ordinal;
                hashtable_add(&sym_info_table, func, sym_entry);

                drwrap_wrap(func, lib_entry, NULL);
            } else {
                drwrap_unwrap(func, lib_entry, NULL);

                hashtable_remove(&sym_info_table, func);
            }
        }
    }
    dr_symbol_export_iterator_stop(exp_iter);
}

static void iterate_imports(const module_data_t *mod)
{
    const char *mod_name = dr_module_preferred_name(mod);

    dr_symbol_import_iterator_t *imp_iter =
        dr_symbol_import_iterator_start(mod->handle, NULL);
    while (dr_symbol_import_iterator_hasnext(imp_iter)) {
        dr_symbol_import_t *sym = dr_symbol_import_iterator_next(imp_iter);
#ifdef XXX
        const char *info = bbtrace_formatinfo_symbol_import(sym, mod_name);
        dr_fprintf(info_file, info);
#else
        char info[256];
        char *info_end = bbtrace_formatinfo_symbol_import2(info, sym);
        dr_write_file(info_file, info, info_end - info);
#endif
    }
    dr_symbol_import_iterator_stop(imp_iter);
}

static void event_module_load(void *drcontext, const module_data_t *mod,
    bool loaded)
{
    if (mod->start != exe_start)
        iterate_exports(mod, true/*add*/);
    else
        iterate_imports(mod);
}

static void event_module_unload(void *drcontext, const module_data_t *mod)
{
    if (mod->start != exe_start)
        iterate_exports(mod, false/*remove*/);
}

static void event_thread_init(void *drcontext)
{
    thread_id_t thread_id = dr_get_thread_id(drcontext);

    per_thread_t *tls_field = create_bbtrace_thread_data(drcontext);

    if (main_thread == 0) {
        main_thread = thread_id;
        dr_printf("MAIN-THREAD:"PFX"\n", main_thread);
    }
    else {
        dr_printf("THREAD:"PFX"\n", thread_id);
    }

    drmgr_set_tls_field(drcontext, tls_idx, tls_field);
    tls_field->thread = thread_id;
}

static void event_thread_exit(void *drcontext)
{
    per_thread_t *tls_field = (per_thread_t *) drmgr_get_tls_field(drcontext, tls_idx);
    size_t tls_field_size = sizeof(per_thread_t) + (sizeof(app_pc) * BUF_TOTAL);

    dr_printf("EXIT-THREAD:"PFX"\n", tls_field->thread);

    bbtrace_dump_thread_data(tls_field);

    dr_thread_free(drcontext, tls_field, tls_field_size);
}


static void clean_call_of_dump_data(uint count)
{
    void *drcontext = dr_get_current_drcontext();

    per_thread_t *tls_field = (per_thread_t *) drmgr_get_tls_field(drcontext, tls_idx);

    bbtrace_dump_thread_data(tls_field);
}

static dr_emit_flags_t event_bb_analysis(void *drcontext,
    void *tag, instrlist_t *bb, bool for_trace, bool translating, OUT void **user_data)
{
    char info[256];
    char disasm[128];

    instr_t *instr = instrlist_first(bb);
    app_pc src = instr_get_app_pc(instr);
    module_data_t* mod = dr_lookup_module(src);

    *user_data = NULL;

    if (mod) {
        if (mod->start == exe_start) {
            instr_t* last_instr = instrlist_last_app(bb);
            app_pc last_pc = instr_get_app_pc(last_instr);
            app_pc end = last_pc + instr_length(drcontext, last_instr);
            instr_disassemble_to_buffer(drcontext, last_instr, disasm, sizeof(disasm));
#ifdef XXX
            bbtrace_formatinfo_block(info, sizeof(info), src, mod->start, end, last_pc, (const char*)disasm);
            dr_fprintf(info_file, info);
#else
            char *info_end = bbtrace_formatinfo_block2(info, src, mod->start, end, last_pc, (const char*)disasm);
            dr_write_file(info_file, info, info_end - info);
#endif

            *user_data = (void *)instr;
        }
        dr_free_module_data(mod);
    }

    return DR_EMIT_DEFAULT;
}

static dr_emit_flags_t event_bb_insert(void *drcontext, void *tag,
    instrlist_t *bb, instr_t *instr, bool for_trace, bool translating, void *user_data)
{
    if (instr == (instr_t*)user_data/*first instr*/) {
        app_pc start = instr_get_app_pc(instr);
        instr_t *goto_skip = INSTR_CREATE_label(drcontext);
#ifdef BBTRACE_RDTSC
        instr_t *goto_skip_rdtsc = INSTR_CREATE_label(drcontext);
#endif
        // per_thread_t *tls_field = (per_thread_t *) drmgr_get_tls_field(drcontext, tls_idx);
        // dr_using_all_private_caches()?

        dr_save_arith_flags(drcontext, bb, instr, SPILL_SLOT_1);
        dr_save_reg(drcontext, bb, instr, DR_REG_XCX, SPILL_SLOT_2);
        dr_save_reg(drcontext, bb, instr, DR_REG_XBX, SPILL_SLOT_3);

        drmgr_insert_read_tls_field(drcontext, tls_idx, bb, instr, DR_REG_XBX);

        // xcx = tls_field->pos
        instrlist_meta_preinsert(bb, instr,
            INSTR_CREATE_mov_ld(drcontext,
                opnd_create_reg(DR_REG_XCX),
                OPND_CREATE_MEM32(DR_REG_XBX, offsetof(per_thread_t, pos)))
            );

#ifdef BBTRACE_RDTSC
        // xcx ? 0
        instrlist_meta_preinsert(bb, instr,
            INSTR_CREATE_test(drcontext,
                opnd_create_reg(DR_REG_XCX),
                opnd_create_reg(DR_REG_XCX))
            );
#endif

        // tls_field->pc_data[xcx] = start
        instrlist_meta_preinsert(bb, instr,
            INSTR_CREATE_mov_st(drcontext,
                opnd_create_base_disp(DR_REG_XBX, DR_REG_XCX, sizeof(uint), sizeof(per_thread_t), OPSZ_4),
                OPND_CREATE_INT32(start))
            );

#ifdef BBTRACE_RDTSC
        // if (xcx != 0) goto skip_rdtsc
        instrlist_meta_preinsert(bb, instr,
            INSTR_CREATE_jcc(drcontext, OP_jnz, opnd_create_instr(goto_skip_rdtsc))
            );

        dr_save_reg(drcontext, bb, instr, DR_REG_XAX, SPILL_SLOT_4);
        dr_save_reg(drcontext, bb, instr, DR_REG_XDX, SPILL_SLOT_5);

        // xdx:xax = rdtsc
        instrlist_meta_preinsert(bb, instr,
            INSTR_CREATE_rdtsc(drcontext)
            );

        // tls_field[ts] = xdx:xax
        instrlist_meta_preinsert(bb, instr,
            INSTR_CREATE_mov_st(drcontext,
                OPND_CREATE_MEM32(DR_REG_XBX, offsetof(per_thread_t, ts)),
                opnd_create_reg(DR_REG_XAX))
            );

        instrlist_meta_preinsert(bb, instr,
            INSTR_CREATE_mov_st(drcontext,
                OPND_CREATE_MEM32(DR_REG_XBX, offsetof(per_thread_t, ts)+4),
                opnd_create_reg(DR_REG_XDX))
            );

        dr_restore_reg(drcontext, bb, instr, DR_REG_XAX, SPILL_SLOT_4);
        dr_restore_reg(drcontext, bb, instr, DR_REG_XDX, SPILL_SLOT_5);

        // label skip_rdtsc:
        instrlist_meta_preinsert(bb, instr, goto_skip_rdtsc);
#endif

        // xcx++
        instrlist_meta_preinsert(bb, instr,
            INSTR_CREATE_inc(drcontext,
                opnd_create_reg(DR_REG_XCX))
            );

        // xcx ? BUF_TOTAL
        instrlist_meta_preinsert(bb, instr,
            INSTR_CREATE_cmp(drcontext,
                opnd_create_reg(DR_REG_XCX),
                OPND_CREATE_INT32(BUF_TOTAL))
            );

        // tls_field->pos = xcx
        instrlist_meta_preinsert(bb, instr,
            INSTR_CREATE_mov_st(drcontext,
                OPND_CREATE_MEM32(DR_REG_XBX, offsetof(per_thread_t, pos)),
                opnd_create_reg(DR_REG_XCX))
            );

        // if (xcx < BUF_TOTAL) goto skip
        instrlist_meta_preinsert(bb, instr,
            INSTR_CREATE_jcc(drcontext, OP_jb, opnd_create_instr(goto_skip))
            );

        dr_insert_clean_call(drcontext, bb, instr,
            (void *) clean_call_of_dump_data,
            false,
            1,
            opnd_create_reg(DR_REG_XCX));

        // label skip:
        instrlist_meta_preinsert(bb, instr, goto_skip);

        dr_restore_reg(drcontext, bb, instr, DR_REG_XCX, SPILL_SLOT_2);
        dr_restore_reg(drcontext, bb, instr, DR_REG_XBX, SPILL_SLOT_3);
        dr_restore_arith_flags(drcontext, bb, instr, SPILL_SLOT_1);

        // instrlist_disassemble(drcontext, tag, bb, STDERR);
    }
    return DR_EMIT_DEFAULT;
}

static bool
event_exception(void *drcontext, dr_exception_t *excpt)
{
#ifdef XXX
    const char *info = bbtrace_formatinfo_exception(excpt);
    dr_fprintf(info_file, info);
#else
    char info[256];
    char *info_end = bbtrace_formatinfo_exception2(info, excpt);
    dr_write_file(info_file, info, info_end - info);
#endif

    return true;
}

static void event_exit(void)
{
    drmgr_unregister_exception_event(event_exception);

    drmgr_unregister_tls_field(tls_idx);

    drwrap_exit();
    drmgr_exit();

    bbtrace_shutdown();

#ifdef XXX
    dr_fprintf(info_file, "{}\n]");
#endif
    dr_close_file(info_file);

    hashtable_delete(&sym_info_table);
}

static void
sym_info_entry_free(void *entry)
{
    dr_global_free(entry, sizeof(dr_symbol_export_t));
}

DR_EXPORT void
dr_client_main(client_id_t id, int argc, const char *argv[])
{
    module_data_t *exe;

    char info_filename[256];

    dr_snprintf(info_filename, sizeof(info_filename),
#ifdef XXX
        "%s.info",
#else
        "%s.csv",
#endif
        bbtrace_log_filename(0)
    );

    dr_set_client_name("Code Flow Record 'BBTrace'", "https://github.com/firodj/bbtrace");

    drmgr_init();
    drwrap_init();

    drwrap_set_global_flags(DRWRAP_NO_FRILLS | DRWRAP_FAST_CLEANCALLS);

    dr_register_exit_event(event_exit);
    drmgr_register_thread_init_event(event_thread_init);
    drmgr_register_thread_exit_event(event_thread_exit);

    drmgr_register_bb_instrumentation_event(event_bb_analysis, event_bb_insert, NULL);
    drmgr_register_module_load_event(event_module_load);
    drmgr_register_module_unload_event(event_module_unload);

    drmgr_register_exception_event(event_exception);

    tls_idx = drmgr_register_tls_field();

    hashtable_init_ex(&sym_info_table, 6, HASH_INTPTR, false, false, sym_info_entry_free, NULL, NULL);

    dr_enable_console_printing();

    bbtrace_init();

    info_file = dr_open_file(info_filename, DR_FILE_WRITE_OVERWRITE | DR_FILE_ALLOW_LARGE);
    if (info_file == INVALID_FILE) {
        dr_fprintf(STDERR, "Error opening %s\n", info_filename);
    } else {
        dr_printf("Info File: %s\n", info_filename);
    }

    exe = dr_get_main_module();
#ifdef XXX
    dr_fprintf(info_file, "[\n");
#endif
    if (exe) {
#ifdef XXX
        const char *info = bbtrace_formatinfo_module(exe);
        dr_fprintf(info_file, info);
#else
        char info[512];
        char *info_end = bbtrace_formatinfo_module2(info, exe);
        dr_write_file(info_file, info, info_end - info);
#endif
        exe_start = exe->start;
        dr_free_module_data(exe);
    }
}
