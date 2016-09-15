#include "dr_api.h"
#include <stddef.h>
#include "drmgr.h"
#include "drwrap.h"
#include "hashtable.h"
#include <intrin.h>
#include "controlflow.h"

static app_pc exe_start;
static thread_id_t main_thread = 0;
static void *mutex;
static int tls_idx;
static file_t trace_file;
static file_t info_file;

#define BUF_TOTAL 1024*1024
#define MAX_TRACE_LOG 4294967295

typedef struct {    
    uint pos;
    uint64 ts;
    thread_id_t thread;
} per_thread_t;

static uint64 log_size = 0;
static int log_count = 0;
static hashtable_t sym_info_table;

static void dump_check_overflow(size_t request_size)
{
    log_size += request_size;
    if (log_size > MAX_TRACE_LOG)
    {
        char trace_filename[32];
        dr_snprintf(trace_filename, 32, "trace.log.%d", ++log_count);

        dr_close_file(trace_file);
        trace_file = dr_open_file(trace_filename, DR_FILE_WRITE_OVERWRITE | DR_FILE_ALLOW_LARGE);
        log_size -= MAX_TRACE_LOG;
    }
}

static void dump_pkt(void *data, size_t size)
{
    dump_check_overflow(size);
    dr_write_file(trace_file, data, size);
}

static void dump_data(per_thread_t *tls_field)
{
    size_t sz;
    pkt_trace_t pkt_trace;
    app_pc* pc_data = (app_pc*)((byte*)tls_field + sizeof(per_thread_t));
    uint count = tls_field->pos;

    if (!count) return;

    sz = sizeof(app_pc) * count;
    
    pkt_trace.header.code = PKT_CODE_TRACE;
    pkt_trace.header.ts = tls_field->ts;
    pkt_trace.header.thread = tls_field->thread;    
    pkt_trace.size = count;

    dump_check_overflow( sz + sizeof(pkt_trace) );

    dr_write_file(trace_file, &pkt_trace, sizeof(pkt_trace));
    dr_write_file(trace_file, pc_data, sz);

    tls_field->pos = 0;
    tls_field->ts = 0;
}

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
        dump_data(tls_field);
    }

    sym = hashtable_lookup(&sym_info_table, func);
    if (sym) {
        mod = dr_lookup_module(func);
        if (mod) {
            dr_fprintf(info_file, 
                "{\"symbol_entry\":\""PFX"\",\"module_start_ref\":\""PFX"\",\"symbol_name\":\"%s\",\"symbol_ordinal\":%d},\n",
                func, mod->start, sym->name, sym->ordinal);
            dr_free_module_data(mod);
        }
        res = hashtable_remove(&sym_info_table, func);
    }
}

static void iterate_exports(const module_data_t *mod, bool add)
{
	const char *mod_name = dr_module_preferred_name(mod);
    dr_symbol_export_iterator_t *exp_iter =
        dr_symbol_export_iterator_start(mod->handle);

    dr_fprintf(info_file,
            "{\"module_name\":\"%s\",\"module_start\":\""PFX"\",\"module_end\":\""PFX"\",\"module_entry\":\""PFX"\"},\n",
            mod_name, mod->start, mod->end, mod->entry_point);

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
        dr_printf("IMPORT %s!%s@%d\n", sym->modname, sym->name, sym->ordinal);
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

	size_t tls_field_size = sizeof(per_thread_t) + (sizeof(app_pc) * BUF_TOTAL);
	per_thread_t *tls_field = (per_thread_t *)dr_thread_alloc(drcontext, tls_field_size);

    if (main_thread == 0) {
        main_thread = thread_id;
        dr_printf("MAIN-THREAD:"PFX"\n", main_thread);
    }
    else {
   		dr_printf("THREAD:"PFX"\n", thread_id);
    }

	drmgr_set_tls_field(drcontext, tls_idx, tls_field);
	memset(tls_field, 0, tls_field_size);    
    tls_field->thread = thread_id;
}

static void event_thread_exit(void *drcontext)
{    
	per_thread_t *tls_field = (per_thread_t *) drmgr_get_tls_field(drcontext, tls_idx);
    size_t tls_field_size = sizeof(per_thread_t) + (sizeof(app_pc) * BUF_TOTAL);
 
	dr_printf("EXIT-THREAD:"PFX"\n", tls_field->thread);

	dump_data(tls_field);

	dr_thread_free(drcontext, tls_field, tls_field_size);
}


static void clean_call(uint count)
{
    void *drcontext = dr_get_current_drcontext();    

    per_thread_t *tls_field = (per_thread_t *) drmgr_get_tls_field(drcontext, tls_idx);
    
    dump_data(tls_field);
}

static dr_emit_flags_t event_bb_analysis(void *drcontext,
	void *tag, instrlist_t *bb, bool for_trace, bool translating, OUT void **user_data)
{
	instr_t *instr = instrlist_first(bb);
	app_pc src = instr_get_app_pc(instr);
	
	module_data_t* mod = dr_lookup_module(src);
	*user_data = NULL;
	if (mod) {
		if (mod->start == exe_start) {
            uint length = 0;
            instr_t *walk_instr;
            // char dis[512] = {0};

            for (walk_instr  = instrlist_first_app(bb);
                walk_instr != NULL;
                walk_instr = instr_get_next_app(walk_instr)) {
                length += instr_length(drcontext, walk_instr);
            }

            // if (walk_instr = instrlist_last_app(bb))
            //    instr_disassemble_to_buffer(drcontext, walk_instr, dis, 512);

			*user_data = (void *) instr;

            dr_fprintf(info_file,
                "{\"block_entry\":\""PFX"\",\"module_start_ref\":\""PFX"\",\"block_end\":\""PFX"\"},\n",
                src, mod->start, src+length);
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
        instr_t *goto_skip_rdtsc = INSTR_CREATE_label(drcontext);

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

        // xcx ? 0
        instrlist_meta_preinsert(bb, instr,
            INSTR_CREATE_test(drcontext,
                opnd_create_reg(DR_REG_XCX),
                opnd_create_reg(DR_REG_XCX))
            );

        // tls_field->pc_data[xcx] = start
		instrlist_meta_preinsert(bb, instr,
			INSTR_CREATE_mov_st(drcontext,
				opnd_create_base_disp(DR_REG_XBX, DR_REG_XCX, sizeof(uint), sizeof(per_thread_t), OPSZ_4),
				OPND_CREATE_INT32(start))
			);

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
			(void *) clean_call,
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

static void event_exit(void)
{	
    drmgr_unregister_tls_field(tls_idx);

	drwrap_exit();
    drmgr_exit();

    dr_mutex_destroy(mutex);

    dr_close_file(trace_file);

    dr_fprintf(info_file, "{}\n]");
    dr_close_file(info_file);

    hashtable_delete(&sym_info_table);
}

static void
sym_info_entry_free(void *entry)
{   
    dr_global_free(entry, sizeof(dr_symbol_export_t));
}

DR_EXPORT void dr_client_main(client_id_t id, int argc, const char *argv[])
{
	module_data_t *exe;
	const char *exe_name = NULL;

	dr_set_client_name("DrControlFlow", "http://firodj.wordpress.com");

	trace_file = dr_open_file("trace.log", DR_FILE_WRITE_OVERWRITE | DR_FILE_ALLOW_LARGE);    
    if (trace_file == INVALID_FILE) {
        dr_fprintf(STDERR, "Error opening %s\n", "trace.log");        
    }
    info_file = dr_open_file("trace.json", DR_FILE_WRITE_OVERWRITE | DR_FILE_ALLOW_LARGE);
    if (trace_file == INVALID_FILE) {
        dr_fprintf(STDERR, "Error opening %s\n", "trace.info");        
    }

    drmgr_init();
    drwrap_init();

    drwrap_set_global_flags(DRWRAP_NO_FRILLS | DRWRAP_FAST_CLEANCALLS);

	dr_register_exit_event(event_exit);
	drmgr_register_thread_init_event(event_thread_init);
    drmgr_register_thread_exit_event(event_thread_exit);
	
	drmgr_register_bb_instrumentation_event(event_bb_analysis, event_bb_insert, NULL);
	drmgr_register_module_load_event(event_module_load);
    drmgr_register_module_unload_event(event_module_unload);

    dr_enable_console_printing();

    mutex = dr_mutex_create();
    tls_idx = drmgr_register_tls_field();

    hashtable_init_ex(&sym_info_table, 6, HASH_INTPTR, false, false, sym_info_entry_free, NULL, NULL);

    exe = dr_get_main_module();
    dr_fprintf(info_file, "[\n");
    if (exe) {
        exe_start = exe->start;
    	exe_name = dr_module_preferred_name(exe);

    	dr_fprintf(info_file,
            "{\"module_name\":\"%s\",\"module_start\":\""PFX"\",\"module_end\":\""PFX"\",\"module_entry\":\""PFX"\"},\n",
            exe_name, exe_start, exe->end, exe->entry_point);

    	dr_free_module_data(exe);
    }
}