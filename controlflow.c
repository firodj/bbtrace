#include "dr_api.h"
#include <stddef.h>
#include "drmgr.h"
#include "drwrap.h"
#include "drx.h"

static app_pc exe_start;
static thread_id_t main_thread = 0;
static void *mutex;
static int tls_idx;
static file_t trace_file;
static file_t info_file;

#define BUF_TOTAL 1024*1024

typedef struct {	
	uint pos;
} per_thread_t;

static void dump_data(app_pc* pc_data, uint count)
{
	dr_write_file(trace_file, pc_data, sizeof(app_pc) * count);
}

static void lib_entry(void *wrapcxt, INOUT void **user_data)
{
    const char *sym_name = (const char *) *user_data;
    const char *mod_name = NULL;
    app_pc func = drwrap_get_func(wrapcxt);
    module_data_t *mod;
    app_pc ret_addr = NULL;
    void *drcontext = drwrap_get_drcontext(wrapcxt);
    thread_id_t thread_id = dr_get_thread_id(drcontext);
    per_thread_t *tls_field = (per_thread_t *) drmgr_get_tls_field(drcontext, tls_idx);
    bool from_exe = false;
    byte *data = (byte*)tls_field + sizeof(per_thread_t);
    app_pc *pc_data = (app_pc*)data;

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

    pc_data[tls_field->pos] = func;
    tls_field->pos++;
    if (tls_field->pos >= BUF_TOTAL) {    	
    	dump_data(pc_data, tls_field->pos);
    	tls_field->pos = 0;
    }

    /*
    mod = dr_lookup_module(func);
    if (mod) {
    	mod_name = dr_module_preferred_name(mod);    	
    }

    dr_printf("CALL:%s!%s@"PFX" RET:"PFX" TID:"PFX"\n", mod_name, sym_name, func, ret_addr);

    if (mod) {
    	dr_free_module_data(mod);
    }
    */
}

static void iterate_exports(const module_data_t *mod, bool add)
{
	const char *mod_name = dr_module_preferred_name(mod);
    dr_symbol_export_iterator_t *exp_iter =
        dr_symbol_export_iterator_start(mod->handle);

    dr_fprintf(info_file, "dll:\n\tname:%s\n\tstart:"PFX"\n\tend:"PFX"\n\tentry:"PFX"\n\texports:\n", mod_name, mod->start, mod->end, mod->entry_point);

    while (dr_symbol_export_iterator_hasnext(exp_iter)) {
        dr_symbol_export_t *sym = dr_symbol_export_iterator_next(exp_iter);
        app_pc func = NULL;
        if (sym->is_code)
            func = sym->addr;
        if (func != NULL) {
            if (add) {                
                drwrap_wrap_ex(func, lib_entry, NULL, (void *) sym->name, 0);

                dr_fprintf(info_file, "\t\t"PFX":\n\t\t\tname:%s\n\t\t\tordinal:"PFX"\n", func, sym->name, sym->ordinal);
            } else {                
                drwrap_unwrap(func, lib_entry, NULL);
            }
        }
    }
    dr_symbol_export_iterator_stop(exp_iter);
}

static void event_module_load(void *drcontext, const module_data_t *mod,
	bool loaded)
{
    if (mod->start != exe_start)
        iterate_exports(mod, true/*add*/);
}

static void event_module_unload(void *drcontext, const module_data_t *mod)
{
    if (mod->start != exe_start)
        iterate_exports(mod, false/*remove*/);
}

static void event_thread_init(void *drcontext)
{
	thread_id_t thread_id = dr_get_thread_id(drcontext);
		
	size_t tls_field_size = sizeof(per_thread_t) + (sizeof(uint) * BUF_TOTAL);
	per_thread_t *tls_field = (per_thread_t *)dr_thread_alloc(drcontext, tls_field_size);

    if (main_thread == 0) {
        main_thread = thread_id;
        dr_printf("MAIN-THREAD:"PFX"\n", main_thread);
    }
    else {
   		dr_printf("THREAD:"PFX"\n", thread_id);
    }

     /* create an instance of our data structure for this thread */
	
	/* store it in the slot provided in the drcontext */
	drmgr_set_tls_field(drcontext, tls_idx, tls_field);
	memset(tls_field, 0, tls_field_size);
}

static void event_thread_exit(void *drcontext)
{
	thread_id_t thread_id = dr_get_thread_id(drcontext);
	per_thread_t *tls_field = (per_thread_t *) drmgr_get_tls_field(drcontext, tls_idx);
	byte *data = (byte*)tls_field + sizeof(per_thread_t);
    app_pc *pc_data = (app_pc*)data;

	dr_printf("EXIT-THREAD:"PFX"\n", thread_id);

	dump_data(pc_data, tls_field->pos);

	size_t tls_field_size = sizeof(per_thread_t) + (sizeof(uint) * BUF_TOTAL);
	dr_thread_free(drcontext, tls_field, tls_field_size);
}

static dr_emit_flags_t event_bb_analysis(void *drcontext,
	void *tag, instrlist_t *bb, bool for_trace, bool translating, OUT void **user_data)
{
	instr_t *instr;
	app_pc src;

	instr = instrlist_first(bb);
	src = instr_get_app_pc(instr);

	module_data_t* mod = dr_lookup_module(src);
	*user_data = NULL;
	if (mod) {
		if (mod->start == exe_start) {
			*user_data = (void *) instr;
		}
		dr_free_module_data(mod);
	}
	
	return DR_EMIT_DEFAULT;
}


static void clean_call(uint count)
{
	void *drcontext = dr_get_current_drcontext();
	per_thread_t *tls_field = (per_thread_t *) drmgr_get_tls_field(drcontext, tls_idx);
    byte *data = (byte*)tls_field + sizeof(per_thread_t);
    
    dump_data((app_pc*)data, count);
}

static dr_emit_flags_t event_bb_insert(void *drcontext, void *tag, 
	instrlist_t *bb, instr_t *instr, bool for_trace, bool translating, void *user_data)
{
	if (instr == (instr_t*)user_data/*first instr*/) {
		app_pc start = instr_get_app_pc(instr);
		per_thread_t *tls_field = (per_thread_t *) drmgr_get_tls_field(drcontext, tls_idx);
		instr_t *goto_skip = INSTR_CREATE_label(drcontext);

		dr_save_arith_flags(drcontext, bb, instr, SPILL_SLOT_1);
		dr_save_reg(drcontext, bb, instr, DR_REG_XCX, SPILL_SLOT_2);
		dr_save_reg(drcontext, bb, instr, DR_REG_XBX, SPILL_SLOT_3);
		
		drmgr_insert_read_tls_field(drcontext, tls_idx, bb, instr, DR_REG_XBX);
		// dr_using_all_private_caches() ?

		instrlist_meta_preinsert(bb, instr,
			INSTR_CREATE_mov_ld(drcontext,
				opnd_create_reg(DR_REG_XCX),
				OPND_CREATE_MEM32(DR_REG_XBX, offsetof(per_thread_t, pos)))
			);

		instrlist_meta_preinsert(bb, instr,
			INSTR_CREATE_mov_st(drcontext,
				opnd_create_base_disp(DR_REG_XBX, DR_REG_XCX, sizeof(uint), sizeof(per_thread_t), OPSZ_4),
				OPND_CREATE_INT32(start))
			);

		instrlist_meta_preinsert(bb, instr,
			INSTR_CREATE_inc(drcontext,	
				opnd_create_reg(DR_REG_XCX))
			);

		instrlist_meta_preinsert(bb, instr,
			INSTR_CREATE_cmp(drcontext, 
				opnd_create_reg(DR_REG_XCX),
				OPND_CREATE_INT32(BUF_TOTAL))
			);

		instrlist_meta_preinsert(bb, instr,
			INSTR_CREATE_jcc(drcontext, OP_jb, opnd_create_instr(goto_skip))
			);

		dr_insert_clean_call(drcontext, bb, instr, 
			(void *) clean_call,
            false,
            1,
            opnd_create_reg(DR_REG_XCX));

		instrlist_meta_preinsert(bb, instr,
			INSTR_CREATE_xor(drcontext,
				opnd_create_reg(DR_REG_XCX),
				opnd_create_reg(DR_REG_XCX))
			);

		instrlist_meta_preinsert(bb, instr, goto_skip);

		instrlist_meta_preinsert(bb, instr,
			INSTR_CREATE_mov_st(drcontext,
				opnd_create_base_disp(DR_REG_XBX, DR_REG_NULL, 0, offsetof(per_thread_t, pos), OPSZ_4),
				opnd_create_reg(DR_REG_XCX))
			);

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
    dr_close_file(info_file);
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
    info_file = dr_open_file("trace.info", DR_FILE_WRITE_OVERWRITE | DR_FILE_ALLOW_LARGE);
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

    exe = dr_get_main_module();
    if (exe) {
        exe_start = exe->start;
    	exe_name = dr_module_preferred_name(exe);
    	
    	dr_fprintf(info_file, "exe:\n\tname:%s\n\tstart:"PFX"\n\tend:"PFX"\n\tentry:"PFX"\n", exe_name, exe_start, exe->end, exe->entry_point);

    	dr_free_module_data(exe);
    }
}