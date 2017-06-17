#include "bbtrace_core.h"

static app_pc exe_start;
static thread_id_t main_thread = 0;

void test_bbtrace_log_filename()
{
	const char *actual = NULL;
	
	actual = bbtrace_log_filename(0);
	// "trace.log";
	dr_fprintf(STDERR, "%s\n", actual);

	actual = bbtrace_log_filename(10);
	// "trace.log.10";
	dr_fprintf(STDERR, "%s\n", actual);
}

void test_bbtrace_formatinfo_module() {
	module_data_t exe;
	const char *actual = NULL;

	memset(&exe, 0, sizeof(exe));

	exe.start = (app_pc)0x400000;
	exe.end   = (app_pc)0x440000;
	exe.entry_point = (app_pc)0x40a000;
	exe.names.module_name = "notepad.exe";

	actual = bbtrace_formatinfo_module(&exe);
	dr_fprintf(STDERR, "%s\n", actual);
}

void test_bbtrace_formatinfo_symbol() {
	dr_symbol_export_t sym;
	const char *actual = NULL;

	memset(&sym, 0, sizeof(sym));

	sym.name = "GetMaxMin";
	sym.ordinal = 99;

	actual = bbtrace_formatinfo_symbol(&sym, (app_pc)0x30f0, (app_pc)0x40b0);
	dr_fprintf(STDERR, "%s\n", actual);
}

void test_bbtrace_formatinfo_block() {
	const char *actual = NULL;

	actual = bbtrace_formatinfo_block((app_pc)0x4000, (app_pc)0x3000, 12);
	dr_fprintf(STDERR, "%s\n", actual);
}

void test_instrlist_app_length(void *drcontext) {
	uint actual = 0;
	
	instrlist_t* ilist = instrlist_create(drcontext);
	if (NULL == ilist) {
		return;
	}
	
	instrlist_append(ilist,
		 INSTR_CREATE_nop(drcontext));
	instrlist_append(ilist,
		 INSTR_CREATE_xor(drcontext,
		 	opnd_create_reg(DR_REG_XAX),
		 	opnd_create_reg(DR_REG_XAX)));

	actual = instrlist_app_length(drcontext, ilist);

	instrlist_clear_and_destroy(drcontext, ilist);

	dr_fprintf(STDERR, "%d\n", actual);
}

void test_bbtrace_dump_thread_data(void *drcontext) {
  size_t tls_field_size = sizeof(per_thread_t) + (sizeof(app_pc) * BUF_TOTAL);
  per_thread_t *tls_field = (per_thread_t *)dr_thread_alloc(drcontext, tls_field_size);
 
  bbtrace_init();
  bbtrace_dump_thread_data(tls_field);
  bbtrace_shutdown();
}

/*
TEST(oh, ah) {	
	instrlist_t* ilist = instrlist_create(drcontext);
	instr_t* where = NULL;
	uint length = 0;	

	printf("drcontext = "PFX"\n", drcontext);
	//byte opcodes[17*2];
	//byte *end_opcodes;
	ASSERT_FALSE(NULL == ilist);

	instrlist_append(ilist,
		 INSTR_CREATE_ret(drcontext));
	where = instrlist_first_app(ilist);

	dr_save_arith_flags(drcontext, ilist, where, SPILL_SLOT_1);
	dr_save_reg(drcontext, ilist, where, DR_REG_XCX, SPILL_SLOT_2);
	dr_save_reg(drcontext, ilist, where, DR_REG_XBX, SPILL_SLOT_3);

	length = instrlist_length(drcontext, ilist);
	instrlist_clear_and_destroy(drcontext, ilist);

	printf("Length = %d\n", length);
	//end_opcodes = instrlist_encode(drcontext, ilist, opcodes, false);
}
*/

static void run_tests(void *drcontext)
{
	dr_fprintf(STDERR, "[ ] test_bbtrace_log_filename:\n");
	test_bbtrace_log_filename();

	dr_fprintf(STDERR, "[ ] test_bbtrace_formatinfo_module:\n");
	test_bbtrace_formatinfo_module();

	dr_fprintf(STDERR, "[ ] test_bbtrace_formatinfo_symbol:\n");
	test_bbtrace_formatinfo_symbol();

	dr_fprintf(STDERR, "[ ] test_bbtrace_formatinfo_block:\n");
	test_bbtrace_formatinfo_block();

	dr_fprintf(STDERR, "[ ] test_instrlist_app_length:\n");
	test_instrlist_app_length(drcontext);

	dr_fprintf(STDERR, "[ ] test_bbtrace_dump_thread_data:\n");
  test_bbtrace_dump_thread_data(drcontext);
}

static dr_emit_flags_t
bb_event(void *drcontext, void* tag, instrlist_t *bb, bool for_trace, bool translating)
{
	return DR_EMIT_DEFAULT;
}

static void exit_event(void)
{

}

static void
thread_init_event(void *drcontext)
{
	thread_id_t thread_id = dr_get_thread_id(drcontext);

	if (main_thread == 0) main_thread = thread_id;

	if (thread_id == main_thread) {
		run_tests(drcontext);
	}
}

static void
thread_exit_event(void *drcontext)
{

}

DR_EXPORT void dr_client_main(client_id_t id, int argc, const char *argv[])
{
	module_data_t *exe = dr_get_main_module();

	if (exe) {
		exe_start = exe->start;
		dr_free_module_data(exe);
	}

	dr_enable_console_printing();

	dr_register_exit_event(exit_event);
	dr_register_bb_event(bb_event);	
	dr_register_thread_init_event(thread_init_event);
	dr_register_thread_exit_event(thread_exit_event);
}
