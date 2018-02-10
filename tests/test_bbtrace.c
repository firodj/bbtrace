#include "bbtrace_core.h"

static app_pc exe_start;
static thread_id_t main_thread = 0;

void test_bbtrace_log_filename()
{
	const char *actual = NULL;

	actual = bbtrace_log_filename(0);
	dr_fprintf(STDERR, "%s\n", actual);

	actual = bbtrace_log_filename(10);
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
  exe.full_path = "C:\\Windows\\WinSxS\\x86_microsoft.windows.common-controls_6595b64144ccf1df_6.0.7601.17514_none_41e6975e2bd6f2b2\\comctl32.dll";

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
	char actual[256];

	bbtrace_formatinfo_block(actual, sizeof(actual),
      (app_pc)0x4000, (app_pc)0x4400,
      (app_pc)0x3000, (app_pc)0x43FA, "nop");
	dr_fprintf(STDERR, "%s\n", actual);
}

void test_bbtrace_formatinfo_symbol_import() {
	dr_symbol_import_t sym;

	const char *actual = NULL;
    const char *modname = "SPEED2.EXE";

	memset(&sym, 0, sizeof(sym));

	sym.modname = "advapi32.dll";
    sym.name = "RegQueryValueExA";
	sym.ordinal = 99;

	actual = bbtrace_formatinfo_symbol_import(&sym, modname);
	dr_fprintf(STDERR, "%s\n", actual);
}

void test_bbtrace_formatinfo_exception() {
	dr_exception_t excpt;
	const char *actual = NULL;

	memset(&excpt, 0, sizeof(excpt));

    EXCEPTION_RECORD record;
	memset(&record, 0, sizeof(record));

    record.ExceptionCode = 0x40010006;
    record.ExceptionAddress  = (void*)0x7764c41f;
    record.ExceptionInformation[1] = 0x0018fd34;
    excpt.record = &record;

	actual = bbtrace_formatinfo_exception(&excpt);
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
  bbtrace_init();

  per_thread_t *tls_field = create_bbtrace_thread_data(drcontext);
  size_t written;

  dr_fprintf(STDERR, "pos=%u, ts=%u\n", tls_field->pos, tls_field->ts);
  dr_fprintf(STDERR, "filling thread data (> 4G) ...\n");
  for(uint64 i=0; i < (5*1024*1024*256); i++) {
    byte *data = (byte*)tls_field + sizeof(per_thread_t);
    app_pc *pc_data = (app_pc*)data;

    pc_data[tls_field->pos++] = (app_pc)(i % 256);
    if (tls_field->pos >= BUF_TOTAL) {
        written = bbtrace_dump_thread_data(tls_field);
    }
  }
  dr_fprintf(STDERR, "last written = %u\n", written);

  written = bbtrace_dump_thread_data(tls_field);
  dr_fprintf(STDERR, "flushed written = %u\n", written);

  bbtrace_shutdown();
}

void test_bbtrace_escape_string() {
  char out[256];
  bbtrace_escape_string("D:\\With \"Quote\"", out, 256);
  dr_fprintf(STDERR, "escaped = %s\n", out);
}

void test_bbtrace_append_string() {
  char out[256];
  char *next = out;
  next = bbtrace_append_string(next, "satu", 4, true);
  next = bbtrace_append_string(next, "dua", 3, false);
  dr_fprintf(STDERR, "output = %s\n", out);
}

void test_bbtrace_append_integer() {
  char out[256];
  char *next = out;
  next = bbtrace_append_integer(next, 12345678, true);
  next = bbtrace_append_integer(next, 0, false);
  dr_fprintf(STDERR, "output = %s\n", out);
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

	dr_fprintf(STDERR, "[ ] test_bbtrace_formatinfo_symbol_import:\n");
	test_bbtrace_formatinfo_symbol_import();

	dr_fprintf(STDERR, "[ ] test_bbtrace_formatinfo_exception:\n");
	test_bbtrace_formatinfo_exception();

	dr_fprintf(STDERR, "[ ] test_instrlist_app_length:\n");
	test_instrlist_app_length(drcontext);

#if 0
	dr_fprintf(STDERR, "[ ] test_bbtrace_dump_thread_data:\n");
	test_bbtrace_dump_thread_data(drcontext);
#endif

	dr_fprintf(STDERR, "[ ] test_bbtrace_escape_string:\n");
	test_bbtrace_escape_string();

	dr_fprintf(STDERR, "[ ] test_bbtrace_append_string:\n");
	test_bbtrace_append_string();

	dr_fprintf(STDERR, "[ ] test_bbtrace_append_integer:\n");
	test_bbtrace_append_integer();

	dr_fprintf(STDERR, "[ ] DONE testing.\n");
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
