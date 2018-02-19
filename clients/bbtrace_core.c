#include "bbtrace_core.h"
#include <intrin.h>
#include "branchlut2.h"

#pragma intrinsic(__rdtsc)

static uint64 g_log_size;
static uint g_log_count;
static void *g_dump_mutex;
static file_t g_trace_file;

size_t
bbtrace_escape_string(const char *str, char *out, size_t n)
{
  size_t j=0;
  if (str) {
    for (size_t i=0; str[i] && j<n-2; i++) {
      if (str[i] == '\\') {
        out[j++] = '\\';
        out[j++] = '\\';
      } else
      if (str[i] == '"') {
        out[j++] = '\\';
        out[j++] = '"';
      } else {
        out[j++] = str[i];
      }
    }
  }
  out[j++] = '\0';
  return j;
}

char *
bbtrace_append_string(char *dst, const char *val, bool comma)
{
    char *result = dst;
    if (val) {
      *result++ = '"';
      for (const char *src = val; *src != '\0'; src++) {
        if (*src == '"') *result++ = '"';
        *result++ = *src;
      }
      *result++ = '"';
    }
    if (comma) *result++ = ',';
    return result;
}

char *
bbtrace_append_integer(char *dst, uint val, bool comma)
{
    char *result = dst;
    result = u32toa_branchlut2(val, result);
    if (comma) *result++ = ',';
    return result;
}

char *
bbtrace_append_hex(char *dst, uint val, bool comma)
{
    char *result = dst;
    *result++ = '0';
    *result++ = 'x';
    char *stop = result;
    result += 8;
    char *current = result;
    while (current > stop) {
      current--;
      if (val) {
        const digit = val & 0xF;
        if (digit < 10) {
          *current = '0' + digit;
        } else {
          *current = 'a' + digit - 10;
        }
        val = val >> 4;
      } else {
        *current = '0';
      }
    }
    if (comma) *result++ = ',';
    return result;
}

const char *
bbtrace_log_filename(uint count)
{
	static char filename[32];
  const char *app_name = dr_get_application_name();
	if (count > 0)
		dr_snprintf(filename, sizeof(filename), "bbtrace.%s.log.%04d", app_name, count);
	else
		dr_snprintf(filename, sizeof(filename), "bbtrace.%s.log", app_name);
	return filename;
}

const char *
bbtrace_formatinfo_module(const module_data_t *mod)
{
	static char info[1024];
	const char *mod_name = dr_module_preferred_name(mod);
	char path[512];

	bbtrace_escape_string(mod->full_path, path, sizeof(path));

	dr_snprintf(info, sizeof(info),
		"{\n"
		"\t\"module_name\":\"%s\",\n"
		"\t\"module_start\":\""PFX"\",\n"
		"\t\"module_end\":\""PFX"\",\n"
		"\t\"module_entry\":\""PFX"\",\n"
		"\t\"module_path\":\"%s\"\n"
		"},",
		mod_name, mod->start, mod->end, mod->entry_point,
		path);

	return info;
}

const char *
bbtrace_formatinfo_symbol(dr_symbol_export_t *sym, app_pc mod_start, app_pc func_entry)
{
	static char info[256];

	dr_snprintf(info, sizeof(info),
        "{\n"
        "\t\"symbol_entry\":\""PFX"\",\n"
        "\t\"module_start_ref\":\""PFX"\",\n"
        "\t\"symbol_name\":\"%s\",\n"
        "\t\"symbol_ordinal\":%d\n"
        "},",
        func_entry, mod_start, sym->name, sym->ordinal);

	return info;
}

const char *
bbtrace_formatinfo_symbol_import(dr_symbol_import_t *sym, const char *mod_name)
{
	static char info[256];

	dr_snprintf(info, sizeof(info),
        "{\n"
        "\t\"module_name\":\"%s\",\n"
        "\t\"import_module_name\":\"%s\",\n"
        "\t\"symbol_name\":\"%s\",\n"
        "\t\"symbol_ordinal\":%d\n"
        "},",
        mod_name, sym->modname, sym->name, sym->ordinal);

	return info;
}

int
bbtrace_formatinfo_block(char *info, size_t info_sz, app_pc block_entry, app_pc mod_start, app_pc block_end, app_pc last_pc, const char * last_asm)
{
	return dr_snprintf(info, info_sz,
		"{\n"
		"\t\"block_entry\":\""PFX"\",\n"
		"\t\"module_start_ref\":\""PFX"\",\n"
		"\t\"block_end\":\""PFX"\",\n"
		"\t\"last_pc\":\""PFX"\",\n"
    "\t\"last_asm\":\"%s\"\n"
		"},",
		block_entry, mod_start, block_end, last_pc, last_asm);
}

const char *
bbtrace_formatinfo_exception(dr_exception_t *excpt)
{
	static char info[256];

  void *fault_address = (void *)excpt->record->ExceptionInformation[1];
	dr_snprintf(info, sizeof(info),
      "{\n"
      "\t\"exception_code\":\""PFX"\",\n"
      "\t\"exception_address\":\""PFX"\",\n"
      "\t\"fault_address\":\""PFX"\"\n"
      "},",
      excpt->record->ExceptionCode,
      excpt->record->ExceptionAddress,
      fault_address);

  return info;
}

char *
bbtrace_formatinfo_module2(char *buf, const module_data_t *mod)
{
  const char *mod_name = dr_module_preferred_name(mod);
  char *next = buf;

  next = bbtrace_append_string(next, "module", true);
  next = bbtrace_append_hex(next, (uint) mod->entry_point, true);
  next = bbtrace_append_hex(next, (uint) mod->start, true);
  next = bbtrace_append_hex(next, (uint) mod->end, true);
  next = bbtrace_append_string(next, mod_name, true);
  next = bbtrace_append_string(next, mod->full_path, false);
  *next++ = '\n';
  return next;
}

char *
bbtrace_formatinfo_symbol2(char *buf, dr_symbol_export_t *sym, app_pc mod_start, app_pc func_entry)
{
  char *next = buf;

  next = bbtrace_append_string(next, "symbol", true);
  next = bbtrace_append_hex(next, (uint) func_entry, true);
  next = bbtrace_append_hex(next, (uint) mod_start, true);
  next = bbtrace_append_integer(next, (uint) sym->ordinal, true);
  next = bbtrace_append_string(next, sym->name, false);
  *next++ = '\n';
  return next;
}

char *
bbtrace_formatinfo_symbol_import2(char *buf, dr_symbol_import_t *sym)
{
  char *next = buf;

  next = bbtrace_append_string(next, "import", true);
  next = bbtrace_append_string(next, sym->modname, true);
  next = bbtrace_append_integer(next, (uint) sym->ordinal, true);
  next = bbtrace_append_string(next, sym->name, false);
  *next++ = '\n';
  return next;
}

char *
bbtrace_formatinfo_block2(char *buf, app_pc block_entry, app_pc mod_start, app_pc block_end, app_pc last_pc, const char * last_asm)
{
  char *next = buf;

  next = bbtrace_append_string(next, "block", true);
  next = bbtrace_append_hex(next, (uint) block_entry, true);
  next = bbtrace_append_hex(next, (uint) mod_start, true);
  next = bbtrace_append_hex(next, (uint) block_end, true);
  next = bbtrace_append_hex(next, (uint) last_pc, true);
  next = bbtrace_append_string(next, last_asm, false);
  *next++ = '\n';
  return next;
}

char *
bbtrace_formatinfo_exception2(char *buf, dr_exception_t *excpt)
{
  void *fault_address = (void *)excpt->record->ExceptionInformation[1];
  char *next = buf;

  next = bbtrace_append_string(next, "exception", true);
  next = bbtrace_append_hex(next, (uint) fault_address, true);
  next = bbtrace_append_hex(next, (uint) excpt->record->ExceptionCode, true);
  next = bbtrace_append_hex(next, (uint) excpt->record->ExceptionAddress, false);
  *next++ = '\n';
  return next;
}

size_t
bbtrace_dump_thread_data(per_thread_t *tls_field)
{
    size_t sz;
    pkt_trace_t pkt_trace;
    app_pc* pc_data = (app_pc*)((byte*)tls_field + sizeof(per_thread_t));
    uint count = tls_field->pos;

    if (!count) return 0;

    sz = sizeof(app_pc) * count;

    pkt_trace.header.code = PKT_CODE_TRACE;
    pkt_trace.header.ts = tls_field->ts;
    pkt_trace.header.thread = tls_field->thread;
    pkt_trace.size = count;

    dr_mutex_lock(g_dump_mutex);

    size_t request_size = sz + sizeof(pkt_trace);

    g_log_size += request_size;
    if (g_log_size > MAX_TRACE_LOG)
    {
        const char *trace_filename = bbtrace_log_filename(++g_log_count);

        dr_close_file(g_trace_file);

        g_trace_file = dr_open_file(trace_filename, DR_FILE_WRITE_OVERWRITE | DR_FILE_ALLOW_LARGE);
        if (g_trace_file == INVALID_FILE) {
            dr_fprintf(STDERR, "Error opening %s\n", trace_filename);
        } else {
            dr_printf("Trace File: %s\n", trace_filename);
        }

        g_log_size -= MAX_TRACE_LOG;
    }

    dr_write_file(g_trace_file, &pkt_trace, sizeof(pkt_trace));
    dr_write_file(g_trace_file, pc_data, sz);

    //dr_printf("Dump Trace: %d bytes\n", sz + sizeof(pkt_trace));

    dr_mutex_unlock(g_dump_mutex);

    tls_field->pos = 0;
    tls_field->ts = __rdtsc();

    return request_size;
}

uint
instrlist_app_length(void *drcontext, instrlist_t *ilist)
{
	uint length = 0;
	for (instr_t *walk_instr = instrlist_first_app(ilist);
        walk_instr != NULL;
        walk_instr = instr_get_next_app(walk_instr))
	{
        length += instr_length(drcontext, walk_instr);
    }
    return length;
}

uint
instrlist_length(void *drcontext, instrlist_t *ilist)
{
	uint length = 0;
	for (instr_t *walk_instr = instrlist_first(ilist);
        walk_instr != NULL;
        walk_instr = instr_get_next(walk_instr))
	{
        length += instr_length(drcontext, walk_instr);
    }
    return length;
}

per_thread_t*
create_bbtrace_thread_data(void *drcontext)
{
    size_t tls_field_size = sizeof(per_thread_t) + (sizeof(app_pc) * BUF_TOTAL);
    per_thread_t *tls_field = (per_thread_t *)dr_thread_alloc(drcontext, tls_field_size);
    memset(tls_field, 0, tls_field_size);
    tls_field->ts = __rdtsc();
    return tls_field;
}

void
bbtrace_init()
{
  g_log_size = 0;
  g_log_count = 0;
  g_dump_mutex = dr_mutex_create();

  const char *trace_filename = bbtrace_log_filename(++g_log_count);

  g_trace_file = dr_open_file(trace_filename, DR_FILE_WRITE_OVERWRITE | DR_FILE_ALLOW_LARGE);
  if (g_trace_file == INVALID_FILE) {
      dr_fprintf(STDERR, "Error opening %s\n", trace_filename);
  } else {
      dr_printf("Trace File: %s\n", trace_filename);
  }
}

void
bbtrace_shutdown()
{
  dr_mutex_destroy(g_dump_mutex);
  dr_close_file(g_trace_file);
}
