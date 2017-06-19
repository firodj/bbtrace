#include "bbtrace_core.h"
#include <intrin.h>  
  
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
  out[j++] = 0;
  return j;
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
	static char info[256];
	const char *mod_name = dr_module_preferred_name(mod);
  char path[256];

  bbtrace_escape_string(mod->full_path, path, 256);

	dr_snprintf(info, sizeof(info),
		"{\n"
		"\t\"module_name\":\"%s\",\n"
		"\t\"module_start\":\""PFX"\",\n"
		"\t\"module_end\":\""PFX"\",\n"
		"\t\"module_entry\":\""PFX"\",\n"
		"\t\"module_path\":\"%s\"\n"
		"}",
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
        "}",
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
        "}",
        mod_name, sym->modname, sym->name, sym->ordinal);

	return info;
}

const char*
bbtrace_formatinfo_block(app_pc block_entry, app_pc mod_start, uint length)
{
	static char info[256];

	dr_snprintf(info, sizeof(info),
		"{\n"
		"\t\"block_entry\":\""PFX"\",\n"
		"\t\"module_start_ref\":\""PFX"\",\n"
		"\t\"block_end\":\""PFX"\"\n"
		"}",
		block_entry, mod_start, block_entry+length);

	return info;
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
      "}",
      excpt->record->ExceptionCode, 
      excpt->record->ExceptionAddress,
      fault_address);

  return info;
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
