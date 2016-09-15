#include "bbtrace_core.h"

const char *
bbtrace_log_filename(uint count)
{
	static char filename[32];
	if (count > 0)
		dr_snprintf(filename, sizeof(filename), "trace.log.%d", count);
	else
		dr_snprintf(filename, sizeof(filename), "trace.log");
	return filename;
}

const char *
bbtrace_formatinfo_module(module_data_t *mod) 
{
	static char info[256];
	const char *mod_name = dr_module_preferred_name(mod);

	dr_snprintf(info, sizeof(info),
		"{\"module_name\":\"%s\","
		"\"module_start\":\""PFX"\","
		"\"module_end\":\""PFX"\","
		"\"module_entry\":\""PFX"\"}",
		mod_name, mod->start, mod->end, mod->entry_point);

	return info;
}

const char *
bbtrace_formatinfo_symbol(dr_symbol_export_t *sym, app_pc mod_start, app_pc func_entry)
{
	static char info[256];

	dr_snprintf(info, sizeof(info),
        "{\"symbol_entry\":\""PFX"\","
        "\"module_start_ref\":\""PFX"\","
        "\"symbol_name\":\"%s\","
        "\"symbol_ordinal\":%d}",
        func_entry, mod_start, sym->name, sym->ordinal);

	return info;
}

const char*
bbtrace_formatinfo_block(app_pc block_entry, app_pc mod_start, uint length)
{
	static char info[256];

	dr_snprintf(info, sizeof(info),
	    "{\"block_entry\":\""PFX"\","
	    "\"module_start_ref\":\""PFX"\","
	    "\"block_end\":\""PFX"\"}",
	    block_entry, mod_start, block_entry+length);

	return info;
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