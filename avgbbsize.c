#include "dr_api.h"

#ifdef WINDOWS
	#define DISPLAY_STRING(msg) dr_messagebox(msg)
#else
	#define DISPLAY_STRING(msg) dr_printf("%s\n", msg)
#endif

typedef struct bb_counts {
	uint64 blocks;
	uint64 total_size;
} bb_counts;

static bb_counts counts_as_built;

void *as_built_lock;

static void
event_exit(void);

static dr_emit_flags_t
event_basic_block(void *drcontext, void *tag, instrlist_t *bb,
				  bool for_trace, bool translating);

DR_EXPORT void
dr_client_main(client_id_t id, int argc, const char *argv[])
{
	/* register events */
	dr_register_exit_event(event_exit);
	dr_register_bb_event(event_basic_block);

	/* initialize lock */
	as_built_lock = dr_mutex_create();
}

static void
event_exit(void)
{
	/* Display results - we must first snpritnf the string as on windows
	 * dr_printf(), dr_messagebox() and dr_fprintf() can't print floats. */
	char msg[512];
	int len;
	len = _snprintf(msg, sizeof(msg)/sizeof(msg[0]),
					"Number of basic blocks built : %"UINT64_FORMAT_CODE"\n"
					"     Average size            : %5.2lf instructions\n",
					counts_as_built.blocks,
					counts_as_built.total_size / (double)counts_as_built.blocks);
	DR_ASSERT(len > 0);
	msg[sizeof(msg)/sizeof(msg[0])-1] = '\0'; /* NUll terminate */
	DISPLAY_STRING(msg);

	/* free mutex */
	dr_mutex_destroy(as_built_lock);
}

static dr_emit_flags_t
event_basic_block(void *drcontext, void *tag, instrlist_t *bb,
				  bool for_trace, bool translating)
{
	uint num_instructions = 0;
	instr_t *instr;

	/* count the number of instructions in this block */
	for (instr = instrlist_first(bb); instr != NULL; instr = instr_get_next(instr)) {
		num_instructions++;
	} 

	/* update the as-built counts */
	dr_mutex_lock(as_built_lock);
	counts_as_built.blocks++;
	counts_as_built.total_size += num_instructions;
	dr_mutex_unlock(as_built_lock);
	return DR_EMIT_DEFAULT;
} 