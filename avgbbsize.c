#include "dr_api.h"

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
}

static void
event_exit(void)
{
	/* empty */
}

static dr_emit_flags_t
event_basic_block(void *drcontext, void *tag, instrlist_t *bb,
				  bool for_trace, bool translating)
{
	/* empty */
	return DR_EMIT_DEFAULT;
}
