#include "dr_api.h"
#include "drmgr.h"
#include "drutil.h"
#include "drwrap.h"
#include "droption.h"

#include "bbtrace.h"

static droption_t<bool> enable_memtrace(
    DROPTION_SCOPE_CLIENT, "memtrace", false,
    "Enable memory access trace",
    "Record all memory read/write access, looping counter and stops");

void
event_exit(void)
{
    bbtrace_exit();
}

DR_EXPORT void
dr_client_main(client_id_t id, int argc, const char *argv[])
{
    dr_set_client_name("DynamoRIO bbtrace",
        "http://dynamorio.org/issues");

    /* Options */
    if (!droption_parser_t::parse_argv(DROPTION_SCOPE_CLIENT, argc, argv, NULL, NULL))
        dr_printf("WARNING: Unable to parse_argv!\n");

    bbtrace_init(id, enable_memtrace.get_value());

    dr_register_exit_event(event_exit);

    dr_enable_console_printing();

    dr_printf("Option: memtrace: %d\n", enable_memtrace.get_value());
}
