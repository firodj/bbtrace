#include "dr_api.h"
#include "drmgr.h"
#include "drutil.h"
#include "drwrap.h"
#include "bbtrace.h"

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

    bbtrace_init(id);

    dr_register_exit_event(event_exit);

    dr_enable_console_printing();
}
