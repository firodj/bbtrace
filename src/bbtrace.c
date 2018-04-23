#include "dr_api.h"
#include "drmgr.h"
#include "drutil.h"
#include "drwrap.h"
#include "bbtrace.h"

void
event_exit(void)
{
    bbtrace_exit();

    drwrap_exit();
    drutil_exit();
    drmgr_exit();
}

DR_EXPORT void
dr_client_main(client_id_t id, int argc, const char *argv[])
{
    dr_set_client_name("DynamoRIO bbtrace",
        "http://dynamorio.org/issues");

    drmgr_init();
    drutil_init();
    drwrap_init();

    bbtrace_init(id);

    drwrap_set_global_flags(DRWRAP_NO_FRILLS | DRWRAP_FAST_CLEANCALLS);

    dr_register_exit_event(event_exit);

    dr_enable_console_printing();
}
