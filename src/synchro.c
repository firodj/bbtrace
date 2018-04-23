#include "synchro.h"
#include "hashtable.h"
#include "datatypes.h"

static hashtable_t cs_table;
static hashtable_t hmutex_table;
static hashtable_t hevent_table;

void
synchro_init(void)
{
    hashtable_init(&cs_table, 6, HASH_INTPTR, false);
    hashtable_init(&hmutex_table, 6, HASH_INTPTR, false);
    hashtable_init(&hevent_table, 6, HASH_INTPTR, false);
}

void
synchro_exit(void)
{
    hashtable_delete(&hevent_table);
    hashtable_delete(&hmutex_table);
    hashtable_delete(&cs_table);
}

uint
synchro_inc_cs(void *cs)
{
    uint count = (uint)hashtable_lookup(&cs_table, cs);
    hashtable_add_replace(&cs_table, cs, (void*) ++count);
    return count;
}

uint
synchro_inc_hmutex(void *hmutex, uint kind)
{
    hashtable_t *table = &hmutex_table;
    if (kind == SYNC_EVENT) table = &hevent_table;

    uint count = (uint)hashtable_lookup(table, hmutex);
    hashtable_add_replace(table, hmutex, (void*) ++count);
    return count;
}

void
synchro_del_hmutex(void *hmutex)
{
    uint count = (uint)hashtable_lookup(&hmutex_table, hmutex);
    if (count) {
        hashtable_remove(&hmutex_table, hmutex);
    }
}

uint
synchro_kind_hmutex(void *hmutex)
{
    uint count;
    count = (uint)hashtable_lookup(&hmutex_table, hmutex);
    if (count) return SYNC_MUTEX;

    count = (uint)hashtable_lookup(&hevent_table, hmutex);
    if (count) return SYNC_EVENT;

    return 0;
}
