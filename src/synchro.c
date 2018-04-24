#include "synchro.h"
#include "hashtable.h"
#include "datatypes.h"

static hashtable_t cs_table;
static hashtable_t hmutex_table;
static hashtable_t hevent_table;
static void* hevent_lock;

void
synchro_init(void)
{
    hashtable_init(&cs_table, 6, HASH_INTPTR, false);
    hashtable_init(&hmutex_table, 6, HASH_INTPTR, false);
    hashtable_init(&hevent_table, 6, HASH_INTPTR, false);
    hevent_lock = dr_mutex_create();
}

void
synchro_exit(void)
{
    dr_mutex_destroy(hevent_lock);
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
    void *lock = 0;

    hashtable_t *table = &hmutex_table;

    if (kind == SYNC_EVENT) {
        table = &hevent_table;
        lock = hevent_lock;
    }

    if (lock) dr_mutex_lock(lock);

    uint count = (uint)hashtable_lookup(table, hmutex);
    hashtable_add_replace(table, hmutex, (void*) ++count);

    if (lock) dr_mutex_unlock(lock);

    return count;
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
