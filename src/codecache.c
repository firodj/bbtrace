#include "dr_api.h"
#include "codecache.h"

static app_pc code_cache = NULL;

void
codecache_init(void *clean_call, reg_t back)
{
    void         *drcontext;
    instrlist_t  *ilist;
    instr_t      *where;
    byte         *end;

    if (code_cache) return;

    drcontext  = dr_get_current_drcontext();
    code_cache = dr_nonheap_alloc(PAGE_SIZE,
                                  DR_MEMPROT_READ  |
                                  DR_MEMPROT_WRITE |
                                  DR_MEMPROT_EXEC);
    ilist = instrlist_create(drcontext);
    /* The lean procecure simply performs a clean call, and then jump back */
    /* jump back to the DR's code cache */
    where = INSTR_CREATE_jmp_ind(drcontext, opnd_create_reg(back));
    instrlist_meta_append(ilist, where);
    /* clean call */
    dr_insert_clean_call(drcontext, ilist, where, (void *)clean_call, false, 0);
    /* Encodes the instructions into memory and then cleans up. */
    end = instrlist_encode(drcontext, ilist, code_cache, false);
    DR_ASSERT((end - code_cache) < PAGE_SIZE);
    instrlist_clear_and_destroy(drcontext, ilist);
    /* set the memory as just +rx now */
    dr_memory_protect(code_cache, PAGE_SIZE, DR_MEMPROT_READ | DR_MEMPROT_EXEC);
}

void
codecache_exit(void)
{
    dr_nonheap_free(code_cache, PAGE_SIZE);
}

app_pc
codecache_get(void) {
    return code_cache;
}
