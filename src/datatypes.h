#pragma once

#include <stddef.h>

#ifdef WITHOUT_DR
  #include "stdint.h"
  typedef uint64_t uint64;
  typedef uint32_t uint;
  typedef uint reg_t;
  typedef uint app_pc;
#else
  #include "dr_defines.h"
#endif

#define MAX_NUM_MEM_REFS 8192*2
#define MEM_BUF_SIZE (sizeof(mem_ref_t) * MAX_NUM_MEM_REFS)

// Python: for i in xrange(3, -1, -1): print "%X" % (ord('Xyzn'[i])),
#define KIND_NONE 0x00000000
#define KIND_READ 0x64616552
#define KIND_WRITE 0x74697257
#define KIND_EXCEPTION 0x70637845
#define KIND_MODULE 0x6C646F4D
#define KIND_SYMBOL 0x6C6D7953
#define KIND_STRING 0x6E727453
#define KIND_LIB_CALL 0x6C61634C
#define KIND_LIB_RET 0x7465724C
#define KIND_APP_CALL 0x6C616341
#define KIND_APP_RET 0x74657241
#define KIND_THREAD 0x64726854
#define KIND_WNDPROC 0x70646E57
#define KIND_ARGS 0x73677241
#define KIND_BB 0x6B6C6242
#define KIND_LOOP 0x706F6F4C // 'Loop'
// #define KIND_STOP 0x504F5453 // 'Stop' (loop-stop unused)
#define KIND_SYNC 0x636E7953  // 'Sync'

#define SYNC_MUTEX 0x7874754D // 'Mutx'
#define SYNC_EVENT 0x746E7645 // 'Evnt'
#define SYNC_CRITSEC 0x74697243

typedef uint kind_t;

enum {
    LINK_JMP = 0,
    LINK_CALL,
    LINK_RETURN
};

#define LINK_SHIFT_FIELD 8

typedef struct _mem_ref_t {
    uint kind;
    uint addr;
    uint size;
    app_pc pc;
} mem_ref_t; // 16

typedef struct _buf_exception_t {
    uint kind;
    uint fault_address;
    uint code;
    app_pc pc;
} buf_exception_t; // 16

typedef struct _buf_module_t {
    uint kind;
    app_pc entry_point;
    uint start;
    uint end;
    uint shared_dll;
    char name[12];
} buf_module_t; // 2*16

typedef struct _buf_lib_call_t {
    uint kind;
    app_pc func;
    app_pc ret_addr;
    uint arg;
} buf_lib_call_t; // 16

typedef struct _buf_lib_ret_t {
    uint kind;
    app_pc func;
    app_pc ret_addr;
    uint retval;
} buf_lib_ret_t; // 16

typedef struct _buf_string_t {
    uint kind;
    char value[12+ (5*16)];
} buf_string_t; // 6*16

typedef struct _buf_app_call_t {
    uint kind;
    app_pc instr_addr;
    app_pc target_addr;
    reg_t tos;
} buf_app_call_t; // 16

typedef struct _buf_app_ret_t {
    uint kind;
    app_pc instr_addr;
    app_pc target_addr;
    uint unused;
} buf_app_ret_t; // 16

typedef struct _buf_symbol_t {
    uint kind;
    uint shared_dll;
    app_pc func;
    uint ordinal;
    char name[16 * 5];
} buf_symbol_t; // 6*16

typedef struct _buf_event_t {
    uint kind;
    uint params[3];
} buf_event_t; // 16

typedef struct _range_t {
    void* start;
    void* end;
} range_t;
