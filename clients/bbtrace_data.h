#pragma once

#ifdef _MSC_VER
  #include "dr_defines.h"
#else
  #include "stdint.h"
  typedef uint64_t uint64;
  typedef uint32_t uint;
  typedef uint thread_id_t;
#endif

typedef enum {
	PKT_CODE_TRACE = 1
} pkt_code_t;

#pragma pack(1)
typedef struct {
	pkt_code_t code;
    uint64 ts;
    uint thread;
} pkt_header_t;

typedef struct {
    pkt_header_t header;
    uint size;
} pkt_trace_t;
#pragma pack()

typedef struct {
    uint pos;
    uint64 ts;
    thread_id_t thread;
} per_thread_t;

