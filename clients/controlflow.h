#pragma once

typedef enum {
	PKT_CODE_TRACE
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
