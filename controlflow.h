#pragma once

#pragma pack(1)

typedef struct {
	uint code;
	uint64 ts;
	uint thread;
} pkt_thread_t;

typedef struct {
	uint code;
	uint64 ts;
	uint thread;
	uint size;
} pkt_trace_t;

#pragma pack()