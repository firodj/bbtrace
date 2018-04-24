#pragma once

class df_apicall_c {
public:
    app_pc func;
    std::string name;
    app_pc ret_addr;
    std::vector<uint> callargs;
    std::vector<std::string> callstrings;
    std::vector<uint> retargs;
    std::vector<std::string> retstrings;
    df_apicall_c():
        func(0), ret_addr(0) {}
};

class thread_info_c {
public:
    logparser_c logparser;
    bool running;
    bool finished;
    uint last_kind;
    std::vector<df_apicall_c> apicalls;
    df_apicall_c *apicall_now;
    uint hevent_wait;
    uint hevent_seq;
    uint hmutex_wait;
    uint hmutex_seq;
    uint64 filepos;
    app_pc within_bb;
    uint id;
    std::string last_call_name; // DELETE ME
    uint bb_count;

    thread_info_c():
        running(false),
        finished(false),
        hevent_wait(0),
        hmutex_wait(0),
        apicall_now(nullptr),
        filepos(0),
        within_bb(0),
        id(0),
        bb_count(0),
        last_kind(KIND_NONE) {}
};

typedef std::map<uint, thread_info_c> map_thread_info_t;
