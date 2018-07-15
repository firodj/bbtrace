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
    void Dump();
    void SaveState(std::ostream &out);
    void RestoreState(std::istream &in);
};

class df_stackitem_c {
public:
    uint kind;
    app_pc pc;
    app_pc next;
    uint link;
};

class thread_info_c {
public:
    logparser_c logparser;
    bool running;
    bool finished;
    uint last_kind;
    std::vector<df_apicall_c> apicalls;
    std::vector<df_stackitem_c> stacks;
    df_stackitem_c last_bb;
    df_apicall_c *apicall_now;
    mem_ref_t pending_bb;
    uint pending_state;
    uint hevent_wait;
    uint hevent_seq;
    uint hmutex_wait;
    uint hmutex_seq;
    uint critsec_wait;
    uint critsec_seq;
    uint64 filepos;
    app_pc within_bb;
    uint id;
    uint bb_count;

    thread_info_c():
        running(false),
        finished(false),
        hevent_wait(0),
        hmutex_wait(0),
        critsec_wait(0),
        apicall_now(nullptr),
        pending_state(0),
        filepos(0),
        within_bb(0),
        id(0),
        bb_count(0),
        last_kind(KIND_NONE) {}

    void Dump();
    void SaveState(std::ostream &out);
    void RestoreState(std::istream &in);
};

typedef std::map<uint, thread_info_c> map_thread_info_t;
