#pragma once

#include <mutex>
#include <condition_variable>
#include <sstream>
#include <queue>

#define WITHOUT_DR
#include "datatypes.h"

#include "logparser.h"
#include "threadinfo.hpp"

#define LR_SHOW_BB 0x1
#define LR_SHOW_LIBCALL 0x2

typedef std::map<uint, uint> map_uint_uint_t;
typedef std::map<uint, uint64> map_uint_uint64_t;
typedef std::map<app_pc, std::string> map_app_pc_string_t;

enum RunnerMessageType {
    MSG_UNDEFINED = 0,
    MSG_CREATE_THREAD,
    MSG_RESUME_THREAD,
    MSG_API_CALL,
    MSG_BB_END,
    MSG_THREAD_FINISHED,
    MSG_STOP
};

struct runner_message_t {
    uint thread_id;
    RunnerMessageType msg_type;
    std::string data;
};

struct sync_sequence_t {
public:
    uint seq;
    uint64 ts;
    std::mutex mx;
    std::condition_variable cv;
    
    sync_sequence_t(): seq(0), ts(0) {}
};

typedef std::map<uint, sync_sequence_t> map_sync_sequence_t;

class LogRunner
{
private:
    map_app_pc_string_t symbol_names_;
    map_sync_sequence_t wait_seqs_; // hmutex / hevent
    map_sync_sequence_t critsec_seqs_; // critsec

    std::map<uint, thread_info_c> info_threads_;
    std::map<uint, thread_info_c>::iterator it_thread_;
    std::string filename_;
    uint show_options_;
    std::vector<uint> filter_apicall_addrs_;
    std::vector<std::string> filter_apicall_names_;
    uint64 thread_ts_;
    uint64 bb_counts_;

    std::mutex message_mu_;
    std::condition_variable message_cv_;
    std::queue<runner_message_t> messages_;

    bool request_stop_;

protected:
    void DoKindBB(thread_info_c &thread_info, mem_ref_t &buf_bb);
    void DoEndBB(thread_info_c &thread_info /* , bb mem read/write */);
    void DoKindSymbol(thread_info_c &thread_info, buf_symbol_t &buf_sym);
    void DoKindLibCall(thread_info_c &thread_info, buf_lib_call_t &buf_libcall);
    void DoKindLibRet(thread_info_c &thread_info, buf_lib_ret_t &buf_libret);
    void DoKindArgs(thread_info_c &thread_info, buf_event_t &buf_args);
    void DoKindString(thread_info_c &thread_info, buf_string_t &buf_str);
    void DoKindSync(thread_info_c &thread_info, buf_event_t &buf_sync);
    void DoKindWndProc(thread_info_c &thread_info, buf_event_t &buf_wndproc);

    virtual void OnApiCall(uint thread_id, df_apicall_c &apicall_ret);
    virtual void OnBB(uint thread_id, df_stackitem_c &last_bb);

public:
    LogRunner(): show_options_(0), thread_ts_(0) {}

    bool Open(std::string &filename);

    void SetOptions(uint show_options)
    {
        show_options_ = show_options;
    }

    void FinishThread(thread_info_c &thread_info);

    bool Step();
    bool ThreadStep(thread_info_c &thread_info);

    bool Run();
    static void ThreadRun(thread_info_c &thread_info);
    void PostMessage(uint thread_id, RunnerMessageType msg_type, std::string &data);

    void ThreadWaitCritSec(thread_info_c &thread_info);
    void ThreadWaitEvent(thread_info_c &thread_info);
    void ThreadWaitMutex(thread_info_c &thread_info);

    void CheckPending(thread_info_c &thread_info)
    {
        ThreadWaitCritSec(thread_info);
        ThreadWaitEvent(thread_info);
        ThreadWaitMutex(thread_info);
    }

    void ApiCallRet(thread_info_c &thread_info);

    void OnCreateThread(df_apicall_c &apicall, uint64 ts);
    void OnResumeThread(df_apicall_c &apicall, uint64 ts);

    void Summary();

    uint64& thread_ts() {
        return thread_ts_;
    }

    void FilterApiCall(std::string &name)
    {
        filter_apicall_names_.push_back(name);
    }

    void SaveSymbols(std::ostream &out);
    void SaveState(std::ostream &out);
    void Dump(int indent = 0);

    void RestoreSymbols(std::istream &in);
    void RestoreState(std::istream &in);
};
