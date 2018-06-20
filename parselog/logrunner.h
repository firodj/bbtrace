#pragma once

typedef std::map<uint, uint> map_uint_uint_t;
typedef std::map<app_pc, std::string> map_app_pc_string_t;

class LogRunner
{
private:
    map_app_pc_string_t symbol_names_;
    map_uint_uint_t wait_seqs_; // hmutex / hevent
    map_uint_uint_t critsec_seqs_; // critsec
    std::map<uint, thread_info_c> info_threads_;
    std::map<uint, thread_info_c>::iterator it_thread_;
    std::string filename_;
    uint show_options_;
    uint bb_count_;
    std::vector<uint> filter_apicall_addrs_;
    std::vector<std::string> filter_apicall_names_;

public:
    LogRunner(): bb_count_(0), show_options_(0) {}

    bool Open(std::string &filename);

    void SetOptions(uint show_options)
    {
        show_options_ = show_options;
    }

    void FinishThread(thread_info_c &thread_info);

    bool Step();

    void DoKindBB(thread_info_c &thread_info, mem_ref_t &buf_bb);
    void DoKindSymbol(thread_info_c &thread_info, buf_symbol_t &buf_sym);
    void DoKindLibCall(thread_info_c &thread_info, buf_lib_call_t &buf_libcall);
    void DoKindLibRet(thread_info_c &thread_info, buf_lib_ret_t &buf_libret);
    void DoKindArgs(thread_info_c &thread_info, buf_event_t &buf_args);
    void DoKindString(thread_info_c &thread_info, buf_string_t &buf_str);
    void DoKindSync(thread_info_c &thread_info, buf_event_t &buf_sync);
    void DoKindCritSec(thread_info_c &thread_info, buf_event_t &buf_sync);
    void DoKindWndProc(thread_info_c &thread_info, buf_event_t &buf_wndproc);
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

    void DoEndBB(thread_info_c &thread_info /* , bb mem read/write */);
    void OnCreateThread(df_apicall_c &apicall);
    void OnResumeThread(df_apicall_c &apicall);
    void OnCreateFile(df_apicall_c &apicall);
    void OnCloseHandle(df_apicall_c &apicall);

    void Summary();

    uint& bb_count() {
        return bb_count_;
    }

    void FilterApiCall(std::string &name)
    {
        filter_apicall_names_.push_back(name);
    }

    void SaveSymbols(std::ostream &out);
    void SaveState(std::ostream &out);

    void RestoreSymbols(std::istream &in);
    void RestoreState(std::istream &in);
};
