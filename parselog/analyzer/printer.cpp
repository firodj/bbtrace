#include <iostream>
#include "../observer.hpp"

#define LR_SHOW_BB 0x1
#define LR_SHOW_MEM 0x2
#define LR_SHOW_LIBCALL 0x4
#define LR_SHOW_WNDPROC 0x8

class Printer: public LogRunnerObserver
{
private:
    uint show_options_;
    
public:
    Printer(): LogRunnerObserver() {
        show_options_ = 0;
    }

    const char * GetName() override { return "Printer"; }

    void
    OnThread(uint thread_id, uint handle_id, uint sp) override
    {
        std::cout << std::dec << thread_id << "] ";
        std::cout << "Thread ID:" << std::dec << handle_id
            << " SP:0x" << std::hex << sp
            << std::endl;
    }

    void
    OnBB(uint thread_id, df_stackitem_c &last_bb, vec_memaccess_t &memaccesses) override
    { 
        if (show_options_ & LR_SHOW_BB) {
            std::cout << std::dec << thread_id << "] ";
            last_bb.Dump();
        }

        if (show_options_ & LR_SHOW_MEM) {
            for (auto &memaccess: memaccesses)
                memaccess.Dump(1);
        }
    }

    void
    OnApiCall(uint thread_id, df_apicall_c &apicall_ret) override
    {
        bool verbose = show_options_ & LR_SHOW_LIBCALL;

        // if (!verbose)
        // for (auto filter_addr : filter_apicall_addrs_) {
        //     if (filter_addr == apicall_ret.func) {
        //         verbose = true; break;
        //     }
        // }
        if (verbose) {
            std::cout << std::dec << thread_id << "] ";
            apicall_ret.Dump();
        }
    }

    void
    OnApiUntracked(uint thread_id, df_stackitem_c &bb_untracked_api) override
    {
        bool verbose = show_options_ & LR_SHOW_LIBCALL;

        if (verbose) {
            std::cout << std::dec << thread_id << "] Untracked api by bb:0x" << std::hex << bb_untracked_api.pc
                << " ts:" << std::dec << bb_untracked_api.ts
                << std::endl;
        }
    }

    void OnPush(uint thread_id, df_stackitem_c &the_bb) override
    {

    }

    void OnPop(uint thread_id, df_stackitem_c &the_bb) override
    {

    }
};

Printer observer = Printer();