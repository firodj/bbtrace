#include <iostream>
#include <mutex>
#include <string>
#include "../observer.hpp"
#include "../flamegraph.h"

std::mutex g_flamegraph_mx;
FlameGraph g_flamegraph;

class Grapher: public LogRunnerObserver
{
    bool
    assign_block(block_t &block, df_stackitem_c &last_bb) {
        if (last_bb.kind == KIND_BB) {
            block.kind = block_t::BLOCK;
        }
        block.addr = last_bb.pc;
        block.end = last_bb.next;
        block.last = last_bb.next - last_bb.len_last;
        switch (last_bb.link) {
            case LINK_CALL: block.jump = block_t::CALL; break;
            case LINK_RETURN: block.jump = block_t::RET; break;
            case LINK_JMP: block.jump = block_t::JMP; break;
            default: block.jump = block_t::NONE;
        }
        return true;
    }

    bool verbose_;
    int push_count_;

public:

    std::string GetName() override { return "Grapher"; }

    void
    OnBB(uint thread_id, df_stackitem_c &last_bb, vec_memaccess_t &memaccesses) override
    {
        // if (last_bb.ts > 10) verbose_ = true;

        if (false && last_bb.is_sub) {
            std::cout << std::dec << thread_id << "] On BB: ";
            last_bb.Dump();
        }

        if (! g_flamegraph.BlockExists(last_bb.pc)) 
        {
            std::lock_guard<std::mutex> lock(g_flamegraph_mx);
            block_t block;
            if (assign_block(block, last_bb))
                g_flamegraph.AddBlock(block);
        }

        block_t *block = g_flamegraph.GetBlock(last_bb.pc);
        history_t &history = g_flamegraph.GetHistory(thread_id);
        
        try {
            uint depth = last_bb.s_depth + 1;
            if (last_bb.is_sub || history.last_block == nullptr) {
                history.start_sub(block, depth);
            } else {
                history.last_bb(block, depth);
            }
        } catch (std::exception &e ) {
            std::cerr << "Exception: " << e.what() << std::endl;
            logrunner_->RequestToStop();
        }
    }

    void
    OnApiCall(uint thread_id, df_apicall_c &apicall_ret) override
    {
        if (verbose_) {
            std::cout << std::dec << thread_id << "] OnApiCall: ";
            apicall_ret.Dump();
        }

        //if (push_count_++ > 10) RequestToStop();
    }

    void
    OnApiUntracked(uint thread_id, df_stackitem_c &bb_untracked_api) override
    {
        if (verbose_) {       
            std::cout << std::dec << thread_id << "] Untracked API: ";
            bb_untracked_api.Dump();
        }
    }

    void OnPush(uint thread_id, df_stackitem_c &the_bb, df_apicall_c *apicall_now) override 
    {
        if (verbose_) {
            // std::cout << "OnPush: ";
            // the_bb.Dump();
        }
    }

    void OnPop(uint thread_id, df_stackitem_c &the_bb) override
    {
        if (verbose_) {
            std::cout << std::dec << thread_id << "] On Pop: ";
            the_bb.Dump();
        }
        
        // if (push_count_++ > 100) logrunner_->RequestToStop();
    }

    void
    OnStart() override {
        push_count_ = 0;
        verbose_ = false;
    }

    void
    OnFinish() override {
        std::string prefixname = logrunner_->GetPrefix();

        std::string csvname = prefixname + ".bb.csv";
        g_flamegraph.DumpBlocksCSV(csvname);

        std::string treename = prefixname + ".fgraph";
        std::string exename = logrunner_->GetExecutable();
        if (! exename.empty()) {
            treename = exename + ".fgraph";
        }
        
        g_flamegraph.PrintTreeBIN(treename);
        // g_flamegraph.DumpHistory();
    }
};

Grapher observer = Grapher();