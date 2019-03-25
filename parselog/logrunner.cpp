#include <iostream>
#include <fstream>
#include <sstream>
#include <string>
#include <map>
#include <vector>
#include <iterator>
#include <stdexcept>   // for exception, runtime_error, out_of_range
#include <utility>
#include <thread>
#include <algorithm>
#include <cassert>

#include "logrunner.h"
#include "observer.hpp"
#include "serializer.h"

bool
LogRunner::Open(std::string &filename) {
    filename_ = filename;
    const uint main_thread_id = 0;

    if (info_threads_[main_thread_id].logparser.open(filename_.c_str())) {
        std::cout << "Open:" << filename_ << std::endl;
        info_threads_[main_thread_id].running = true;
        info_threads_[main_thread_id].the_runner = this;
    } else {
        std::cout << "Fail to open .bin: " << filename_ << std::endl;
        info_threads_[main_thread_id].finished = true;
        return false;
    }

    return true;
}

void
LogRunner::FinishThread(thread_info_c &thread_info)
{
    while (! thread_info.apicalls.empty()) {
        thread_info.apicall_now = &thread_info.apicalls.back();
        ApiCallRet(thread_info);
    }

    if (thread_info.within_bb) {
        DoEndBB(thread_info /* , bb mem read/write */);
    }
    
    thread_info.finished = true;
}

bool
LogRunner::Step(map_thread_info_t::iterator &it_thread)
{
    uint inactive = 0;
    for(; inactive < info_threads_.size();
            inactive++, it_thread++) {
        if (it_thread == info_threads_.end()) {
            if (request_stop_) return false;

            it_thread = info_threads_.begin();
        }

        thread_info_c &thread_info = it_thread->second;

        if (thread_info.finished)
            continue;
        if (!thread_info.running)
            CheckPending(thread_info);
        if (thread_info.running) {
            break;
        }
    }

    if (inactive == info_threads_.size()) {
        return false;
    }

    uint thread_id = it_thread->first;
    thread_info_c &thread_info = it_thread->second;
    auto it_current = it_thread++;

    if (! ThreadStep(thread_info)) {
        assert(thread_info.finished);
        thread_stats_c &thread_stats = stats_threads_[thread_info.id];
        thread_stats.Apply(thread_info);
        info_threads_.erase(it_current);
    }

    return true;
}

/**
 * return true when continue to process event.
 *        false when reach to end /finish.
 */
bool
LogRunner::ThreadStep(thread_info_c &thread_info)
{
    thread_info.now_ts++;

    while (thread_info.running) {
        uint kind;

        // Check Lib Ret first
        if (thread_info.apicall_now) {
            kind = thread_info.logparser.peek();
            if (thread_info.last_kind == KIND_LIB_RET && kind != KIND_ARGS && kind != KIND_STRING) {
                ApiCallRet(thread_info);
                break;
            }
        }

        // Forward peek kind
        if (thread_info.within_bb) {
            kind = thread_info.logparser.peek();
            if (kind == KIND_BB || kind == KIND_LIB_CALL) {
                DoEndBB(thread_info);
                break;
            }
        }

        char *item;
        if (thread_info.pending_state == 1) {
            item = (char*)&thread_info.pending_bb;
            thread_info.pending_state = 0;
        } else {
            // Consume kind
            item = thread_info.logparser.fetch();
            thread_info.filepos = thread_info.logparser.tell();
#if 0
            kind = *(uint*)item;
            std::cout << std::dec << thread_info.id << "] " << std::dec << thread_info.now_ts
                << " KIND: " << std::string((char*)&kind, 4) << std::endl;
#endif
        }

        if (!item) {
            FinishThread(thread_info);
            return false;
        }
        kind = *(uint*)item;
        mem_ref_t *buf_bb;
        buf_exception_t *buf_exc;
        buf_module_t *buf_mod;

        switch (kind) {
            case KIND_THREAD:
                {
                    buf_event_t *buf_evt = (buf_event_t*)item;
                    OnThread(thread_info.id, buf_evt->params[0], buf_evt->params[1]);
                }
                break;
            case KIND_BB: {
                buf_bb = (mem_ref_t*)item;
#if 0
                uint len_last_instr = buf_bb->size & ((1 << LINK_SHIFT_FIELD) - 1);
                uint bb_link = buf_bb->size >> LINK_SHIFT_FIELD;
                std::cout << std::dec << thread_info.id << "] ";
                std::cout << "bb.pc:0x" << std::hex << buf_bb->pc;
                std::cout << " next:0x" << std::hex << (buf_bb->addr + len_last_instr);
                std::cout << " bb.link:";
                switch (bb_link) {
                    case LINK_CALL: std::cout << "CALL"; break;
                    case LINK_RETURN: std::cout << "RETURN"; break;
                    case LINK_JMP: std::cout << "JMP"; break;
                }
                std::cout << std::endl;
#endif
                if (thread_info.pending_state == 1) {
                    std::cout << thread_info.pending_state;
                    std::cout << " " << std::dec << thread_info.id;
                    std::cout << " 0x" << std::hex << buf_bb->pc;
                    std::cout << std::endl;
                    throw std::runtime_error("repending ?");
                }

                if (thread_info.apicall_now && thread_info.apicall_now->ret_addr == buf_bb->pc) {
                    thread_info.pending_bb = *buf_bb;
                    thread_info.pending_state = 2;
                    continue;
                } else {
                    DoKindBB(thread_info, *(mem_ref_t*)item);
                }
            }
                break;
            case KIND_LOOP:
                buf_bb = reinterpret_cast<mem_ref_t*>(item);
                DoMemLoop(thread_info, *buf_bb);
                break;
            case KIND_READ:
                buf_bb = reinterpret_cast<mem_ref_t*>(item);
                DoMemRW(thread_info, *buf_bb, false);
                break;
            case KIND_WRITE:
                buf_bb = reinterpret_cast<mem_ref_t*>(item);
                DoMemRW(thread_info, *buf_bb, true);
                break;
            case KIND_EXCEPTION:
                buf_exc = reinterpret_cast<buf_exception_t*>(item);
                std::cout << std::dec << thread_info.id << "] ";
                std::cout << "0x" << std::hex << buf_exc->pc << " EXCEPTION 0x" << buf_exc->fault_address
                    << " code:0x" << buf_exc->code << std::endl;
                break;
            case KIND_MODULE:
                buf_mod = reinterpret_cast<buf_module_t*>(item);
                {
                    const char* copyupto = std::find(buf_mod->name, buf_mod->name + sizeof(buf_mod->name), 0);
                    std::string name(buf_mod->name, copyupto - buf_mod->name);
                    std::cout << "MODULE " << name << std::endl;
                }
                break;
            case KIND_SYMBOL:
                DoKindSymbol(thread_info, *(buf_symbol_t*)item);
                break;
            case KIND_LIB_CALL:
                DoKindLibCall(thread_info, *(buf_lib_call_t*)item);
                break;
            case KIND_LIB_RET:
                DoKindLibRet(thread_info, *(buf_lib_ret_t*)item);
                if (thread_info.pending_state == 2) {
                    thread_info.pending_state = 1;
                    thread_info.last_kind = kind;
                    continue;
                }
                break;
            case KIND_APP_CALL:
                // buf_app_call_t *buf_item = reinterpret_cast<buf_app_call_t*>(item);
                break;
            case KIND_APP_RET:
                // buf_app_ret_t *buf_item = reinterpret_cast<buf_app_ret_t*>(item);
                break;
            case KIND_WNDPROC:
                DoKindWndProc(thread_info, *(buf_event_t*)item);
                break;
            case KIND_SYNC:
                DoKindSync(thread_info, *(buf_event_t*)item);
                break;
            case KIND_ARGS:
                DoKindArgs(thread_info, *(buf_event_t*)item);
                break;
            case KIND_STRING:
                DoKindString(thread_info, *(buf_string_t*)item);
                break;
            default: {
                std::ostringstream oss;
                oss << "Unknown LogRunner::ThreadStep kind 0x" << std::hex << kind;
                if (kind) {
                    oss << " KIND: " << std::string((char*)&kind, 4) << std::endl;
                }
                throw std::runtime_error(oss.str());
            }
        } //

        // Last Kind
        if (kind != KIND_ARGS && kind != KIND_STRING && kind != KIND_READ && kind != KIND_WRITE) {
            thread_info.last_kind = kind;
        }
    }

    return true;
}

bool LogRunner::Run()
{
    map_thread_info_t::iterator it_thread = info_threads_.end();

    request_stop_ = false;
    is_multithread_ = false;

    OnStart();

    while (Step(it_thread)) ;

    OnFinish();

    return true;
}

bool LogRunner::RunMT()
{
    const uint main_thread_id = 0;
    request_stop_ = false;
    is_multithread_ = true;

    assert(info_threads_.find(main_thread_id) != info_threads_.end());

    OnStart();

    for (auto &it: info_threads_) {
        assert(it.second.the_thread == nullptr);
        it.second.the_thread = std::unique_ptr<std::thread>(
            new std::thread(LogRunner::ThreadRun, std::ref(it.second))
            );
    }

    bool finished = false;
    while (! finished) {
        std::unique_lock<std::mutex> lk(message_mu_);
        message_cv_.wait(lk, [this]{ return !messages_.empty(); });

        while (!messages_.empty()) {
            runner_message_t &message = messages_.front();
            switch (message.msg_type) {
                case MSG_CREATE_THREAD: {
                    df_apicall_c apicall_ret;
                    std::istringstream is_data(message.data);
                    apicall_ret.RestoreState( is_data );
                    uint64 ts = read_u64(is_data);
                    OnCreateThread(apicall_ret, ts);
                    }
                    break;
                case MSG_RESUME_THREAD: {
                    df_apicall_c apicall_ret;
                    std::istringstream is_data(message.data);
                    apicall_ret.RestoreState( is_data );
                    uint64 ts = read_u64(is_data);
                    OnResumeThread(apicall_ret, ts);
                    }
                    break;
                case MSG_THREAD_FINISHED: {
                    thread_info_c &thread_info = info_threads_[message.thread_id];
                    std::cout << message.thread_id << "] wait thread exit." << std::endl;
                    thread_info.the_thread->join();
                    thread_info.the_thread.reset();
                    assert(thread_info.the_thread == nullptr);
                    if (thread_info.finished) {
                        thread_stats_c &thread_stats = stats_threads_[thread_info.id];
                        thread_stats.Apply(thread_info);
                        info_threads_.erase(message.thread_id);
                    }

                    if ( std::all_of(info_threads_.begin(), 
                        info_threads_.end(), 
                        [](map_thread_info_t::value_type &v){
                            return v.second.the_thread == nullptr;
                        }) )
                        finished = true;
                    }
                    break;
                case MSG_REQUEST_STOP: {
                        request_stop_ = true;
                        resume_cv_.notify_all();
                    }
                    break;
                default:
                    std::cout << "Unknown msg_type!" << std::endl;
            }
            messages_.pop();
        }
    }

    OnFinish();

    return true;
}

void LogRunner::ThreadRun(thread_info_c &thread_info)
{
    while (! thread_info.finished && ! thread_info.the_runner->request_stop_) {
        if (thread_info.running) {
            if (! thread_info.the_runner->ThreadStep(thread_info) ) break;
        } else {
            thread_info.the_runner->CheckPending(thread_info);
        }
    }

    std::string data;
    
    thread_info.the_runner->PostMessage(thread_info.id, MSG_THREAD_FINISHED, data);
}

void
LogRunner::RequestToStop()
{
    std::string data;

    if (is_multithread_)
        PostMessage(0, MSG_REQUEST_STOP, data);
    else
        request_stop_ = true;
}

void
LogRunner::DoKindBB(thread_info_c &thread_info, mem_ref_t &buf_bb)
{
    thread_info.within_bb = (uint) buf_bb.pc;
    uint len_last_instr = buf_bb.size & ((1 << LINK_SHIFT_FIELD) - 1);
    uint bb_link = buf_bb.size >> LINK_SHIFT_FIELD;
    app_pc next_bb = buf_bb.addr + len_last_instr;
    bool bb_is_sub = thread_info.bb_count == 0;

#if 0
    if (thread_info.id == 0) {
        std::cout << std::dec << thread_info.id << "] ";
        std::cout << "bb.pc " << std::hex << buf_bb.pc;
        std::cout << " next " << std::hex << next_bb;
        std::cout << " bb.link ";
        switch (bb_link) {
            case LINK_CALL: std::cout << "CALL"; break;
            case LINK_RETURN: std::cout << "RETURN"; break;
            case LINK_JMP: std::cout << "JMP"; break;
        }
        std::cout << std::endl;
    }
#endif
    // fixes stacks for bb with called (usually) to untracked api
    df_stackitem_c bb_untracked_api;

    if (thread_info.last_bb.link == LINK_CALL) {
        bb_is_sub = true;
        size_t i = thread_info.stacks.size();
        if (i) {
            df_stackitem_c& last_item = thread_info.stacks[i-1];
            if (last_item.kind == KIND_BB && last_item.next == thread_info.within_bb) {
                if (thread_info.last_kind == KIND_BB)
                    bb_untracked_api = last_item;

                while (thread_info.stacks.size() > i-1) {
                    df_stackitem_c& item = thread_info.stacks.back();
                    item.ts = thread_info.now_ts;
                    OnPop(thread_info.id, item);
                    thread_info.stacks.pop_back();
                }
                // thread_info.stacks.erase(
                //     thread_info.stacks.begin()+i-1,
                //     thread_info.stacks.end());

                bb_is_sub = false;
            }
        }
    }
    if (thread_info.last_bb.link == LINK_RETURN) {
        size_t i;
        for (i = thread_info.stacks.size(); i > 0; --i) {
            df_stackitem_c& item = thread_info.stacks[i-1];
            if (item.kind == KIND_BB && item.next == thread_info.within_bb) {
                while (thread_info.stacks.size() > i-1) {
                    df_stackitem_c& item = thread_info.stacks.back();
                    item.ts = thread_info.now_ts;
                    OnPop(thread_info.id, item);
                    thread_info.stacks.pop_back();
                }
                // thread_info.stacks.erase(
                //     thread_info.stacks.begin()+i-1,
                //     thread_info.stacks.end());
                break;
            }
            if (item.kind == KIND_LIB_CALL)
                break;
        }
        if (i == 0) {
            if (thread_info.id == 0) {
                bb_is_sub = true;

                std::cout << std::dec << thread_info.id;
                std::cout << "] DoKindBB: mismatch stack, return to 0x" << std::hex << thread_info.within_bb
                    << " from 0x" << thread_info.last_bb.pc
                    << " stack size = " << std::dec << thread_info.stacks.size();

                if (thread_info.stacks.size()) {
                    df_stackitem_c& item = thread_info.stacks.back();
                    std::cout << " TOP: 0x" << std::hex << item.pc;
                    if (item.kind) {
                        std::cout << " '" << std::string((char*)&item.kind, 4) << "'";
                    }
                }

                if (thread_info.apicalls.size() ) {
                    df_apicall_c &libret_last = thread_info.apicalls.back();
                    std::cout << " Lib:0x " << std::hex << libret_last.func;
                    std::cout << " " << libret_last.name;
                    std::cout << " Ret:0x " << std::hex << libret_last.ret_addr;
                }
                std::cout << " (" << std::dec << thread_info.now_ts << ")";
                std::cout << std::endl;

                //throw std::runtime_error ("DIE!");
            }
        }
    }

    if (bb_untracked_api.pc) {
        bb_untracked_api.ts = thread_info.now_ts++;
        OnApiUntracked(thread_info.id, bb_untracked_api);
    }

    thread_info.last_bb.kind = KIND_BB;
    thread_info.last_bb.pc   = buf_bb.pc;
    thread_info.last_bb.next = next_bb;
    thread_info.last_bb.link = bb_link;
    thread_info.last_bb.len_last = len_last_instr;
    thread_info.last_bb.is_sub = bb_is_sub;
    thread_info.last_bb.ts   = thread_info.now_ts;
    thread_info.last_bb.s_depth = thread_info.stacks.size();

    if (bb_link == LINK_CALL) {
        thread_info.stacks.push_back(df_stackitem_c());
        df_stackitem_c& item = thread_info.stacks.back();
        item = thread_info.last_bb;
    }

    thread_info.bb_count++;
}

void
LogRunner::DoKindSymbol(thread_info_c &thread_info, buf_symbol_t &buf_sym)
{
    const char* copyupto = std::find(buf_sym.name, buf_sym.name + sizeof(buf_sym.name), 0);
    std::string name(buf_sym.name, copyupto - buf_sym.name);
    symbol_names_[buf_sym.func] = name;

    for (auto filter_name : filter_apicall_names_) {
        if (name == filter_name) {
            filter_apicall_addrs_.push_back(buf_sym.func);
            std::cout << "Filter apicall: " << filter_name << " addr:0x" << std::hex << buf_sym.func << std::endl;
        }
    }
}

void
LogRunner::DoKindLibCall(thread_info_c &thread_info, buf_lib_call_t &buf_libcall)
{
    const bool verbose = false;

    std::string name;
    if (symbol_names_.find(buf_libcall.func) != symbol_names_.end()) {
        name = symbol_names_[buf_libcall.func];
    }

    if (verbose) {
        if (thread_info.id == 0) {
            std::cout << std::dec << thread_info.id << "] ";
            std::cout << "Lib Call func:0x" << std::hex << buf_libcall.func;
            std::cout << " '" << name;
            std::cout << "' Ret:0x" << buf_libcall.ret_addr;
            std::cout << std::endl;
        }
    }

    int s_depth = thread_info.stacks.size();
    thread_info.stacks.push_back(df_stackitem_c());
    df_stackitem_c& item = thread_info.stacks.back();

    item.kind = KIND_LIB_CALL;
    item.pc   = buf_libcall.func;
    item.next = buf_libcall.ret_addr;
    item.link = 0;
    item.len_last = 0;
    item.is_sub = true;
    item.ts   = thread_info.now_ts;
    item.s_depth = s_depth;

    thread_info.apicalls.push_back(df_apicall_c());
    thread_info.apicall_now = &thread_info.apicalls.back();

    thread_info.apicall_now->func = buf_libcall.func;
    thread_info.apicall_now->ret_addr = buf_libcall.ret_addr;
    thread_info.apicall_now->name = name;
    thread_info.apicall_now->callargs.push_back((uint)buf_libcall.arg);
    thread_info.apicall_now->ts = thread_info.now_ts;
    thread_info.apicall_now->s_depth = s_depth;

    OnPush(thread_info.id, item, thread_info.apicall_now);
}

void
LogRunner::DoKindLibRet(thread_info_c &thread_info, buf_lib_ret_t &buf_libret)
{
    const bool verbose = false;
    std::string name;
    if (symbol_names_.find(buf_libret.func) != symbol_names_.end()) {
        name = symbol_names_[buf_libret.func];
    }

    if (verbose) {
        if (thread_info.id == 0) {
            std::cout << std::dec << thread_info.id << "] ";
            std::cout << "Lib Ret func:0x" << std::hex << buf_libret.func;
            std::cout << " '" << name;
            std::cout << "' Ret:0x" << buf_libret.ret_addr;
            std::cout << std::endl;
        }
    }

    if (thread_info.apicalls.size() == 0) {
        std::cout << "Apicall stacks empty!" << std::endl;
        throw std::runtime_error ("Apicall stacks empty!");
    }

    df_apicall_c &libret_last = thread_info.apicalls.back();
    if (libret_last.func != buf_libret.func &&
        libret_last.ret_addr != buf_libret.ret_addr) {
        std::cout << "Unmatch lib ret!" << std::endl;
        throw std::runtime_error ("Unmatch lib ret!");
    }

    size_t i;
    for (i = thread_info.stacks.size(); i > 0; --i) {
        df_stackitem_c& item = thread_info.stacks[i-1];
        if (item.kind == KIND_LIB_CALL && item.next == buf_libret.ret_addr) {
            while (thread_info.stacks.size() > i-1) {
                df_stackitem_c& item = thread_info.stacks.back();
                item.ts = thread_info.now_ts;
                OnPop(thread_info.id, item);
                thread_info.stacks.pop_back();
            }
            // thread_info.stacks.erase(
            //     thread_info.stacks.begin()+i-1,
            //     thread_info.stacks.end());
            break;
        }
    }
    if (i == 0) {
        std::cout << std::dec << thread_info.id;
        std::cout << "] DoKindLibRet: mismatch stack, return to 0x" << std::hex << buf_libret.ret_addr
            << " from func 0x" << libret_last.func
            << " stack size = " << std::dec << thread_info.stacks.size()
            << std::endl;
    }

    if (thread_info.apicalls.size()) {
        thread_info.apicall_now = &thread_info.apicalls.back();
        thread_info.apicall_now->retargs.push_back((uint)buf_libret.retval);
    }
}

void
LogRunner::DoKindArgs(thread_info_c &thread_info, buf_event_t &buf_args)
{
    df_apicall_c &libcall_now = thread_info.apicalls.back();

    if (thread_info.last_kind == KIND_LIB_CALL) {
        for (int a=0; a<3; ++a) libcall_now.callargs.push_back((uint)buf_args.params[a]);
    } else
    if (thread_info.last_kind == KIND_LIB_RET) {
        for (int a=0; a<3; ++a) libcall_now.retargs.push_back((uint)buf_args.params[a]);
    } else
    {
        throw std::runtime_error("Uknown kind for ARGS");
    }
}

void
LogRunner::DoKindString(thread_info_c &thread_info, buf_string_t &buf_str)
{
    const char* copyupto = std::find(buf_str.value, buf_str.value + sizeof(buf_str.value), 0);
    std::string value(buf_str.value, copyupto - buf_str.value);

    df_apicall_c &libcall_now = thread_info.apicalls.back();

    if (thread_info.last_kind == KIND_LIB_CALL) {
        libcall_now.callstrings.push_back(value);
    } else
    if (thread_info.last_kind == KIND_LIB_RET) {
        libcall_now.retstrings.push_back(value);
    } else
    {
        throw std::runtime_error("Uknown kind for STRING");
    }

#if 0
    std::cout << std::dec << thread_info.id << "] ";
    std::cout << "string '" << value << "'" << std::endl;
#endif
}

void
LogRunner::DoKindSync(thread_info_c &thread_info, buf_event_t &buf_sync)
{
    uint sync_kind = buf_sync.params[2];
    uint wait = buf_sync.params[0];
    uint seq = buf_sync.params[1];

    map_sync_sequence_t *p_wait_seqs = &wait_seqs_;
    if (sync_kind == SYNC_CRITSEC) {
        p_wait_seqs = &critsec_seqs_;
    }

    bool non_suspend = false;    
    sync_sequence_t &ss = (*p_wait_seqs)[wait];

    {
        std::lock_guard<std::mutex> lk( resume_mx_ );

        non_suspend = ss.seq == (seq - 1);

        if (non_suspend) {
            ss.seq = seq;
            ss.ts = thread_info.now_ts +1;
        } else {
            switch (sync_kind) {
            case SYNC_EVENT: {
                thread_info.hevent_wait = wait;
                thread_info.hevent_seq = seq;
                thread_info.running = false;
                // std::cout << std::dec << thread_info.id << "] ";
                // std::cout << "thread pause - event #" << std::dec << wait
                //     << " !" << seq << std::endl;
                }
                break;
            case SYNC_MUTEX: {
                thread_info.hmutex_wait = wait;
                thread_info.hmutex_seq = seq;
                thread_info.running = false;
                // std::cout << std::dec << thread_info.id << "] ";
                // std::cout << "thread pause - mutex #" << std::dec << wait
                //     << " !" << seq << std::endl;
                }
                break;
            case SYNC_CRITSEC: {
                thread_info.critsec_wait = wait;
                thread_info.critsec_seq = seq;
                thread_info.running = false;
                // std::cout << std::dec << thread_info.id << "] ";
                // std::cout << "thread pause - critsec #" << std::dec << wait
                //     << " !" << seq << std::endl;
                }
                break;
            }
        }
    }

    resume_cv_.notify_all();
}
 
void
LogRunner::DoMemRW(thread_info_c &thread_info, mem_ref_t &mem_rw, bool is_write)
{
    app_pc bb = thread_info.within_bb;

    if (thread_info.within_bb == 0) {
        // std::cout << "pending: " << thread_info.pending_state << " bb: 0x" << std::hex << thread_info.pending_bb.pc << std::endl;
        if (thread_info.pending_state == 2 && thread_info.pending_bb.kind == KIND_BB)
            bb = thread_info.pending_bb.pc;
        else
            throw std::runtime_error("Whose bb access memory?");
    }

    thread_info.memaccesses.push_back(df_memaccess_c());
    df_memaccess_c &memaccess_cur = thread_info.memaccesses.back();

    memaccess_cur.pc = mem_rw.pc;
    memaccess_cur.addr = mem_rw.addr;
    memaccess_cur.size = mem_rw.size;
    memaccess_cur.is_write = is_write;
    memaccess_cur.is_loop = false;
    
#if 0
    std::cout << std::dec << thread_info.id << "] 0x" << std::hex << bb << " | 0x" << mem_rw.pc;
    if (mem_rw.kind == KIND_WRITE) std::cout << " WRITE ";
    if (mem_rw.kind == KIND_READ) std::cout << " READ ";
    
    std::cout << "0x" << mem_rw.addr 
        << " [" << std::dec << mem_rw.size << "]";
    
    std::cout << std::endl;
#endif
}

void
LogRunner::DoMemLoop(thread_info_c &thread_info, mem_ref_t &mem_loop)
{
    if (thread_info.memaccesses.size() == 0)
        throw std::runtime_error("loop for who? missing mem access for loop");
    
    df_memaccess_c &memaccess_cur = thread_info.memaccesses.back();
    if (memaccess_cur.pc != mem_loop.pc)
        throw std::runtime_error("mismatch loop and mem access pc");

    memaccess_cur.is_loop = true;
    memaccess_cur.loop_from = mem_loop.addr;
    memaccess_cur.loop_to = mem_loop.size;

#if 0
    // AFTER Mem R/W
    std::cout << thread_info.id << "] 0x" << std::hex << mem_loop->pc << " LOOP from:" << std::dec << mem_loop->addr
        << " to:" << mem_loop->size << std::endl;
#endif
}

void
LogRunner::DoKindWndProc(thread_info_c &thread_info, buf_event_t &buf_wndproc)
{
    bool verbose = false; // show_options_ & LR_SHOW_WNDPROC;
    if (!verbose) return;

    uint umsg = buf_wndproc.params[0];
    uint wparam = buf_wndproc.params[1];
    uint lparam = buf_wndproc.params[2];

    std::cout << std::dec << thread_info.id << "] ";
    std::cout << "wnd proc (0x" << std::hex << umsg << ", 0x" << wparam << ", 0x" << lparam
        << ")" << std::endl;
}

void
LogRunner::ThreadWaitCritSec(thread_info_c &thread_info)
{
    if (thread_info.critsec_wait) {
        sync_sequence_t &ss = critsec_seqs_[thread_info.critsec_wait];
        std::unique_lock<std::mutex> lk(resume_mx_);

        if (is_multithread_) {
            resume_cv_.wait(lk, [&]{ return ss.seq == thread_info.critsec_seq - 1 || thread_info.the_runner->request_stop_; });
            if (thread_info.the_runner->request_stop_) return;
        } else 
        {
            if (!(ss.seq == thread_info.critsec_seq - 1)) return;
        }
        ss.seq = thread_info.critsec_seq;
        uint64 ts = ss.ts;

        thread_info.running = true;
        thread_info.now_ts = ts;
        thread_info.critsec_wait = 0;
    }
}

void
LogRunner::ThreadWaitEvent(thread_info_c &thread_info)
{
    if (thread_info.hevent_wait) {
        sync_sequence_t &ss = wait_seqs_[thread_info.hevent_wait];
        std::unique_lock<std::mutex> lk(resume_mx_);

        if (is_multithread_) {
            resume_cv_.wait(lk, [&]{ return ss.seq == thread_info.hevent_seq - 1 || thread_info.the_runner->request_stop_; });
            if (thread_info.the_runner->request_stop_) return;
        } else
        {
            if (!(ss.seq == thread_info.hevent_seq - 1)) return;
        }
        ss.seq = thread_info.hevent_seq;
        uint64 ts = ss.ts;

        thread_info.running = true;
        thread_info.now_ts = ts;
        thread_info.hevent_wait = 0;
    }
}

void
LogRunner::ThreadWaitMutex(thread_info_c &thread_info)
{
    if (thread_info.hmutex_wait) {
        sync_sequence_t &ss = wait_seqs_[thread_info.hmutex_wait];
        std::unique_lock<std::mutex> lk(resume_mx_);

        if (is_multithread_) {
            resume_cv_.wait(lk, [&]{ return ss.seq == thread_info.hmutex_seq - 1 || thread_info.the_runner->request_stop_; });
            if (thread_info.the_runner->request_stop_) return;
        } else
        {
            if (!(ss.seq == thread_info.hmutex_seq - 1)) return;
        }
        ss.seq = thread_info.hmutex_seq;
        uint64 ts = ss.ts;

        thread_info.running = true;
        thread_info.now_ts = ts;
        thread_info.hmutex_wait = 0;
    }
}

void
LogRunner::ThreadWaitRunning(thread_info_c &thread_info)
{
    if (thread_info.running && ! thread_info.finished) {
        std::unique_lock<std::mutex> lk(resume_mx_);

        if (is_multithread_) {
            resume_cv_.wait(lk, [&]{ return thread_info.running || thread_info.the_runner->request_stop_; });
            if (thread_info.the_runner->request_stop_) return;
        }
    }
}

void
LogRunner::PostMessage(uint thread_id, RunnerMessageType msg_type, std::string &data)
{
    {
        std::lock_guard<std::mutex> lk(message_mu_);

        messages_.push(runner_message_t());
        runner_message_t &message = messages_.back();

        message.thread_id = thread_id;
        message.msg_type = msg_type;
        message.data = data;
    }
    message_cv_.notify_all();
}

void
LogRunner::ApiCallRet(thread_info_c &thread_info)
{
    df_apicall_c apicall_ret = *thread_info.apicall_now;
    thread_info.apicalls.pop_back();
    thread_info.apicall_now = nullptr;

    // these api calls are mandatory for sync
    std::ostringstream os_data;
    apicall_ret.SaveState(os_data);
    std::string data = os_data.str();

    write_u64(os_data, thread_info.now_ts);
    std::string data_with_ts = os_data.str();

    if (apicall_ret.name == "CreateThread") {
        if (is_multithread_)
            thread_info.the_runner->PostMessage(thread_info.id, MSG_CREATE_THREAD, data_with_ts);
        else
            OnCreateThread(apicall_ret, thread_info.now_ts);
    }
    else if (apicall_ret.name == "ResumeThread") {
        if (is_multithread_)
            thread_info.the_runner->PostMessage(thread_info.id, MSG_RESUME_THREAD, data_with_ts);
        else
            OnResumeThread(apicall_ret, thread_info.now_ts);
    }

    OnApiCall(thread_info.id, apicall_ret);
}

void
LogRunner::DoEndBB(thread_info_c &thread_info)
{
    if (thread_info.within_bb != thread_info.last_bb.pc) {
        throw std::runtime_error("Mismatch last_bb with within_bb !");
    }
    OnBB(thread_info.id, thread_info.last_bb, thread_info.memaccesses);

    thread_info.memaccesses.clear();
    thread_info.within_bb = 0;

    if (thread_info.last_bb.link == LINK_CALL) {
        df_stackitem_c& item = thread_info.stacks.back();
        OnPush(thread_info.id, item);
    }
}

void
LogRunner::OnCreateThread(df_apicall_c &apicall, uint64 ts)
{
    uint new_thread_id = apicall.retargs[1];
    bool new_suspended = (apicall.callargs[3] & 0x4) == 0x4;

    if (info_threads_.find(new_thread_id) != info_threads_.end()) {
        std::cout << "Already created with thread id? "
            << std::dec << new_thread_id << std::endl;
    } else if (new_thread_id) {
        std::ostringstream oss;
        oss << filename_ << "." << std::dec << new_thread_id;

        thread_info_c &thread_info = info_threads_[new_thread_id];

        thread_info.now_ts = ts;
        thread_info.the_runner = this;

        if (! thread_info.logparser.open(oss.str().c_str())) {
            std::cout << "Fail to open .bin: " << oss.str() << std::endl;
            thread_info.finished = true;
        } else {
            thread_info.running = new_suspended ? false : true;

            if (thread_info.running) {
                std::cout << std::dec << new_thread_id << "] ";
                std::cout << "thread starting." << std::endl;
            } else {
                std::cout << std::dec << new_thread_id << "] ";
                std::cout << "thread created." << std::endl;
            }
        }

        if (thread_info.finished) {
            thread_stats_c &thread_stats = stats_threads_[new_thread_id];
            thread_stats.Apply(thread_info);
            info_threads_.erase(new_thread_id);
        } else {
            thread_info.id = new_thread_id;
            if (is_multithread_) {
                assert(thread_info.the_thread == nullptr);
                thread_info.the_thread = std::unique_ptr<std::thread>(
                    new std::thread(LogRunner::ThreadRun, std::ref(thread_info))
                    );
            }
        }
    }
}

void
LogRunner::OnResumeThread(df_apicall_c &apicall, uint64 ts)
{
    uint resume_thread_id = apicall.retargs[1];
    if (info_threads_.find(resume_thread_id) != info_threads_.end()) {
        {
            std::lock_guard<std::mutex> lk(resume_mx_);

            info_threads_[resume_thread_id].now_ts = ts;
            info_threads_[resume_thread_id].running = true;
        }
        resume_cv_.notify_all();

        std::cout << std::dec << resume_thread_id << "] ";
        std::cout << "thread resuming (" << ts << ")" << std::endl;
    }
}
void
LogRunner::Summary()
{
    // Summary
    for (auto &it : info_threads_) {
        uint thread_id = it.first;
        thread_info_c &thread_info = it.second;

        thread_stats_c &thread_stats = stats_threads_[thread_info.id];
        thread_stats.Apply(thread_info);

        if (!thread_info.finished) {
            std::cout << std::dec << thread_id << "] thread not finished!";
            if (thread_info.running) {
                std::cout << " running";
            } else {
                std::cout << " suspended";
                if (thread_info.hevent_wait) {
                    std::cout << " event #" << thread_info.hevent_wait << " at " << thread_info.hevent_seq;
                    std::cout << " of " << wait_seqs_[thread_info.hevent_wait].seq;
                }
                if (thread_info.hmutex_wait) {
                    std::cout << " mutex #" << thread_info.hmutex_wait << " at " << thread_info.hmutex_seq;
                    std::cout << " of " << wait_seqs_[thread_info.hmutex_wait].seq;
                }
                if (thread_info.critsec_wait) {
                    std::cout << " critsec #" << thread_info.critsec_wait << " at " << thread_info.critsec_seq;
                    std::cout << " of " << critsec_seqs_[thread_info.critsec_wait].seq;
                }
            }
            std::cout << std::endl;
        }
    }
    
    uint bb_counts = 0;
    uint64 max_ts = 0;
    for (auto &it: stats_threads_) {
        bb_counts += it.second.bb_counts;
        if (max_ts < it.second.ts) max_ts = it.second.ts;
    }

    std::cout << "bb counts: " << bb_counts << std::endl;
    std::cout << "max ts: " << max_ts << std::endl;
}

void
LogRunner::SaveSymbols(std::ostream &out)
{
    out << "symb";

    write_u32(out, symbol_names_.size());

    for (auto &it : symbol_names_) {
        write_u32(out, it.first);
        write_str(out, it.second);
    }
}

void
LogRunner::RestoreSymbols(std::istream &in)
{
    if (!read_match(in, "symb")) return;
    symbol_names_.clear();

    for(int i = read_u32(in); i; i--) {
        uint32_t addr = read_u32(in);

        symbol_names_[addr] = read_str(in);

        // std::cout << "symbol_names " << std::hex << addr << " " << symbol_names_[addr] << std::endl;
    }
}

void
LogRunner::SaveState(std::ostream &out)
{
    out << "wait";
    write_u32(out, wait_seqs_.size());

    for (auto &it : wait_seqs_) {
        write_u32(out, it.first);
        write_u32(out, it.second.seq);
        write_u64(out, it.second.ts);
    }

    out << "crit";
    write_u32(out, critsec_seqs_.size());

    for (auto &it : critsec_seqs_) {
        write_u32(out, it.first);
        write_u32(out, it.second.seq);
        write_u64(out, it.second.ts);
    }

    out << "thrd";
    write_u32(out, info_threads_.size());

    for (auto &it : info_threads_) {
        thread_info_c &thread_info = it.second;

        write_u32(out, it.first);

        thread_info.SaveState(out);
    }

    out << "user";
    write_u32(out, observers_.size());

    for (auto &observer : observers_) {
        std::vector<char> data;
        write_str(out, observer->GetName());
        observer->SaveState(data);
        uint32_t sz = data.size();
        write_u32(out, sz);
        write_data(out, data.data(), sz);
    }
}

void
LogRunner::RestoreState(std::istream &in)
{
    if (filename_.empty())
        return;

    if (!read_match(in, "wait"))
        throw std::runtime_error("mismatch marker 'wait'");

    wait_seqs_.clear();

    for(int i = read_u32(in); i; i--) {
        uint32_t first = read_u32(in);
        uint32_t seq = read_u32(in);
        uint64_t ts = read_u64(in);
        wait_seqs_[first].seq = seq;
        wait_seqs_[first].ts = ts;
    }

    if (!read_match(in, "crit"))
        throw std::runtime_error("mismatch marker 'crit'");

    critsec_seqs_.clear();

    for(int i = read_u32(in); i; i--) {
        uint32_t first = read_u32(in);
        uint32_t seq = read_u32(in);
        uint64_t ts = read_u64(in);
        critsec_seqs_[first].seq = seq;
        critsec_seqs_[first].ts = ts;
    }

    if (!read_match(in, "thrd"))
        throw std::runtime_error("mismatch marker 'thrd'");

    info_threads_.clear();

    for(int i = read_u32(in); i; i--) {
        uint32_t first = read_u32(in);

        thread_info_c &thread_info = info_threads_[first];

        if (first == 0) {
            thread_info.logparser.open(filename_.c_str());
        } else {
            std::ostringstream oss;
            oss << filename_ << "." << std::dec << first;
            thread_info.logparser.open(oss.str().c_str());
        }

        thread_info.RestoreState(in);
        thread_info.logparser.seek(thread_info.filepos);
        thread_info.the_runner = this;
        thread_info.the_thread = nullptr;
    }

    if (!read_match(in, "user")) return;
    for(int i = read_u32(in); i; i--) {
        std::string name = read_str(in);
        uint32_t sz = read_u32(in);
        std::vector<char> data(sz);
        read_data(in, data.data(), sz);

        for (auto &observer : observers_) {
            if (observer->GetName() == name) {
                observer->RestoreState(data);
                break;
            }
        }
    }
}

void
LogRunner::Dump(int indent)
{
    std::string _tab = std::string(indent, ' ');

    for (auto &kv : wait_seqs_) {
        std::cout << _tab << "wait_seqs_[" << kv.first << "] : " << kv.second.seq << " @" << kv.second.ts << std::endl;
    }
    for (auto &kv : critsec_seqs_) {
        std::cout << _tab << "critsec_seqs_[" << kv.first << "] : " << kv.second.seq << " @" << kv.second.ts << std::endl;
    }
    for (auto &kv : info_threads_) {
        std::cout << _tab << "info_threads_[" << kv.first << "] : " << std::endl;
        kv.second.Dump(indent + 2);
    }
}

void
thread_info_c::SaveState(std::ostream &out)
{
    out << "info";

    write_u32(out, id);

    write_bool(out, running);

    write_bool(out, finished);

    write_u32(out, last_kind);

    write_u32(out, hevent_wait);

    write_u32(out, hevent_seq);

    write_u32(out, hmutex_wait);

    write_u32(out, hmutex_seq);

    write_u32(out, critsec_wait);

    write_u32(out, critsec_seq);

    write_u64(out, filepos);

    write_u32(out, within_bb);

    write_u32(out, bb_count);

    write_u64(out, now_ts);

    write_u32(out, apicalls.size());

    int j = -1;
    for (uint i = 0; i < apicalls.size(); ++i) {
        df_apicall_c &apicall_cur = apicalls[i];
        apicall_cur.SaveState(out);

        if (apicall_now == &apicall_cur) j = i;
    }

    write_u32(out, j);

    // stacks
    write_u32(out, stacks.size());

    for (uint i = 0; i < stacks.size(); ++i) {
        df_stackitem_c &stackitem_cur = stacks[i];
        stackitem_cur.SaveState(out);
    }

    // pending state
    write_u32(out, pending_state);

    if (pending_state) {
        write_data(out, (char*)&pending_bb, 16);
    }
    
    last_bb.SaveState(out);

    // memaccesses
    write_u32(out, memaccesses.size());

    for (uint i = 0; i < memaccesses.size(); ++i) {
        df_memaccess_c &memaccess_cur = memaccesses[i];
        memaccess_cur.SaveState(out);
    }
}

void
thread_info_c::RestoreState(std::istream &in)
{
    if (!read_match(in, "info"))
        throw std::runtime_error("mismatch marker 'info'");

    id = read_u32(in);
    running = read_bool(in);
    finished = read_bool(in);

    last_kind = read_u32(in);
    hevent_wait = read_u32(in);
    hevent_seq = read_u32(in);
    hmutex_wait = read_u32(in);
    hmutex_seq = read_u32(in);
    critsec_wait = read_u32(in);
    critsec_seq = read_u32(in);
    filepos = read_u64(in);
    within_bb = (app_pc)read_u32(in);
    bb_count = read_u32(in);
    now_ts = read_u64(in);

    apicalls.clear();

    for(int i = read_u32(in);   // apicalls size
        i; i--) {
        apicalls.push_back(df_apicall_c());
        apicall_now = &apicalls.back();
        apicall_now->RestoreState(in);
    }

    int j = (signed)read_u32(in); // apicall_now
    apicall_now = j == -1 ? nullptr : &apicalls[j];

    // stacks
    stacks.clear();
    
    for(int i = read_u32(in);   // stacks size
        i; i--) {
        stacks.push_back(df_stackitem_c());
        df_stackitem_c *stackitem_cur = &stacks.back();
        stackitem_cur->RestoreState(in);
    }

    pending_state = read_u32(in);

    if (pending_state) {
        read_data(in, (char*)&pending_bb, 16);
    }
    
    last_bb.RestoreState(in);

    // memaccesses
    memaccesses.clear();
    
    for(int i = read_u32(in);   // memaccesses size
        i; i--) {
        memaccesses.push_back(df_memaccess_c());
        df_memaccess_c *memaccess_cur = &memaccesses.back();
        memaccess_cur->RestoreState(in);
    }
}

void
thread_info_c::Dump(int indent)
{
    std::string _tab = std::string(indent, ' ');

    std::cout << _tab << "thread id: " << std::dec << id << std::endl;
    std::cout << _tab << "filename: " << logparser.filename() << std::endl;
    std::cout << _tab << "running: " << running << std::endl;
    std::cout << _tab << "finished: " << finished << std::endl;

    std::cout << _tab << "last_kind:";
    if (last_kind)
        std::cout << " '" << std::string((char*)&last_kind, 4) << "' ";
    else
        std::cout << "?";
    std::cout << std::endl;

    std::cout << _tab <<  "hevent_wait: " << hevent_wait;
    std::cout << _tab <<  "  hevent_seq: " << hevent_seq << std::endl;
    std::cout << _tab <<  "hmutex_wait: " << hmutex_wait;
    std::cout << _tab <<  "  hmutex_seq: " << hmutex_seq << std::endl;
    std::cout << _tab <<  "critsec_wait: " << critsec_wait;
    std::cout << _tab <<  "  critsec_seq: " << critsec_seq << std::endl;
    std::cout << _tab <<  "filepos: " << filepos << std::endl;
    std::cout << _tab <<  "within_bb: 0x" << std::hex << within_bb << std::endl;
    std::cout << _tab <<  "bb_count: " << std::dec << bb_count << std::endl;
    std::cout << _tab <<  "now_ts: " << now_ts << std::endl;

    int j = -1;
    for (uint i = 0; i < apicalls.size(); ++i) {
        df_apicall_c &apicall_cur = apicalls[i];
        std::cout <<  _tab << "  apicalls[" << i << "]: ";
        apicall_cur.Dump(indent + 2);

        if (apicall_now == &apicall_cur) j = i;
    }
    std::cout << _tab << "apicall_now: " << std::dec << j << std::endl;

    for (uint i = 0; i < stacks.size(); ++i) {
        df_stackitem_c &stackitem_cur = stacks[i];
        std::cout <<  _tab << "  stacks[" << i << "]: ";
        stackitem_cur.Dump(indent + 2);
    }

    std::cout << _tab << "pending_state: " << pending_state << std::endl;
    if (pending_state) {
        std::cout << _tab << "  pending_bb.kind:0x" << std::hex << pending_bb.kind;
        if (pending_bb.kind)
            std::cout << " '" << std::string((char*)&pending_bb.kind, 4) << "' ";
        std::cout << std::endl;
    }
    std::cout << _tab << "last_bb: ";
    last_bb.Dump(indent + 2);

    for (uint i = 0; i < memaccesses.size(); ++i) {
        df_memaccess_c &memaccess_cur = memaccesses[i];
        std::cout <<  _tab << "  memaccesses[" << i << "]: ";
        memaccess_cur.Dump(indent + 2);
    }
}

void
df_apicall_c::SaveState(std::ostream &out)
{
    out << "call";

    write_u32(out, func);
    write_str(out, name);
    write_u32(out, ret_addr);
    write_u64(out, ts);
    write_u32(out, s_depth);

    write_u32(out, callargs.size());

    for (auto carg: callargs) {
        write_u32(out, carg);
    }

    write_u32(out, callstrings.size());

    for (auto cstr: callstrings) {
        write_str(out, cstr);
    }

    write_u32(out, retargs.size());

    for (auto rarg: retargs) {
        write_u32(out, rarg);
    }

    write_u32(out, retstrings.size());

    for (auto rstr: retstrings) {
        write_str(out, rstr);
    }
}

void
df_apicall_c::RestoreState(std::istream &in)
{
    if (!read_match(in, "call")) 
        throw std::runtime_error("mismatch marker 'call'");

    func = read_u32(in);
    name = read_str(in);
    ret_addr = read_u32(in);
    ts = read_u64(in);
    s_depth = read_u32(in);

    callargs.clear();
    for (int i = read_u32(in); i; i--) {
        int carg = read_u32(in);
        callargs.push_back(carg);
    }

    callstrings.clear();
    for (int i = read_u32(in); i; i--) {
        std::string cstr = read_str(in);
        callstrings.push_back(cstr);
    }

    retargs.clear();
    for (int i = read_u32(in); i; i--) {
        int rarg = read_u32(in);
        retargs.push_back(rarg);
    }

    retstrings.clear();
    for (int i = read_u32(in); i; i--) {
        std::string rstr = read_str(in);
        retstrings.push_back(rstr);
    }
}

void
df_apicall_c::Dump(int indent)
{
    std::string _tab = std::string(indent, ' ');

    std::cout << _tab << "call " << name << "@0x" << std::hex << func << "(";
    for (auto carg: callargs) {
        std::cout << std::dec << carg << ",";
    }
    for (auto cstr: callstrings) {
        std::cout << cstr << ",";
    }
    std::cout << ") -> result {";
    for (auto rarg: retargs) {
        std::cout << std::dec << rarg << ",";
    }
    for (auto rstr: retstrings) {
        std::cout << rstr << ",";
    }
    std::cout << "} return: 0x" << std::hex << ret_addr;
    std::cout << " ts:" << std::dec << ts;
    std::cout << " s-depth:" << s_depth;
    std::cout << std::endl;
}

void
df_stackitem_c::Dump(int indent)
{
    std::string _tab = std::string(indent, ' ');

    std::cout << _tab << "kind:";
    if (kind)
        std::cout << " '" << std::string((char*)&kind, 4) << "'";
    else
        std::cout << "?";

    if (is_sub)
        std::cout << " (sub)";
    std::cout << " pc:0x" << std::hex << pc << " next:0x" << next << " " << std::dec;
    switch (link) {
        case LINK_CALL: std::cout << "CALL"; break;
        case LINK_RETURN: std::cout << "RETURN"; break;
        case LINK_JMP: std::cout << "JMP"; break;
        default: std::cout << link;
    }
    std::cout << " ts:" << std::dec << ts;
    std::cout << " s-depth:" << s_depth;
    std::cout << std::endl;
}

void df_stackitem_c::SaveState(std::ostream &out)
{
    out << "stem";

    write_u32(out, kind);
    write_u32(out, pc);
    write_u32(out, next);
    write_u32(out, flags);
    write_u64(out, ts);
    write_u32(out, s_depth);
}

void df_stackitem_c::RestoreState(std::istream &in)
{
    if (!read_match(in, "stem"))
        throw std::runtime_error("mismatch marker 'stem'");

    kind = read_u32(in);
    pc = read_u32(in);
    next = read_u32(in);
    flags = read_u32(in);
    ts = read_u64(in);
    s_depth = read_u32(in);
}

void
df_memaccess_c::Dump(int indent)
{
    std::string _tab = std::string(indent, ' ');

    std::cout << _tab;
    if (is_write) std::cout << "mem write 0x"; else std::cout << "mem read 0x";
    std::cout << std::hex << addr << " pc:0x" << pc;
    std::cout << " size:" << std::dec << size;
    if (is_loop) {
        std::cout << " loop:" << loop_from << ".." << loop_to;
    }
    std::cout << std::endl;
}

void
df_memaccess_c::SaveState(std::ostream &out)
{
    out << "memo";

    write_u32(out, pc);
    write_u32(out, addr);
    write_u32(out, size);
    write_bool(out, is_write);
    write_bool(out, is_loop);
    if (is_loop) {
        write_u32(out, loop_from);
        write_u32(out, loop_to);
    }
}

void
df_memaccess_c::RestoreState(std::istream &in)
{
    if (!read_match(in, "memo"))
        throw std::runtime_error("mismatch marker 'memo'");

    pc = read_u32(in);
    addr = read_u32(in);
    size = read_u32(in);
    is_write = read_bool(in);
    is_loop = read_bool(in);
    if (is_loop) {
        loop_from = read_u32(in);
        loop_to = read_u32(in);
    }
}

LogRunner*
LogRunner::instance() {
    static std::unique_ptr<LogRunner> logrunner = std::unique_ptr<LogRunner>(new LogRunner());
    return logrunner.get();
};

LogRunnerObserver::LogRunnerObserver() {
    LogRunner *logrunner = LogRunner::instance();
    logrunner_ = logrunner;
    logrunner->AddObserver(this);
}

void
LogRunner::AddObserver(LogRunnerObserver *observer)
{
    for (auto &stored_observer : observers_) {
        if (stored_observer->GetName() == observer->GetName()) {
            std::cout << "Observer: " << observer->GetName() << " already stored." << std::endl;
            return;
        }
    }
    observers_.push_back(observer);
}

void
LogRunner::ListObservers() {
    std::cout << "observers: " << observers_.size() << std::endl;
    for (auto &observer : observers_) {
        std::cout << "- " << observer->GetName() << std::endl;
    }
}

void
LogRunner::OnThread(uint thread_id, uint handle_id, uint sp)
{
    for (auto &observer : observers_)
        observer->OnThread(thread_id, handle_id, sp);
}

void LogRunner::OnPush(uint thread_id, df_stackitem_c &the_bb, df_apicall_c *apicall_now)
{
    for (auto &observer : observers_)
        observer->OnPush(thread_id, the_bb, apicall_now);
}

void LogRunner::OnPop(uint thread_id, df_stackitem_c &the_bb)
{
    for (auto &observer : observers_)
        observer->OnPop(thread_id, the_bb);
}

void
LogRunner::OnBB(uint thread_id, df_stackitem_c &last_bb, vec_memaccess_t &memaccesses)
{
    for (auto &observer : observers_)
        observer->OnBB(thread_id, last_bb, memaccesses);
}

void
LogRunner::OnApiCall(uint thread_id, df_apicall_c &apicall_ret)
{
    for (auto &observer : observers_)
        observer->OnApiCall(thread_id, apicall_ret);
}

void
LogRunner::OnApiUntracked(uint thread_id, df_stackitem_c &bb_untracked_api)
{
    for (auto &observer : observers_)
        observer->OnApiUntracked(thread_id, bb_untracked_api);
}

void
LogRunner::OnStart()
{
    for (auto &observer : observers_)
        observer->OnStart();
}

void
LogRunner::OnFinish()
{
    for (auto &observer : observers_)
        observer->OnFinish();
}

void
LogRunner::DoCommand(int argc, const char* argv[])
{
    for (auto &observer : observers_)
        observer->OnCommand(argc, argv);
}

std::string
LogRunner::GetPrefix()
{
    std::string prefix = filename_;
    if (filename_.empty())
        throw std::runtime_error("GetPrefix on empty filename (not Open yet?)");
    std::string::size_type n;
    n = filename_.rfind('.');
    if (n != std::string::npos) {
        prefix = filename_.substr(0, n);
    }

    return prefix;
}

// TODO: will be remove to dataflow
void
LogRunner::SetExecutable(std::string exename)
{
    std::ifstream f(exename);
    if (f.good()) 
        exename_ = exename;
    else {
        throw std::runtime_error("SetExecutable on not existent exename");
    }
}

std::string
LogRunner::GetExecutable()
{
    return exename_;
}