#include <iostream>
#include <fstream>
#include <sstream>
#include <string>
#include <map>
#include <vector>
#include <iterator>
#include <stdexcept>   // for exception, runtime_error, out_of_range

#include "logrunner.h"
#include "serializer.h"

bool
LogRunner::Open(std::string &filename) {
    filename_ = filename;
    const uint main_thread_id = 0;

    if (info_threads_[main_thread_id].logparser.open(filename_.c_str())) {
        std::cout << "Open:" << filename_ << std::endl;
        info_threads_[main_thread_id].running = true;
        info_threads_[main_thread_id].running_ts = 0;
    } else {
        std::cout << "Fail to open .bin: " << filename_ << std::endl;
        info_threads_[main_thread_id].finished = true;
        return false;
    }

    it_thread_ = info_threads_.end();
    thread_ts_ = 1;
    bb_counts_ = 0;
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
    bb_counts_ += thread_info.bb_count;

    std::cout << std::dec << thread_info.id << "] ";
    std::cout << "thread finished. ";
    std::cout << "bb count: " << thread_info.bb_count << std::endl;
}

bool
LogRunner::Step()
{
    uint inactive = 0;
    for(; inactive < info_threads_.size();
            inactive++, it_thread_++) {
        if (it_thread_ == info_threads_.end()) {
            it_thread_ = info_threads_.begin();
            thread_ts_++;
        }
        if (it_thread_->second.finished)
            continue;
        if (!it_thread_->second.running)
            CheckPending(it_thread_->second);
        if (it_thread_->second.running && thread_ts_ > it_thread_->second.running_ts)
            break;
    }

    if (inactive == info_threads_.size()) {
        return false;
    }

    uint thread_id = it_thread_->first;
    thread_info_c &thread_info = it_thread_->second;
    auto it_next = std::next(it_thread_, 1);

    while (thread_info.running) {
        uint kind;

        // Check Lib Ret first
        if (thread_info.apicall_now) {
            kind = thread_info.logparser.peek();
            if (kind != KIND_ARGS && kind != KIND_STRING && thread_info.last_kind == KIND_LIB_RET) {
                ApiCallRet(thread_info);
                break;
            }
        }

        // Forward peek kind
        if (thread_info.within_bb) {
            kind = thread_info.logparser.peek();
            if (kind == KIND_BB || kind == KIND_LIB_CALL) {
                DoEndBB(thread_info /* , bb mem read/write */);
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
        }

        if (!item) {
            FinishThread(thread_info);
            info_threads_.erase(it_thread_);
            break;
        }
        kind = *(uint*)item;
        mem_ref_t *buf_bb;

        switch (kind) {
            case KIND_BB:
                buf_bb = (mem_ref_t*)item;
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
                break;
            case KIND_LOOP:
                // mem_ref_t *buf_item = reinterpret_cast<mem_ref_t*>(item);
                break;
            case KIND_READ:
                // mem_ref_t *buf_item = reinterpret_cast<mem_ref_t*>(item);
                break;
            case KIND_WRITE:
                // mem_ref_t *buf_item = reinterpret_cast<mem_ref_t*>(item);
                break;
            case KIND_EXCEPTION:
                // buf_exception_t *buf_item = reinterpret_cast<buf_exception_t*>(item);
                break;
            case KIND_MODULE:
                // buf_module_t *buf_mod = reinterpret_cast<buf_module_t*>(item);
                // const char* copyupto = std::find(buf_mod->name, buf_mod->name + sizeof(buf_mod->name), 0);
                // std::string name(buf_mod->name, copyupto - buf_mod->name);
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
            default:
                throw std::runtime_error("unknown kind");
        } //

        //std::cout << std::string((char*)&kind, 4) << std::endl;

        // Last Kind
        if (kind != KIND_ARGS && kind != KIND_STRING) {
            thread_info.last_kind = kind;
        }
    }

    it_thread_ = it_next;

    return true;
}

void
LogRunner::DoKindBB(thread_info_c &thread_info, mem_ref_t &buf_bb)
{
    thread_info.within_bb = (uint) buf_bb.pc;
    uint len_last_instr = buf_bb.size & ((1 << LINK_SHIFT_FIELD) - 1);
    uint bb_link = buf_bb.size >> LINK_SHIFT_FIELD;
    app_pc next_bb = buf_bb.addr + len_last_instr;

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
    if (thread_info.last_bb.link == LINK_CALL) {
        size_t i = thread_info.stacks.size();
        if (i) {
            df_stackitem_c& item = thread_info.stacks[i-1];
            if (item.kind == KIND_BB && item.next == thread_info.within_bb) {
                thread_info.stacks.erase(
                    thread_info.stacks.begin()+i-1,
                    thread_info.stacks.end());
            }
        }
    }
    if (thread_info.last_bb.link == LINK_RETURN) {
        size_t i;
        for (i = thread_info.stacks.size(); i > 0; --i) {
            df_stackitem_c& item = thread_info.stacks[i-1];
            if (item.kind == KIND_BB && item.next == thread_info.within_bb) {
                thread_info.stacks.erase(
                    thread_info.stacks.begin()+i-1,
                    thread_info.stacks.end());
                break;
            }
            if (item.kind == KIND_LIB_CALL)
                break;
        }
        if (i == 0) {
            if (thread_info.id == 0) {
                std::cout << std::dec << thread_info.id;
                std::cout << "] Mismatch stack, return to 0x" << std::hex << thread_info.within_bb
                    << " from 0x" << thread_info.last_bb.pc
                    << " stack size = " << std::dec << thread_info.stacks.size();

                if (thread_info.stacks.size()) {
                    df_stackitem_c& item = thread_info.stacks.back();
                    std::cout << " TOP: 0x" << std::hex << item.pc;
                }

                if (thread_info.apicalls.size() ) {
                    df_apicall_c &libret_last = thread_info.apicalls.back();
                    std::cout << " Lib:0x " << std::hex << libret_last.func;
                    std::cout << " " << libret_last.name;
                    std::cout << " Ret:0x " << std::hex << libret_last.ret_addr;
                }
                std::cout << " (A:" << std::dec << thread_ts_ << ")";
                std::cout << std::endl;

                //throw std::runtime_error ("DIE!");
            }
        }
    }

    thread_info.last_bb.kind = KIND_BB;
    thread_info.last_bb.pc   = buf_bb.pc;
    thread_info.last_bb.next = next_bb;
    thread_info.last_bb.link = bb_link;
    thread_info.last_bb.ts   = thread_ts_;

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

    thread_info.stacks.push_back(df_stackitem_c());
    df_stackitem_c& item = thread_info.stacks.back();

    item.kind = KIND_LIB_CALL;
    item.pc   = buf_libcall.func;
    item.next = buf_libcall.ret_addr;
    item.link = 0;

    thread_info.apicalls.push_back(df_apicall_c());
    thread_info.apicall_now = &thread_info.apicalls.back();

    thread_info.apicall_now->func = buf_libcall.func;
    thread_info.apicall_now->ret_addr = buf_libcall.ret_addr;
    thread_info.apicall_now->name = name;
    thread_info.apicall_now->callargs.push_back((uint)buf_libcall.arg);
    thread_info.apicall_now->ts = thread_ts_;
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
            thread_info.stacks.erase(
                thread_info.stacks.begin()+i-1,
                thread_info.stacks.end());
            break;
        }
    }
    if (i == 0) {
        std::cout << std::dec << thread_info.id;
        std::cout << "] Mismatch stack, return to 0x" << std::hex << buf_libret.ret_addr
            << " from func 0x" << libret_last.func
            << " stack size = " << std::dec << thread_info.stacks.size()
            << std::endl;
    }

    if (thread_info.apicalls.size()) {
        // FIXME!
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

    map_uint_uint_t *p_wait_seqs = &wait_seqs_;
    if (sync_kind == SYNC_CRITSEC) p_wait_seqs = &critsec_seqs_;

    if ((*p_wait_seqs)[wait] == seq - 1) {
        (*p_wait_seqs)[wait] = seq;
    } else {
        switch (sync_kind) {
        case SYNC_EVENT:
            thread_info.hevent_wait = wait;
            thread_info.hevent_seq = seq;
            thread_info.running = false;
#if 0
            std::cout << std::dec << thread_info.id << "] ";
            std::cout << "thread pause - event #" << std::dec << wait
                << " !" << seq << std::endl;
#endif
            break;
        case SYNC_MUTEX:
            thread_info.hmutex_wait = wait;
            thread_info.hmutex_seq = seq;
            thread_info.running = false;
#if 0
            std::cout << std::dec << thread_info.id << "] ";
            std::cout << "thread pause - mutex #" << std::dec << wait
                << " !" << seq << std::endl;
#endif
            break;
        case SYNC_CRITSEC:
            thread_info.critsec_wait = wait;
            thread_info.critsec_seq = seq;
            thread_info.running = false;
#if 0
            std::cout << std::dec << thread_info.id << "] ";
            std::cout << "thread pause - critsec #" << std::dec << wait
                << " !" << seq << std::endl;
#endif
            break;
        }
    }
}

void
LogRunner::DoKindCritSec(thread_info_c &thread_info, buf_event_t &buf_sync)
{
    uint wait = buf_sync.params[0];
    uint seq = buf_sync.params[1];

    if (critsec_seqs_[wait] == seq - 1) {
        critsec_seqs_[wait] = seq;
    } else {
    }
}

void
LogRunner::DoKindWndProc(thread_info_c &thread_info, buf_event_t &buf_wndproc)
{
    uint umsg = buf_wndproc.params[0];
    uint wparam = buf_wndproc.params[1];
    uint lparam = buf_wndproc.params[2];

#if 0
    std::cout << std::dec << thread_info.id << "] ";
    std::cout << "wnd proc (" << std::hex << umsg << ", " << wparam << ", " << lparam
        << ")" << std::endl;
#endif
}

void
LogRunner::ThreadWaitCritSec(thread_info_c &thread_info)
{
    if (thread_info.critsec_wait) {
        if (critsec_seqs_[thread_info.critsec_wait] == thread_info.critsec_seq - 1) {
            critsec_seqs_[thread_info.critsec_wait] = thread_info.critsec_seq;
#if 0
            std::cout << std::dec << thread_info.id << "] ";
            std::cout << "thread continue - event: #" << std::dec << thread_info.critsec_wait << std::endl;
#endif
            thread_info.running = true;
            thread_info.running_ts = thread_ts_;
            thread_info.critsec_wait = 0;
        }
    }
}

void
LogRunner::ThreadWaitEvent(thread_info_c &thread_info)
{
    if (thread_info.hevent_wait) {
        if (wait_seqs_[thread_info.hevent_wait] == thread_info.hevent_seq - 1) {
            wait_seqs_[thread_info.hevent_wait] = thread_info.hevent_seq;
#if 0
            std::cout << std::dec << thread_info.id << "] ";
            std::cout << "thread continue - event: #" << std::dec << thread_info.hevent_wait << std::endl;
#endif
            thread_info.running = true;
            thread_info.running_ts = thread_ts_;
            thread_info.hevent_wait = 0;
        }
    }
}

void
LogRunner::ThreadWaitMutex(thread_info_c &thread_info)
{
    if (thread_info.hmutex_wait) {
        if (wait_seqs_[thread_info.hmutex_wait] == thread_info.hmutex_seq - 1) {
            wait_seqs_[thread_info.hmutex_wait] = thread_info.hmutex_seq;
#if 0
            std::cout << std::dec << thread_info.id << "] ";
            std::cout << "thread continue - mutex: #" << std::dec << thread_info.hmutex_wait << std::endl;
#endif
            thread_info.running = true;
            thread_info.running_ts = thread_ts_;
            thread_info.hmutex_wait = 0;
        }
    }
}

void
LogRunner::OnApiCall(thread_info_c &thread_info, df_apicall_c &apicall_ret)
{
    bool verbose = show_options_ & LR_SHOW_LIBCALL;
    if (!verbose)
    for (auto filter_addr : filter_apicall_addrs_) {
        if (filter_addr == apicall_ret.func) {
            verbose = true; break;
        }
    }
    if (verbose) {
        std::cout << std::dec << thread_ts() << "@ ";
        std::cout << std::dec << thread_info.id << "] ";
        apicall_ret.Dump();
    }
}

void
LogRunner::ApiCallRet(thread_info_c &thread_info)
{
    df_apicall_c apicall_ret = *thread_info.apicall_now;
    thread_info.apicalls.pop_back();
    thread_info.apicall_now = nullptr;

    // these api calls are mandatory for sync
    if (apicall_ret.name == "CreateThread")
        OnCreateThread(apicall_ret);
    else if (apicall_ret.name == "ResumeThread")
        OnResumeThread(apicall_ret);

    OnApiCall(thread_info, apicall_ret);
}

void
LogRunner::DoEndBB(thread_info_c &thread_info /* , bb mem read/write */)
{
    if (thread_info.within_bb != thread_info.last_bb.pc) {
        throw std::runtime_error("Mismatch last_bb with within_bb !");
    } 
    OnBB(thread_info, thread_info.last_bb);
    thread_info.within_bb = 0;
}

void
LogRunner::OnBB(thread_info_c &thread_info, df_stackitem_c &last_bb)
{
    if (show_options_ & LR_SHOW_BB) {
        std::cout << std::dec << thread_ts() << "@ ";
        std::cout << std::dec << thread_info.id << "] ";
        last_bb.Dump();
    }
}

void
LogRunner::OnCreateThread(df_apicall_c &apicall)
{
    uint new_thread_id = apicall.retargs[1];
    bool new_suspended = (apicall.callargs[3] & 0x4) == 0x4;

    if (info_threads_.find(new_thread_id) != info_threads_.end()) {
        std::cout << "Already created with thread id? "
            << std::dec << new_thread_id << std::endl;
    } else if (new_thread_id) {
        std::ostringstream oss;
        oss << filename_ << "." << std::dec << new_thread_id;

        if (! info_threads_[new_thread_id].logparser.open(oss.str().c_str())) {
            std::cout << "Fail to open .bin: " << oss.str() << std::endl;
            info_threads_[new_thread_id].finished = true;
        } else {
            info_threads_[new_thread_id].running = new_suspended ? false : true;

            if (info_threads_[new_thread_id].running) {
                info_threads_[new_thread_id].running_ts = thread_ts_;
                std::cout << std::dec << new_thread_id << "] ";
                std::cout << "thread starting." << std::endl;
            } else {
                std::cout << std::dec << new_thread_id << "] ";
                std::cout << "thread created." << std::endl;
            }
        }

        if (info_threads_[new_thread_id].finished) {
            info_threads_.erase(new_thread_id);
        } else {
            info_threads_[new_thread_id].id = new_thread_id;
        }
    }
}

void
LogRunner::OnResumeThread(df_apicall_c &apicall)
{
    uint resume_thread_id = apicall.retargs[1];
    if (info_threads_.find(resume_thread_id) != info_threads_.end()) {
        info_threads_[resume_thread_id].running = true;
        info_threads_[resume_thread_id].running_ts = thread_ts_;
        std::cout << std::dec << resume_thread_id << "] ";
        std::cout << "thread resuming (A:" << thread_ts_ << ")" << std::endl;
    }
}
void
LogRunner::Summary()
{
    uint bb_counts = 0;

    // Summary
    for (auto it = info_threads_.begin(); it != info_threads_.end(); ++it) {
        uint thread_id = it->first;
        thread_info_c &thread_info = it->second;

        if (!thread_info.finished) {
            std::cout << std::dec << thread_id << "] thread not finished!";
            if (thread_info.running) {
                std::cout << " running";
            } else {
                std::cout << " suspended";
                if (thread_info.hevent_wait) {
                    std::cout << " event #" << thread_info.hevent_wait << " at " << thread_info.hevent_seq;
                    std::cout << " of " << wait_seqs_[thread_info.hevent_wait];
                }
                if (thread_info.hmutex_wait) {
                    std::cout << " mutex #" << thread_info.hmutex_wait << " at " << thread_info.hmutex_seq;
                    std::cout << " of " << wait_seqs_[thread_info.hmutex_wait];
                }
                if (thread_info.critsec_wait) {
                    std::cout << " critsec #" << thread_info.critsec_wait << " at " << thread_info.critsec_seq;
                    std::cout << " of " << critsec_seqs_[thread_info.critsec_wait];
                }
            }
            std::cout << std::endl;

            FinishThread(thread_info);
        }
    }

    std::cout << "bb counts: " << bb_counts_ << std::endl;
    std::cout << "thread ts: " << thread_ts_ << std::endl;
}

void
LogRunner::SaveSymbols(std::ostream &out)
{
    out << "symb";

    write_u32(out, symbol_names_.size());

    for (auto it : symbol_names_) {
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

    for (auto it : wait_seqs_) {
        write_u32(out, it.first);
        write_u32(out, it.second);
    }

    out << "crit";
    write_u32(out, critsec_seqs_.size());

    for (auto it : critsec_seqs_) {
        write_u32(out, it.first);
        write_u32(out, it.second);
    }

    out << "thrd";
    write_u32(out, info_threads_.size());

    for (auto it = info_threads_.begin(); it != info_threads_.end(); ++it) {
        thread_info_c &thread_info = it->second;

        write_u32(out, it->first);

        thread_info.SaveState(out);
    }

    write_u32(out, it_thread_->first);

    write_u64(out, thread_ts_);
    
    write_u64(out, bb_counts_);
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
        uint32_t second = read_u32(in);
        wait_seqs_[first] = second;
    }

    if (!read_match(in, "crit"))
        throw std::runtime_error("mismatch marker 'crit'");

    critsec_seqs_.clear();

    for(int i = read_u32(in); i; i--) {
        uint32_t first = read_u32(in);
        uint32_t second = read_u32(in);
        critsec_seqs_[first] = second;
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
    }

    uint32_t thread_id = read_u32(in);

    it_thread_ = info_threads_.find(thread_id);
    if (it_thread_ == info_threads_.end())
        throw std::runtime_error("ERROR: don't know current thread");

    thread_ts_ = read_u64(in);
    bb_counts_ = read_u64(in);
}

void
LogRunner::Dump(int indent)
{
    std::string _tab = std::string(indent, ' ');

    for (auto &kv : wait_seqs_) {
        std::cout << _tab << "wait_seqs_[" << kv.first << "] : " << kv.second << std::endl;
    }
    for (auto &kv : critsec_seqs_) {
        std::cout << _tab << "critsec_seqs_[" << kv.first << "] : " << kv.second << std::endl;
    }
    for (auto &kv : info_threads_) {
        std::cout << _tab << "info_threads_[" << kv.first << "] : " << std::endl;
        kv.second.Dump(indent + 2);
    }
    std::cout << _tab << "it_thread_: " << std::dec << it_thread_->second.id <<  std::endl;
    std::cout << _tab << std::dec << "thread_ts_: " << thread_ts_ <<  std::endl;
    std::cout << _tab << "bb_counts_: " << bb_counts_ <<  std::endl;
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

    write_u64(out, running_ts);

    write_u32(out, apicalls.size());

    int j = -1;
    for (uint i = 0; i < apicalls.size(); ++i) {
        df_apicall_c &apicall_cur = apicalls[i];
        apicall_cur.SaveState(out);

        if (apicall_now == &apicall_cur) j = i;
    }

    write_u32(out, j);

    write_u32(out, stacks.size());

    int k = -1;
    for (uint i = 0; i < stacks.size(); ++i) {
        df_stackitem_c &stackitem_cur = stacks[i];
        stackitem_cur.SaveState(out);
    }

    write_u32(out, pending_state);

    if (pending_state) {
        write_data(out, (char*)&pending_bb, 16);
    }

    last_bb.SaveState(out);
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
    running_ts = read_u64(in);

    apicalls.clear();

    for(int i = read_u32(in);   // apicalls size
        i; i--) {
        apicalls.push_back(df_apicall_c());
        apicall_now = &apicalls.back();
        apicall_now->RestoreState(in);
    }

    int j = (signed)read_u32(in); // apicall_now
    apicall_now = j == -1 ? nullptr : &apicalls[j];

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
}

void
thread_info_c::Dump(int indent)
{
    std::string _tab = std::string(indent, ' ');

    std::cout << _tab << "thread id: " << std::dec << id << std::endl;
    std::cout << _tab << "filename: " << logparser.filename() << std::endl;
    std::cout << _tab << "running: " << running << std::endl;
    std::cout << _tab << "finished: " << finished << std::endl;

    std::cout << _tab << "last_kind:0x" << std::hex << last_kind << std::dec;
    if (last_kind)
        std::cout << " '" << std::string((char*)&last_kind, 4) << "' ";
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
    std::cout << _tab <<  "running_ts: " << running_ts << std::endl;

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
}

void
df_apicall_c::SaveState(std::ostream &out)
{
    out << "call";

    write_u32(out, func);
    write_str(out, name);
    write_u32(out, ret_addr);
    write_u64(out, ts);

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

    std::cout << _tab << "call " << name << "@" << func << "( ";
    for (auto carg: callargs) {
        std::cout << std::dec << carg << ", ";
    }
    for (auto cstr: callstrings) {
        std::cout << cstr << ", ";
    }
    std::cout << ") -> { ";
    for (auto rarg: retargs) {
        std::cout << std::dec << rarg << ", ";
    }
    for (auto rstr: retstrings) {
        std::cout << rstr << ", ";
    }
    std::cout << "} => 0x" << std::hex << ret_addr;
    std::cout << " ts:" << std::dec << ts;
    std::cout << std::endl;
}

void
df_stackitem_c::Dump(int indent)
{
    std::string _tab = std::string(indent, ' ');

    std::cout << _tab << "kind:0x" << std::hex << kind;
    if (kind)
        std::cout << " '" << std::string((char*)&kind, 4) << "'";
    std::cout << " pc:0x" << std::hex << pc << " next:0x" << next << " " << std::dec;
    switch (link) {
        case LINK_CALL: std::cout << "CALL"; break;
        case LINK_RETURN: std::cout << "RETURN"; break;
        case LINK_JMP: std::cout << "JMP"; break;
        default: std::cout << link;
    }
    std::cout << " ts:" << std::dec << ts;
    std::cout << std::endl;
}

void df_stackitem_c::SaveState(std::ostream &out)
{
    out << "stem";

    write_u32(out, kind);
    write_u32(out, pc);
    write_u32(out, next);
    write_u32(out, link);
    write_u64(out, ts);
}

void df_stackitem_c::RestoreState(std::istream &in)
{
    if (!read_match(in, "stem"))
        throw std::runtime_error("mismatch marker 'stem'");

    kind = read_u32(in);
    pc = read_u32(in);
    next = read_u32(in);
    link = read_u32(in);
    ts = read_u64(in);
}