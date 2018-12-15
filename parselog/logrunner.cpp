#include <iostream>
#include <fstream>
#include <sstream>
#include <string>
#include <map>
#include <vector>
#include <stdexcept>   // for exception, runtime_error, out_of_range

#include "logrunner.h"
#include "serializer.h"

#define LR_SHOW_BB 0x1
#define LR_SHOW_LIBCALL 0x2

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

    std::cout << std::dec << thread_info.id << "] ";
    std::cout << "thread finished. ";
    std::cout << "bb count: " << thread_info.bb_count << std::endl;
}

bool
LogRunner::Step()
{
    bool is_pending_thread_ts = false;
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
    auto it_current = it_thread_++;
    if (it_thread_ == info_threads_.end()) {
        it_thread_ = info_threads_.begin();
        is_pending_thread_ts = true;
    }

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
            info_threads_.erase(it_current);
            break;
        }
        kind = *(uint*)item;
        mem_ref_t *buf_bb;

        switch (kind) {
            case KIND_BB:
                buf_bb = (mem_ref_t*)item;
                if (thread_info.pending_state == 1) {
                    std::cout << thread_info.pending_state;
                    std::cout << " " << std::dec <<  thread_info.id;
                    std::cout << " " << std::hex <<  buf_bb->pc;
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

    if (is_pending_thread_ts) thread_ts_++;

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
                std::cout << "] Mismatch stack for 0x" << std::hex << thread_info.within_bb
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
                std::cout << std::endl;

                //throw std::runtime_error ("DIE!");
            }
        }
    }

    thread_info.last_bb.kind = KIND_BB;
    thread_info.last_bb.pc   = buf_bb.pc;
    thread_info.last_bb.next = next_bb;
    thread_info.last_bb.link = bb_link;

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
            std::cout << "Filter apicall: " << filter_name << " addr: " << std::hex << buf_sym.func << std::endl;
        }
    }
}

void
LogRunner::DoKindLibCall(thread_info_c &thread_info, buf_lib_call_t &buf_libcall)
{
    std::string name;
    if (symbol_names_.find(buf_libcall.func) != symbol_names_.end()) {
        name = symbol_names_[buf_libcall.func];
    }

#if 0
    if (thread_info.id == 0) {
        std::cout << std::dec << thread_info.id << "] ";
        std::cout << "Lib Call: 0x" << std::hex << buf_libcall.func;
        std::cout << " " << name;
        std::cout << " Ret:0x" << buf_libcall.ret_addr;
        std::cout << std::endl;
    }
#endif
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
}

void
LogRunner::DoKindLibRet(thread_info_c &thread_info, buf_lib_ret_t &buf_libret)
{
    std::string name;
    if (symbol_names_.find(buf_libret.func) != symbol_names_.end()) {
        name = symbol_names_[buf_libret.func];
    }

#if 0
    if (thread_info.id == 0) {
        std::cout << std::dec << thread_info.id << "] ";
        std::cout << "Lib Ret :0x " << std::hex << buf_libret.func;
        std::cout << " " << name;
        std::cout << " Ret:0x" << buf_libret.ret_addr;
        std::cout << std::endl;
    }
#endif
    if (thread_info.apicalls.size() == 0)
        throw std::runtime_error ("Apicall stacks empty!");

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
        std::cout << "] Mismatch stack for 0x" << std::hex << buf_libret.ret_addr
            << " from func 0x" << libret_last.func
            << " stack size = " << std::dec << thread_info.stacks.size()
            << std::endl;
    }

    thread_info.apicall_now = &thread_info.apicalls.back();
    thread_info.apicall_now->retargs.push_back((uint)buf_libret.retval);
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
df_apicall_c::Dump()
{
    std::cout << "call " << name << "@" << func << "( ";
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
    std::cout << "} => " << std::hex << ret_addr << std::endl;
}

void
LogRunner::OnApiCall(uint thread_id, df_apicall_c &apicall_ret)
{
    for (auto filter_addr : filter_apicall_addrs_) {
        if (filter_addr == apicall_ret.func) {
            std::cout << std::dec << thread_id << "] ";
            apicall_ret.Dump();
        }
    }
}

void
LogRunner::ApiCallRet(thread_info_c &thread_info)
{
    df_apicall_c apicall_ret = *thread_info.apicall_now;
    thread_info.apicalls.pop_back();
    thread_info.apicall_now = nullptr;

    if (apicall_ret.name == "CreateThread")
        OnCreateThread(apicall_ret);
    else if (apicall_ret.name == "ResumeThread")
        OnResumeThread(apicall_ret);

    OnApiCall(thread_info.id, apicall_ret);
}

void
LogRunner::DoEndBB(thread_info_c &thread_info /* , bb mem read/write */)
{
    if (show_options_ & LR_SHOW_BB) {
        std::cout << std::dec << thread_info.id << "] ";
        std::cout << "bb " << std::hex << thread_info.within_bb << std::endl;
    }
    thread_info.within_bb = 0;
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

        bb_counts += thread_info.bb_count;
    }

    std::cout << "bb counts: " << bb_counts << std::endl;
    std::cout << "thread ts: " << thread_ts_ << std::endl;
}

void thread_info_c::Dump()
{
    std::cout << "id: " << id << std::endl;
    std::cout << "running: " << running << std::endl;
    std::cout << "finished: " << finished << std::endl;

    std::cout << "last_kind: " << last_kind;
    if (last_kind)
        std::cout << " '" << std::string((char*)&last_kind, 4) << "' ";
    std::cout << std::endl;

    std::cout << "hevent_wait: " << hevent_wait << std::endl;
    std::cout << "hevent_seq: " << hevent_seq << std::endl;
    std::cout << "hmutex_wait: " << hmutex_wait << std::endl;
    std::cout << "hmutex_seq: " << hmutex_seq << std::endl;
    std::cout << "critsec_wait: " << critsec_wait << std::endl;
    std::cout << "critsec_seq: " << critsec_seq << std::endl;
    std::cout << "filepos: " << filepos << std::endl;
    std::cout << "within_bb: " << within_bb << std::endl;
    std::cout << "bb_count: " << bb_count << std::endl;
    std::cout << "running_ts: " << running_ts << std::endl;

    int j = -1;
    for (uint i = 0; i < apicalls.size(); ++i) {
        df_apicall_c &apicall_cur = apicalls[i];
        std::cout << "apicalls[" << i << "]: ";
        apicall_cur.Dump();

        if (apicall_now == &apicall_cur) j = i;
    }
    std::cout << "apicall_now: " << std::dec << j << std::endl;
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
    bool const verbose = true;

    out << "wait";
    write_u32(out, wait_seqs_.size());

    for (auto it : wait_seqs_) {
        write_u32(out, it.first);
        write_u32(out, it.second);
        if (verbose) std::cout << "wait_seqs_, " << it.first << ": " <<it.second << std::endl;
    }

    out << "crit";
    write_u32(out, critsec_seqs_.size());

    for (auto it : critsec_seqs_) {
        write_u32(out, it.first);
        write_u32(out, it.second);
        if (verbose) std::cout << "critsec_seqs_, " << it.first << ": " <<it.second << std::endl;
    }

    out << "thrd";
    write_u32(out, info_threads_.size());

    for (auto it = info_threads_.begin(); it != info_threads_.end(); ++it) {
        thread_info_c &thread_info = it->second;

        write_u32(out, it->first);

        if (verbose) std::cout << "info_threads_, #" << it->first << " ";
        thread_info.SaveState(out);
    }

    write_u32(out, it_thread_->first);
    if (verbose) std::cout << "it_thread_: " << it_thread_->first <<  std::endl;

    write_u64(out, thread_ts_);
    if (verbose) std::cout << "thread_ts_: " << thread_ts_ <<  std::endl;
}

void
LogRunner::RestoreState(std::istream &in)
{
    const bool verbose = true;

    if (filename_.empty()) return;

    if (!read_match(in, "wait")) return;
    wait_seqs_.clear();

    for(int i = read_u32(in); i; i--) {
        uint32_t first = read_u32(in);
        uint32_t second = read_u32(in);
        wait_seqs_[first] = second;

        if (verbose) std::cout << "wait_seqs_, " << first << ": " << second << std::endl;
    }

    if (!read_match(in, "crit")) return;
    critsec_seqs_.clear();

    for(int i = read_u32(in); i; i--) {
        uint32_t first = read_u32(in);
        uint32_t second = read_u32(in);
        critsec_seqs_[first] = second;
        if (verbose) std::cout << "critsec_seqs_, " << first << ": " << second << std::endl;
    }

    if (!read_match(in, "thrd")) return;
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

        std::cout << "info_threads_, #" << first << " " << thread_info.logparser.filename() << " ";

        thread_info.RestoreState(in);
        thread_info.logparser.seek(thread_info.filepos);
    }

    uint32_t thread_id = read_u32(in);
    std::cout << "it_thread_: " << thread_id <<  std::endl;

    it_thread_ = info_threads_.find(thread_id);
    if (it_thread_ == info_threads_.end()) {
        std::cout << "ERROR: don't know current thread" << std::endl;
    }

    thread_ts_ = read_u64(in);
    std::cout << "thread_ts_: " << thread_ts_ <<  std::endl;
}

void
thread_info_c::SaveState(std::ostream &out)
{
    const bool verbose = true;

    out << "info";

    write_u32(out, id);
    if (verbose) std::cout << "id: " << id << std::endl;

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
    if (verbose) std::cout << "filepos: " << filepos << std::endl;

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
}

void
thread_info_c::RestoreState(std::istream &in)
{
    const bool verbose = true;

    if (!read_match(in, "info")) return;

    id = read_u32(in);
    std::cout << "id: " << id << std::endl;

    running = read_bool(in);
    if (verbose) std::cout << "  running     : " << running << std::endl;

    finished = read_bool(in);
    if (verbose) std::cout << "  finished    : " << finished << std::endl;

    last_kind = read_u32(in);
    if (verbose) {
        std::cout << "  last_kind   : " << last_kind;
        if (last_kind)
           std::cout << " '" << std::string((char*)&last_kind, 4) << "' ";
        std::cout << std::endl;
    }

    hevent_wait = read_u32(in);
    if (verbose) std::cout << "  hevent_wait : " << hevent_wait << std::endl;

    hevent_seq = read_u32(in);
    if (verbose) std::cout << "  hevent_seq  : " << hevent_seq << std::endl;

    hmutex_wait = read_u32(in);
    if (verbose) std::cout << "  hmutex_wait : " << hmutex_wait << std::endl;

    hmutex_seq = read_u32(in);
    if (verbose) std::cout << "  hmutex_seq  : " << hmutex_seq << std::endl;

    critsec_wait = read_u32(in);
    if (verbose) std::cout << "  critsec_wait: " << critsec_wait << std::endl;

    critsec_seq = read_u32(in);
    if (verbose) std::cout << "  critsec_seq : " << critsec_seq << std::endl;

    filepos = read_u64(in);
    if (verbose) std::cout << "  filepos     : " << filepos << std::endl;

    within_bb = (app_pc)read_u32(in);
    if (verbose) std::cout << "  within_bb   : " << std::hex << within_bb << std::endl;

    bb_count = read_u32(in);
    if (verbose) std::cout << "  bb_count    : " << std::dec << bb_count << std::endl;

    running_ts = read_u64(in);

    apicalls.clear();

    for(int i = read_u32(in);   // apicalls size
        i; i--) {
        apicalls.push_back(df_apicall_c());
        apicall_now = &apicalls.back();

        if (verbose) std::cout << "  apicalls, " << i << ": ";

        apicall_now->RestoreState(in);
    }

    int j = (signed)read_u32(in); // apicall_now
    apicall_now = j == -1 ? nullptr : &apicalls[j];

    if (verbose) std::cout << "  apicall_now : " << std::dec << j << std::endl;

    stacks.clear();
    
    for(int i = read_u32(in);   // stacks size
        i; i--) {
        stacks.push_back(df_stackitem_c());
        df_stackitem_c *stackitem_cur = &stacks.back();

        if (verbose) std::cout << "  stacks, " << i << ": ";

        stackitem_cur->RestoreState(in);
    }

    pending_state = read_u32(in);

    if (pending_state) {
        read_data(in, (char*)&pending_bb, 16);
    }
}

void
df_apicall_c::SaveState(std::ostream &out)
{
    out << "call";

    write_u32(out, func);
    write_str(out, name);
    write_u32(out, ret_addr);

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
    const bool verbose = true;

    if (!read_match(in, "call")) return;

    func = read_u32(in);
    name = read_str(in);
    ret_addr = read_u32(in);

    if (verbose) std::cout << "call " << name << "@" << func << "( ";

    callargs.clear();
    for (int i = read_u32(in); i; i--) {
        int carg = read_u32(in);
        callargs.push_back(carg);
        if (verbose) std::cout << std::dec << carg << ", ";
    }

    callstrings.clear();
    for (int i = read_u32(in); i; i--) {
        std::string cstr = read_str(in);
        callstrings.push_back(cstr);
        std::cout << cstr << ", ";
    }

    if (verbose) std::cout << ") -> { ";

    retargs.clear();
    for (int i = read_u32(in); i; i--) {
        int rarg = read_u32(in);
        retargs.push_back(rarg);
        if (verbose) std::cout << std::dec << rarg << ", ";
    }

    retstrings.clear();
    for (int i = read_u32(in); i; i--) {
        std::string rstr = read_str(in);
        retstrings.push_back(rstr);
        if (verbose) std::cout << rstr << ", ";
    }

    if (verbose) std::cout << "} => " << std::hex << ret_addr << std::endl;
}

void df_stackitem_c::Dump()
{

}
void df_stackitem_c::SaveState(std::ostream &out)
{
    out << "stem";

    write_u32(out, kind);
    write_u32(out, pc);
    write_u32(out, next);
    write_u32(out, link);
}

void df_stackitem_c::RestoreState(std::istream &in)
{
    const bool verbose = true;

    if (!read_match(in, "stem")) return;

    kind = read_u32(in);
    pc = read_u32(in);
    next = read_u32(in);
    link = read_u32(in);

    if (verbose) std::cout << kind << pc << next << link << std::endl;
}