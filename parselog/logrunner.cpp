#include <iostream>
#include <fstream>
#include <sstream>
#include <string>
 #include <map>
 #include <vector>
#include <stdexcept>   // for exception, runtime_error, out_of_range

#define WITHOUT_DR
#include "datatypes.h"

#include "logparser.h"
#include "threadinfo.hpp"
#include "logrunner.h"

#define LR_SHOW_BB 0x1
#define LR_SHOW_LIBCALL 0x2

bool
LogRunner::Open(std::string &filename) {
    filename_ = filename;
    const uint main_thread_id = 0;

    if (info_threads_[main_thread_id].logparser.open(filename_.c_str())) {
        std::cout << "Open:" << filename_ << std::endl;
        info_threads_[main_thread_id].running = true;
    } else {
        std::cout << "Fail to open .bin: " << filename_ << std::endl;
        info_threads_[0].finished = true;
        return false;
    }

    if (info_threads_[main_thread_id].finished) {
        info_threads_.erase(main_thread_id);
    }

    it_thread_ = info_threads_.end();
    bb_count_ = 0;
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
    bb_count_ += thread_info.bb_count;

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
        if (it_thread_ == info_threads_.end())
            it_thread_ = info_threads_.begin();
        if (it_thread_->second.finished)
            continue;
        if (!it_thread_->second.running)
            CheckPending(it_thread_->second);
        if (it_thread_->second.running)
            break;
    }

    if (inactive == info_threads_.size())
        return false;

    uint thread_id = it_thread_->first;
    thread_info_c &thread_info = it_thread_->second;
    auto it_current = it_thread_++;

    while (thread_info.running) {
        uint kind;

        // Check Lib Ret first
        if (thread_info.apicall_now) {
            kind = thread_info.logparser.peek();
            if (kind != KIND_ARGS && kind != KIND_STRING) {
                if (thread_info.last_kind == KIND_LIB_RET) {
                    ApiCallRet(thread_info);
                    break;
                }
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

        // Consume kind
        char *item = thread_info.logparser.fetch(&thread_info.filepos);
        if (!item) {
            FinishThread(thread_info);
            info_threads_.erase(it_current);
            break;
        }
        kind = *(uint*)item;

        switch (kind) {
            case KIND_BB:
                DoKindBB(thread_info, *(mem_ref_t*)item);
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

    return true;
}

void
LogRunner::DoKindBB(thread_info_c &thread_info, mem_ref_t &buf_bb)
{
    thread_info.within_bb = (uint) buf_bb.pc;
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

    df_apicall_c &libret_last = thread_info.apicalls.back();
    if (libret_last.func != buf_libret.func &&
        libret_last.ret_addr != buf_libret.ret_addr) {
        std::cout << "Unmatch lib ret!" << std::endl;
        throw std::runtime_error ("Unmatch lib ret!");
    }

    thread_info.apicall_now = &thread_info.apicalls.back();
    thread_info.apicall_now->retargs.push_back((uint)buf_libret.retval);

    // librets.push_back(libret_last);
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
            thread_info.hmutex_wait = 0;
        }
    }
}

void
df_apicall_c::dump()
{
    std::cout << "call " << name << "( ";
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
LogRunner::ApiCallRet(thread_info_c &thread_info)
{
    df_apicall_c apicall_ret = *thread_info.apicall_now;
    thread_info.apicalls.pop_back();
    thread_info.apicall_now = nullptr;

    if (apicall_ret.name == "CreateThread") {
        OnCreateThread(apicall_ret);
    } else
    if (apicall_ret.name == "ResumeThread") {
        OnResumeThread(apicall_ret);
    }

    for (auto filter_addr : filter_apicall_addrs_) {
        if (filter_addr == apicall_ret.func) {
            std::cout << std::dec << thread_info.id << "] ";
            apicall_ret.dump();
        }
    }
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
    uint new_handle = apicall.retargs[0];
    uint new_thread_id = apicall.retargs[1];
    bool new_suspended = (apicall.callargs[3] & 0x4) == 0x4;

    if (thread_id_handles_.find(new_handle) != thread_id_handles_.end()) {
        std::cout << "Already created thread id? " << new_thread_id << std::endl;
    } else if (new_thread_id) {
        thread_id_handles_[new_handle] = new_thread_id;

        std::ostringstream oss;
        oss << filename_ << "." << std::dec << new_thread_id;

        if (! info_threads_[new_thread_id].logparser.open(oss.str().c_str())) {
            std::cout << "Fail to open .bin: " << oss.str() << std::endl;
            info_threads_[new_thread_id].finished = true;
        } else {
            info_threads_[new_thread_id].running = new_suspended ? false : true;

            if (info_threads_[new_thread_id].running) {
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
    uint new_handle = apicall.callargs[0];
    if (thread_id_handles_.find(new_handle) != thread_id_handles_.end()) {
        uint resume_thread_id = thread_id_handles_[new_handle];
        if (info_threads_.find(resume_thread_id) != info_threads_.end()) {
            info_threads_[resume_thread_id].running = true;

            std::cout << std::dec << resume_thread_id << "] ";
            std::cout << "thread resuming." << std::endl;
        }
    }
}

void
LogRunner::Summary()
{
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

    std::cout << "bb count: " << bb_count_ << std::endl;
}
