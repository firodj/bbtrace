#pragma once

#define WITHOUT_DR
#include "../src/datatypes.h"
#include "threadinfo.hpp"

class LogRunnerObserver;
class LogRunnerInterface
{
public:
    virtual std::string GetPrefix() = 0;
    virtual std::string GetExecutable() = 0;
    virtual void RequestToStop() = 0;
};

class LogRunnerObserver {
protected:
    LogRunnerInterface *logrunner_;

public:
    LogRunnerObserver();

    virtual std::string GetName() { return "LogRunnerObserver"; }
    virtual void OnApiCall(uint thread_id, df_apicall_c &apicall_ret) {}
    virtual void OnBB(uint thread_id, df_stackitem_c &last_bb, vec_memaccess_t &memaccesses) {}
    virtual void OnApiUntracked(uint thread_id, df_stackitem_c &bb_untracked_api) {}
    virtual void OnThread(uint thread_id, uint handle_id, uint sp) {}
    virtual void OnPush(uint thread_id, df_stackitem_c &the_bb, df_apicall_c *apicall_now) {}
    virtual void OnPop(uint thread_id, df_stackitem_c &the_bb) {}
    virtual void OnStart() {}
    virtual void OnFinish() {}
    virtual void OnCommand(int argc, const char* argv[]) {};
    virtual void RestoreState(std::vector<char> &data) {}
    virtual void SaveState(std::vector<char> &data) {}
};