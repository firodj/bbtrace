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
public:
    LogRunnerObserver();

    virtual std::string GetName() { return "LogRunnerObserver"; }
    virtual void OnApiCall(uint thread_id, DataFlowApiCall &apicall_ret) {}
    virtual void OnBB(uint thread_id, DataFlowStackItem &last_bb, DataFlowMemAccesses &memaccesses) {}
    virtual void OnApiUntracked(uint thread_id, DataFlowStackItem &bb_untracked_api) {}
    virtual void OnThread(uint thread_id, uint handle_id, uint sp) {}
    virtual void OnPush(uint thread_id, DataFlowStackItem &the_bb, DataFlowApiCall *apicall_now) {}
    virtual void OnPop(uint thread_id, DataFlowStackItem &the_bb) {}
    virtual void OnStart() {}
    virtual void OnFinish() {}
    virtual void OnCommand(int argc, const char* argv[]) {};
    virtual void RestoreState(std::vector<char> &data) {}
    virtual void SaveState(std::vector<char> &data) {}

protected:
    LogRunnerInterface *logrunner_;
};