#pragma once

#define WITHOUT_DR
#include "../src/datatypes.h"
#include "threadinfo.hpp"

class LogRunner;
class LogRunnerObserver {
protected:
    LogRunner *logrunner_;

public:
    LogRunnerObserver();

    virtual const char *GetName() = 0;

    virtual void OnApiCall(uint thread_id, df_apicall_c &apicall_ret) = 0;
    virtual void OnBB(uint thread_id, df_stackitem_c &last_bb, vec_memaccess_t &memaccesses) = 0;
    virtual void OnApiUntracked(uint thread_id, df_stackitem_c &bb_untracked_api) = 0;
    virtual void OnThread(uint thread_id, uint handle_id, uint sp) = 0;
    virtual void OnPush(uint thread_id, df_stackitem_c &the_bb) = 0;
    virtual void OnPop(uint thread_id, df_stackitem_c &the_bb) = 0;
};