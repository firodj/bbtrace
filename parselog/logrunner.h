#pragma once

#include <mutex>
#include <condition_variable>
#include <sstream>
#include <queue>

#define WITHOUT_DR
#include "datatypes.h"

#include "logparser.h"
#include "threadinfo.hpp"
#include "observer.hpp"

typedef std::map<uint, uint> map_uint_uint_t;
typedef std::map<uint, uint64> map_uint_uint64_t;
typedef std::map<app_pc, std::string> map_app_pc_string_t;

enum RunnerMessageType {
  kMsgUndefined = 0,
  kMsgCreateThread,
  kMsgResumeThread,
  kMsgThreadFinished,
  kMsgRequestStop
};

struct RunnerMessage {
  uint thread_id;
  RunnerMessageType msg_type;
  std::string data;
};

struct SyncSequence {
public:
  uint seq;
  uint64 ts;

  SyncSequence(): seq(0), ts(0) {}
};

struct ThreadStats {
public:
  uint bb_counts;
  uint64 ts;

  ThreadStats(): bb_counts(0), ts(0) {}

  void
  Apply(thread_info_c &thread_info)
  {
    bb_counts = thread_info.bb_count;
    ts = thread_info.now_ts;
  }
};

typedef std::map<uint, SyncSequence> MapOfSyncSequence;
typedef std::map<uint, thread_info_c> MapOfThreadInfo;
typedef std::map<uint, ThreadStats> MapOfThreadStats;

class LogRunnerObserver;

class LogRunner: public LogRunnerInterface
{
public:
  enum RunPhase {
    kPhaseNone = 0,
    kPhasePre,
    kPhasePost
  };

  LogRunner() {}
  static LogRunner* GetInstance();

  // Contracts
  virtual std::string GetPrefix() override;
  virtual std::string GetExecutable() override;
  virtual void RequestToStop() override;

  void AddObserver(LogRunnerObserver *observer);
  void ListObservers();
  bool Open(std::string &filename);
  void SetExecutable(std::string exename);
  void FinishThread(thread_info_c &thread_info);

  bool Step(MapOfThreadInfo::iterator &it_thread);
  bool ThreadStep(thread_info_c &thread_info);

  bool Run(RunPhase phase = kPhaseNone);
  bool RunMT();
  static void ThreadRun(thread_info_c &thread_info);
  void PostMessage(uint thread_id, RunnerMessageType msg_type, std::string &data);

  void DoCommand(int argc, const char* argv[]);

  void ThreadWaitCritSec(thread_info_c &thread_info);
  void ThreadWaitEvent(thread_info_c &thread_info);
  void ThreadWaitMutex(thread_info_c &thread_info);
  void ThreadWaitRunning(thread_info_c &thread_info);

  void CheckPending(thread_info_c &thread_info)
  {
    ThreadWaitCritSec(thread_info);
    ThreadWaitEvent(thread_info);
    ThreadWaitMutex(thread_info);
    ThreadWaitRunning(thread_info);
  }

  void ApiCallRet(thread_info_c &thread_info);

  void OnCreateThread(df_apicall_c &apicall, uint64 ts);
  void OnResumeThread(df_apicall_c &apicall, uint64 ts);

  void Summary();

  void FilterApiCall(std::string &name)
  {
    filter_apicall_names_.push_back(name);
  }

  void SaveSymbols(std::ostream &out);
  void SaveState(std::ostream &out);
  void Dump(int indent = 0);

  void RestoreSymbols(std::istream &in);
  void RestoreState(std::istream &in);

  std::mutex resume_mx_;
  std::condition_variable resume_cv_;
  MapOfThreadInfo &info_threads() { return info_threads_; }


protected:
  MapOfThreadInfo info_threads_;
  MapOfThreadStats stats_threads_;
  std::string filename_;
  std::string exename_;
  std::vector<uint> filter_apicall_addrs_;
  std::vector<std::string> filter_apicall_names_;

  bool request_stop_;
  bool is_multithread_;

  void DoKindBB(thread_info_c &thread_info, mem_ref_t &buf_bb);
  void DoEndBB(thread_info_c &thread_info /* , bb mem read/write */);
  void DoKindSymbol(thread_info_c &thread_info, buf_symbol_t &buf_sym);
  void DoKindLibCall(thread_info_c &thread_info, buf_lib_call_t &buf_libcall);
  void DoKindLibRet(thread_info_c &thread_info, buf_lib_ret_t &buf_libret);
  void DoKindArgs(thread_info_c &thread_info, buf_event_t &buf_args);
  void DoKindString(thread_info_c &thread_info, buf_string_t &buf_str);
  void DoKindSync(thread_info_c &thread_info, buf_event_t &buf_sync);
  void DoKindWndProc(thread_info_c &thread_info, buf_event_t &buf_wndproc);
  void DoMemRW(thread_info_c &thread_info, mem_ref_t &mem_rw, bool is_write);
  void DoMemLoop(thread_info_c &thread_info, mem_ref_t &mem_loop);
  void OnApiCall(uint thread_id, df_apicall_c &apicall_ret);
  void OnApiUntracked(uint thread_id, df_stackitem_c &bb_untracked_api);
  void OnBB(uint thread_id, df_stackitem_c &last_bb, vec_memaccess_t &memaccesses);
  void OnThread(uint thread_id, uint handle_id, uint sp);
  void OnPush(uint thread_id, df_stackitem_c &the_bb, df_apicall_c *apicall_now = nullptr);
  void OnPop(uint thread_id, df_stackitem_c &the_bb);
  void OnStart();
  void OnFinish();

private:
  map_app_pc_string_t symbol_names_;
  MapOfSyncSequence wait_seqs_; // hmutex / hevent
  MapOfSyncSequence critsec_seqs_; // critsec

  std::mutex message_mu_;
  std::condition_variable message_cv_;
  std::queue<RunnerMessage> messages_;
  std::vector<LogRunnerObserver*> observers_;

};
