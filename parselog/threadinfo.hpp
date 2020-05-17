#pragma once

#include <thread>
#include <vector>
#include <string>
#include <map>
#include "logparser.h"

struct DataFlowApiCall {
public:
  app_pc func;
  std::string name;
  app_pc ret_addr;
  std::vector<uint> callargs;
  std::vector<std::string> callstrings;
  std::vector<uint> retargs;
  std::vector<std::string> retstrings;
  uint64 ts;
  int s_depth;
  DataFlowApiCall():
    func(0), ret_addr(0), ts(0) {}
  void Dump(int indent = 0);
  void SaveState(std::ostream &out);
  void RestoreState(std::istream &in);
};

struct DataFlowStackItem {
public:
  uint kind;
  app_pc pc;
  app_pc next;
  union {
    uint flags;
    struct {
      uint link:2;
      bool is_sub:1;
      uint len_last:5; // take most 15 bytes (need 4bits)
    };
  };
  uint64 ts;
  int s_depth;
  DataFlowStackItem():
    pc(0), ts(0), flags(0) {}
  void Dump(int indent = 0);
  void SaveState(std::ostream &out);
  void RestoreState(std::istream &in);
};

struct DataFlowMemAccess {
public:
  app_pc pc;
  uint addr;
  uint size;
  union {
    uint flags;
    struct {
      bool is_write:1;
      bool is_loop:1;
    };
  };
  uint loop_from;
  uint loop_to;
  DataFlowMemAccess():
    pc(0), addr(0), size(0), is_write(false), is_loop(false) {}

  void Dump(int indent = 0);
  void SaveState(std::ostream &out);
  void RestoreState(std::istream &in);
};

typedef std::vector<DataFlowMemAccess> DataFlowMemAccesses;

class LogRunner;

class ThreadInfo {
public:
  enum PendingStates {
    kPendNone = 0,
    kPendAfterRet,
    kPendWantRet
  };

  LogParser logparser;
  bool running;
  bool finished;
  uint last_kind;
  std::vector<DataFlowApiCall> apicalls;
  std::vector<DataFlowStackItem> stacks;
  DataFlowStackItem last_bb;
  DataFlowApiCall *apicall_now;
  mem_ref_t pending_bb;
  PendingStates pending_state;
  uint hevent_wait;
  uint hevent_seq;
  uint hmutex_wait;
  uint hmutex_seq;
  uint critsec_wait;
  uint critsec_seq;
  uint64 filepos;
  app_pc within_bb;
  uint id;
  uint bb_count;
  uint64 now_ts;
  std::unique_ptr<std::thread> the_thread;
  LogRunner* the_runner;
  DataFlowMemAccesses memaccesses;

  ThreadInfo():
    running(false),
    finished(false),
    hevent_wait(0),
    hmutex_wait(0),
    critsec_wait(0),
    apicall_now(nullptr),
    pending_state(kPendNone),
    filepos(0),
    within_bb(0),
    id(0),
    bb_count(0),
    last_kind(KIND_NONE),
    now_ts(0),
    the_thread(nullptr),
    the_runner(nullptr)
    {}

  void Dump(int indent = 0);
  void SaveState(std::ostream &out);
  void RestoreState(std::istream &in);
};

typedef std::map<uint, ThreadInfo> ThreadInfoMap;
