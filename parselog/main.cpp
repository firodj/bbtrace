#ifdef _MSC_VER
  #include <windows.h>
#else
  typedef char* PCHAR;
#endif

#include <iostream>
#include <iomanip>
#include <fstream>
#include <sstream>
#include <string>
#include <cstring>
#include <stdexcept>
#include <map>
#include <vector>
#include <cassert>
#include <csignal>
#include <chrono>
#include <ctime>
#include <functional>

#include "logrunner.h"
#include "replxx.hxx"
#include "argh.h"

volatile std::sig_atomic_t g_signal_status;
static LogRunner *g_runner = nullptr;

using Replxx = replxx::Replxx;

class AutoPause {
public:
  ~AutoPause() {
#ifdef _MSC_VER
    Pause();
#endif
  }
  void Pause()
  {
    std::cout << "Press any key to conitnue . . .";
    std::cin.get();
  }
};

void SplitArg(char* s, std::vector<const char*> &ar) {
  char *p = 0;
  for (; *s; s++) {
    if (*s == '\t' || *s == ' ') {
      if (p) {
        *s = 0;
        ar.emplace_back(p);
        p = 0;
      }
    } else {
      if (!p) p = s;
    }
  }

  if (p)
    ar.emplace_back(p);
}

void SplitString(std::string s, std::vector<std::string>& ar) {
  std::string delimiter = ",";

  size_t pos = 0;
  std::string token;
  while ((pos = s.find(delimiter)) != std::string::npos) {
    token = s.substr(0, pos);
    ar.push_back(token);
    s.erase(0, pos + delimiter.length());
  }
}

struct Options {
public:
  std::string filename;
  std::string exename;

  uint opt_memtrack = 0;
  bool opt_input_state = false;
  bool opt_use_multithread = false;

  std::vector<std::string> opt_procnames;

  Options()
  {
  }

  bool Process(int argc, PCHAR* argv)
  {
    argh::parser cmdl;
    cmdl.parse(argc, argv, argh::parser::PREFER_PARAM_FOR_UNREG_OPTION);

    if (!(cmdl(1) >> filename)) {
      std::cerr << "Please provide .bin file" << std::endl;
      return false;
    }

    if (cmdl["-i"])
      opt_input_state = true;

    cmdl("-z") >> exename;

    std::string procnames;
    if (cmdl("-p") >> procnames) {
      SplitString(procnames, opt_procnames);

      for (auto &procname: opt_procnames)
        std::cout << "Track proc:" << procname << std::endl;
    }

    std::string memtrack;
    if (cmdl("-m") >> memtrack) {
      opt_memtrack = std::strtoul(memtrack.c_str(), nullptr, 0);
      std::cout << "Track mem:" << std::hex << opt_memtrack << std::endl;
    }

    if (cmdl["-j"]) {
      opt_use_multithread = true;
      std::cout << "enable Multithread." << std::endl;
    }

    return true;
  }
};

Options g_options;

void SignalHandler(int signal) {
  g_signal_status = signal;
  if (g_runner)
    g_runner->RequestToStop();
}

std::string GetStatesName(std::string &filename, uint cnt) {
  std::ostringstream oss;
  oss << filename << ".sav-" << std::dec << cnt;
  return oss.str();
}

uint GetAvailableStates(std::string &filename) {
  for(uint cnt = 1; true; cnt++) {
    std::ifstream f(GetStatesName(filename, cnt));
    if (! f.good()) return cnt;
  }

  return 0;
}

Replxx::completions_t HookCompletion(std::string const& context, int& contextLen,
  std::vector<std::string> const& suggests) {
  Replxx::completions_t completions;

  std::string prefix { context };

  for (auto const& e : suggests) {
    if (e.compare(0, prefix.size(), prefix) == 0) {
      completions.emplace_back(e.c_str());
    }
  }

  return completions;
}

void Load() {
  uint sav_cnt = GetAvailableStates(g_options.filename);
  if (sav_cnt <= 1) return;

  std::ostringstream oss;
  oss << GetStatesName(g_options.filename, sav_cnt-1) << ".symbols";

  std::ifstream fsymb;
  fsymb.open(oss.str(), std::ifstream::in | std::ifstream::binary);
  std::cout << "Reading from " << oss.str() << std::endl;
  g_runner->RestoreSymbols(fsymb);

  oss.str("");
  oss.clear();
  oss << GetStatesName(g_options.filename, sav_cnt-1);

  std::ifstream frun;
  frun.open(oss.str(), std::ifstream::in | std::ifstream::binary);
  std::cout << "Reading from " << oss.str() << std::endl;
  g_runner->RestoreState(frun);

  //g_runner->Dump();
}

void Save() {
  uint sav_cnt = GetAvailableStates(g_options.filename);
  std::ostringstream oss;
  oss << GetStatesName(g_options.filename, sav_cnt) << ".symbols";

  std::ofstream fsymb;
  fsymb.open(oss.str(), std::ofstream::out | std::ofstream::binary);
  std::cout << "Writing to " << oss.str() << std::endl;
  g_runner->SaveSymbols(fsymb);

  oss.str("");
  oss.clear();
  oss << GetStatesName(g_options.filename, sav_cnt);

  std::ofstream frun;
  frun.open(oss.str(), std::ofstream::out | std::ofstream::binary);
  std::cout << "Writing to " << oss.str() << std::endl;
  g_runner->SaveState(frun);
}

int main(int argc, PCHAR* argv) {
  // AutoPause auto_pause;

  // words to be completed
  std::vector<std::string> suggests {
    "run", "quit", "exit", "save", "load", "history", "clear", "help"
  };

  Replxx rx;
  rx.install_window_change_handler();

  std::string prompt {"\x1b[1;32mbbtrace\x1b[0m> "};

  assert(sizeof(mem_ref_t) == 16);
  assert(sizeof(buf_string_t) == 6*16);

  if (! g_options.Process(argc, argv)) {
    AutoPause auto_pause;
    return 1;
  }

  // the path to the history file
  std::string history_file {"./replxx_history.txt"};

  // load the history file if it exists
  rx.history_load(history_file);

  // set the max history size
  rx.set_max_history_size(128);

  // set the max number of hint rows to show
  rx.set_max_hint_rows(3);

  // set the callbacks
  rx.set_completion_callback( std::bind( &HookCompletion, std::placeholders::_1, std::placeholders::_2, std::cref( suggests ) ) );

  // Install a signal handler
  std::signal(SIGINT, SignalHandler);

  g_runner = LogRunner::instance();
  g_runner->ListObservers();

  if (! g_runner->Open(g_options.filename)) {
    AutoPause auto_pause;
    return 1;
  }

  if (! g_options.exename.empty()) {
    g_runner->SetExecutable(g_options.exename);
  }

  if (g_options.opt_input_state)
    Load();

  for (auto name : g_options.opt_procnames)
    g_runner->FilterApiCall(name);

  // main repl loop
  for (;;) {
    char const* cinput{ nullptr };

    do {
      cinput = rx.input(prompt);
    } while ( ( cinput == nullptr ) && ( errno == EAGAIN ) );

    if (cinput == nullptr) {
      break;
    }

    // change cinput into a std::string
    // easier to manipulate
    std::string input {cinput};
    std::vector<const char*> ar_input;

    SplitArg((char*)cinput, ar_input);
    argh::parser args(ar_input.size(), ar_input.data());

    if (! args.size()) {
      // user hit enter on an empty line

      continue;
    } else if (args[0] == "quit" || args[0] == "exit") {
      // exit the repl

      break;
    } else if (args[0] == "run") {
      auto start = std::chrono::system_clock::now();
      if (g_options.opt_use_multithread)
        g_runner->RunMT();
      else
        g_runner->Run();
      auto end = std::chrono::system_clock::now();

      g_signal_status = 0;

      auto minutes = std::chrono::duration_cast<std::chrono::minutes>(end-start);
      auto seconds = std::chrono::duration_cast<std::chrono::seconds>(end-start-minutes);
      std::time_t end_time = std::chrono::system_clock::to_time_t(end);

      std::cout << "+++" << std::endl;
      std::cout << "finished at " << std::ctime(&end_time)
          << "elapsed time: " << minutes.count() << ":" << seconds.count() << "s" << std::endl;

      std::cout << "===" << std::endl;
      g_runner->Summary();

      rx.history_add(input);
    } else if (args[0] == "save") {
      Save();

      rx.history_add(input);
    } else if (args[0] == "load") {
      Load();

      rx.history_add(input);
    } else if (args[0] == "history") {
      // display the current history
      for (size_t i = 0, sz = rx.history_size(); i < sz; ++i) {
        std::cout << std::setw(4) << i << ": " << rx.history_line(i) << "\n";
      }

      rx.history_add(input);
      continue;

    } else if (args[0] == "clear") {
      // clear the screen
      rx.clear_screen();

      rx.history_add(input);
      continue;
    } else if (args[0] == "help") {
      std::cout << "help      Show this help" << std::endl;
      std::cout << "clear     Clear screen" << std::endl;
      std::cout << "history   List command history" << std::endl;
      std::cout << "load      Load state" << std::endl;
      std::cout << "run       Run parse log" << std::endl;
      std::cout << "save      Save state" << std::endl;
      std::cout << "quit      Quit" << std::endl;
    } else {
      g_runner->DoCommand(ar_input.size(), ar_input.data());
    }
  }

  // save the history
  rx.history_save(history_file);

  return 0;
}
