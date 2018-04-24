#ifdef _MSC_VER
  #include <windows.h>
  #include "guicon.h"
#else
  typedef char* PCHAR;
#endif

#define WITHOUT_DR
#include "datatypes.h"

#include <iostream>
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

#define WITH_ANALYZER 1
#define WITH_SEQ 1

#include "logparser.hpp"
#include "logrunner.hpp"

static map_app_pc_string_t g_symbol_names;
static map_uint_uint_t g_thread_id_handles;
static map_uint_uint_t g_wait_seqs; // hmutex / hevent
static map_thread_info_t g_info_threads;
volatile std::sig_atomic_t gSignalStatus;

class AutoPause {
public:
    ~AutoPause() {
#ifdef _MSC_VER
        pause();
#endif
    }
    void pause()
    {
        std::cout << "Press any key to conitnue . . .";
        std::cin.get();
    }
};

void signal_handler(int signal)
{
    gSignalStatus = signal;
}

#ifdef _MSC_VER
int WINAPI
WinMain(HINSTANCE hInstance,
    HINSTANCE hPrevInstance,
    LPSTR lpCmdLine,
    int nCmdShow)
{
    int argc;
    PCHAR* argv;
    RedirectIOToConsole();
    argv = CommandLineToArgvA(lpCmdLine, &argc);
    AutoPause auto_pause;
#else
int
main(int argc, PCHAR* argv)
{
#endif
    assert(sizeof(mem_ref_t) == 16);
    assert(sizeof(buf_string_t) == 6*16);

    if (argc < 2) {
        std::cout << "Please provide .bin file" << std::endl;
        return 1;
    }

#if WITH_ANALYZER
    std::cout << "WITH ANALYZER, ";
#else
    std::cout << "without analyzer, ";
#endif
#if WITH_SEQ
    std::cout << "WITH SEQ, ";
#else
    std::cout << "without seq, ";
#endif
    std::cout << std::endl;

    std::string filename;

    uint opt_memtrack = 0;

    std::vector<std::string> opt_procnames;
    std::vector<uint> opt_procaddrs;

    bool show_libcall = true;
    bool show_appcall = true;
    bool show_memtrace= true;
    bool show_synchro = true;
    bool show_string  = true;
    bool show_other   = true;
    bool last_call_shown = true;

    for (int a=1; a<argc; a++) {
        char *argn = argv[a];
        if (argn && *argn == '-')
          argn++;
        else {
          filename = argv[1];
          continue;
        }

        std::string opt_name(argn);

        if (opt_name == "t") {
            std::cout << "Skimming only" << std::endl;
            show_libcall = false;
            show_appcall = false;
            show_memtrace = false;
            show_synchro = false;
            show_other   = false;
            last_call_shown = false;
        } else
        if (opt_name == "p") {
            if (++a < argc) {
                opt_procnames.push_back(argv[a]);
                std::cout << "Track proc:" << argv[a] << std::endl;

                show_appcall = false;
                show_memtrace= false;
                show_synchro = false;
                show_other   = false;
                show_string  = false;
                last_call_shown = false;
            } else {
                std::cout << "Please provide proc name!" << std::endl;
                return 1;
            }
        } else
        if (opt_name == "m") {
            if (++a < argc) {
                opt_memtrack = std::strtoul(argv[a], nullptr, 0);
                if (!opt_memtrack) {
                    std::cout << "Invalid memory addr!" << std::endl;
                    return 1;
                }
                std::cout << "Track mem:" << std::hex << opt_memtrack << std::endl;

                show_appcall = false;
                show_libcall = false;
                show_synchro = false;
                show_other   = false;
                last_call_shown = false;
            } else {
                std::cout << "Please provide memory addr!" << std::endl;
                return 1;
            }
        } else
        if (opt_name == "1") {
            show_memtrace   = false;
            show_other      = false;
            show_synchro    = true;
            last_call_shown = false;
            show_appcall    = false;
        } else {
            std::cout << "Unknown option:" << opt_name << std::endl;
            return 1;
        }
    }

    // Install a signal handler
    std::signal(SIGINT, signal_handler);

    LogRunner runner;
    runner.Open(filename);
    runner.SetOptions(0);

    auto start = std::chrono::system_clock::now();
    while (runner.Step() && gSignalStatus == 0)
        ;
    auto end = std::chrono::system_clock::now();

    std::cout << "===" << std::endl;
    runner.Summary();

    auto minutes = std::chrono::duration_cast<std::chrono::minutes>(end-start);
    auto seconds = std::chrono::duration_cast<std::chrono::seconds>(end-start-minutes);

    std::time_t end_time = std::chrono::system_clock::to_time_t(end);
    std::cout << "finished at " << std::ctime(&end_time)
              << "elapsed time: " << minutes.count() << ":" << seconds.count() << "s" << std::endl;

    return 0;
}
