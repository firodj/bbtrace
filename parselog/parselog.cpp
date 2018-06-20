#ifdef _MSC_VER
  #include <windows.h>
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

#include "logparser.h"
#include "threadinfo.hpp"
#include "logrunner.h"

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

std::string
get_states_name(std::string &filename, uint cnt)
{
    std::ostringstream oss;
    oss << filename << ".sav-" << std::dec << cnt;
    return oss.str();
}

uint
get_available_states(std::string &filename)
{
    for(uint cnt = 1; true; cnt++) {
        std::ifstream f(get_states_name(filename, cnt));
        if (! f.good()) return cnt;
    }

    return 0;
}

int
main(int argc, PCHAR* argv)
{
    AutoPause auto_pause;

    assert(sizeof(mem_ref_t) == 16);
    assert(sizeof(buf_string_t) == 6*16);

    if (argc < 2) {
        std::cout << "Please provide .bin file" << std::endl;
        return 1;
    }

    std::string filename;

    uint opt_memtrack = 0;
    bool opt_input_state = false;

    std::vector<std::string> opt_procnames;

    for (int a=1; a<argc; a++) {
        char *argn = argv[a];
        if (argn && *argn == '-')
          argn++;
        else {
          filename = argv[1];
          continue;
        }

        std::string opt_name(argn);

        if (opt_name == "p") {
            if (++a < argc) {
                opt_procnames.push_back(argv[a]);
                std::cout << "Track proc:" << argv[a] << std::endl;
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
            } else {
                std::cout << "Please provide memory addr!" << std::endl;
                return 1;
            }
        } else
        if (opt_name == "i") {
            opt_input_state = true;
            /*
            if (++a < argc) {
                argv[a];
            } else {
                std::cout << "Please provide running state";
                return 1;
            }
            */
        } else {
            std::cout << "Unknown option:" << opt_name << std::endl;
            return 1;
        }
    }

    // Install a signal handler
    std::signal(SIGINT, signal_handler);

    LogRunner runner;
    if (runner.Open(filename)) {
        if (opt_input_state) {
            uint sav_cnt = get_available_states(filename);
            if (sav_cnt > 1) {
                std::ostringstream oss;
                oss << get_states_name(filename, sav_cnt-1) << ".symbols";

                std::ifstream fsymb;
                fsymb.open(oss.str(), std::ofstream::in | std::ofstream::binary);
                std::cout << "Reading from " << oss.str() << std::endl;
                runner.RestoreSymbols(fsymb);

                oss.str("");
                oss.clear();
                oss << get_states_name(filename, sav_cnt-1);

                std::ifstream frun;
                frun.open(oss.str(), std::ofstream::in | std::ofstream::binary);
                std::cout << "Reading from " << oss.str() << std::endl;
                runner.RestoreState(frun);
            }
        }

        for (auto name : opt_procnames)
            runner.FilterApiCall(name);
        runner.SetOptions(0);

        auto start = std::chrono::system_clock::now();
        while (runner.Step() && gSignalStatus == 0)
            ;
        auto end = std::chrono::system_clock::now();

        if (gSignalStatus) {
            uint sav_cnt = get_available_states(filename);
            std::ostringstream oss;
            oss << get_states_name(filename, sav_cnt) << ".symbols";

            std::ofstream fsymb;
            fsymb.open(oss.str(), std::ofstream::out | std::ofstream::binary);
            std::cout << "Writing to " << oss.str() << std::endl;
            runner.SaveSymbols(fsymb);

            oss.str("");
            oss.clear();
            oss << get_states_name(filename, sav_cnt);

            std::ofstream frun;
            frun.open(oss.str(), std::ofstream::out | std::ofstream::binary);
            std::cout << "Writing to " << oss.str() << std::endl;
            runner.SaveState(frun);

            gSignalStatus = 0;
        }

        std::cout << "+++" << std::endl;
        auto minutes = std::chrono::duration_cast<std::chrono::minutes>(end-start);
        auto seconds = std::chrono::duration_cast<std::chrono::seconds>(end-start-minutes);

        std::time_t end_time = std::chrono::system_clock::to_time_t(end);
        std::cout << "finished at " << std::ctime(&end_time)
                  << "elapsed time: " << minutes.count() << ":" << seconds.count() << "s" << std::endl;

    }
    std::cout << "===" << std::endl;
    runner.Summary();

    return 0;
}
