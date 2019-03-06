#ifdef _MSC_VER
  #include <windows.h>
#else
  typedef char* PCHAR;
#endif

#include <iostream>
#include <fstream>
#include <sstream>
#include <string>
#include <cstring>
#include <stdexcept>
#include <unordered_map>
#include <map>
#include <vector>
#include <cassert>
#include <csignal>
#include <chrono>
#include <ctime>
#include <mutex>

#include "../logrunner.h"

typedef std::unordered_map<uint, df_stackitem_c> bb_collection_t;

bb_collection_t basic_blocks;
std::mutex g_basic_blocks_mx;

class MyLogRunner: public LogRunner
{
public:
    void
    OnBB(uint thread_id, df_stackitem_c &last_bb, vec_memaccess_t &memaccesses) override
    {
        if (basic_blocks.find(last_bb.pc) != basic_blocks.end()) return;

        {
            std::lock_guard<std::mutex> lock(g_basic_blocks_mx);
            basic_blocks[last_bb.pc] = last_bb;
        }
    }

    void
    DumpCSV()
    {
        std::string csvname = filename_;

        std::string::size_type n;
        n = filename_.rfind('.');
        if (n != std::string::npos) {
            csvname = filename_.substr(0, n);
        }
        csvname += ".csv";

        std::ofstream outfile;
        outfile.open(csvname.c_str());
        std::cout << "Dump CSV: " << csvname << " ..." << std::endl;
        outfile << "pc,next,is_sub,link,ts" << std::endl;
        for (bb_collection_t::value_type kv : basic_blocks)
        {
            df_stackitem_c &last_bb = kv.second;

            // std::cout << std::dec << thread_id << ",";
            outfile << "0x" << std::hex << last_bb.pc << ",";
            outfile << "0x" << last_bb.next << ",";
            outfile << std::dec << last_bb.is_sub << ",";
            switch (last_bb.link) {
                case LINK_CALL: outfile << "CALL"; break;
                case LINK_RETURN: outfile << "RETURN"; break;
                case LINK_JMP: outfile << "JMP"; break;
                default: outfile << last_bb.link;
            }
            outfile << "," << last_bb.ts << std::endl;
        }
    }
};

static MyLogRunner *g_runner = nullptr;

// Ctrl+C Handler

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

void
signal_handler(int signal)
{
    gSignalStatus = signal;
    if (g_runner)
        g_runner->RequestToStop();
}

// Options
std::string g_filename;
bool opt_use_multithread = false;

bool
parse_args(int argc, PCHAR* argv)
{
    if (argc < 2) {
        std::cout << "Please provide .bin file" << std::endl;
        return true;
    }

    for (int a=1; a<argc; a++) {
        char *argn = argv[a];
        if (argn && *argn == '-')
            argn++;
        else {
            g_filename = argv[a];
            continue;
        }

        std::string opt_name(argn);
        if (opt_name == "j") {
            opt_use_multithread = true;
            std::cout << "enable Multithread." << std::endl;
        } else {
            std::cout << "Unknown option: '" << opt_name << "'" << std::endl;
            return true;
        }
    }

    return false;
}

// Main App
int
main(int argc, PCHAR* argv)
{
    AutoPause auto_pause;

    assert(sizeof(mem_ref_t) == 16);
    assert(sizeof(buf_string_t) == 6*16);

    if (parse_args(argc, argv)) return 1;

    // Install a signal handler
    std::signal(SIGINT, signal_handler);

    MyLogRunner runner;
    g_runner = &runner;

    if (runner.Open(g_filename)) {
        runner.SetOptions(0); // LR_SHOW_BB | LR_SHOW_MEM | LR_SHOW_LIBCALL
        //runner.SetOptions( LR_SHOW_BB | LR_SHOW_LIBCALL);

        auto start = std::chrono::system_clock::now();
        if (opt_use_multithread)
            runner.RunMT();
        else
            runner.Run();
        auto end = std::chrono::system_clock::now();

        if (gSignalStatus) {
            std::cout << "Break!" << std::endl;
            gSignalStatus = 0;
        }

        std::cout << "+++" << std::endl;
        auto minutes = std::chrono::duration_cast<std::chrono::minutes>(end-start);
        auto seconds = std::chrono::duration_cast<std::chrono::seconds>(end-start-minutes);

        std::time_t end_time = std::chrono::system_clock::to_time_t(end);
        std::cout << "finished at " << std::ctime(&end_time)
                  << "elapsed time: " << minutes.count() << ":" << seconds.count() << "s" << std::endl;

        runner.DumpCSV();
    }
    std::cout << "===" << std::endl;
    runner.Summary();

    return 0;
}