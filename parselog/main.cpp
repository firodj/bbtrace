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

volatile std::sig_atomic_t gSignalStatus;
static LogRunner *g_runner = nullptr;

using Replxx = replxx::Replxx;

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

class Options {
public:
    std::string filename;

    uint opt_memtrack = 0;
    bool opt_input_state = false;
    bool opt_use_multithread = false;

    std::vector<std::string> opt_procnames;

    argh::parser cmdl;

    Options()
    {
    }

    void split_string(std::string s, std::vector<std::string>& ar) {
        std::string delimiter = ",";

        size_t pos = 0;
        std::string token;
        while ((pos = s.find(delimiter)) != std::string::npos) {
            token = s.substr(0, pos);
            ar.push_back(token);
            s.erase(0, pos + delimiter.length());
        }
    }

    bool process(int argc, PCHAR* argv)
    {
        cmdl.parse(argc, argv, argh::parser::PREFER_PARAM_FOR_UNREG_OPTION);

        if (!(cmdl(1) >> filename)) {
            std::cerr << "Please provide .bin file" << std::endl;
            return false;
        }

        if (cmdl["-i"])
            opt_input_state = true;
        
        std::string procnames;
        if (cmdl("-p") >> procnames) {
            split_string(procnames, opt_procnames);

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

void signal_handler(int signal)
{
    gSignalStatus = signal;
    if (g_runner)
        g_runner->RequestToStop();
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

Replxx::completions_t
hook_completion(std::string const& context, int& contextLen, std::vector<std::string> const& suggests) {
	Replxx::completions_t completions;

	std::string prefix { context };

    for (auto const& e : suggests) {
        if (e.compare(0, prefix.size(), prefix) == 0) {
            completions.emplace_back(e.c_str());
        }
    }

	return completions;
}

void
load()
{
    uint sav_cnt = get_available_states(g_options.filename);
    if (sav_cnt <= 1) return;

    std::ostringstream oss;
    oss << get_states_name(g_options.filename, sav_cnt-1) << ".symbols";

    std::ifstream fsymb;
    fsymb.open(oss.str(), std::ifstream::in | std::ifstream::binary);
    std::cout << "Reading from " << oss.str() << std::endl;
    g_runner->RestoreSymbols(fsymb);

    oss.str("");
    oss.clear();
    oss << get_states_name(g_options.filename, sav_cnt-1);

    std::ifstream frun;
    frun.open(oss.str(), std::ifstream::in | std::ifstream::binary);
    std::cout << "Reading from " << oss.str() << std::endl;
    g_runner->RestoreState(frun);

    //g_runner->Dump();
}

void
save()
{
    uint sav_cnt = get_available_states(g_options.filename);
    std::ostringstream oss;
    oss << get_states_name(g_options.filename, sav_cnt) << ".symbols";

    std::ofstream fsymb;
    fsymb.open(oss.str(), std::ofstream::out | std::ofstream::binary);
    std::cout << "Writing to " << oss.str() << std::endl;
    g_runner->SaveSymbols(fsymb);

    oss.str("");
    oss.clear();
    oss << get_states_name(g_options.filename, sav_cnt);

    std::ofstream frun;
    frun.open(oss.str(), std::ofstream::out | std::ofstream::binary);
    std::cout << "Writing to " << oss.str() << std::endl;
    g_runner->SaveState(frun);
}

int
main(int argc, PCHAR* argv)
{
    // AutoPause auto_pause;

	// words to be completed
	std::vector<std::string> suggests {
		"run", "quit", "exit", "save", "load",
    };

    Replxx rx;
	rx.install_window_change_handler();

    std::string prompt {"\x1b[1;32mbbtrace\x1b[0m> "};

    assert(sizeof(mem_ref_t) == 16);
    assert(sizeof(buf_string_t) == 6*16);

    if (! g_options.process(argc, argv)) {
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
	rx.set_completion_callback( std::bind( &hook_completion, std::placeholders::_1, std::placeholders::_2, std::cref( suggests ) ) );

    // Install a signal handler
    std::signal(SIGINT, signal_handler);

    g_runner = LogRunner::instance();
    g_runner->ListObservers();

    if (! g_runner->Open(g_options.filename)) {
        AutoPause auto_pause;
        return 1;
    }

    if (g_options.opt_input_state)
        load();

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

        if (input.empty()) {
            // user hit enter on an empty line

            continue;

        } else if (input.compare(0, 4, "quit") == 0 || input.compare(0, 4, "exit") == 0) {
            // exit the repl

            break;
        } else if (input.compare(0, 3, "run") == 0) {
            auto start = std::chrono::system_clock::now();
            if (g_options.opt_use_multithread)
                g_runner->RunMT();
            else
                g_runner->Run();
            auto end = std::chrono::system_clock::now();

            gSignalStatus = 0;

            auto minutes = std::chrono::duration_cast<std::chrono::minutes>(end-start);
            auto seconds = std::chrono::duration_cast<std::chrono::seconds>(end-start-minutes);
            std::time_t end_time = std::chrono::system_clock::to_time_t(end);

            std::cout << "+++" << std::endl;
            std::cout << "finished at " << std::ctime(&end_time)
                    << "elapsed time: " << minutes.count() << ":" << seconds.count() << "s" << std::endl;
                
            std::cout << "===" << std::endl;
            g_runner->Summary();
        } else if (input.compare(0, 4, "save") == 0) {
            save();
        } else if (input.compare(0, 4, "load") == 0) {
            load();
        }
    }
    

    return 0;
}
