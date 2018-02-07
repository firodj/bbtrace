#define CSV_IO_NO_THREAD 1
#define MAX_FILE_NAME_LENGTH 512
#define BLOCK_LEN (1<<24)

#include <cstdio>
#include <cstring>
#include <cstdlib>
#include <cstdint>
#include <iostream>
#include <unordered_map>
#include <sstream>
#include "async_reader.h"
#include "tracelog_reader.h"
#include "bbtrace_core.h"


int main(int argc, const char* argv[])
{
    if (argc <= 1) {
        std::cout << "Syntax:" << argv[0] << "<trace-log>.0001" << std::endl;
        return 0;
    }

    try
    {
        TraceLog tlog(argv[1]);
        std::ostringstream csvname(tlog.log_name(), std::ios_base::ate);
        csvname << ".csv";
        std::cout << "csvname:" << csvname.str() << std::endl;

        LineReader in(csvname.str());

        char*line;
        do{
            line = in.next_line();
            if(!line) break;

            char sep = ',';
            char quote = '"';
            for(int i=0; line; i++) {
                char *col_begin = line;
                char *col_end = col_begin;
                while(*col_end != sep && *col_end != '\0') {
                    if(*col_end != quote)
                        ++col_end;
                    else{
                        do{
                            ++col_end;
                            while(*col_end != quote){
                                if (*col_end == '\0'){
                                    throw std::runtime_error("Escaped string not closed");
                                }
                                ++col_end;
                            }
                            ++col_end;
                        }while(*col_end == quote);
                    }
                }
                if(*col_end == '\0'){
                    line = nullptr;
                }else{
                    *col_end = '\0';
                    line = col_end + 1;
                }
                //std::cout << col_begin << std::endl;
            }
            //std::cout << line;
        } while(true);

        pkt_trace_t *pkt_trace;
        char *dat;

        for (int i=0; dat = tlog.next_packet(&pkt_trace); i++) {
            //std::cout << "pkt_trace[" << i << "].size: " << pkt_trace->size << std::endl;
        }

    } catch ( std::exception &e )
    {
        std::cerr << "Caught " << e.what( ) << std::endl;
        std::cerr << "Type " << typeid( e ).name( ) << std::endl;
        return -1;
    }
    return 0;
}
