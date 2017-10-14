#include <cstdio>
#include <cstring>
#include <cstdlib>
#include <unordered_map>
#include "inttypes.h"
#include "bbtrace_core.h"

typedef std::unordered_map<uint, app_pc> last_block_t;
typedef std::unordered_map<app_pc, bool> app_pc_list_t;
typedef std::unordered_map<app_pc, app_pc_list_t> app_pc_map_t;

int main(int argc, const char* argv[])
{
    if (argc <= 1) {
        printf("Syntax: %s <tarce-log.0001>\n", argv[0]);
        return 0;
    }

    const char *s = strstr(argv[1], ".0001");
    if (!s) {
        printf("File should be .0001!");
        return -1;
    }

    char log_name[256];
    size_t len = (size_t)s-(size_t)argv[1];

    strncpy(log_name, argv[1], len);
    log_name[len] = 0;

    char file_name[256];
    pkt_trace_t pkt_trace;
    char * buffer = (char*) malloc(sizeof(app_pc) * BUF_TOTAL);

    last_block_t last_block;
    app_pc_map_t pc_to_pc;

    for(int n=1;;n++) {
        sprintf(file_name, "%s.%04d", log_name, n);
        FILE *fp = fopen(file_name, "rb");
        if (!fp) {
            if (n == 1) {
                printf("File not found! %s", file_name);
                return -1;
            }
            break;
        }
        printf("Read %s:", file_name);

        while (!feof(fp)) {
            fread(&pkt_trace, sizeof(pkt_trace), 1, fp);
            fread(buffer, pkt_trace.size * sizeof(app_pc), 1, fp);

            app_pc *pc = (app_pc*)buffer;
            for(int i=0; i<pkt_trace.size; i++, pc++) {
                const app_pc current_pc = *pc;
                if (last_block.find(pkt_trace.header.thread) == last_block.end()) {
                    last_block[pkt_trace.header.thread] = (app_pc)0;
                } else {
                    const app_pc last_pc = last_block[pkt_trace.header.thread];
                    if (pc_to_pc.find( current_pc ) == pc_to_pc.end()) {
                        pc_to_pc[current_pc][last_pc] = false;
                    } else {
                        if (pc_to_pc[current_pc].find(last_pc) == pc_to_pc[current_pc].end()) {
                            pc_to_pc[current_pc][last_pc] = false;
                        } else {
                            pc_to_pc[current_pc][last_pc] = true;
                        }
                    }
                }

                last_block[pkt_trace.header.thread] = current_pc;
            }

            printf(".");
        }

        fclose(fp);
        printf("\n");
    }

    free (buffer);

    sprintf(file_name, "%s.flow", log_name);
    FILE *fp = fopen(file_name, "w");

    printf("Write %s...\n", file_name);
    for (app_pc_map_t::const_iterator it1 = pc_to_pc.begin(); it1 != pc_to_pc.end(); ++it1) {
        for (app_pc_list_t::const_iterator it2 = it1->second.begin(); it2 != it1->second.end(); ++it2) {
            fprintf(fp, "\"0x%08x\", \"0x%08x\", %d\n", (uint) it1->first, (uint) it2->first, it2->second);
        }
    }

    fclose(fp);

    return 0;
}
