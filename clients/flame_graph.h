#pragma once

#include <map>
#include <tracelog_reader.h>
#include <cassert>
#include <fstream>
#include <iomanip>

typedef struct {
    uint x_0;
    uint x_1;
    int y;
    block_t *start_block;
    block_t *end_block;
} coach_t;

typedef std::vector<std::shared_ptr<coach_t>> coaches_t;

typedef struct {
    uint thread_id;
    block_t *last_block;
    int y;
    uint x;
    coaches_t railways;
    coaches_t coaches;
} history_t;

typedef std::map<uint, history_t> histories_t;

#pragma pack(1)
typedef struct {
    uint thread_id;
    uint max_x;
    int max_y;
    size_t num_coaches;
} pkt_history_t;

typedef struct {
    uint x_0;
    uint x_1;
    int y;
    uint addr;  // start_block->addr
} pkt_coach_t;
#pragma pack()

typedef std::unordered_map<uint, uint64_t> app_pc_list_t;
typedef std::unordered_map<uint, app_pc_list_t> app_pc_map_t;

class FlameGraph{
private:
    blocks_t blocks_;
    histories_t histories_;
    app_pc_map_t pc_to_pc_;

    history_t& GetHistory(uint thread_id)
    {
        histories_t::iterator it = histories_.find(thread_id);
        if (it == histories_.end()) {
            histories_[thread_id] = {thread_id, nullptr, 0, 0, {}, {}};
        }

        return histories_[thread_id];
    }

    int Peek(history_t &history, block_t *block) {
        int y;
        for (y = history.y-1; y >= 0; y--) {
            auto last_coach = history.railways[y];
            if (last_coach->end_block &&
                last_coach->end_block->kind == BLOCK &&
                last_coach->end_block->end == block->addr) break;
        }
        return y;
    }

    void Stop(history_t &history, int pop_y)
    {
        for (int y = history.y; y > pop_y; y--) {
            auto last_coach = history.railways[y];
            last_coach->x_1 = history.x;
            history.railways[y] = nullptr;
        }
    }

public:
    FlameGraph(){
    }

    bool BlockExists(uint addr) {
        return blocks_.find(addr) != blocks_.end();
    }

    void AddBlock(block_t block) {
        if (BlockExists(block.addr)) return;
        blocks_[block.addr] = block;
    }

    void DoStart(history_t &history, block_t *block)
    {
        history.x++;

        if (history.railways.size() <= history.y) {
            assert(history.railways.size() == history.y);
            history.railways.push_back(nullptr);
        } else {
            auto last_coach = history.railways[history.y];
            if (last_coach && last_coach->x_1 == 0) last_coach->x_1 = history.x;
        }

        auto coach = std::make_shared<coach_t>();
        coach->y = history.y;
        coach->x_0 = history.x;
        coach->x_1 = 0;
        coach->start_block = block;
        coach->end_block = nullptr;

        history.coaches.push_back(coach);
        history.railways[history.y] = coach;

        // std::cout << "start x: " << history.x << " addr:" << block->addr << std::endl;
    }

    bool DoPopInto(history_t &history, block_t *block)
    {
        assert(block->kind == BLOCK);

        int pop_y = Peek(history, block);

        if (pop_y < 0) return false;

        auto past_coach = history.railways[history.y];
        past_coach->x_1 = history.x;
        past_coach->end_block = history.last_block;

        Stop(history, pop_y);

        history.y = pop_y;

        auto last_coach = history.railways[pop_y];
        last_coach->x_1 = history.x;
        last_coach->end_block = block;

        // std::cout << "pop into: " << block->addr << " y: " << history.y << std::endl;

        return true;
    }

    void UpdateXref(history_t &history, block_t *block)
    {
        uint current_pc = block->addr;
        uint last_pc = history.last_block->last;

        if (pc_to_pc_.find( current_pc ) == pc_to_pc_.end()) {
            pc_to_pc_[current_pc][last_pc] = 0;
        } else {
            if (pc_to_pc_[current_pc].find(last_pc) == pc_to_pc_[current_pc].end()) {
                pc_to_pc_[current_pc][last_pc] = 0;
            } else {
                pc_to_pc_[current_pc][last_pc]++;
            }
        }
    }

    void DoPush(history_t &history, block_t *block)
    {
        history.x++;

        auto last_coach = history.railways[history.y];
        last_coach->x_1 = history.x;
        last_coach->end_block = history.last_block;

        history.y++;

        if (history.railways.size() <= history.y) {
            assert(history.railways.size() == history.y);
            history.railways.push_back(nullptr);
        }

        auto coach = std::make_shared<coach_t>();
        coach->y = history.y;
        coach->x_0 = history.x;
        coach->x_1 = 0;
        coach->start_block = block;
        coach->end_block = nullptr;

        history.coaches.push_back(coach);
        history.railways[history.y] = coach;

        // std::cout << "push x: " << history.x - 1 << " end addr: " << history.last_block->addr << " return: " << history.last_block->end << " -|> y: " << history.y << " addr: " << block->addr << std::endl;
    }

    void Finish()
    {
        for (auto& kv : histories_) {
            history_t &history = kv.second;
            Stop(history, -1);
        }
    }

    uint Step(uint thread_id, uint current_pc) {
        history_t &history = GetHistory(thread_id);

        blocks_t::iterator it = blocks_.find(current_pc);
        if (it == blocks_.end()) {
            std::ostringstream msg;
            msg << "Missing block info:" << current_pc;
            throw std::runtime_error(msg.str());
        }

        block_t *block = &it->second;

        // std::cout << "* kind:" << block->kind << " addr:" << block->addr << " jump:" << block->jump << std::endl;

        if (history.last_block == nullptr) {
            DoStart(history, block);
        } else {
            if (history.last_block->kind == BLOCK) {
                if (block->kind == BLOCK) {
                    if (history.last_block->jump == CALL) {
                        if (block->addr != history.last_block->end) {
                            UpdateXref(history, block);
                            DoPush(history, block);
                        } else {
                            DoStart(history, block);
                        }
                    } else
                    if (history.last_block->jump == RET) {
                        if (!DoPopInto(history, block)) {
                            DoStart(history, block);
                        }
                    } else
                    if (history.last_block->jump == JMP) {
                        //
                    }
                } else {
                    assert(block->kind == SYMBOL);
                    if (history.last_block->jump == CALL) {
                        DoPush(history, block);
                    } else {
                        DoStart(history, block);
                    }
                }
            } else {
                assert(history.last_block->kind == SYMBOL);
                if (block->kind == BLOCK) {
                    if (!DoPopInto(history, block)) {
                        DoPush(history, block);
                    }
                } else {
                    assert(block->kind == SYMBOL);
                    DoPush(history, block);
                }
            }

        }

        history.last_block = block;

        return history.x;
    }

    void Print(const char *filename)
    {
        std::cout << "Writing: " << filename << std::endl;

        std::ofstream outfile(filename, std::ofstream::binary);

        for (auto& kv : histories_) {
            history_t &history = kv.second;

            std::cout << "thread id: " << history.thread_id << std::endl;
            std::cout << "x: " << history.x << std::endl;
            std::cout << "y: " << history.y << std::endl;
            std::cout << "coaches size: " << history.coaches.size() << std::endl;
            std::cout << "railways size: " << history.railways.size() << std::endl;

            pkt_history_t pkt_history;

            pkt_history.thread_id = history.thread_id;
            pkt_history.max_y = history.railways.size();
            pkt_history.max_x = history.x;
            pkt_history.num_coaches = history.coaches.size();

            outfile.write((const char *)&pkt_history, sizeof(pkt_history));

            uint i = 0;
            for (auto coach : history.coaches) {
                i++;

                pkt_coach_t pkt_coach;

                pkt_coach.x_0 = coach->x_0;
                pkt_coach.x_1 = coach->x_1;
                pkt_coach.y = coach->y;
                pkt_coach.addr = coach->start_block->addr;

                outfile.write((const char *)&pkt_coach, sizeof(pkt_coach));
                if (i % 100000 == 0) std::cout << ".";
            }
        }

        std::cout << std::endl;
    }

    void Flow(const char *filename)
    {
        std::cout << "Writing: " << filename << std::endl;

        std::ofstream outfile(filename, std::ofstream::out);

        for (app_pc_map_t::const_iterator it1 = pc_to_pc_.begin(); it1 != pc_to_pc_.end(); ++it1) {
            for (app_pc_list_t::const_iterator it2 = it1->second.begin(); it2 != it1->second.end(); ++it2) {
                outfile << std::internal << std::setfill('0')
                        << std::setw(10) << std::hex << std::showbase << it1->first << ","
                        << std::setw(10) << std::showbase << it2->first << ","
                        << std::dec << it2->second << std::endl;
            }
        }
    }
};
