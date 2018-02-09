#pragma once

#include <map>
#include <tracelog_reader.h>
#include <cassert>
#include <fstream>

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

class FlameGraph{
private:
    blocks_t blocks_;
    histories_t histories_;

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

    void Print()
    {
        for (auto& kv : histories_) {
            history_t &history = kv.second;

            std::cout << "thread id: " << history.thread_id << std::endl;
            std::cout << "x: " << history.x << std::endl;
            std::cout << "y: " << history.y << std::endl;
            std::cout << "coaches size: " << history.coaches.size() << std::endl;
            std::cout << "railways size: " << history.railways.size() << std::endl;

            std::ofstream outfile("coaches.csv",std::ofstream::binary);

            uint i = 0;
            for (auto coach : history.coaches) {
                i++;
                outfile << coach->x_0 << "," << coach->x_1 << "," << coach->y << ","
                    << coach->start_block->addr << "," << coach->start_block->kind << ","
                    << history.thread_id << ",";
                if (coach->end_block) {
                    outfile << coach->end_block->addr << "," << coach->end_block->kind;
                } else {
                    outfile << 0 << "," << 0;
                }
                outfile << std::endl;
                if (i % 10000 == 0) std::cout << i << std::endl;
            }
        }
    }
};
