#pragma once

#include <map>
#include <tracelog_reader.h>
#include <cassert>
#include <fstream>
#include <iomanip>

class tree_t;

typedef std::map<uint, tree_t> tree_children_t;

class tree_t {
public:
    tree_t* parent;
    tree_children_t children;

    block_t *start_block;
    block_t *end_block;

    uint64_t size;
    uint64_t hits;

	tree_t(tree_t * _parent, block_t * _block) :
		parent(_parent), start_block(_block), size(1), hits(0), end_block(nullptr)
	{
	}

	tree_t() : tree_t(nullptr, nullptr)
	{
	}

  virtual ~tree_t()
  {
  }
};

class history_t {
public:
    uint thread_id;
    block_t *last_block;
    tree_t root;
    tree_t* last_tree;

	history_t(): last_tree(nullptr), last_block(nullptr), thread_id(0)
	{
		last_tree = &root;
	}

  virtual ~history_t()
  {
  }
};

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
            histories_[thread_id].thread_id = thread_id;
        }

        return histories_[thread_id];
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

    void DoStart2(history_t &history, block_t *block)
    {
        if (history.last_tree->children.find(block->addr) == history.last_tree->children.end()) {
            history.last_tree->children[block->addr].parent = history.last_tree;
            history.last_tree->children[block->addr].start_block = block;
        }

        history.last_tree = &history.last_tree->children[block->addr];
        history.last_tree->end_block = nullptr;
        history.last_tree->hits++;
    }

    bool DoPopInto2(history_t &history, block_t *block)
    {
        tree_t *current = nullptr;
        tree_t *found = nullptr;

        for (current = history.last_tree->parent; current; current = current->parent) {
            if (current->end_block &&
                current->end_block->kind == BLOCK &&
                current->end_block->end == block->addr) {
                    found = current;
                    break;
            }
        }

        if (found) {
            history.last_tree->end_block = history.last_block;
            history.last_tree = found;
            history.last_tree->end_block = block;
            return true;
        }

        return false;
    }

    void DoPush2(history_t &history, block_t *block)
    {
        history.last_tree->end_block = history.last_block;

        if (history.last_tree->children.find(block->addr) == history.last_tree->children.end()) {
            history.last_tree->children[block->addr].parent = history.last_tree;
            history.last_tree->children[block->addr].start_block = block;
        }

        history.last_tree = &history.last_tree->children[block->addr];
        history.last_tree->end_block = nullptr;
        history.last_tree->hits++;
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

    void Step(uint thread_id, uint current_pc) {
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
            DoStart2(history, block);
        } else {
            if (history.last_block->kind == BLOCK) {
                if (block->kind == BLOCK) {
                    if (history.last_block->jump == CALL) {
                        if (block->addr != history.last_block->end) {
                            UpdateXref(history, block);
                            DoPush2(history, block);
                        } else {
                            DoStart2(history, block);
                        }
                    } else
                    if (history.last_block->jump == RET) {
                        if (!DoPopInto2(history, block)) DoStart2(history, block);
                    } else
                    if (history.last_block->jump == JMP) {
                        //
                    }
                } else {
                    assert(block->kind == SYMBOL);
                    if (history.last_block->jump == CALL) {
                        DoPush2(history, block);
                    } else {
                        DoStart2(history, block);
                    }
                }
            } else {
                assert(history.last_block->kind == SYMBOL);
                if (block->kind == BLOCK) {
                    if (!DoPopInto2(history, block)) DoPush2(history, block);
                } else {
                    assert(block->kind == SYMBOL);
                    DoPush2(history, block);
                }
            }

        }

        history.last_block = block;
    }

    uint64_t CalculateSizeTree(tree_t *tree)
    {
      for(auto& kv : tree->children) {
          tree_t *child = &kv.second;
          tree->size += CalculateSizeTree(child);
      }
      return tree->size;
    }

    void OutputTree(std::ostream &out, tree_t *tree, int level = 0) {
      if (level == 0) {
          out << "+ ";
      } else {
          out << "   ";
          for (int tab = level; tab > 1; tab--) {
            out << "|  ";
          }
          out << "|_ ";
      }

      if (tree->start_block) {
        out << std::internal << std::setfill('0')
            << std::setw(10) << std::hex << std::showbase << tree->start_block->addr << std::endl;
      } else {
        out << "(root)" << std::endl;
      }

      for(auto& kv : tree->children) {
        tree_t *child = &kv.second;
        OutputTree(out, child, level + 1);
      }
    }

    void PrintTree(const char *filename)
    {
        std::cout << "Writing: " << filename << std::endl;
        std::ofstream outfile(filename, std::ofstream::binary);

        for (auto& kv : histories_) {
            history_t &history = kv.second;

            std::cout << "thread id: " << history.thread_id << std::endl;

            uint64_t size = CalculateSizeTree(&history.root);
            std::cout << "size: " << size << std::endl;

            //OutputTree(outfile, &history.root, 0);
        }
    }
#if 0
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
#endif

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
