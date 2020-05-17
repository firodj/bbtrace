#pragma once

#include <cassert>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <map>
#include <unordered_map>
#include <vector>
#include <sstream>

#define WITHOUT_DR
#include "../src/datatypes.h"

typedef struct {
  typedef enum {BLOCK, APICALL} block_kind_t;
  typedef enum {NONE, JMP, CALL, RET} block_jump_t;

  block_kind_t kind;
  uint addr;
  block_jump_t jump;
  uint end;
  uint last;
  std::string name;
  uint thread_id;
  uint64_t ts;
} block_t;

typedef struct {
  uint addr;
  uint end;
} region_t;

typedef std::map<uint, block_t> blocks_t;
typedef std::map<uint, std::string> symbols_t;

typedef std::map<uint, region_t> regions_t;
typedef std::map<uint, uint> map_uint_uint_t;

class tree_t;

typedef std::map<uint, tree_t*> tree_children_t;
typedef std::vector<uint> array_uint_t;

class tree_t {
public:
  tree_t* parent;
  tree_children_t children;
  array_uint_t children_order;

  block_t *start_block;
  block_t *end_block;

  uint size;
  uint64 hits;
  uint depth;

  tree_t(tree_t * _parent, block_t * _block) :
    parent(_parent), start_block(_block), size(0), hits(0), end_block(nullptr), depth(0)
  {
  }

  tree_t() : tree_t(nullptr, nullptr)
  {
  }

  virtual ~tree_t()
  {
    for(auto& kv : children) {
      tree_t *child = kv.second;
      delete child;
    }
  }

  bool is_root() {
    return parent == nullptr;
  }

  tree_t *get_child(block_t *_block, uint _depth)
  {
    // Determine _parent
    assert(_depth >= 1);
    tree_t *_parent = get_parent(_depth - 1);

    if (!_parent) {
      std::ostringstream ss;
      ss << "cannot find parent with depth:" << _depth;
      throw std::runtime_error(ss.str());
    }

    // Find duplicate block
    tree_t *_child = nullptr;
    if (_parent->children.find(_block->addr) == _parent->children.end()) {
      _child = new tree_t(this, _block);
      _parent->children[_block->addr] = _child;
      _child->depth = _parent->depth + 1;
      _parent->children_order.push_back(_block->addr);
    } else {
      _child = _parent->children[_block->addr];
    }
    return _child;
  }

  tree_t *get_parent(uint _depth)
  {
    tree_t *_parent = this;

    for (;_parent;_parent=_parent->parent)
      if (_parent->depth == _depth) break;

    return _parent;
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

  void start_sub(block_t *block, uint depth)
  {
    last_tree = last_tree->get_child(block, depth);

    if (last_tree->depth != depth) {
      std::ostringstream ss;
      ss << "mismatch depth in:" << depth << " tree:" << last_tree->depth;
      throw std::runtime_error(ss.str());
    }

    last_tree->end_block = nullptr;
    last_tree->hits++;

    last_block = block;
  }

  void last_bb(block_t *block, uint depth)
  {
    tree_t *current = last_tree->get_parent(depth);
    if (! current) {
      std::ostringstream ss;
      ss << "cannot set last_bb in:" << depth;
      throw std::runtime_error(ss.str());
    }

    current->end_block = last_block;

    last_block = block;
  }
};

typedef std::map<uint, history_t> histories_t;

#pragma pack(1)
typedef struct {
  uint32_t addr;
  uint32_t size;
} pkt_tree_t;
#pragma pack()

typedef std::unordered_map<uint, uint64_t> app_pc_list_t;
typedef std::unordered_map<uint, app_pc_list_t> app_pc_map_t;

class FlameGraph{
private:
  blocks_t blocks_;
  array_uint_t blocks_order_;
  symbols_t symbols_;
  histories_t histories_;
  array_uint_t histories_order_;
  app_pc_map_t pc_to_pc_;

public:
  history_t& GetHistory(uint thread_id)
  {
    histories_t::iterator it = histories_.find(thread_id);
    if (it == histories_.end()) {
      histories_[thread_id].thread_id = thread_id;
      histories_order_.push_back(thread_id);
    }

    return histories_[thread_id];
  }

  block_t* GetBlock(uint addr)
  {
    blocks_t::iterator it = blocks_.find(addr);
    if (it == blocks_.end()) return nullptr;
    return &it->second;
  }

  FlameGraph(){
  }

  bool BlockExists(uint addr) {
    return blocks_.find(addr) != blocks_.end();
  }

  void AddBlock(block_t &block) {
    if (BlockExists(block.addr)) return;
    blocks_[block.addr] = block;
    blocks_order_.push_back(block.addr);

    if (block.kind == block_t::APICALL) {
      symbols_[block.addr] = block.name;
    }
  }
#if 0
  void DoStart2(history_t &history, block_t *block)
  {
    if (history.last_tree->parent) {
      history.last_tree->end_block = history.last_block;
      history.last_tree = history.last_tree->parent->get_child(block);
      history.last_tree->end_block = nullptr;
      history.last_tree->hits++;
    } else {
      history.last_tree = history.last_tree->get_child(block);
      history.last_tree->end_block = nullptr;
      history.last_tree->hits++;
    }
  }

  bool DoPopInto2(history_t &history, block_t *block)
  {
    tree_t *current = nullptr;
    tree_t *found = nullptr;

    for (current = history.last_tree->parent; current; current = current->parent) {
      if (current->end_block &&
        current->end_block->kind == block_t::BLOCK &&
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
    history.last_tree = history.last_tree->get_child(block);
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
      if (history.last_block->kind == block_t::BLOCK) {
        if (block->kind == block_t::BLOCK) {
          if (history.last_block->jump == block_t::CALL) {
            if (block->addr == history.last_block->end) {
              //
            } else {
              UpdateXref(history, block);
              DoPush2(history, block);
            }
          } else
          if (history.last_block->jump == block_t::RET) {
            if (!DoPopInto2(history, block))
              DoStart2(history, block);
          } else
          if (history.last_block->jump == block_t::JMP) {
            //
          }
        } else {
          assert(block->kind == block_t::APICALL);
          if (history.last_block->jump == block_t::CALL) {
            DoPush2(history, block);
          } else {
            DoStart2(history, block);
          }
        }
      } else {
        assert(history.last_block->kind == block_t::APICALL);
        if (block->kind == block_t::BLOCK) {
          if (!DoPopInto2(history, block))
            DoPush2(history, block);
        } else {
          assert(block->kind == block_t::APICALL);
          //
        }
      }

    }

    history.last_block = block;
  }

#endif

  uint CalculateSizeTree(tree_t *tree, int level = 0)
  {
    if (tree->size == 0) {
      for(auto& kv : tree->children) {
        tree_t *child = kv.second;
        tree->size += CalculateSizeTree(child, level + 1);
      }
      tree->size += 1; //itself;
    }
    return tree->size;
  }

  void OutputTree(std::ostream *out, tree_t *tree, int level = 0) {
    pkt_tree_t pkt_tree;

    pkt_tree.addr = 0;
    pkt_tree.size = tree->size;
    std::string name;

    if (tree->start_block) {
      pkt_tree.addr = tree->start_block->addr;

      if (tree->start_block->kind == block_t::APICALL) {
        name = tree->start_block->name;
      }
    }

    out->write((const char *)&pkt_tree, sizeof(pkt_tree));

    for(auto k : tree->children_order) {
      tree_t *child = tree->children[k];
      OutputTree(out, child, level + 1);
    }
  }

  void OutputSymbols(std::ostream *out)
  {
    uint32_t size = symbols_.size();
    std::cout << "symbols size: " << size << std::endl;
    out->write((const char*)&size, sizeof(size));

    for (auto &symbol: symbols_) {
      uint8_t name_len = symbol.second.length() > 255 ? 255 : symbol.second.length();
      if (name_len) {
        uint32_t addr = symbol.first;
        out->write((const char*)&addr, sizeof(addr)); // 4
        out->write((const char*)&name_len, sizeof(name_len)); // 1
        out->write(symbol.second.c_str(), name_len); // N
      }
    }
  }

  void PrintTreeBIN(std::string filename)
  {
    std::cout << "Writing: " << filename << std::endl;
    std::ofstream outfile(filename, std::ofstream::binary);

    OutputSymbols(&outfile);

    for (auto k : histories_order_) {
      history_t &history = histories_[k];

      std::cout << "thread id: " << history.thread_id << std::endl;

      uint size = history.root.size;
      if (!size)
        size = CalculateSizeTree(&history.root);

      std::cout << "dump tree: ..." << size << std::endl;
      OutputTree(&outfile, &history.root, 0);
    }
  }

  void DumpTree(tree_t *tree, int level = 0) {
    uint32_t addr = tree->start_block ? tree->start_block->addr : 0;
    uint size = tree->size;

    std::cout << std::string(level, ' ');
    std::cout << "+ addr: 0x" << std::hex << addr;
    std::cout << " (" <<  std::dec << size << ")" << std::endl;

    for(auto k : tree->children_order) {
      tree_t *child = tree->children[k];
      DumpTree(child, level + 1);
    }
  }

  void DumpHistory()
  {
    for (auto k : histories_order_) {
      history_t &history = histories_[k];

      std::cout << "Thread id: " << history.thread_id << std::endl;

      uint size = history.root.size;
      if (!size)
        size = CalculateSizeTree(&history.root);

      DumpTree(&history.root, 0);
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

  void DumpRegions() {
    map_uint_uint_t ends;
    regions_t regions;
    for (auto k: blocks_order_)
    {
      block_t &block = blocks_[k];
      if (block.kind == block_t::APICALL) continue;
      bool is_added = false;
      // try to append existing
      {
        auto it = ends.find(block.addr);
        if (it != ends.end()) {
          region_t &region = regions[it->second];
          region.end = block.end;
          ends[region.end] = region.addr;
          ends.erase(it);
          is_added = true;
        }
      }
      // try to prepend existing
      {
        auto it = regions.find(block.end);
        if (it != regions.end()) {
          region_t &region = it->second;
          region.addr = block.addr;
          regions[region.addr] = region;
          regions.erase(it);
          ends[region.end] = region.addr;
          is_added = true;
        }
      }
      if (!is_added) {
        auto it = regions.find(block.addr);
        if (it == regions.end()) {
          region_t region;
          region.addr = block.addr;
          region.end = block.end;
          regions[region.addr] = region;
          ends[region.end] = region.addr;
        }
      }
    }

    std::cout << std::hex << "--selected-range ";
    for (auto it = regions.begin(); it != regions.end(); )
    {
      std::cout << "0x" << it->second.addr << "-0x" << it->second.end;
      if (++it != regions.end()) std::cout << ",";
    }
    std::cout << std::endl;
  }

  void DumpBlocksCSV(std::string &csvname)
  {
    std::cout << "Dump CSV: " << csvname << " ..." << std::endl;

    std::ofstream outfile;
    outfile.open(csvname.c_str());

    outfile << "ts,tid,pc,kind,next,jump" << std::endl;
    for (auto k: blocks_order_)
    {
      block_t &block = blocks_[k];

      outfile << std::dec << block.ts << ",";
      outfile << "0x" << std::hex << std::nouppercase << block.thread_id << ",";
      outfile << "0x" << block.addr << ",";
      switch(block.kind) {
        case block_t::BLOCK:
          outfile << "BLOCK,"; break;
        case block_t::APICALL:
          outfile << "APICALL,"; break;
        default:
          outfile << ",";
      }
      outfile << "0x" << block.end << ",";
      switch (block.jump) {
        case block_t::CALL: outfile << "CALL"; break;
        case block_t::RET: outfile << "RET"; break;
        case block_t::JMP: outfile << "JMP"; break;
        default: outfile << "";
      }
      outfile << std::endl;
    }
  }
};