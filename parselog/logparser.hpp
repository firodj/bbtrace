#pragma once

#include <string>
#include <fstream>
#include "buffer.hpp"

class logparser_c {
private:
    std::string filename_;
    std::ifstream input_;
    buffer_c buffer_;

public:
    bool open(const char* filename)
    {
        filename_ = filename;
        input_.open(filename, std::ios_base::binary);
        if (input_) {
            buffer_.reset(0);
            return true;
        }
        return false;
    }

    char* fetch(uint64 *filepos = nullptr)
    {
        while (true) {
            char *item = buffer_.fetch(filepos);
            if (item) return item;
            if (!buffer_.extract(input_)) break;
        }
        return nullptr;
    }

    uint peek(uint64 *filepos = nullptr)
    {
        while (true) {
            uint kind = buffer_.peek(filepos);
            if (kind != KIND_NONE) return kind;
            if (!buffer_.extract(input_)) break;
        }
        return KIND_NONE;
    }
};
