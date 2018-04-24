#pragma once

#include "buffer.h"

class logparser_c {
private:
    std::string filename_;
    std::ifstream input_;
    buffer_c buffer_;

public:
    bool open(const char* filename);
    char* fetch(uint64 *filepos = nullptr);
    uint peek(uint64 *filepos = nullptr);
};
