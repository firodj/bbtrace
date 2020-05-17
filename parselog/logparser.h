#pragma once

#include <fstream>
#include "buffer.h"

class LogParser {
public:
    bool Open(const char* filename);
    char* Fetch();
    uint Peek();
    void Seek(uint64 filepos);
    uint64 Tell();

    std::string filename() { return filename_; };

private:
    std::string filename_;
    std::ifstream input_;
    buffer_c buffer_;
};
