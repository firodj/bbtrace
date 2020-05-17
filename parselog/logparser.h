#pragma once

#include <fstream>
#include "parsebuffer.h"

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
    ParseBuffer buffer_;
};
