#pragma once

#include <fstream>
#include "buffer.h"

class logparser_c {
private:
    std::string filename_;
    std::ifstream input_;
    buffer_c buffer_;

public:
    bool open(const char* filename);
    char* fetch();
    uint peek();
    void seek(uint64 filepos);
    uint64 tell();

    std::string filename() { return filename_; };
};
