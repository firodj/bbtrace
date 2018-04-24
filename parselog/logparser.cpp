#include <string>
#include <fstream>

#define WITHOUT_DR
#include "datatypes.h"

#include "logparser.h"

bool
logparser_c::open(const char* filename)
{
    filename_ = filename;
    input_.open(filename, std::ios_base::binary);
    if (input_) {
        buffer_.reset(0);
        return true;
    }
    return false;
}

char*
logparser_c::fetch(uint64 *filepos)
{
    while (true) {
        char *item = buffer_.fetch(filepos);
        if (item) return item;
        if (!buffer_.extract(input_)) break;
    }
    return nullptr;
}

uint
logparser_c::peek(uint64 *filepos)
{
    while (true) {
        uint kind = buffer_.peek(filepos);
        if (kind != KIND_NONE) return kind;
        if (!buffer_.extract(input_)) break;
    }
    return KIND_NONE;
}
