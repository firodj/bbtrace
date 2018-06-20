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
logparser_c::fetch()
{
    while (true) {
        char *item = buffer_.fetch();
        if (item) return item;
        if (!buffer_.extract(input_)) break;
    }
    return nullptr;
}

uint
logparser_c::peek()
{
    while (true) {
        uint kind = buffer_.peek();
        if (kind != KIND_NONE) return kind;
        if (!buffer_.extract(input_)) break;
    }
    return KIND_NONE;
}

void
logparser_c::seek(uint64 filepos)
{
    if (input_) {
        input_.seekg(filepos);
        buffer_.reset(filepos);
    }
}

uint64_t
logparser_c::tell()
{
    return buffer_.inpos();
}
