#include <iostream>
#include <cstring>

#include "serializer.h"
#define WITHOUT_DR
#include "datatypes.h"

void write_u32(std::ostream &out, uint32_t u32) {
    out.write((char*)&u32, sizeof(u32));
}

void write_u64(std::ostream &out, uint64_t u64) {
    out.write((char*)&u64, sizeof(u64));
}

void write_bool(std::ostream &out, int b) {
    out.put((char)b);
}

void write_str(std::ostream &out, std::string const &str) {
    int sz = str.size();
    if (sz > 255) sz = 255;
    out.put((char)sz);
    out.write(str.c_str(), sz);
}

void write_data(std::ostream &out, char*data, uint sz) {
    out.write(data, sz);
}

uint32_t read_u32(std::istream &in) {
    uint32_t u32;
    in.read((char*)&u32, sizeof(u32));
    return u32;
}

uint64_t read_u64(std::istream &in) {
    uint64_t u64;
    in.read((char*)&u64, sizeof(u64));
    return u64;
}

int read_bool(std::istream &in) {
    int b = in.get();
    return b;
}

std::string read_str(std::istream &in) {
    std::string str;
    char strpas[256];
    strpas[0] = in.get();
    in.read(&strpas[1], strpas[0]);

    str.assign(&strpas[1], strpas[0]);
    return str;
}

bool read_match(std::istream &in, const char *signature) {
    int current = in.tellg();
    char cstr[16];
    size_t l = strlen(signature);
    if (l > 16) l = 16;

    in.read(cstr, l);
    if (strncmp(cstr, signature, l) == 0)
        return true;
    in.seekg(current);
    return false;

}

void read_data(std::istream &in,char*data, uint sz) {
    in.read(data, sz);
}
