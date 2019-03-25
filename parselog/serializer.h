#pragma once

void write_u32(std::ostream &out, uint32_t u32);
void write_u64(std::ostream &out, uint64_t u64);
void write_bool(std::ostream &out, int b);
void write_str(std::ostream &out, std::string const &str);
void write_data(std::ostream &out, char*data, uint32_t sz);

uint32_t read_u32(std::istream &in);
uint64_t read_u64(std::istream &in);
int read_bool(std::istream &in);
std::string read_str(std::istream &in);
bool read_match(std::istream &in, const char *signature);
void read_data(std::istream &in, char*data, uint32_t sz);
