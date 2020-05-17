#include <string>
#include <fstream>

#define WITHOUT_DR
#include "datatypes.h"

#include "logparser.h"

bool LogParser::Open(const char* filename) {
  filename_ = filename;
  input_.open(filename, std::ios_base::binary);
  if (input_) {
    buffer_.Reset(0);
    return true;
  }
  return false;
}

char* LogParser::Fetch() {
  while (true) {
    char *item = buffer_.Fetch();
    if (item) return item;
    if (!buffer_.Extract(input_)) break;
  }
  return nullptr;
}

uint LogParser::Peek() {
  while (true) {
    uint kind = buffer_.Peek();
    if (kind != KIND_NONE) return kind;
    if (!buffer_.Extract(input_)) break;
  }
  return KIND_NONE;
}

void LogParser::Seek(uint64 filepos) {
  if (input_) {
    input_.seekg(filepos);
    buffer_.Reset(filepos);
  }
}

uint64_t LogParser::Tell() {
  return buffer_.inpos();
}
