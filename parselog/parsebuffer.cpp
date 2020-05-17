#include <iostream>
#include <sstream>

#define WITHOUT_DR
#include "datatypes.h"

#include "parsebuffer.h"

ParseBuffer::ParseBuffer() {
  allocated_ = 16 * 8192 * 128;
  data_ = new char[allocated_];
  Reset();
}

ParseBuffer::~ParseBuffer() {
  delete[] data_;
}

void ParseBuffer::Reset(uint64 inpos) {
  pos_ = 0;
  available_ = 0;
  inpos_ = inpos;
}

size_t ParseBuffer::Extract(std::istream &in) {
  if (pos_ > 0) {
    uint new_pos = available_ - pos_;
    memcpy(&data_[0], &data_[pos_], new_pos);
    pos_ = new_pos;
  }
  in.read(&data_[pos_], allocated_ - pos_);
  size_t bytes = in.gcount();
  available_ = pos_ + bytes;
  pos_ = 0;

  return bytes;
}

kind_t ParseBuffer::Peek() {
  kind_t kind;
  if (pos_ + sizeof(kind) > available_) return KIND_NONE;
  kind = *reinterpret_cast<kind_t*>(data());
  return kind;
}

char* ParseBuffer::Fetch() {
  kind_t kind;
  if (pos_ + sizeof(kind) > available_) return NULL;
  kind = *reinterpret_cast<kind_t*>(data());
  size_t size = KindSize(kind);
  if (size == 0) return NULL;
  if (pos_ + size > available_) return NULL;
  char *buf_item = data();
  pos_ += size;
  inpos_ += size;
  return buf_item;
}

// static
size_t ParseBuffer::KindSize(kind_t kind) {
  switch (kind) {
  case KIND_READ:
  case KIND_WRITE:
  case KIND_LOOP:
  case KIND_BB:
    return sizeof(mem_ref_t);
  case KIND_EXCEPTION:
    return sizeof(buf_exception_t);
  case KIND_MODULE:
    return sizeof(buf_module_t);
  case KIND_SYMBOL:
    return sizeof(buf_symbol_t);
  case KIND_STRING:
    return sizeof(buf_string_t);
  case KIND_LIB_CALL:
    return sizeof(buf_lib_call_t);
  case KIND_LIB_RET:
    return sizeof(buf_lib_ret_t);
  case KIND_APP_CALL:
    return sizeof(buf_app_call_t);
  case KIND_APP_RET:
    return sizeof(buf_app_ret_t);
  case KIND_WNDPROC:
  case KIND_SYNC:
  case KIND_ARGS:
  case KIND_THREAD:
    return sizeof(buf_event_t);
  default: {
    std::ostringstream oss;
    oss << "Unknown ParseBuffer::KindSize for kind 0x" << std::hex << kind;
    if (kind) {
      oss << " KIND: " << std::string((char*)&kind, 4) << std::endl;
    }
    throw std::runtime_error(oss.str());
    }
  }
  return 0;
}
