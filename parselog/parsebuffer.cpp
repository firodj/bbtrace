#include <iostream>
#include <sstream>

#define WITHOUT_DR
#include "datatypes.h"

#include "parsebuffer.h"

ParseBuffer::ParseBuffer() {
  allocated_ = 16 * 8192 * 128;
  data_ = new char[allocated_];
  reset();
}

ParseBuffer::~ParseBuffer() {
  delete[] data_;
}

void
ParseBuffer::reset(uint64 inpos) {
  pos_ = 0;
  available_ = 0;
  inpos_ = inpos;
}

uint
ParseBuffer::extract(std::istream &in) {
  if (pos_ > 0) {
    uint new_pos = available_ - pos_;
    memcpy(&data_[0], &data_[pos_], new_pos);
    pos_ = new_pos;
  }
  in.read(&data_[pos_], allocated_ - pos_);
  uint bytes = in.gcount();
  available_ = pos_ + bytes;
  pos_ = 0;

  return bytes;
}

uint
ParseBuffer::peek() {
  uint kind;
  if (pos_ + sizeof(kind) > available_) return KIND_NONE;
  kind = *reinterpret_cast<uint*>(data());
  return kind;
}

char*
ParseBuffer::fetch() {
  uint kind;
  if (pos_ + sizeof(kind) > available_) return NULL;
  kind = *reinterpret_cast<uint*>(data());
  uint size = buf_size(kind);
  if (size == 0) return NULL;
  if (pos_ + size > available_) return NULL;
  char *buf_item = data();
  pos_ += size;
  inpos_ += size;
  return buf_item;
}

uint // static
ParseBuffer::buf_size(uint kind) {
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
    oss << "Unknown ParseBuffer::buf_size kind 0x" << std::hex << kind;
    if (kind) {
      oss << " KIND: " << std::string((char*)&kind, 4) << std::endl;
    }
    throw std::runtime_error(oss.str());
    }
  }
  return 0;
}
