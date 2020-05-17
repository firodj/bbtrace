#pragma once

class ParseBuffer {
public:
  ParseBuffer();
  ~ParseBuffer();

  void Reset(uint64 inpos = 0);
  size_t Extract(std::istream &in);
  kind_t Peek();
  char* Fetch();
  static size_t KindSize(uint kind);

  char *data() { return &data_[pos_]; }
  const uint length() { return allocated() - pos_; }
  const uint allocated() { return allocated_; }
  uint64 inpos() { return inpos_; };

private:
  char *data_;
  uint pos_;
  uint allocated_;
  uint available_;
  uint64 inpos_;
};
