#pragma once

class ParseBuffer {
private:
    char *data_;
    uint pos_;
    uint allocated_;
    uint available_;
    uint64 inpos_;
public:
    ParseBuffer();
    ~ParseBuffer();

    void reset(uint64 inpos = 0);
    uint extract(std::istream &in);

    char *data() {
        return &data_[pos_];
    }

    const uint length() {
        return allocated() - pos_;
    }

    const uint allocated() {
        return allocated_;
    }

    uint peek();
    char* fetch();

    static uint buf_size(uint kind);
    uint64 inpos() { return inpos_; };
};
