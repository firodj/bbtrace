#pragma once

class buffer_c {
private:
    char *data_;
    uint pos_;
    uint allocated_;
    uint available_;
    uint64 inpos_;
public:
    buffer_c();
    ~buffer_c();

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

    uint peek(uint64 *inpos = nullptr);
    char* fetch(uint64 *inpos = nullptr);

    static uint buf_size(uint kind);
};
