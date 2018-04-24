#pragma once

#include "datatypes.h"

class buffer_c {
private:
    char *data_;
    uint pos_;
    uint allocated_;
    uint available_;
    uint64 inpos_;
public:
    buffer_c() {
        allocated_ = 16 * 8192 * 128;
        data_ = new char[allocated_];
        reset();
    }

    ~buffer_c() {
        delete[] data_;
    }

    void reset(uint64 inpos = 0) {
        pos_ = 0;
        available_ = 0;
        inpos_ = inpos;
    }

    uint extract(std::istream &in) {
        if (pos_ > 0) {
            uint new_pos = available_ - pos_;
            memcpy(&data_[0], &data_[pos_], new_pos);
            pos_ = new_pos;
            inpos_ += pos_;
        }
        in.read(&data_[pos_], allocated_ - pos_);
        uint bytes = in.gcount();
        available_ = pos_ + bytes;
        pos_ = 0;

        return bytes;
    }

    char *data() {
        return &data_[pos_];
    }

    const uint length() {
        return allocated() - pos_;
    }

    const uint allocated() {
        return allocated_;
    }

    uint peek(uint64 *inpos = nullptr) {
        uint kind;
        if (pos_ + sizeof(kind) > available_) return KIND_NONE;
        kind = *reinterpret_cast<uint*>(data());
        if (inpos) *inpos = inpos_ + pos_;
        return kind;
    }

    char* fetch(uint64 *inpos = nullptr) {
        uint kind;
        if (pos_ + sizeof(kind) > available_) return NULL;
        kind = *reinterpret_cast<uint*>(data());
        uint size = buf_size(kind);
        if (size == 0) return NULL;
        if (pos_ + size > available_) return NULL;
        char *buf_item = data();
        if (inpos) *inpos = inpos_ + pos_;
        pos_ += size;
        return buf_item;
    }

    static uint buf_size(uint kind) {
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
        case KIND_CRITSEC:
        case KIND_SYNC:
        case KIND_ARGS:
            return sizeof(buf_event_t);
        }
        return 0;
    }
};
