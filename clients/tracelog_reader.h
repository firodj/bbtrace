/**
 * License: MIT
 * Copyright: (2017) Fadhil Mandaga <firodj@gmail.com>
 */
#pragma once

#include <cassert>
#include <map>
#include "bbtrace_data.h"

typedef enum {BLOCK, SYMBOL} block_kind_t;
typedef enum {NONE, JMP, CALL, RET} block_jump_t;
typedef struct {
  block_kind_t kind;
  uint addr;
  block_jump_t jump;
  uint end;
  uint last;
} block_t;

typedef std::map<uint, block_t> blocks_t;

class TraceLog
{
private:
    std::unique_ptr<char[]> buffer_; // must be constructed before (and thus destructed after) the reader!
    char log_name_[MAX_FILE_NAME_LENGTH+1];
    int log_number_;
#ifdef CSV_IO_NO_THREAD
    SynchronousReader reader_;
#else
    AsynchronousReader reader_;
#endif
    int data_begin_;
    int data_end_;

    static std::unique_ptr<ByteSourceBase> open_file(const char* log_name, int log_number)
    {
        char file_name[MAX_FILE_NAME_LENGTH+1];
        sprintf(file_name, "%s.%04d", log_name, log_number);

        FILE *file = std::fopen(file_name, "rb");
        if (file == 0){
            int x = errno; // store errno as soon as possible, doing it after constructor call can fail.
            if (log_number <= 1) {
                throw std::runtime_error("Error can not open file");
            }
            return nullptr;
        }
        return std::unique_ptr<ByteSourceBase>(new OwningStdIOByteSourceBase(file));
    }

    bool init(std::unique_ptr<ByteSourceBase>byte_source)
    {
        if (byte_source == nullptr) return false;

        data_begin_ = 0;
        data_end_ = byte_source->read(buffer_.get(), 2 * BLOCK_LEN);

        if (data_end_ == 2 * BLOCK_LEN) {
            reader_.init(std::move(byte_source));
            reader_.start_read(buffer_.get() + 2 * BLOCK_LEN, BLOCK_LEN);
        }
        return true;
    }


public:
    explicit TraceLog(const char *file_name)
    {
        set_file_name(file_name);
        buffer_ = std::unique_ptr<char[]>(new char[3 * BLOCK_LEN]);
        init(open_file(log_name_, log_number_));
    }

    void set_file_name(const char* file_name)
    {
        const char *tail_is_number_one = strstr(file_name, ".0001");
        if (!tail_is_number_one) {
            throw std::runtime_error("File should be .0001!");
        }

        size_t len = (size_t)tail_is_number_one - (size_t)file_name;
        strncpy(log_name_, file_name, len);
        log_name_[len] = '\0';
        log_number_ = 1;
    }

    char *log_name() {
        return log_name_;
    }

    bool is_should_shifting() {
        return data_begin_ >= BLOCK_LEN;
    }

    char *next_packet(pkt_trace_t** pkt_trace_ptr){
        if (data_begin_ == data_end_) {
            log_number_++;
            if (!init(open_file(log_name_, log_number_)))
                return 0;
        }

        // shift buffer block
        if (is_should_shifting()){
            std::memcpy(buffer_.get(), buffer_.get() + BLOCK_LEN, BLOCK_LEN);
            data_begin_ -= BLOCK_LEN;
            data_end_ -= BLOCK_LEN;
            if(reader_.is_valid()) {
                data_end_ += reader_.finish_read();
                std::memcpy(buffer_.get() + BLOCK_LEN, buffer_.get() + 2 * BLOCK_LEN, BLOCK_LEN);
                reader_.start_read(buffer_.get() + 2 * BLOCK_LEN, BLOCK_LEN);
            }
        }

        *pkt_trace_ptr = (pkt_trace_t*)(buffer_.get() + data_begin_);
        data_begin_ += sizeof(pkt_trace_t);
        char *ret = buffer_.get() + data_begin_;
        data_begin_ += (*pkt_trace_ptr)->size * sizeof(uint);

        return ret;
    }
};

