/**
 *
 * License: BSD-3
 * Copyright:
 * (2012-2015) Ben Strasser <code@ben-strasser.net>
 * (2017) Fadhil Mandaga <firodj@gmail.com>
 *
 */
#pragma once

#ifndef CSV_IO_NO_THREAD
#include <mutex>
#include <thread>
#include <condition_variable>
#endif
#include <memory>
#include <algorithm>
#include <cassert>


class ByteSourceBase{
public:
    virtual int read(char*buffer, int size)=0;
    virtual ~ByteSourceBase(){}
};

class OwningStdIOByteSourceBase: public ByteSourceBase{
public:
    explicit OwningStdIOByteSourceBase(FILE*file):file(file){
        // Tell the std library that we want to do the buffering ourself.
        std::setvbuf(file, 0, _IONBF, 0);
    }

    int read(char*buffer, int size){
        return std::fread(buffer, 1, size, file);
    }

    ~OwningStdIOByteSourceBase(){
        std::fclose(file);
    }

private:
    FILE*file;
};

class SynchronousReader{
public:
    void init(std::unique_ptr<ByteSourceBase>byte_source){
        byte_source_ = std::move(byte_source);
    }

    bool is_valid() const{
        return byte_source_ != nullptr;
    }

    void start_read(char* buffer, int desired_byte_count){
        buffer_ = buffer;
        desired_byte_count_ = desired_byte_count;
    }

    int finish_read(){
        return byte_source_->read(buffer_, desired_byte_count_);
    }

private:
    std::unique_ptr<ByteSourceBase> byte_source_;
    char* buffer_;
    int desired_byte_count_;
};

#ifndef CSV_IO_NO_THREAD
class AsynchronousReader{
public:
    void init(std::unique_ptr<ByteSourceBase>arg_byte_source){
        std::unique_lock<std::mutex>guard(lock_);
        byte_source_ = std::move(arg_byte_source);
        desired_byte_count_ = -1;
        termination_requested_ = false;
        worker_ = std::thread(
            [&]{
                std::unique_lock<std::mutex>guard(lock_);
                try{
                    for(;;){
                        read_requested_condition_.wait(
                            guard,
                            [&]{
                                return desired_byte_count_ != -1 || termination_requested_;
                            }
                        );
                        if(termination_requested_)
                            return;

                        read_byte_count_ = byte_source_->read(buffer_, desired_byte_count_);
                        desired_byte_count_ = -1;
                        if(read_byte_count_ == 0)
                            break;
                        read_finished_condition_.notify_one();
                    }
                }catch(...){
                    read_error_ = std::current_exception();
                }
                read_finished_condition_.notify_one();
            }
        );
    }

    bool is_valid()const{
        return byte_source_ != nullptr;
    }

    void start_read(char*arg_buffer, int arg_desired_byte_count){
        std::unique_lock<std::mutex>guard(lock_);
        buffer_ = arg_buffer;
        desired_byte_count_ = arg_desired_byte_count;
        read_byte_count_ = -1;
        read_requested_condition_.notify_one();
    }

    int finish_read(){
        std::unique_lock<std::mutex>guard(lock_);
        read_finished_condition_.wait(
            guard,
            [&]{
                return read_byte_count_ != -1 || read_error_;
            }
        );
        if(read_error_)
            std::rethrow_exception(read_error_);
        else
            return read_byte_count_;
    }

    ~AsynchronousReader(){
        if(byte_source_ != nullptr){
            {
                std::unique_lock<std::mutex>guard(lock_);
                termination_requested_ = true;
            }
            read_requested_condition_.notify_one();
            worker_.join();
        }
    }

private:
    std::unique_ptr<ByteSourceBase>byte_source_;

    std::thread worker_;

    bool termination_requested_;
    std::exception_ptr read_error_;
    char*buffer_;
    int desired_byte_count_;
    int read_byte_count_;

    std::mutex lock_;
    std::condition_variable read_finished_condition_;
    std::condition_variable read_requested_condition_;
};
#endif

class LineReader{
private:
    std::unique_ptr<char[]> buffer_; // must be constructed before (and thus destructed after) the reader!
#ifdef CSV_IO_NO_THREAD
    SynchronousReader reader_;
#else
    AsynchronousReader reader_;
#endif
    int data_begin_;
    int data_end_;

    char file_name_[MAX_FILE_NAME_LENGTH+1];
    unsigned file_line_;

    static std::unique_ptr<ByteSourceBase> open_file(const char*file_name){
        // We open the file in binary mode as it makes no difference under *nix
        // and under Windows we handle \r\n newlines ourself.
        FILE *file = std::fopen(file_name, "rb");
        if (file == 0){
            int x = errno; // store errno as soon as possible, doing it after constructor call can fail.
            throw std::runtime_error("Error can not open file");
        }
        return std::unique_ptr<ByteSourceBase>(new OwningStdIOByteSourceBase(file));
    }

    void init(std::unique_ptr<ByteSourceBase>byte_source){
        file_line_ = 0;

        buffer_ = std::unique_ptr<char[]>(new char[3 * BLOCK_LEN]);
        data_begin_ = 0;
        data_end_ = byte_source->read(buffer_.get(), 2 * BLOCK_LEN);

        // Ignore UTF-8 BOM
        if (data_end_ >= 3 && buffer_[0] == '\xEF' && buffer_[1] == '\xBB' && buffer_[2] == '\xBF') {
            data_begin_ = 3;
        }

        if (data_end_ == 2 * BLOCK_LEN) {
            reader_.init(std::move(byte_source));
            reader_.start_read(buffer_.get() + 2 * BLOCK_LEN, BLOCK_LEN);
        }
    }

public:
    explicit LineReader(const char* file_name){
        set_file_name(file_name);
        init(open_file(file_name_));
    }

    explicit LineReader(const std::string& file_name){
        set_file_name(file_name.c_str());
        init(open_file(file_name.c_str()));
    }

    void set_file_name(const std::string& file_name){
        set_file_name(file_name.c_str());
    }

    void set_file_name(const char* file_name){
        strncpy(file_name_, file_name, MAX_FILE_NAME_LENGTH);
        file_name_[MAX_FILE_NAME_LENGTH] = '\0';
    }

    unsigned file_line() const{
        return file_line_;
    }

    bool is_should_shifting()
    {
        return (data_begin_ >= BLOCK_LEN);
    }

    char *next_line(){
        if (data_begin_ == data_end_)
            return 0;

        ++file_line_;

        assert(data_begin_ < data_end_);
        assert(data_end_ <= BLOCK_LEN * 2);

        // shift buffer block
        if (is_should_shifting()){
            std::memcpy(buffer_.get(), buffer_.get() + BLOCK_LEN, BLOCK_LEN);
            data_begin_ -= BLOCK_LEN;
            data_end_ -= BLOCK_LEN;
            if(reader_.is_valid())
            {
                data_end_ += reader_.finish_read();
                std::memcpy(buffer_.get() + BLOCK_LEN, buffer_.get() + 2 * BLOCK_LEN, BLOCK_LEN);
                reader_.start_read(buffer_.get() + 2 * BLOCK_LEN, BLOCK_LEN);
            }
        }

        // find line end
        int line_end = data_begin_;
        while(buffer_[line_end] != '\n' && line_end != data_end_){
            ++line_end;
        }

        if (line_end - data_begin_ + 1 > BLOCK_LEN) {
            throw std::runtime_error("Error line length limit exceeded");
        }

        if(buffer_[line_end] == '\n'){
            buffer_[line_end] = '\0';
        }else{
            // some files are missing the newline at the end of the
            // last line
            ++data_end_;
            buffer_[line_end] = '\0';
        }

        // handle windows \r\n-line breaks
        if(line_end != data_begin_ && buffer_[line_end-1] == '\r')
            buffer_[line_end-1] = '\0';

        char *ret = buffer_.get() + data_begin_;
        data_begin_ = line_end+1;
        return ret;
    }
};


