#pragma once

#include <cassert>
#include <fstream>
#include <mutex>

extern std::mutex log_mutex;
extern std::ofstream log_fs;

void set_log_file(const char *log_file);
const char* timestamp();

class LogWriter {
public:
    LogWriter(bool assert_fail, std::mutex &log_mutex, std::ofstream& log_fs)
        : assert_fail_(assert_fail), log_mutex_(log_mutex), log_fs_(log_fs) {
        log_mutex_.lock();
    }
    ~LogWriter() {
        log_fs_ << '\n';
        log_fs_.flush();
        if (assert_fail_) assert(0);
        log_mutex_.unlock();
    }

    std::ofstream& log_fs() { return log_fs_; }
private:
    const bool assert_fail_;
    std::mutex &log_mutex_;
    std::ofstream &log_fs_;
};

#define LOG() LogWriter(false, log_mutex, log_fs).log_fs() \
    << '[' << timestamp() << ' ' << __FILE__ << ':' << __LINE__ << "] "
#define CHECK(EXPR) if (!(EXPR)) LogWriter(true, log_mutex, log_fs).log_fs() \
    << '[' << timestamp() << ' ' << __FILE__ << ':' << __LINE__ << "] " \
    << "Check failed on `" #EXPR "` "

