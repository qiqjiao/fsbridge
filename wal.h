#pragma once

#include <list>
#include <memory>
#include <mutex>
#include <string>
#include <thread>
#include <unordered_map>
#include <vector>

#include "message.pb.h"

using fsbridge::BlockProto;

struct WalInfo {
    int fd = 0;
    std::unordered_map<std::string, std::shared_ptr<BlockProto>> undone_blocks;
};

struct FileInfo {
    int base_rd_fd = -1;
    int base_wr_fd = -1;
    bool busy = false;
    std::string path;
    std::list<std::shared_ptr<BlockProto>> blocks;
};

// Wal files:
//   work_path/[0-9]+.wal
// Wall file format:
//   int64_t offset, int32_t size, int16 path_len, char[path_len], bool is_done, char[size|0] 
class Wal {
public:
    Wal(const std::string& work_path, const std::string& base_path)
        : work_path_(work_path), base_path_(base_path) {
        Init();
    }
    ~Wal();

    void Init();

    int Read(const char *path, char *buf, size_t size, off_t offset);
    int Write(const char *path, const char *buf, size_t size, off_t offset);
    int Release(const char *path);
    int Fsync(const char *path, int isdatasync);

    void FlushAndStop(const char *path);
    void Resume();

private:
    void ProcessWal(const std::string &path);
    void Work();

    const std::string work_path_;
    const std::string base_path_;

    std::mutex mu_;
    std::unordered_map<std::string, WalInfo> wal_infos_;
    std::unordered_map<std::string, FileInfo> file_infos_;
    std::vector<std::thread> workers_;

    int32_t cur_wal_seq_ = 0;
    int32_t cur_wal_size_ = 0;
    int32_t cur_wal_fd_ = -1;
    std::vector<std::shared_ptr<BlockProto>> cur_wal_blocks_;
    time_t last_flush_ = -1;
};
