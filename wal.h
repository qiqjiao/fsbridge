#pragma once

#include <map>
#include <memory>
#include <mutex>
#include <string>
#include <thread>
#include <unordered_map>
#include <vector>

#include "message.pb.h"

using fsbridge::BlockProto;

struct WalInfo {
    int fd = -1;
    bool all_flushed = false;
    std::unordered_map<std::string, std::shared_ptr<BlockProto>> blocks;
};

struct FileInfo {
    int base_rd_fd = -1;
    int base_wr_fd = -1;
    std::vector<std::shared_ptr<BlockProto>> blocks;
};

// Wal files: work_path/[0-9]+.wal
// Wall file format: [proto_size(4), data_size(4), data, proto]
class Wal {
public:
    Wal(const std::string& work_path, const std::string& base_path,
        bool allow_base_read)
        : work_path_(work_path), base_path_(base_path),
          allow_base_read_(allow_base_read) {
        Init();
    }
    ~Wal();

    int Read(const char *path, char *buf, size_t size, off_t offset);
    int Write(const char *path, const char *buf, size_t size, off_t offset);
    int Release(const char *path);
    int Fsync(const char *path, int isdatasync);

    void FlushAndStop(const char *path);
    void Resume();

private:
    void Init();
    void ProcessWal(int32_t wal_seq);
    void FlushToBase();
    void GC();

    const std::string work_path_;
    const std::string base_path_;
    const bool allow_base_read_;

    std::mutex mu_;
    std::map<int32_t, WalInfo> wal_infos_;
    std::unordered_map<std::string, FileInfo> file_infos_;
    std::vector<std::thread> workers_;

    int32_t cur_wal_seq_ = 0;
    time_t last_flush_ = -1;
};
