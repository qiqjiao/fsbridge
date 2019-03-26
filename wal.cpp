#include "wal.h"

#include <dirent.h>
#include <unistd.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

#include <algorithm>
#include <chrono>
#include <iomanip>
#include <map>
#include <sstream>

#include "log.h"

std::string WalPath(const std::string& work_path, int32_t seq) {
    std::stringstream ss;
    ss << work_path << '/' << std::setfill ('0') << std::setw(sizeof(seq)*2)
       << std::hex << seq << ".wal";
    return ss.str();
}

std::string BlockKey(const BlockProto& b) {
    std::ostringstream oss;
    oss << b.path() << '.' << b.size() << '.' << b.offset();
    return oss.str();
}

Wal::~Wal() {}

int Wal::Read(const char *path, char *buf, size_t size, off_t offset) {
    LOG(2) << "Read file: " << path << ", " << size << "," << offset;

    if (size == 0) return 0;

    std::unique_lock<std::mutex> lck(mu_);

    FileInfo *info = &file_infos_[path];
    if (info->base_rd_fd == -1) {
        const std::string p = base_path_ + path;
        if ((info->base_rd_fd = open(p.c_str(), O_RDONLY)) == -1) {
            LOG(0) << path << ", " << strerror(errno);
            return -errno;
        }
    }

    std::vector<std::pair<off_t, size_t>> segs;
    auto fill = [&](const BlockProto &b, int fd) -> int {
        CHECK(fd != -1);
        int res = 0;
        if (b.offset() >= offset && b.offset() < offset + size) {
            off_t o = b.offset() - offset;
            size_t s = std::min(size - o, (size_t)b.size());
            res = pread(fd, buf + o, s, b.wal_offset());
            segs.emplace_back(b.offset(), s);
        } else if (b.offset() + b.size() - 1 >= offset &&
                   b.offset() + b.size() - 1 < offset + size) {
            off_t o = offset - b.offset();
            size_t s = std::min((size_t)(b.size() - o), size);
            res = pread(fd, buf, s, b.wal_offset() + o);
            segs.emplace_back(offset, s);
        }
        return res;
    };
    for (const auto &b : info->blocks) {
        LOG(2) << "Check block: " << b->ShortDebugString();
        if (b->state() == BlockProto::kDisposable) continue;
        auto itr = wal_infos_.find(b->wal_seq());
        CHECK(itr != wal_infos_.end()) << b->ShortDebugString();
        int res = fill(*b, itr->second.fd);
        if (res == -1) {
            LOG(1) << "Fill seg failed: " << path << ", " << strerror(errno);
            return -errno;
        }
    }

    lck.unlock();

    std::sort(segs.begin(), segs.end());
    segs.emplace_back(offset + size, 0);

    const bool read_base = allow_base_read_ || (rand() % 100 < 5);
    off_t cur_offset = offset;
    for (const auto &seg : segs) {
        if (cur_offset < seg.first) {
            if (!read_base)  {
              // Just return whatever in local wall files.
              return cur_offset - offset;
            }

            // Proper handling for filling the non-local gaps from remote file.
            off_t o = cur_offset - offset;
            size_t s = seg.first - cur_offset;
            int res = pread(info->base_rd_fd, buf + o, s, cur_offset);
            if (res == -1) {
                LOG(0) << path << ", " << strerror(errno);
                return -errno;
            }
            if (res < s) {
                return o + res;
            }
            cur_offset = seg.first + seg.second;
        } else if (cur_offset < seg.first + seg.second) {
            cur_offset = seg.first + seg.second;
        }
    }

    LOG(2) << "Read " << path << ", size " << size;
    return size;
}

int Wal::Write(const char *path, const char *buf, size_t size, off_t offset) {
    LOG(2) << "Write file: " << path << ", " << size << "," << offset;

    if (size == 0) return 0;

    std::lock_guard<std::mutex> lck(mu_);

    const int wal_seq = cur_wal_seq_;
    WalInfo *wal_info = &wal_infos_[wal_seq];
    if (wal_info->fd == -1) {
        const std::string wal_path = WalPath(work_path_, wal_seq);
        LOG(0) << "Creating wal: " << wal_path;
        wal_info->fd = open(wal_path.c_str(), O_RDWR|O_CREAT);
        CHECK(wal_info->fd != -1) << wal_path << ", " << strerror(errno);
    }

    off_t off = lseek(wal_info->fd, 0, SEEK_END);
    CHECK(off != -1);

    auto b = std::make_shared<BlockProto>();
    b->set_offset(offset);
    b->set_size(size);
    b->set_path(path);
    b->set_state(BlockProto::kInWal);
    b->set_wal_seq(wal_seq);
    b->set_key(BlockKey(*b));
    b->set_wal_offset(off + 8);

    const std::string s = b->SerializeAsString();
    const int32_t b_sz = s.size();
    CHECK(write(wal_info->fd, &b_sz, 4) == 4);
    CHECK(write(wal_info->fd, &size, 4) == 4);
    CHECK(write(wal_info->fd, buf, size) == size);
    CHECK(write(wal_info->fd, s.data(), s.size()) == s.size());

    wal_info->blocks[b->key()] = b;
    file_infos_[path].blocks.push_back(b);

    CHECK(fsync(wal_info->fd) != -1) << strerror(errno);

    if (wal_info->blocks.size() >= 1024) {
        LOG(0) << "Closing wal: " << wal_seq;
        last_flush_ = std::time(nullptr);
        cur_wal_seq_++;
    }

    return size;
}

int Wal::Release(const char *path) {
    return 0;
}

int Wal::Fsync(const char *path, int isdatasync) {
    // LOG(1) << "Fsync on " << path;

    // std::lock_guard<std::mutex> lck(mu_);
    // WalInfo *wal_info = &wal_infos_[cur_wal_seq_];
    // if (wal_info->fd != -1)
    //     return fsync(wal_info->fd);
    return 0;
}

void Wal::FlushAndStop(const char *path) {}

void Wal::Resume() {}

void Wal::Init() {
    std::vector<int32_t> wal_seqs;

    struct dirent *dir;
    DIR *d = opendir(work_path_.c_str());
    CHECK(d != NULL) << work_path_ << ',' << strerror(errno);
    while ((dir = readdir(d)) != NULL) {
        const char *p = strstr(dir->d_name, ".wal");
        if (p != NULL) {
            wal_seqs.push_back(std::stoi(std::string(dir->d_name, p - dir->d_name), NULL, 16));
        }
    }
    closedir(d);

    std::sort(wal_seqs.begin(), wal_seqs.end());
    for (int seq : wal_seqs) {
      ProcessWal(seq);
    }
    cur_wal_seq_ = wal_seqs.empty() ? 0 : wal_seqs.back() + 1;

    workers_.emplace_back([this]() { while (true) { FlushToBase(); } });
    workers_.emplace_back([this]() { while (true) { GC(); } });
}

void Wal::ProcessWal(int32_t wal_seq) {
    LOG(0) << "Processing wal: " << wal_seq;

    WalInfo *info = nullptr;
    {
        std::lock_guard<std::mutex> lck(mu_);
        const std::string path = WalPath(work_path_, wal_seq);
        info = &wal_infos_[wal_seq];
        info->fd = open(path.c_str(), O_RDWR);
        CHECK(info->fd != -1) << path << ", " << strerror(errno);
    }

    while (true) {
        int32_t b_sz = 0, d_sz = 0, r;

        r = read(info->fd, &b_sz, 4);
        CHECK(r != -1) << wal_seq << "," << strerror(errno);
        if (r != 4) break;

        r = read(info->fd, &d_sz, 4);
        CHECK(r != -1) << wal_seq << "," << strerror(errno);
        if (r != 4) break;

        CHECK(lseek(info->fd, d_sz, SEEK_CUR) != -1) << wal_seq << "," << strerror(errno);

        std::unique_ptr<char[]> buf(new char[b_sz]);
        r = read(info->fd, buf.get(), b_sz);
        CHECK(r != -1) << wal_seq << "," << strerror(errno);
        if (r != b_sz) break;

        auto b = std::make_shared<BlockProto>();
        CHECK(b->ParseFromArray(buf.get(), b_sz)) << wal_seq << "," << buf.get();

        if (b->state() == BlockProto::kFlushed) {
            CHECK(info->blocks.count(b->key()) != 0);
            info->blocks[b->key()]->set_state(BlockProto::kFlushed);
        } else {
            info->blocks[b->key()] = b;
            file_infos_[b->path()].blocks.push_back(b);
        }
    }
}

void Wal::FlushToBase() {
    // Check whether we should use a new wal file.
    {
        std::lock_guard<std::mutex> lck(mu_);
        time_t now = std::time(nullptr);
        WalInfo *wal_info = &wal_infos_[cur_wal_seq_];
        if (wal_info->fd != -1 && now - last_flush_ > 60) {
            LOG(0) << "Closing wal: " << cur_wal_seq_;
            CHECK(fsync(wal_info->fd) != -1) << strerror(errno);
            last_flush_ = now;
            cur_wal_seq_++;
        }
    }

    // Find a wal to flush.
    WalInfo *wal_info = nullptr;
    {
        std::lock_guard<std::mutex> lck(mu_);
        for (auto &wal_itr : wal_infos_) {
            if (wal_itr.second.all_flushed || wal_itr.first == cur_wal_seq_) continue;
            wal_info = &wal_itr.second;
            LOG(0) << "Flushing wal: " << wal_itr.first;
            break;
        }
    }
    if (wal_info == nullptr) {
        std::this_thread::sleep_for(std::chrono::seconds(1));
        return;
    }

    std::set<int> fds;
    for (auto &block_itr : wal_info->blocks) {
        auto block = block_itr.second;

        if (block->state() != BlockProto::kInWal) continue;

        std::unique_lock<std::mutex> lck(mu_);
        FileInfo *file_info = &file_infos_[block->path()];
        if (file_info->base_wr_fd == -1) {
            const std::string path = base_path_ + block->path();
            file_info->base_wr_fd = open(path.c_str(), O_WRONLY);
            CHECK(file_info->base_wr_fd != -1) << path << "," << strerror(errno);
        }

        std::unique_ptr<char[]> buf(new char[block->size()]);
        CHECK(pread(wal_info->fd, buf.get(), block->size(),
                    block->wal_offset()) == block->size()) << strerror(errno);

        lck.unlock();

        fds.insert(file_info->base_wr_fd);

        CHECK(pwrite(file_info->base_wr_fd, buf.get(), block->size(),
                     block->offset()) == block->size());

        LOG(2) << "Block flushed: " << block->path() << "," << block->offset()
               << "," << block->size();
    }

    for (int fd : fds) {
        CHECK(fsync(fd) != -1) << strerror(errno);
    }

    for (auto &block_itr : wal_info->blocks) {
        auto block = block_itr.second;

        if (block->state() != BlockProto::kInWal) continue;

        std::unique_lock<std::mutex> lck(mu_);

        off_t off = lseek(wal_info->fd, 0, SEEK_END);
        CHECK(off != -1);

        block->set_state(BlockProto::kFlushed);
        const std::string s = block->SerializeAsString();
        const int32_t b_sz = s.size(), d_sz = 0;
        CHECK(write(wal_info->fd, &b_sz, 4) == 4);
        CHECK(write(wal_info->fd, &d_sz, 4) == 4);
        CHECK(write(wal_info->fd, s.data(), s.size()) == b_sz);
    }

    CHECK(fsync(wal_info->fd) != -1) << strerror(errno);

    {
        std::lock_guard<std::mutex> lck(mu_);
        wal_info->all_flushed = true;
    }

    std::this_thread::sleep_for(std::chrono::milliseconds(20));
}

void Wal::GC() {
    std::unique_lock<std::mutex> lck(mu_);

    // Clean old wal files.
    while (wal_infos_.size() > 64) {
        auto wal_itr = wal_infos_.begin();

        if (!wal_itr->second.all_flushed) break;

        for (auto &b_itr : wal_itr->second.blocks) {
            b_itr.second->set_state(BlockProto::kDisposable);
        }

        LOG(0) << "Deleting wal: " << wal_itr->first;

        close(wal_itr->second.fd);
        unlink(WalPath(work_path_, wal_itr->first).c_str());
        wal_infos_.erase(wal_itr);
    }

    // Clean disposable blocks.
    for (auto &file_info_itr : file_infos_) {
        FileInfo &file_info = file_info_itr.second;

        std::vector<std::shared_ptr<BlockProto>> left_blocks;
        left_blocks.reserve(file_info.blocks.size());
        for (auto &b : file_info.blocks) {
            if (b->state() != BlockProto::kDisposable) {
                left_blocks.push_back(b);
            }
        }
        file_info.blocks.swap(left_blocks);
    }

    lck.unlock();
    std::this_thread::sleep_for(std::chrono::seconds(1));
}

