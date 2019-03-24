#include "wal.h"

#include <dirent.h>
#include <unistd.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

#include <cassert>

#include <algorithm>
#include <chrono>
#include <iomanip>
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
    oss << b.offset() << '.' << b.size() << '.' << b.path();
    return oss.str();
}

// int Block::Read(int fd, int cur_offset) {
//     int res = read(fd, &offset, sizeof(offset));
//     CHECK(res != -1) << path << ", " << strerror(errno);
//     if (res == 0) return 0;
// 
//     assert(res == sizeof(offset));
//     assert(read(fd, &size, sizeof(size)) == sizeof(size));
//     assert(read(fd, &path_len, sizeof(path_len)) == sizeof(path_len));
//     path.resize(path_len);
//     assert(read(fd, &path[0], path_len) == path_len);
//     assert(read(fd, &is_done, sizeof(is_done)) == sizeof(is_done));
// 
//     key.append((const char*)&offset, sizeof(offset));
//     key.append((const char*)&size, sizeof(size));
//     key.append((const char*)&path_len, sizeof(path_len));
//     key.append(path.data(), path.size());
// 
//     if (is_done) {
//       res = (cur_offset + 8 + 4 + 2 + path_len + 1 + 7) & -8;
//     } else {
//       wal_offset = cur_offset + 8 + 4 + 2 + path_len + 1;
//       res = (wal_offset + size + 7) & -8;
//     }
// 
//     return res;
// }
// 
// int Block::WriteBuf(int fd, const char *buf) {
//     static const char *zero = "00000000";
// 
//     assert(write(fd, &offset, sizeof(offset)) == sizeof(offset));
//     assert(write(fd, &size, sizeof(size)) == sizeof(size));
//     assert(write(fd, &path_len, sizeof(path_len)) == sizeof(path_len));
//     assert(write(fd, path.data(), path.size()) == path.size());
//     assert(write(fd, &is_done, sizeof(is_done)) == sizeof(is_done));
//     assert(write(fd, buf, size) == size);
// 
//     int sz = 8 + 4 + 2 + path_len + 1 + size;
//     int pad = ((sz + 7) & -8) - sz;
//     CHECK(write(fd, zero, pad) != -1) << pad << "," << strerror(errno);
// 
//     return sz + pad;
// }
// 
// int Block::WriteDone(int fd) {
//     static const char *zero = "00000000";
//     off_t off = lseek(fd, 0, SEEK_END);
//     assert(off != -1);
// 
//     is_done = true;
//     assert(write(fd, &offset, sizeof(offset)) == sizeof(offset));
//     assert(write(fd, &size, sizeof(size)) == sizeof(size));
//     assert(write(fd, &path_len, sizeof(path_len)) == sizeof(path_len));
//     assert(write(fd, path.data(), path.size()) == path.size());
//     assert(write(fd, &is_done, sizeof(is_done)) == sizeof(is_done));
// 
//     int sz = 8 + 4 + 2 + path_len + 1;
//     int pad = ((sz + 7) & -8) - sz;
//     assert(write(fd, zero, pad) != -1);
// 
//     return sz + pad;
// }

Wal::~Wal() {}

void Wal::Init() {
    std::vector<int> wal_seqs;

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
      ProcessWal(WalPath(work_path_, seq));
    }
    cur_wal_seq_ = wal_seqs.empty() ? 0 : wal_seqs.back() + 1;

    for (int i = 0; i < 5; ++i) {
        workers_.emplace_back([this]() { while (true) { Work(); } });
    }
}

int Wal::Read(const char *path, char *buf, size_t size, off_t offset) {
    LOG() << "Read file: " << path << ", " << size << "," << offset;

    if (size == 0) return 0;

    std::unique_lock<std::mutex> lck(mu_);

    FileInfo *info = &file_infos_[path];
    if (info->path.empty())
        info->path = base_path_ + path;
    if (info->base_rd_fd == -1) {
        info->base_rd_fd = open(info->path.c_str(), O_RDONLY);
        if (info->base_rd_fd == -1) {
            LOG() << info->path << ", " << strerror(errno);
            return -errno;
        }
    }

    std::vector<std::pair<off_t, size_t>> segs;
    auto fill = [&](const BlockProto &b, int fd) -> int {
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
        return res == 0 ? 0 : -errno;
    };
    for (const auto &b : info->blocks) {
        if (b->is_done()) continue;
        auto itr = wal_infos_.find(b->wal_path());
        CHECK(itr != wal_infos_.end()) << b->ShortDebugString();
        int res = fill(*b, itr->second.fd);
        if (res != 0) return res;
    }
    for (const auto &b : cur_wal_blocks_) {
        if (b->path() != path) continue;
        int res = fill(*b, cur_wal_fd_);
        if (res != 0) return res;
    }

    lck.unlock();

    std::sort(segs.begin(), segs.end());
    segs.emplace_back(offset + size, 0);

    off_t cur_offset = offset;
    for (const auto &seg : segs) {
        if (cur_offset < seg.first) {
            off_t o = cur_offset - offset;
            size_t s = seg.first - cur_offset;
            int res = pread(info->base_rd_fd, buf + o, s, cur_offset);
            if (res == -1) {
                LOG() << info->path << ", " << strerror(errno);
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

    return size;
}

int Wal::Write(const char *path, const char *buf, size_t size, off_t offset) {
    LOG() << "Write file: " << path << ", " << size << "," << offset;

    if (size == 0) return 0;

    std::lock_guard<std::mutex> lck(mu_);

    if (cur_wal_fd_ == -1) {
        std::string wal_path = WalPath(work_path_, cur_wal_seq_);
        LOG() << "Creating wal: " << wal_path;
        cur_wal_fd_ = open(wal_path.c_str(), O_WRONLY|O_CREAT);
        CHECK(cur_wal_fd_ != -1) << wal_path << ", " << strerror(errno);
        cur_wal_size_ = 0;
    }

    FileInfo *info = &file_infos_[path];
    if (info->path.empty())
        info->path = base_path_ + path;
    if (info->base_wr_fd == -1) {
        info->base_wr_fd = open(info->path.c_str(), O_WRONLY);
        CHECK(info->base_wr_fd != -1) << info->path << ", " << strerror(errno);
    }

    off_t off = lseek(cur_wal_fd_, 0, SEEK_END);
    CHECK(off != -1);

    auto b = std::make_shared<BlockProto>();
    b->set_offset(offset);
    b->set_size(size);
    b->set_path(path);
    b->set_is_done(false);
    b->set_wal_path(WalPath(work_path_, cur_wal_seq_));
    b->set_key(BlockKey(*b));
    b->set_wal_offset(off + 8);

    const std::string s = b->SerializeAsString();
    const int32_t b_sz = s.size();
    CHECK(write(cur_wal_fd_, &b_sz, 4) == 4);
    CHECK(write(cur_wal_fd_, &size, 4) == 4);
    CHECK(write(cur_wal_fd_, buf, size) == size);
    CHECK(write(cur_wal_fd_, s.data(), s.size()) == s.size());

    cur_wal_blocks_.push_back(b);
    cur_wal_size_ += size;

    return size;
}

int Wal::Release(const char *path) {
    return 0;
}

int Wal::Fsync(const char *path, int isdatasync) {
    if (cur_wal_fd_ != -1)
        return fsync(cur_wal_fd_);
    return 0;
}

void Wal::FlushAndStop(const char *path) {}

void Wal::Resume() {}

void Wal::ProcessWal(const std::string &path) {
    LOG() << "Processing wal: " << path;

    WalInfo& info = wal_infos_[path];

    info.fd = open(path.c_str(), O_RDWR);
    CHECK(info.fd != -1) << path << ", " << strerror(errno);

    std::ifstream ifs;
    ifs.exceptions(std::ifstream::failbit|std::ifstream::badbit|std::ifstream::eofbit);
    try {
        ifs.open(path.c_str(), std::ios_base::in|std::ios_base::binary);
        while (ifs) {
            int32_t b_sz = 0, d_sz = 0;
            ifs.read((char*)&b_sz, 4);
            ifs.read((char*)&d_sz, 4);

            ifs.seekg(d_sz, ifs.cur);

            std::unique_ptr<char[]> buf(new char[b_sz]);
            ifs.read(buf.get(), b_sz);

            auto b = std::make_shared<BlockProto>();
            CHECK(b->ParseFromArray(buf.get(), b_sz));

            if (b->is_done()) {
                info.undone_blocks[b->key()]->set_is_done(true);
                info.undone_blocks.erase(b->key());
            } else {
                info.undone_blocks[b->key()] = b;
                auto &file_info = file_infos_[b->path()];
                file_info.blocks.push_back(b);
                if (file_info.path.empty()) {
                    file_info.path = base_path_ + b->path();
                }
            }
        }
    } catch (std::ifstream::failure e) {
        CHECK(ifs.eof()) << e.code() << "," << e.what() << ", " << path;
    }
}

void Wal::Work() {
    {
        std::lock_guard<std::mutex> lck(mu_);
        time_t now = std::time(nullptr);
        if (cur_wal_fd_ != -1 && (cur_wal_size_ >= 4*1024*1024 || now - last_flush_ > 3)) {
            close(cur_wal_fd_);
            cur_wal_fd_ = -1;
            last_flush_ = now;
            cur_wal_blocks_.clear();
            LOG() << "Closing wal: " << cur_wal_seq_;
            ProcessWal(WalPath(work_path_, cur_wal_seq_));
            cur_wal_seq_++;
        }
    }

    FileInfo *file_info = nullptr;
    {
        std::lock_guard<std::mutex> lck(mu_);
        for (auto &itr : file_infos_) {
            if (!itr.second.busy && !itr.second.blocks.empty()) {
                file_info = &itr.second;
                file_info->busy = true;
                break;
            }
        }
    }
    if (file_info == nullptr) {
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
        return;
    }

    if (file_info->base_wr_fd == -1) {
        file_info->base_wr_fd = open(file_info->path.c_str(), O_WRONLY);
        CHECK(file_info->base_wr_fd != -1)
            << file_info->path << ", " << strerror(errno);
    }

    while (true) {
        std::shared_ptr<BlockProto> block;
        {
            std::lock_guard<std::mutex> lck(mu_);
            if (file_info->blocks.empty())
                break;
            block = file_info->blocks.front();
            if (block->is_done()) {
                file_info->blocks.pop_front();
                continue;
            }
        }

        WalInfo &wal_info = wal_infos_[block->wal_path()];
        std::unique_ptr<char[]> buf(new char[block->size()]);
        {
            std::lock_guard<std::mutex> lck(mu_);
            assert(pread(wal_info.fd, buf.get(), block->size(),
                         block->wal_offset()) == block->size());
        }
        assert(pwrite(file_info->base_wr_fd, buf.get(), block->size(),
                      block->offset()) == block->size());
        {
            std::lock_guard<std::mutex> lck(mu_);

            off_t off = lseek(wal_info.fd, 0, SEEK_END);
            assert(off != -1);

            block->set_is_done(true);
            const std::string s = block->SerializeAsString();
            const int32_t b_sz = s.size(), d_sz = 0;
            assert(write(wal_info.fd, &b_sz, 4) == 4);
            assert(write(wal_info.fd, &d_sz, 4) == 4);
            assert(write(wal_info.fd, s.data(), s.size()) == b_sz);
            // LOG() << "Block done: " << block->path() << "," << block->offset()
            //       << "," << block->size();

            file_info->blocks.pop_front();
            wal_info.undone_blocks.erase(block->key());
            if (wal_info.undone_blocks.empty()) {
                close(wal_info.fd);
                unlink(block->wal_path().c_str());
            }
        }
    }

    fsync(file_info->base_wr_fd);

    {
        std::lock_guard<std::mutex> lck(mu_);
        file_info->busy = false;
    }
}

