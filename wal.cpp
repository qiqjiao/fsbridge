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

#include "log.h"

std::string WalPath(const std::string& work_path, int32_t seq) {
    std::stringstream ss;
    ss << work_path << '/' << std::setfill ('0') << std::setw(sizeof(seq)*2)
       << std::hex << seq << ".wal";
    return ss.str();
}

int Block::Read(int fd, int cur_offset) {
    int res = read(fd, &offset, sizeof(offset));
    if (res == -1) {
        LOG() << path << ", " << strerror(errno);
        exit(1);
    }
    if (res == 0) return 0;

    assert(res == sizeof(offset));
    assert(read(fd, &size, sizeof(size)) == sizeof(size));
    assert(read(fd, &path_len, sizeof(path_len)) == sizeof(path_len));
    path.resize(path_len);
    assert(read(fd, &path[0], path_len) == path_len);
    assert(read(fd, &is_done, sizeof(is_done)) == sizeof(is_done));

    key.append((const char*)&offset, sizeof(offset));
    key.append((const char*)&size, sizeof(size));
    key.append((const char*)&path_len, sizeof(path_len));
    key.append(path.data(), path.size());

    if (is_done) {
      res = (cur_offset + 8 + 4 + 2 + path_len + 1 + 7) & -8;
    } else {
      wal_offset = cur_offset + 8 + 4 + 2 + path_len + 1;
      res = (wal_offset + size + 7) & -8;
    }

    return res;
}

int Block::WriteBuf(int fd, const char *buf) {
    static const char *zero = "00000000";

    assert(write(fd, &offset, sizeof(offset)) == sizeof(offset));
    assert(write(fd, &size, sizeof(size)) == sizeof(size));
    assert(write(fd, &path_len, sizeof(path_len)) == sizeof(path_len));
    assert(write(fd, path.data(), path.size()) == path.size());
    assert(write(fd, &is_done, sizeof(is_done)) == sizeof(is_done));
    assert(write(fd, buf, size) == size);

    int sz = 8 + 4 + 2 + path_len + 1 + size;
    int pad = ((sz + 7) & -8) - sz;
    if (write(fd, zero, pad) == -1) {
        LOG() << pad << "," << strerror(errno);
        exit(1);
    }

    return sz + pad;
}

int Block::WriteDone(int fd) {
    static const char *zero = "00000000";
    off_t off = lseek(fd, 0, SEEK_END);
    assert(off != -1);

    is_done = true;
    assert(write(fd, &offset, sizeof(offset)) == sizeof(offset));
    assert(write(fd, &size, sizeof(size)) == sizeof(size));
    assert(write(fd, &path_len, sizeof(path_len)) == sizeof(path_len));
    assert(write(fd, path.data(), path.size()) == path.size());
    assert(write(fd, &is_done, sizeof(is_done)) == sizeof(is_done));

    int sz = 8 + 4 + 2 + path_len + 1;
    int pad = ((sz + 7) & -8) - sz;
    assert(write(fd, zero, pad) != -1);

    return sz + pad;
}

Wal::~Wal() {}

void Wal::Init() {
    DIR *d = opendir(work_path_.c_str());
    if (d == NULL) {
        LOG() << strerror(errno);
        exit(1);
    }

    struct dirent *dir;
    while ((dir = readdir(d)) != NULL) {
        const char *p = strstr(dir->d_name, ".wal");
        if (p != NULL) {
            int seq = std::stoi(std::string(dir->d_name, p - dir->d_name), NULL, 16);
            cur_wal_seq_ = std::max(cur_wal_seq_, seq);
            ProcessWal(WalPath(work_path_, cur_wal_seq_).c_str());
        }
    }

    closedir(d);

    ++cur_wal_seq_;

    for (int i = 0; i < 5; ++i)
        workers_.emplace_back(&Wal::Work, this);
}

int Wal::Read(const char *path, char *buf, size_t size, off_t offset) {
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
    for (const Block &b : cur_wal_blocks_) {
        if (b.path != path) continue;
        if (b.offset >= offset && b.offset < offset + size) {
            off_t o = b.offset - offset;
            size_t s = std::min(size - o, (size_t)b.size);
            memcpy(buf + o, b.data.data(), s);
            segs.emplace_back(b.offset, s);
        } else if (b.offset + size - 1 >= offset && b.offset + size - 1 < offset + size) {
            off_t o = offset - b.offset;
            size_t s = std::min((size_t)(b.size - o), size);
            memcpy(buf, b.data.data() + o, s);
            segs.emplace_back(offset, s);
        }
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
    if (size == 0) return 0;

    std::lock_guard<std::mutex> lck(mu_);

    if (cur_wal_fd_ == -1) {
        std::string wal_path = WalPath(work_path_, cur_wal_seq_);
        LOG() << "Creating wal: " << wal_path;
        cur_wal_fd_ = open(wal_path.c_str(), O_WRONLY|O_CREAT);
        if (cur_wal_fd_ == -1) {
            LOG() << wal_path << ", " << strerror(errno);
            exit(1);
        }
        cur_wal_size_ = 0;
    }

    FileInfo *info = &file_infos_[path];
    if (info->path.empty())
        info->path = base_path_ + path;
    if (info->base_wr_fd == -1) {
        info->base_wr_fd = open(info->path.c_str(), O_WRONLY);
        if (info->base_wr_fd == -1) {
            LOG() << info->path << ", " << strerror(errno);
            exit(1);
        }
    }

    Block b;
    b.offset = offset;
    b.size = size;
    b.path_len = strlen(path);
    b.path = path;
    b.is_done = false;
    b.data = std::string(buf, size);
    cur_wal_size_ += b.WriteBuf(cur_wal_fd_, buf);
    cur_wal_blocks_.push_back(std::move(b));

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

void Wal::ProcessWal(const char *path) {
    LOG() << "Processing wal: " << path;

    WalInfo& info = wal_infos_[path];

    info.fd = open(path, O_RDWR);
    if (info.fd == -1) {
        LOG() << path << ", " << strerror(errno);
        exit(1);
    }

    int wal_offset = 0;
    while (true) {
        auto block = std::make_shared<Block>();
        wal_offset = block->Read(info.fd, wal_offset);
        if (wal_offset == 0) break;
        block->wal_path = path;
        if (block->is_done) {
            info.undone_blocks[block->key]->is_done = true;
            info.undone_blocks.erase(block->key);
        } else {
            info.undone_blocks[block->key] = block;
            file_infos_[block->path].blocks.push_back(block);
        }
        if (lseek(info.fd, wal_offset, SEEK_SET) == -1) {
            LOG() << path << ", " << strerror(errno);
            exit(1);
        }
    }
}

void Wal::Work() {
    while (true) {
        {
            std::lock_guard<std::mutex> lck(mu_);
            time_t now = std::time(nullptr);
            if (cur_wal_fd_ != -1 && (cur_wal_size_ >= 1024*1024 || now - last_flush_ > 3)) {
            //if (cur_wal_fd_ != -1 && (cur_wal_size_ >= 1024*1024)) {
                close(cur_wal_fd_);
                cur_wal_fd_ = -1;
                last_flush_ = now;
                cur_wal_blocks_.clear();
                ProcessWal(WalPath(work_path_, cur_wal_seq_).c_str());
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
            continue;
        }

        if (file_info->base_wr_fd == -1) {
            file_info->base_wr_fd = open(file_info->path.c_str(), O_WRONLY);
            if (file_info->base_wr_fd == -1) {
                LOG() << file_info->path << ", " << strerror(errno);
                exit(1);
            }
        }

        while (true) {
            std::shared_ptr<Block> block;
            {
                std::lock_guard<std::mutex> lck(mu_);
                if (file_info->blocks.empty())
                    break;
                block = file_info->blocks.front();
            }
            assert(!block->is_done);
            WalInfo &wal_info = wal_infos_[block->wal_path];
            std::unique_ptr<char[]> buf(new char[block->size]);
            {
                std::lock_guard<std::mutex> lck(mu_);
                assert(pread(wal_info.fd, buf.get(), block->size, block->wal_offset) == block->size);
            }
            assert(pwrite(file_info->base_wr_fd, buf.get(), block->size, block->offset) == block->size);
            {
                std::lock_guard<std::mutex> lck(mu_);
                assert(block->WriteDone(wal_info.fd) > 0);
                LOG() << "Block done: " << block->path << "," << block->offset << "," << block->size;
                file_info->blocks.pop_front();
                wal_info.undone_blocks.erase(block->key);
                if (wal_info.undone_blocks.empty()) {
                    close(wal_info.fd);
                    unlink(block->wal_path.c_str());
                }
            }
        }

        fsync(file_info->base_wr_fd);

        {
            std::lock_guard<std::mutex> lck(mu_);
            file_info->busy = false;
        }

        std::this_thread::sleep_for(std::chrono::milliseconds(100));
    }
}

