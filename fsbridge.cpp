#define FUSE_USE_VERSION 26

#include <fuse.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <stddef.h>
#include <dirent.h>
#include <unistd.h>
#include <sys/xattr.h>

#include <iostream>
#include <string>

#include "log.h"
#include "wal.h"

struct prog_opts {
    char *base_path;
    int allow_base_read = 0;
    char *work_path;
    char *log_path;
    int log_level = 0;
};

Wal *wal;

static int fsbridge_getattr(const char *path, struct stat *stbuf)
{
    prog_opts *opts = (prog_opts*)(fuse_get_context()->private_data);
    std::string real_path = std::string(opts->base_path) + path;

    if (lstat(real_path.c_str(), stbuf) == -1)
        return -errno;

    return 0;
}

static int fsbridge_mkdir(const char *path, mode_t mode)
{
    prog_opts *opts = (prog_opts*)(fuse_get_context()->private_data);
    std::string real_path = std::string(opts->base_path) + path;

    LOG(2) << "mkdir " << path;

    if (mkdir(real_path.c_str(), mode) == -1)
        return -errno;

    if (chmod(real_path.c_str(), 0777) == -1)
        return -errno;
    // if (chown(real_path.c_str(), fuse_get_context()->uid,
    //           fuse_get_context()->gid) == -1)
    //     return -errno;

    return 0;
}

static int fsbridge_rmdir(const char *path)
{
    prog_opts *opts = (prog_opts*)(fuse_get_context()->private_data);
    std::string real_path = std::string(opts->base_path) + path;

    if (rmdir(real_path.c_str()) == -1)
        return -errno;

    return 0;
}

static int fsbridge_readdir(const char *path, void *buf, fuse_fill_dir_t filler,
                            off_t offset, struct fuse_file_info *fi)
{
    prog_opts *opts = (prog_opts*)(fuse_get_context()->private_data);
    std::string real_path = std::string(opts->base_path) + path;

    DIR *d = opendir(real_path.c_str());
    if (d == NULL)
        return -errno;

    filler(buf, ".", NULL, 0);
    filler(buf, "..", NULL, 0);

    struct dirent *dir;
    while ((dir = readdir(d)) != NULL) {
        filler(buf, dir->d_name, NULL, 0);
    }

    if (closedir(d) == -1)
        return -errno;

    return 0;
}

static int fsbridge_unlink(const char *path)
{
    prog_opts *opts = (prog_opts*)(fuse_get_context()->private_data);
    std::string real_path = std::string(opts->base_path) + path;

    int res;

    res = unlink(real_path.c_str());
    if (res == -1)
        return -errno;

    return 0;
}

static int fsbridge_rename(const char *from, const char *to)
{
    prog_opts *opts = (prog_opts*)(fuse_get_context()->private_data);
    std::string real_from = std::string(opts->base_path) + from;
    std::string real_to = std::string(opts->base_path) + to;

    int res;

    res = rename(real_from.c_str(), real_to.c_str());
    if (res == -1)
        return -errno;

    return 0;
}

static int fsbridge_truncate(const char *path, off_t size)
{
    prog_opts *opts = (prog_opts*)(fuse_get_context()->private_data);
    std::string real_path = std::string(opts->base_path) + path;

    int res;

    res = truncate(real_path.c_str(), size);
    if (res == -1)
        return -errno;

    return 0;
}

static int fsbridge_mknod(const char *path, mode_t mode, dev_t rdev)
{
    prog_opts *opts = (prog_opts*)(fuse_get_context()->private_data);
    std::string real_path = std::string(opts->base_path) + path;

    int res;

    /* On Linux this could just be 'mknod(path, mode, rdev)' but this
       is more portable */
    if (S_ISREG(mode)) {
        res = open(real_path.c_str(), O_CREAT | O_EXCL | O_WRONLY, mode);
        if (res == -1)
            return -errno;
        //if (fchown(res, fuse_get_context()->uid, fuse_get_context()->gid) == -1)
        //    LOG(0) << "Failed to chown for " << path << ","
        //           << fuse_get_context()->uid << "," <<  fuse_get_context()->gid;
        if (fchmod(res, 0777) == -1)
            return -errno;
        close(res);
        return 0;
    }

    if (S_ISFIFO(mode))
        res = mkfifo(real_path.c_str(), mode);
    else
        res = mknod(real_path.c_str(), mode, rdev);
    if (res == -1)
        return -errno;

    return 0;
}

static int fsbridge_open(const char *path, struct fuse_file_info *fi)
{
    prog_opts *opts = (prog_opts*)(fuse_get_context()->private_data);
    std::string real_path = std::string(opts->base_path) + path;

    int res;

    res = open(real_path.c_str(), fi->flags);
    if (res == -1)
        return -errno;

    close(res);
    // fi->fh = res;

    return 0;
}

static int fsbridge_read(const char *path, char *buf, size_t size, off_t offset,
            struct fuse_file_info *fi)
{
    return wal->Read(path, buf, size, offset);
//    prog_opts *opts = (prog_opts*)(fuse_get_context()->private_data);
//    std::string real_path = std::string(opts->base_path) + path;
//
//    int fd = fi->fh;
//    int res;
//
//    res = open(real_path.c_str(), fi->flags);
//    if (res == -1)
//        return -errno;
//
//    res = pread(res, buf, size, offset);
//    //res = pread(fd, buf, size, offset);
//    if (res == -1)
//        res = -errno;
//
//    close(res);
//
//    return res;
}

static int fsbridge_write(const char *path, const char *buf, size_t size,
             off_t offset, struct fuse_file_info *fi)
{
    // int fd = fi->fh;
    int res;

    // res = pwrite(fd, buf, size, offset);
    res = wal->Write(path, buf, size, offset);
    if (res == -1)
        res = -errno;

    return res;
}

static int fsbridge_release(const char *path, struct fuse_file_info *fi)
{
    // close(fi->fh);
    wal->Release(path);
    return 0;
}

static int fsbridge_fsync(const char *path, int isdatasync,
             struct fuse_file_info *fi)
{
    // if (isdatasync != 0)
    //     fdatasync(fi->fh);
    // else
    //     fsync(fi->fh);
    wal->Fsync(path, isdatasync);
    return 0;
}

static int fsbridge_chmod(const char *path, mode_t mode)
{
    prog_opts *opts = (prog_opts*)(fuse_get_context()->private_data);
    std::string real_path = std::string(opts->base_path) + path;

    int res;

    res = chmod(real_path.c_str(), mode);
    if (res == -1)
        return -errno;

    return 0;
}

static int fsbridge_chown(const char *path, uid_t uid, gid_t gid)
{
    prog_opts *opts = (prog_opts*)(fuse_get_context()->private_data);
    std::string real_path = std::string(opts->base_path) + path;

    int res;

    res = lchown(real_path.c_str(), uid, gid);
    if (res == -1)
        return -errno;

    return 0;
}

static int fsbridge_setxattr(const char *path, const char *name, const char *value,
            size_t size, int flags)
{
    prog_opts *opts = (prog_opts*)(fuse_get_context()->private_data);
    std::string real_path = std::string(opts->base_path) + path;

    int res = lsetxattr(real_path.c_str(), name, value, size, flags);
    if (res == -1)
        return -errno;
    return 0;
}

static int fsbridge_getxattr(const char *path, const char *name, char *value,
            size_t size)
{
    prog_opts *opts = (prog_opts*)(fuse_get_context()->private_data);
    std::string real_path = std::string(opts->base_path) + path;

    int res = lgetxattr(real_path.c_str(), name, value, size);
    if (res == -1)
        return -errno;
    return res;
}

static int fsbridge_listxattr(const char *path, char *list, size_t size)
{
    prog_opts *opts = (prog_opts*)(fuse_get_context()->private_data);
    std::string real_path = std::string(opts->base_path) + path;

    int res = llistxattr(real_path.c_str(), list, size);
    if (res == -1)
        return -errno;
    return res;
}

static int fsbridge_removexattr(const char *path, const char *name)
{
    prog_opts *opts = (prog_opts*)(fuse_get_context()->private_data);
    std::string real_path = std::string(opts->base_path) + path;

    int res = lremovexattr(real_path.c_str(), name);
    if (res == -1)
        return -errno;
    return 0;
}

int main(int argc, char *argv[]) {
    const fuse_opt fuse_opts[] = {
        {.templ = "--base_path=%s", .offset = offsetof(prog_opts, base_path), .value = 0},
        {.templ = "--allow_base_read=%d", .offset = offsetof(prog_opts, allow_base_read), .value = 0},
        {.templ = "--work_path=%s", .offset = offsetof(prog_opts, work_path), .value = 0},
        {.templ = "--log_path=%s", .offset = offsetof(prog_opts, log_path), .value = 0},
        {.templ = "--log_level=%d", .offset = offsetof(prog_opts, log_level), .value = 0},
        FUSE_OPT_END,
    };
    fuse_args args = FUSE_ARGS_INIT(argc, argv);
    prog_opts opts = {0};
    if (fuse_opt_parse(&args, &opts, fuse_opts, NULL) == -1) {
        return -1;
    }

    set_log(opts.log_path, opts.log_level);

    LOG(0) << "===============STARTED===============";

    wal = new Wal(opts.work_path, opts.base_path, opts.allow_base_read);

    struct fuse_operations operations = { 0 };
    operations.getattr     = fsbridge_getattr;
    operations.mkdir       = fsbridge_mkdir;
    operations.rmdir       = fsbridge_rmdir;
    operations.readdir     = fsbridge_readdir;
    operations.unlink      = fsbridge_unlink;
    operations.rename      = fsbridge_rename;
    operations.truncate    = fsbridge_truncate;
    operations.mknod       = fsbridge_mknod;
    operations.open        = fsbridge_open;
    operations.read        = fsbridge_read;
    operations.write       = fsbridge_write;
    operations.release     = fsbridge_release;
    operations.fsync       = fsbridge_fsync;
    operations.chmod       = fsbridge_chmod;
    operations.chown       = fsbridge_chown;
    operations.setxattr    = fsbridge_setxattr;
    operations.getxattr    = fsbridge_getxattr;
    operations.listxattr   = fsbridge_listxattr;
    operations.removexattr = fsbridge_removexattr;

    int r = fuse_main(args.argc, args.argv, &operations, &opts);

    fuse_opt_free_args(&args);

    return r;
}
