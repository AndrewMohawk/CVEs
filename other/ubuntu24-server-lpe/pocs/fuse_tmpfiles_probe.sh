#!/bin/sh
set -eu

MNT="${1:-/tmp/fuse-tmpfiles-probe}"
LOG="${2:-/tmp/fuse-tmpfiles-probe.log}"
SRC="${TMPDIR:-/tmp}/fuse_tmpfiles_probe.c"
BIN="${FUSE_PROBE_BIN:-${TMPDIR:-/tmp}/fuse_tmpfiles_probe_bin}"

write_source() {
  cat >"$SRC" <<'C_EOF'
#define FUSE_USE_VERSION 31
#include <errno.h>
#include <fcntl.h>
#include <fuse3/fuse.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/statvfs.h>
#include <time.h>
#include <unistd.h>

static const char *g_log;
static const char payload[] = "attacker-controlled fuse payload\n";

static void log_msg(const char *op, const char *path, const char *fmt, ...) {
    int fd = open(g_log, O_WRONLY | O_CREAT | O_APPEND, 0666);
    if (fd < 0) return;
    struct fuse_context *ctx = fuse_get_context();
    dprintf(fd, "time=%ld op=%s path=%s caller_uid=%ld caller_gid=%ld caller_pid=%ld ",
            (long)time(NULL), op, path ? path : "-", ctx ? (long)ctx->uid : -1,
            ctx ? (long)ctx->gid : -1, ctx ? (long)ctx->pid : -1);
    va_list ap;
    va_start(ap, fmt);
    vdprintf(fd, fmt, ap);
    va_end(ap);
    dprintf(fd, "\n");
    close(fd);
}

static int is_file(const char *p) {
    return !strcmp(p, "/old_file") || !strcmp(p, "/subdir/old_child") ||
           !strcmp(p, "/fake_root_suid") || !strcmp(p, "/cron_payload");
}

static int fill_stat(const char *path, struct stat *st) {
    memset(st, 0, sizeof(*st));
    st->st_atime = st->st_mtime = st->st_ctime = 1;
    if (!strcmp(path, "/")) {
        st->st_mode = S_IFDIR | 0777;
        st->st_nlink = 3;
        st->st_uid = getuid();
        st->st_gid = getgid();
        return 0;
    }
    if (!strcmp(path, "/subdir")) {
        st->st_mode = S_IFDIR | 0777;
        st->st_nlink = 2;
        st->st_uid = getuid();
        st->st_gid = getgid();
        return 0;
    }
    if (!strcmp(path, "/symlink_to_root_marker") || !strcmp(path, "/symlink_to_shadow")) {
        st->st_mode = S_IFLNK | 0777;
        st->st_nlink = 1;
        st->st_uid = getuid();
        st->st_gid = getgid();
        st->st_size = 32;
        return 0;
    }
    if (!strcmp(path, "/fake_fifo")) {
        st->st_mode = S_IFIFO | 0666;
        st->st_nlink = 1;
        st->st_uid = getuid();
        st->st_gid = getgid();
        return 0;
    }
    if (!strcmp(path, "/fake_root_suid")) {
        st->st_mode = S_IFREG | 04777;
        st->st_nlink = 2;
        st->st_uid = 0;
        st->st_gid = 0;
        st->st_size = sizeof(payload) - 1;
        return 0;
    }
    if (is_file(path)) {
        st->st_mode = S_IFREG | 0666;
        st->st_nlink = 1;
        st->st_uid = getuid();
        st->st_gid = getgid();
        st->st_size = sizeof(payload) - 1;
        return 0;
    }
    return -ENOENT;
}

static int probe_getattr(const char *path, struct stat *st, struct fuse_file_info *fi) {
    (void)fi;
    int rc = fill_stat(path, st);
    log_msg("getattr", path, "rc=%d mode=%o uid=%ld gid=%ld", rc, rc ? 0 : st->st_mode,
            rc ? -1L : (long)st->st_uid, rc ? -1L : (long)st->st_gid);
    return rc;
}

static int probe_readdir(const char *path, void *buf, fuse_fill_dir_t filler, off_t off,
                         struct fuse_file_info *fi, enum fuse_readdir_flags flags) {
    (void)off; (void)fi; (void)flags;
    log_msg("readdir", path, "enter");
    if (strcmp(path, "/") && strcmp(path, "/subdir")) return -ENOENT;
    filler(buf, ".", NULL, 0, 0);
    filler(buf, "..", NULL, 0, 0);
    if (!strcmp(path, "/")) {
        filler(buf, "old_file", NULL, 0, 0);
        filler(buf, "subdir", NULL, 0, 0);
        filler(buf, "symlink_to_root_marker", NULL, 0, 0);
        filler(buf, "symlink_to_shadow", NULL, 0, 0);
        filler(buf, "fake_root_suid", NULL, 0, 0);
        filler(buf, "fake_fifo", NULL, 0, 0);
        filler(buf, "cron_payload", NULL, 0, 0);
    } else {
        filler(buf, "old_child", NULL, 0, 0);
    }
    return 0;
}

static int probe_readlink(const char *path, char *buf, size_t size) {
    const char *target = NULL;
    if (!strcmp(path, "/symlink_to_root_marker")) target = "/root/fuse_tmpfiles_root_marker";
    if (!strcmp(path, "/symlink_to_shadow")) target = "/etc/shadow";
    if (!target) return -ENOENT;
    snprintf(buf, size, "%s", target);
    log_msg("readlink", path, "target=%s", target);
    return 0;
}

static int probe_open(const char *path, struct fuse_file_info *fi) {
    (void)fi;
    log_msg("open", path, "flags=0x%x", fi ? fi->flags : 0);
    return is_file(path) ? 0 : -ENOENT;
}

static int probe_read(const char *path, char *buf, size_t size, off_t off, struct fuse_file_info *fi) {
    (void)fi;
    if (!is_file(path)) return -ENOENT;
    size_t len = sizeof(payload) - 1;
    if ((size_t)off >= len) return 0;
    if (size > len - (size_t)off) size = len - (size_t)off;
    memcpy(buf, payload + off, size);
    log_msg("read", path, "off=%ld size=%zu", (long)off, size);
    return (int)size;
}

static int probe_unlink(const char *path) {
    log_msg("unlink", path, "requested");
    return 0;
}

static int probe_rmdir(const char *path) {
    log_msg("rmdir", path, "requested");
    return 0;
}

static int probe_chmod(const char *path, mode_t mode, struct fuse_file_info *fi) {
    (void)fi;
    log_msg("chmod", path, "mode=%o", mode);
    return 0;
}

static int probe_chown(const char *path, uid_t uid, gid_t gid, struct fuse_file_info *fi) {
    (void)fi;
    log_msg("chown", path, "uid=%ld gid=%ld", (long)uid, (long)gid);
    return 0;
}

static int probe_truncate(const char *path, off_t size, struct fuse_file_info *fi) {
    (void)fi;
    log_msg("truncate", path, "size=%ld", (long)size);
    return 0;
}

static int probe_utimens(const char *path, const struct timespec tv[2], struct fuse_file_info *fi) {
    (void)fi;
    log_msg("utimens", path, "atime=%ld mtime=%ld", (long)tv[0].tv_sec, (long)tv[1].tv_sec);
    return 0;
}

static int probe_access(const char *path, int mask) {
    log_msg("access", path, "mask=0x%x", mask);
    return fill_stat(path, &(struct stat){0});
}

static int probe_statfs(const char *path, struct statvfs *st) {
    memset(st, 0, sizeof(*st));
    st->f_bsize = 4096;
    st->f_frsize = 4096;
    st->f_blocks = 1024;
    st->f_bfree = 512;
    st->f_bavail = 512;
    st->f_files = 1024;
    st->f_ffree = 512;
    log_msg("statfs", path, "ok");
    return 0;
}

static const struct fuse_operations ops = {
    .getattr = probe_getattr,
    .readlink = probe_readlink,
    .unlink = probe_unlink,
    .rmdir = probe_rmdir,
    .chmod = probe_chmod,
    .chown = probe_chown,
    .truncate = probe_truncate,
    .open = probe_open,
    .read = probe_read,
    .statfs = probe_statfs,
    .opendir = NULL,
    .readdir = probe_readdir,
    .access = probe_access,
    .utimens = probe_utimens,
};

int main(int argc, char **argv) {
    g_log = getenv("FUSE_PROBE_LOG");
    if (!g_log) g_log = "/tmp/fuse-tmpfiles-probe.log";
    return fuse_main(argc, argv, &ops, NULL);
}
C_EOF
}

if [ "${1:-}" = "--build" ]; then
  write_source
  cc "$SRC" -o "$BIN" $(pkg-config fuse3 --cflags --libs)
  echo "$BIN"
  exit 0
fi

if [ ! -x "$BIN" ]; then
  write_source
  cc "$SRC" -o "$BIN" $(pkg-config fuse3 --cflags --libs)
fi

mkdir -p "$MNT"
: >"$LOG"
export FUSE_PROBE_LOG="$LOG"
exec "$BIN" -f -s "$MNT" -o default_permissions,fsname=fuse_tmpfiles_probe
