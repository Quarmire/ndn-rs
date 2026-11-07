/*
 * fsync shadow: an LD_PRELOAD library that keeps, beside a directory tree, a
 * copy of what a power loss could not take from it.
 *
 * Test fixture of crates/protocols/ndn-sync/tests/durability.rs; compiled
 * there at test time with
 *   cc -shared -fPIC -O2 -o libfsync_shadow.so fsync_shadow.c -ldl
 *
 * Environment:
 *   SHADOW_ROOT  absolute, canonical directory whose files are shadowed
 *   SHADOW_OUT   absolute directory receiving the shadow (outside SHADOW_ROOT)
 *
 * The model (what the shadow holds after the process dies):
 *   - File DATA is durable only at fsync/fdatasync: when either is called on
 *     a regular file under SHADOW_ROOT, the file's whole current content is
 *     copied to SHADOW_OUT/<relative path> (temp file + rename inside the
 *     shadow, so the shadow never holds half a copy), then the real call is
 *     made. Content written by another thread while the copy runs may be
 *     counted durable a little early; everything written before the call is
 *     in the copy. syncfs(2) and sync(2) shadow every regular file under
 *     SHADOW_ROOT the same way.
 *   - NAMES (a file being there at all) are durable once any fsync followed
 *     them, like ext4, where an fsync commits the one metadata journal: at
 *     every fsync/fdatasync of a file or directory under SHADOW_ROOT (and at
 *     syncfs/sync) each regular file then under it gets a marker
 *     SHADOW_OUT/.names/<relative path>. Renames and removals are mirrored
 *     onto the data shadow and the markers as they succeed
 *     (rename/renameat/renameat2, unlink/unlinkat/rmdir): a rename carries
 *     the source's shadow and marker to the target; a rename whose source
 *     has none leaves the target with none; one leaving SHADOW_ROOT drops
 *     them, one entering it brings none.
 *   - sync_file_range(2) is NOT interposed: it neither flushes the disk's
 *     cache nor writes metadata, so it makes nothing durable and does not
 *     move the shadow.
 *   - Only calls through libc are seen; raw syscalls (rustix's linux_raw
 *     backend) are not.
 *
 * A file under SHADOW_ROOT with no data shadow was never fsynced: the test
 * makes it empty or a prefix of what the OS held, or absent when it has no
 * name marker either.
 */
#define _GNU_SOURCE
#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <ftw.h>
#include <limits.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#ifndef RENAME_EXCHANGE
#define RENAME_EXCHANGE (1 << 1)
#endif

static pthread_mutex_t lock = PTHREAD_MUTEX_INITIALIZER;
static unsigned long counter;

static int (*real_fsync)(int);
static int (*real_fdatasync)(int);
static int (*real_syncfs)(int);
static void (*real_sync)(void);
static int (*real_rename)(const char *, const char *);
static int (*real_renameat)(int, const char *, int, const char *);
static int (*real_renameat2)(int, const char *, int, const char *, unsigned int);
static int (*real_unlink)(const char *);
static int (*real_unlinkat)(int, const char *, int);
static int (*real_rmdir)(const char *);

static pthread_once_t resolved = PTHREAD_ONCE_INIT;

static void resolve_once(void)
{
    real_fsync = dlsym(RTLD_NEXT, "fsync");
    real_fdatasync = dlsym(RTLD_NEXT, "fdatasync");
    real_syncfs = dlsym(RTLD_NEXT, "syncfs");
    real_sync = dlsym(RTLD_NEXT, "sync");
    real_rename = dlsym(RTLD_NEXT, "rename");
    real_renameat = dlsym(RTLD_NEXT, "renameat");
    real_renameat2 = dlsym(RTLD_NEXT, "renameat2");
    real_unlink = dlsym(RTLD_NEXT, "unlink");
    real_unlinkat = dlsym(RTLD_NEXT, "unlinkat");
    real_rmdir = dlsym(RTLD_NEXT, "rmdir");
}

static void resolve(void)
{
    pthread_once(&resolved, resolve_once);
}

static void die(const char *what, const char *path)
{
    /* The shadow is the test's evidence: a shadow that silently fell behind
     * would make the test pass or fail for the wrong reason. */
    fprintf(stderr, "fsync_shadow: %s %s: %s; the power-loss image would be wrong, aborting\n",
            what, path, strerror(errno));
    abort();
}

/* Lexically normalise an absolute path ("//", "/./", "/../"). */
static void normalise(char *p)
{
    char out[PATH_MAX];
    size_t n = 0;
    const char *s = p;
    while (*s) {
        while (*s == '/')
            s++;
        if (!*s)
            break;
        const char *e = strchr(s, '/');
        size_t len = e ? (size_t)(e - s) : strlen(s);
        if (len == 1 && s[0] == '.') {
        } else if (len == 2 && s[0] == '.' && s[1] == '.') {
            while (n > 0 && out[n - 1] != '/')
                n--;
            if (n > 0)
                n--;
        } else {
            if (n + 1 + len >= sizeof out)
                return;
            out[n++] = '/';
            memcpy(out + n, s, len);
            n += len;
        }
        s += len;
    }
    if (n == 0)
        out[n++] = '/';
    out[n] = 0;
    memcpy(p, out, n + 1);
}

/* The path `fd` is open at; 0 when it has none (an unlinked file). */
static int fd_path(int fd, char *out)
{
    char link[64];
    snprintf(link, sizeof link, "/proc/self/fd/%d", fd);
    ssize_t n = readlink(link, out, PATH_MAX - 1);
    if (n < 0)
        return 0;
    out[n] = 0;
    const char *del = " (deleted)";
    size_t dl = strlen(del);
    if ((size_t)n >= dl && strcmp(out + n - dl, del) == 0)
        return 0;
    return 1;
}

/* The absolute path `path` names relative to `dirfd`. */
static int at_path(int dirfd, const char *path, char *out)
{
    if (path[0] == '/') {
        snprintf(out, PATH_MAX, "%s", path);
    } else {
        char base[PATH_MAX];
        if (dirfd == AT_FDCWD) {
            if (!getcwd(base, sizeof base))
                return 0;
        } else if (!fd_path(dirfd, base)) {
            return 0;
        }
        snprintf(out, PATH_MAX, "%s/%s", base, path);
    }
    normalise(out);
    return 1;
}

/* The part of `abs` below SHADOW_ROOT ("" for the root itself, else
 * "/a/b"); NULL when `abs` is not under it. */
static const char *rel_of(const char *abs)
{
    const char *root = getenv("SHADOW_ROOT");
    if (!root || !getenv("SHADOW_OUT"))
        return NULL;
    size_t rl = strlen(root);
    if (strncmp(abs, root, rl) != 0 || (abs[rl] != '/' && abs[rl] != 0))
        return NULL;
    return abs + rl;
}

/* The data shadow of `abs`: SHADOW_OUT/<rel>. 0 when not under the root. */
static int shadow_of(const char *abs, char *out)
{
    const char *rel = rel_of(abs);
    if (!rel || !*rel)
        return 0;
    snprintf(out, PATH_MAX, "%s%s", getenv("SHADOW_OUT"), rel);
    return 1;
}

/* The name marker of `abs`: SHADOW_OUT/.names/<rel>, present when the
 * file's name is durable (its directory was fsynced since it got it). */
static int names_of(const char *abs, char *out)
{
    const char *rel = rel_of(abs);
    if (!rel || !*rel)
        return 0;
    snprintf(out, PATH_MAX, "%s/.names%s", getenv("SHADOW_OUT"), rel);
    return 1;
}

static void make_parents(const char *path)
{
    char p[PATH_MAX];
    snprintf(p, sizeof p, "%s", path);
    for (char *s = p + 1; *s; s++) {
        if (*s == '/') {
            *s = 0;
            if (mkdir(p, 0700) != 0 && errno != EEXIST)
                die("mkdir", p);
            *s = '/';
        }
    }
}

/* Copy bytes [from, to) of `in` to the same offsets of `out`. */
static void copy_range(int in, int out, off_t from, off_t to, const char *abs, const char *tmp)
{
    char buf[1 << 16];
    while (from < to) {
        size_t want = (size_t)(to - from) < sizeof buf ? (size_t)(to - from) : sizeof buf;
        ssize_t n = pread(in, buf, want, from);
        if (n < 0) {
            if (errno == EINTR)
                continue;
            die("read", abs);
        }
        if (n == 0)
            return; /* shrunk while copying */
        for (ssize_t off = 0; off < n;) {
            ssize_t w = pwrite(out, buf + off, (size_t)(n - off), from + off);
            if (w < 0) {
                if (errno == EINTR)
                    continue;
                die("write", tmp);
            }
            off += w;
        }
        from += n;
    }
}

/* Copy the regular file `abs` (under SHADOW_ROOT) into its shadow. Holes
 * stay holes (fjall preallocates its journal sparse), so a sync of a big
 * mostly-empty file copies only what it holds. */
static void shadow_copy(const char *abs)
{
    char dst[PATH_MAX], tmp[PATH_MAX + 64];
    struct stat st;
    if (!shadow_of(abs, dst))
        return;
    int in = open(abs, O_RDONLY | O_CLOEXEC);
    if (in < 0)
        return; /* gone, or not ours to read */
    if (fstat(in, &st) != 0 || !S_ISREG(st.st_mode)) {
        close(in);
        return;
    }
    make_parents(dst);
    snprintf(tmp, sizeof tmp, "%s.shadowtmp.%d.%lu", dst, (int)getpid(), ++counter);
    int out = open(tmp, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0600);
    if (out < 0)
        die("create", tmp);
    off_t size = st.st_size, pos = 0;
    while (pos < size) {
        off_t data = lseek(in, pos, SEEK_DATA);
        if (data < 0) {
            if (errno == ENXIO)
                break; /* only a hole from here on */
            data = pos; /* no SEEK_DATA here: copy everything */
        }
        if (data >= size)
            break;
        off_t hole = lseek(in, data, SEEK_HOLE);
        if (hole < 0 || hole > size)
            hole = size;
        copy_range(in, out, data, hole, abs, tmp);
        pos = hole;
    }
    if (ftruncate(out, size) != 0)
        die("truncate", tmp);
    close(in);
    close(out);
    if (real_rename(tmp, dst) != 0)
        die("rename", tmp);
}

static int name_one(const char *path, const struct stat *st, int type, struct FTW *ftw)
{
    char mark[PATH_MAX];
    (void)ftw;
    if (type != FTW_F || !S_ISREG(st->st_mode) || !names_of(path, mark))
        return 0;
    if (access(mark, F_OK) == 0)
        return 0;
    make_parents(mark);
    int fd = open(mark, O_WRONLY | O_CREAT | O_CLOEXEC, 0600);
    if (fd < 0)
        die("create", mark);
    close(fd);
    return 0;
}

/* An fsync commits the filesystem's metadata journal: every name under
 * the root as of now is durable. */
static void name_all(void)
{
    const char *root = getenv("SHADOW_ROOT");
    if (root && getenv("SHADOW_OUT"))
        nftw(root, name_one, 16, FTW_PHYS);
}

static void shadow_fd(int fd)
{
    char abs[PATH_MAX];
    struct stat st;
    if (!fd_path(fd, abs) || !rel_of(abs) || fstat(fd, &st) != 0)
        return;
    if (S_ISREG(st.st_mode))
        shadow_copy(abs);
    name_all();
}

static int walk_one(const char *path, const struct stat *st, int type, struct FTW *ftw)
{
    (void)ftw;
    if (type == FTW_F && S_ISREG(st->st_mode))
        shadow_copy(path);
    return 0;
}

static void shadow_all(void)
{
    const char *root = getenv("SHADOW_ROOT");
    if (root && getenv("SHADOW_OUT")) {
        nftw(root, walk_one, 16, FTW_PHYS);
        name_all();
    }
}

static int remove_one(const char *path, const struct stat *st, int type, struct FTW *ftw)
{
    (void)st;
    (void)ftw;
    if (type == FTW_DP || type == FTW_D)
        real_rmdir(path);
    else
        real_unlink(path);
    return 0;
}

/* Remove the shadow-side path `sh` (file or directory tree), if present. */
static void drop_path(const char *sh)
{
    struct stat st;
    if (lstat(sh, &st) != 0)
        return;
    if (S_ISDIR(st.st_mode))
        nftw(sh, remove_one, 16, FTW_DEPTH | FTW_PHYS);
    else
        real_unlink(sh);
}

/* Drop the data shadow and name marker of `abs`. */
static void shadow_drop(const char *abs)
{
    char sh[PATH_MAX];
    if (shadow_of(abs, sh))
        drop_path(sh);
    if (names_of(abs, sh))
        drop_path(sh);
}

/* Mirror a rename onto one shadow-side tree, given the source's and the
 * target's paths in it (`f_in`/`t_in`: whether each is under the root). */
static void mirror_rename(const char *sf, int f_in, const char *st_, int t_in, unsigned int flags)
{
    struct stat st;
    if (flags & RENAME_EXCHANGE) {
        if (f_in && t_in) {
            char tmp[PATH_MAX + 64];
            int f_has = lstat(sf, &st) == 0;
            int t_has = lstat(st_, &st) == 0;
            snprintf(tmp, sizeof tmp, "%s.shadowswap.%d.%lu", sf, (int)getpid(), ++counter);
            if (f_has && real_rename(sf, tmp) != 0)
                die("rename", sf);
            if (t_has) {
                make_parents(sf);
                if (real_rename(st_, sf) != 0)
                    die("rename", st_);
            }
            if (f_has) {
                make_parents(st_);
                if (real_rename(tmp, st_) != 0)
                    die("rename", tmp);
            }
            return;
        }
    } else if (f_in && t_in && lstat(sf, &st) == 0) {
        drop_path(st_);
        make_parents(st_);
        if (real_rename(sf, st_) != 0)
            die("rename", sf);
        return;
    }
    /* Nothing durable to carry over, or the file left or entered the root. */
    if (f_in)
        drop_path(sf);
    if (t_in)
        drop_path(st_);
}

static void shadow_rename(const char *from, const char *to, unsigned int flags)
{
    char sf[PATH_MAX], st_[PATH_MAX];
    int f_in = shadow_of(from, sf);
    int t_in = shadow_of(to, st_);
    mirror_rename(sf, f_in, st_, t_in, flags);
    f_in = names_of(from, sf);
    t_in = names_of(to, st_);
    mirror_rename(sf, f_in, st_, t_in, flags);
}

int fsync(int fd)
{
    resolve();
    pthread_mutex_lock(&lock);
    shadow_fd(fd);
    pthread_mutex_unlock(&lock);
    return real_fsync(fd);
}

int fdatasync(int fd)
{
    resolve();
    pthread_mutex_lock(&lock);
    shadow_fd(fd);
    pthread_mutex_unlock(&lock);
    return real_fdatasync(fd);
}

int syncfs(int fd)
{
    resolve();
    pthread_mutex_lock(&lock);
    shadow_all();
    pthread_mutex_unlock(&lock);
    return real_syncfs(fd);
}

void sync(void)
{
    resolve();
    pthread_mutex_lock(&lock);
    shadow_all();
    pthread_mutex_unlock(&lock);
    real_sync();
}

static int do_renameat2(int ofd, const char *old, int nfd, const char *new, unsigned int flags,
                        int kind)
{
    char from[PATH_MAX], to[PATH_MAX];
    resolve();
    pthread_mutex_lock(&lock);
    int have = at_path(ofd, old, from) && at_path(nfd, new, to);
    int r;
    if (kind == 0)
        r = real_rename(old, new);
    else if (kind == 1)
        r = real_renameat(ofd, old, nfd, new);
    else
        r = real_renameat2(ofd, old, nfd, new, flags);
    int saved = errno;
    if (r == 0 && have)
        shadow_rename(from, to, flags);
    pthread_mutex_unlock(&lock);
    errno = saved;
    return r;
}

int rename(const char *old, const char *new)
{
    return do_renameat2(AT_FDCWD, old, AT_FDCWD, new, 0, 0);
}

int renameat(int ofd, const char *old, int nfd, const char *new)
{
    return do_renameat2(ofd, old, nfd, new, 0, 1);
}

int renameat2(int ofd, const char *old, int nfd, const char *new, unsigned int flags)
{
    return do_renameat2(ofd, old, nfd, new, flags, 2);
}

static int do_unlinkat(int dirfd, const char *path, int flags, int kind)
{
    char abs[PATH_MAX];
    resolve();
    pthread_mutex_lock(&lock);
    int have = at_path(dirfd, path, abs);
    int r;
    if (kind == 0)
        r = real_unlink(path);
    else if (kind == 1)
        r = real_unlinkat(dirfd, path, flags);
    else
        r = real_rmdir(path);
    int saved = errno;
    if (r == 0 && have)
        shadow_drop(abs);
    pthread_mutex_unlock(&lock);
    errno = saved;
    return r;
}

int unlink(const char *path)
{
    return do_unlinkat(AT_FDCWD, path, 0, 0);
}

int unlinkat(int dirfd, const char *path, int flags)
{
    return do_unlinkat(dirfd, path, flags, 1);
}

int rmdir(const char *path)
{
    return do_unlinkat(AT_FDCWD, path, 0, 2);
}
