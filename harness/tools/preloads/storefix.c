/* Retarget guest store paths (/mnt/base-us, /mnt/us) to the qemu guestroot.
 *
 * qemu-user only applies -L to paths that already exist under the prefix (and
 * skips translation entirely for statx), so the daemon's store validation and
 * object creation hit the host /mnt/base-us and fail. This preload prefixes
 * store paths with $SD_STORE_PREFIX before the libc call; qemu's exists-fallback
 * then lands on the correct host path for both existing and new entries.
 *
 * Declarations are self-contained on purpose: the glibc headers redirect
 * stat64/lstat64/fstatat64 to __*_time64 names, which would prevent
 * interposing the versioned symbols the guest binary imports.
 *
 * Build: arm-linux-gnueabihf-gcc -shared -fPIC -O2 -o storefix.so storefix.c -ldl
 */
#define _GNU_SOURCE
#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <time.h>

static int is_store(const char *p)
{
	return p && p[0] == '/' &&
	       (strncmp(p, "/mnt/base-us", 12) == 0 || strncmp(p, "/mnt/us", 7) == 0);
}

static const char *fixed_path(char *buf, size_t bufsz, const char *path)
{
	const char *pfx = getenv("SD_STORE_PREFIX");
	if (!pfx || !is_store(path))
		return NULL;
	if (snprintf(buf, bufsz, "%s%s", pfx, path) >= (int)bufsz)
		return NULL;
	return buf;
}

#define CALL_FIX(path, fn, ...) do { \
	char fixed[PATH_MAX]; \
	if (fixed_path(fixed, sizeof(fixed), path)) { \
		int r = fn(fixed, ##__VA_ARGS__); \
		if (r == 0 || errno != ENOENT) \
			return r; \
	} \
	return fn(path, ##__VA_ARGS__); \
} while (0)

#define CALL_FIX_AT(dirfd, path, flags, fn, ...) do { \
	char fixed[PATH_MAX]; \
	if (fixed_path(fixed, sizeof(fixed), path)) { \
		int r = fn(dirfd, fixed, ##__VA_ARGS__); \
		if (r == 0 || errno != ENOENT) \
			return r; \
	} \
	return fn(dirfd, path, ##__VA_ARGS__); \
} while (0)

int stat64(const char *path, void *buf)
{
	static int (*real)(const char *, void *);
	if (!real)
		real = dlsym(RTLD_NEXT, "stat64");
	CALL_FIX(path, real, buf);
}

int lstat64(const char *path, void *buf)
{
	static int (*real)(const char *, void *);
	if (!real)
		real = dlsym(RTLD_NEXT, "lstat64");
	CALL_FIX(path, real, buf);
}

int stat(const char *path, void *buf)
{
	static int (*real)(const char *, void *);
	if (!real)
		real = dlsym(RTLD_NEXT, "stat");
	CALL_FIX(path, real, buf);
}

int lstat(const char *path, void *buf)
{
	static int (*real)(const char *, void *);
	if (!real)
		real = dlsym(RTLD_NEXT, "lstat");
	CALL_FIX(path, real, buf);
}

int fstatat64(int dirfd, const char *path, void *buf, int flags)
{
	static int (*real)(int, const char *, void *, int);
	if (!real)
		real = dlsym(RTLD_NEXT, "fstatat64");
	CALL_FIX_AT(dirfd, path, flags, real, buf, flags);
}

int fstatat(int dirfd, const char *path, void *buf, int flags)
{
	static int (*real)(int, const char *, void *, int);
	if (!real)
		real = dlsym(RTLD_NEXT, "fstatat");
	CALL_FIX_AT(dirfd, path, flags, real, buf, flags);
}

long readlink(const char *path, char *buf, unsigned long len)
{
	static long (*real)(const char *, char *, unsigned long);
	if (!real)
		real = dlsym(RTLD_NEXT, "readlink");
	char fixed[PATH_MAX];
	if (fixed_path(fixed, sizeof(fixed), path)) {
		long r = real(fixed, buf, len);
		if (r >= 0 || errno != ENOENT)
			return r;
	}
	return real(path, buf, len);
}

long readlinkat(int dirfd, const char *path, char *buf, unsigned long len)
{
	static long (*real)(int, const char *, char *, unsigned long);
	if (!real)
		real = dlsym(RTLD_NEXT, "readlinkat");
	char fixed[PATH_MAX];
	if (fixed_path(fixed, sizeof(fixed), path)) {
		long r = real(dirfd, fixed, buf, len);
		if (r >= 0 || errno != ENOENT)
			return r;
	}
	return real(dirfd, path, buf, len);
}

int open(const char *path, int flags, ...){
	static int (*real)(const char *, int, ...);
	mode_t mode = 0;
	if (!real)
		real = dlsym(RTLD_NEXT, "open");
	if (flags & O_CREAT) {
		va_list ap;
		va_start(ap, flags);
		mode = va_arg(ap, mode_t);
		va_end(ap);
	}
	char fixed[PATH_MAX];
	if (fixed_path(fixed, sizeof(fixed), path)) {
		int r = real(fixed, flags, mode);
		if (r >= 0 || errno != ENOENT)
			return r;
	}
	return real(path, flags, mode);
}

int openat(int dirfd, const char *path, int flags, ...)
{
	static int (*real)(int, const char *, int, ...);
	mode_t mode = 0;
	if (!real)
		real = dlsym(RTLD_NEXT, "openat");
	if (flags & O_CREAT) {
		va_list ap;
		va_start(ap, flags);
		mode = va_arg(ap, mode_t);
		va_end(ap);
	}
	char fixed[PATH_MAX];
	if (fixed_path(fixed, sizeof(fixed), path)) {
		int r = real(dirfd, fixed, flags, mode);
		if (r >= 0 || errno != ENOENT)
			return r;
	}
	return real(dirfd, path, flags, mode);
}

int mkdir(const char *path, mode_t mode)
{
	static int (*real)(const char *, mode_t);
	if (!real)
		real = dlsym(RTLD_NEXT, "mkdir");
	CALL_FIX(path, real, mode);
}

int mkdirat(int dirfd, const char *path, mode_t mode)
{
	static int (*real)(int, const char *, mode_t);
	if (!real)
		real = dlsym(RTLD_NEXT, "mkdirat");
	CALL_FIX_AT(dirfd, path, mode, real, mode);
}

int rmdir(const char *path)
{
	static int (*real)(const char *);
	if (!real)
		real = dlsym(RTLD_NEXT, "rmdir");
	CALL_FIX(path, real);
}

int unlink(const char *path)
{
	static int (*real)(const char *);
	if (!real)
		real = dlsym(RTLD_NEXT, "unlink");
	CALL_FIX(path, real);
}

int unlinkat(int dirfd, const char *path, int flags)
{
	static int (*real)(int, const char *, int);
	if (!real)
		real = dlsym(RTLD_NEXT, "unlinkat");
	CALL_FIX_AT(dirfd, path, flags, real, flags);
}

int rename(const char *oldp, const char *newp)
{
	static int (*real)(const char *, const char *);
	if (!real)
		real = dlsym(RTLD_NEXT, "rename");
	char fixedOld[PATH_MAX], fixedNew[PATH_MAX];
	const char *of = fixed_path(fixedOld, sizeof(fixedOld), oldp);
	const char *nf = fixed_path(fixedNew, sizeof(fixedNew), newp);
	return real(of ? of : oldp, nf ? nf : newp);
}

int renameat(int olddirfd, const char *oldp, int newdirfd, const char *newp)
{
	static int (*real)(int, const char *, int, const char *);
	if (!real)
		real = dlsym(RTLD_NEXT, "renameat");
	char fixedOld[PATH_MAX], fixedNew[PATH_MAX];
	const char *of = fixed_path(fixedOld, sizeof(fixedOld), oldp);
	const char *nf = fixed_path(fixedNew, sizeof(fixedNew), newp);
	return real(olddirfd, of ? of : oldp, newdirfd, nf ? nf : newp);
}

int symlink(const char *target, const char *linkpath)
{
	static int (*real)(const char *, const char *);
	if (!real)
		real = dlsym(RTLD_NEXT, "symlink");
	char fixed[PATH_MAX];
	const char *lf = fixed_path(fixed, sizeof(fixed), linkpath);
	return real(target, lf ? lf : linkpath);
}

int link(const char *oldp, const char *newp)
{
	static int (*real)(const char *, const char *);
	if (!real)
		real = dlsym(RTLD_NEXT, "link");
	char fixed[PATH_MAX];
	const char *nf = fixed_path(fixed, sizeof(fixed), newp);
	return real(oldp, nf ? nf : newp);
}

int chmod(const char *path, mode_t mode)
{
	static int (*real)(const char *, mode_t);
	if (!real)
		real = dlsym(RTLD_NEXT, "chmod");
	CALL_FIX(path, real, mode);
}

int truncate(const char *path, off_t length)
{
	static int (*real)(const char *, off_t);
	if (!real)
		real = dlsym(RTLD_NEXT, "truncate");
	CALL_FIX(path, real, length);
}

int utimensat(int dirfd, const char *path, const struct timespec times[2], int flags)
{
	static int (*real)(int, const char *, const struct timespec[2], int);
	if (!real)
		real = dlsym(RTLD_NEXT, "utimensat");
	CALL_FIX_AT(dirfd, path, times, real, times, flags);
}
