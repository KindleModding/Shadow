/* qemu-user -L does not prefix statx(); return ENOSYS so glibc falls back to
 * the legacy fstatat64/stat64 syscalls which qemu does translate. */
#include <errno.h>

struct statx;

int statx(int dirfd, const char *path, int flags, unsigned int mask,
          struct statx *buf)
{
    (void)dirfd; (void)path; (void)flags; (void)mask; (void)buf;
    errno = 38; /* ENOSYS */
    return -1;
}
