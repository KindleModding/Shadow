/* Dump the guest stack on every stat64() of a path containing "ghost". */
#define _GNU_SOURCE
#include <stddef.h>
#include <dlfcn.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>

typedef int (*stat64_t)(const char *, void *);
static stat64_t real_stat64;
static int count;

int stat64(const char *path, void *buf)
{
    if (!real_stat64)
        real_stat64 = (stat64_t) dlsym(RTLD_NEXT, "stat64");

    if (path && strstr(path, "ghost")) {
        unsigned long sp, ra;
        char name[64];
        int fd;
        asm volatile ("mov %0, sp" : "=r" (sp));
        ra = (unsigned long) __builtin_return_address(0);
        snprintf(name, sizeof(name), "/tmp/opencode/stackdump.%03d.bin",
                 count++);
        fd = open(name, O_WRONLY | O_CREAT | O_TRUNC, 0644);
        if (fd >= 0) {
            unsigned long hdr[2] = { sp, ra };
            if (write(fd, hdr, sizeof(hdr)) < 0) {}
            if (write(fd, (void *) sp, 0x4000) < 0) {}
            close(fd);
        }
    }
    return real_stat64(path, buf);
}
