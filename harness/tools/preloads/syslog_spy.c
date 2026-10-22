#include <stdarg.h>
#include <stdio.h>
#include <unistd.h>

void syslog(int prio, const char *fmt, ...)
{
    char buf[1024];
    va_list ap;
    int n;
    (void)prio;
    va_start(ap, fmt);
    n = vsnprintf(buf, sizeof(buf) - 2, fmt, ap);
    va_end(ap);
    if (n < 0) n = 0;
    if (n > (int)sizeof(buf) - 2) n = sizeof(buf) - 2;
    buf[n++] = '\n';
    write(2, "SYSLOG: ", 8);
    write(2, buf, n);
}
