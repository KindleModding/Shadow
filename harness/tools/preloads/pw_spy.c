#include <sys/types.h>
#include <pwd.h>

struct passwd *getpwuid(uid_t uid)
{
    static struct passwd pw;
    static char name[] = "droid";
    pw.pw_name = name;
    pw.pw_uid = uid;
    pw.pw_gid = uid;
    pw.pw_dir = name;
    pw.pw_shell = (char *)"/bin/sh";
    return &pw;
}
