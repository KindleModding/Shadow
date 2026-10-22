/* In-process replacement for the gdb event injection.
 *
 * Hooks g_main_loop_run (the point where the daemon is fully initialised and
 * about to enter the loop), computes the main executable's base with
 * dl_iterate_phdr, and calls the daemon's event-writer FUN_000289d4(14,0,0,0)
 * - exactly what the gdb script did - then runs the real loop.
 *
 * Build: arm-linux-gnueabihf-gcc -shared -fPIC -O2 -o inject.so inject.c -ldl
 */
#define _GNU_SOURCE
#include <dlfcn.h>
#include <link.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
static uintptr_t main_base;
static int injected;

static uintptr_t parse_hex(const char *s)
{
	uintptr_t v = 0;
	if (s[0] == '0' && (s[1] == 'x' || s[1] == 'X'))
		s += 2;
	for (; *s; s++) {
		unsigned d;
		if (*s >= '0' && *s <= '9')
			d = *s - '0';
		else if (*s >= 'a' && *s <= 'f')
			d = *s - 'a' + 10;
		else if (*s >= 'A' && *s <= 'F')
			d = *s - 'A' + 10;
		else
			break;
		v = (v << 4) | d;
	}
	return v;
}

static uintptr_t inject_off(void)
{
	const char *env = getenv("MTP_INJECT_OFF");
	if (env && env[0])
		return parse_hex(env);
	return 0x189d4;
}

static int phdr_cb(struct dl_phdr_info *info, size_t size, void *data)
{
	(void)size;
	(void)data;
	if (!info->dlpi_name || info->dlpi_name[0] == '\0') {
		if (!main_base)
			main_base = info->dlpi_addr;
		return 0;
	}
	if (strstr(info->dlpi_name, "tizen-mtp")) {
		main_base = info->dlpi_addr;
		return 1;
	}
	return 0;
}

void g_main_loop_run(void *loop)
{
	static void (*real_run)(void *) = NULL;
	if (real_run == NULL)
		real_run = (void (*)(void *))dlsym(RTLD_NEXT, "g_main_loop_run");

	if (!injected) {
		injected = 1;
		if (!main_base)
			dl_iterate_phdr(phdr_cb, NULL);
		if (main_base) {
			void (*inject_event)(int, int, int, int) =
				(void (*)(int, int, int, int))
				((main_base + inject_off()) | 1);
			inject_event(14, 0, 0, 0);
		}
	}
	if (real_run)
		real_run(loop);
}
