/* glib slice allocator spy: log 32..56 byte slice allocs/frees with the first
 * 44 bytes of content (same M/F/D line format as malloc_spy).
 * Build: arm-linux-gnueabihf-gcc -shared -fPIC -O2 -o slice_spy.so slice_spy.c -ldl
 */
#define _GNU_SOURCE
#include <dlfcn.h>

typedef unsigned int u32;
typedef unsigned long uptr;
typedef void *(*slice_alloc_t)(uptr);
typedef void (*slice_free_t)(uptr, void *);

extern long write(int, const void *, unsigned long);

static slice_alloc_t real_alloc;
static slice_free_t real_free1;
static int inhook;

static void puthex(uptr v, char *o, int *i)
{
	static const char d[] = "0123456789abcdef";
	int s;
	for (s = 28; s >= 0; s -= 4)
		o[(*i)++] = d[(v >> s) & 0xf];
}

static void logln(char tag, void *p, u32 n, void *caller)
{
	char b[64];
	int i = 0;
	b[i++] = tag;
	b[i++] = ' ';
	puthex((uptr)p, b, &i);
	b[i++] = ' ';
	b[i++] = 'n';
	b[i++] = '=';
	puthex(n, b, &i);
	b[i++] = ' ';
	b[i++] = '@';
	puthex((uptr)caller, b, &i);
	b[i++] = '\n';
	(void)!write(2, b, i);
}

static void dumpline(void *p)
{
	static const char d[] = "0123456789abcdef";
	char b[128];
	unsigned char *q = (unsigned char *)p;
	int i = 0, k;
	b[i++] = 'D';
	b[i++] = ' ';
	for (k = 0; k < 44; k++) {
		b[i++] = d[q[k] >> 4];
		b[i++] = d[q[k] & 0xf];
	}
	b[i++] = '\n';
	(void)!write(2, b, i);
}

void *g_slice_alloc(uptr n)
{
	void *c = __builtin_return_address(0);
	void *p;

	if (real_alloc == 0)
		real_alloc = (slice_alloc_t)dlsym(RTLD_NEXT, "g_slice_alloc");
	p = real_alloc(n);
	if (!inhook && n >= 32 && n <= 56 && p) {
		inhook = 1;
		logln('M', p, (u32)n, c);
		dumpline(p);
		inhook = 0;
	}
	return p;
}

void *g_slice_alloc0(uptr n)
{
	void *c = __builtin_return_address(0);
	void *p;
	void *(*f)(uptr) = (void *(*)(uptr))dlsym(RTLD_NEXT, "g_slice_alloc0");

	p = f(n);
	if (!inhook && n >= 32 && n <= 56 && p) {
		inhook = 1;
		logln('C', p, (u32)n, c);
		dumpline(p);
		inhook = 0;
	}
	return p;
}

void g_slice_free1(uptr n, void *p)
{
	void *c = __builtin_return_address(0);

	if (real_free1 == 0)
		real_free1 = (slice_free_t)dlsym(RTLD_NEXT, "g_slice_free1");
	if (!inhook && n >= 32 && n <= 56 && p) {
		inhook = 1;
		logln('F', p, (u32)n, c);
		dumpline(p);
		inhook = 0;
	}
	real_free1(n, p);
}
