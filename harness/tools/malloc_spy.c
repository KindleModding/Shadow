/* malloc/free interposer for the ARM harness (kindle libc 2.35).
 *
 * Logs 32..56 byte allocations and frees of 0x30 chunks, with the caller
 * address, via write(2) (no malloc recursion).
 *
 * Build:
 *   arm-linux-gnueabihf-gcc -shared -fPIC -O2 -o malloc_spy.so malloc_spy.c
 * Run:
 *   LD_PRELOAD=<abs path>/malloc_spy.so ...
 */
typedef unsigned int u32;
typedef unsigned long uptr;

extern long write(int, const void *, unsigned long);

extern void *__libc_malloc(unsigned int);
extern void *__libc_calloc(unsigned int, unsigned int);
extern void *__libc_realloc(void *, unsigned int);
extern void __libc_free(void *);
extern void *__libc_memalign(unsigned int, unsigned int);

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

void *malloc(unsigned int n)
{
	void *c = __builtin_return_address(0);
	void *p;

	if (!inhook && n >= 32 && n <= 56) {
		inhook = 1;
		logln('Q', 0, n, c);
		inhook = 0;
	}
	p = __libc_malloc(n);

	if (!inhook && n >= 32 && n <= 56) {
		inhook = 1;
		logln('M', p, n, c);
		if (p)
			dumpline(p);
		inhook = 0;
	}
	return p;
}

void *calloc(unsigned int a, unsigned int b)
{
	void *c = __builtin_return_address(0);
	void *p = __libc_calloc(a, b);

	if (!inhook && p != 0 && a * b >= 32 && a * b <= 56) {
		inhook = 1;
		logln('C', p, a * b, c);
		inhook = 0;
	}
	return p;
}

void *realloc(void *q, unsigned int n)
{
	void *c = __builtin_return_address(0);
	void *p = __libc_realloc(q, n);

	if (!inhook && n >= 32 && n <= 56) {
		inhook = 1;
		logln('R', p, n, c);
		inhook = 0;
	}
	return p;
}

void free(void *p)
{
	void *c = __builtin_return_address(0);

	if (!inhook && p != 0) {
		u32 sz = *(u32 *)((char *)p - 4) & ~7u;
		if (sz == 0x30) {
			inhook = 1;
			logln('F', p, sz, c);
			dumpline(p);
			inhook = 0;
		}
	}
	__libc_free(p);
}
