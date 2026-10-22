/* Bridge preload: run the daemon with the REAL libmtp-helper while stubbing
 * only the entry points that need the device's IPC/gadget services.
 * Build: arm-linux-gnueabihf-gcc -shared -fPIC -O2 -o bridge.so bridge.c -ldl
 */
#define _GNU_SOURCE
#include <dlfcn.h>

int mtp_responder_init(void)
{
	int (*f)(void) = (int (*)(void))dlsym(RTLD_NEXT, "mtp_responder_init");
	if (f)
		f();
	return 0;   /* pretend success even if IPC init failed */
}

void init_mtp_gadget(void) { }
void disable_mtp_gadget(void) { }
void mtp_responder_cleanup(void) { }
int register_communication_endpoint(void *p) { (void)p; return 0; }

int should_process_event(void *a)
{
	int (*f)(void *) = (int (*)(void *))dlsym(RTLD_NEXT,
						  "should_process_event");
	if (f)
		return f(a);
	return 1;
}
