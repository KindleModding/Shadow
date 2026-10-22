/* Minimal libmtp-helper.so.1.0 stub so the real tizen-mtp runs under qemu.
 * Semantics chosen from the call sites in the decomp:
 *  - mtp_responder_init() == 0 means success
 *  - *_name/serial write into caller buffers and return success (0 => caller
 *    falls back to constants)
 *  - filters/hooks are no-ops returning 0
 */
int debug_logs_enabled = 1;

int mtp_responder_init(void) { return 0; }
void init_mtp_gadget(void) {}
void mtp_responder_cleanup(void) {}
int register_communication_endpoint(void *p) { (void)p; return 0; }

int get_device_name(void *buf) { (void)buf; return 0; }
int get_device_serial_number(void *buf) { (void)buf; return 0; }
int get_hidden_folders_count(void) { return 0; }

int is_extension_blocked(void *a) { (void)a; return 0; }
int should_hide_folder(void *a) { (void)a; return 0; }
int should_process_event(void *a) { (void)a; return 1; }
int handle_state_change_event(void *a) { (void)a; return 0; }

void disable_mtp_gadget(void) {}
void record_encrypted_folder_operation(void) {}
void record_file_operation_failure(void) {}
void record_file_transfer_count(void) {}
void record_successful_file_enumeration_time(void) {}
void record_transferred_file_extension(void) {}
void record_usb_plugin(void) {}
