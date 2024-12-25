// jailbreak.h from openpwnage

#ifndef jailbreak_h
#define jailbreak_h

#include <mach/mach.h>

#define TTB_SIZE            4096
#define L1_SECT_S_BIT       (1 << 16)
#define L1_SECT_PROTO       (1 << 1) /* 0b10 */
#define L1_SECT_AP_URW      (1 << 10) | (1 << 11)
#define L1_SECT_APX         (1 << 15)
#define L1_SECT_DEFPROT     (L1_SECT_AP_URW | L1_SECT_APX)
#define L1_SECT_SORDER      (0) /* 0b00, not cacheable, strongly ordered. */
#define L1_SECT_DEFCACHE    (L1_SECT_SORDER)
#define L1_PROTO_TTE(entry) (entry | L1_SECT_S_BIT | L1_SECT_DEFPROT | L1_SECT_DEFCACHE)

#define UNSLID_BASE 0x80001000
#define CHUNK_SIZE 0x800

bool unsandbox8(mach_port_t tfp0, uint32_t kernel_base, bool untether_on);
bool is_pmap_patch_success(task_t tfp0, uintptr_t kernel_base);
bool isA5orA5X(void);

extern NSString *system_machine;
extern NSString *system_version;
extern NSString *kernv;
extern bool install_openssh;
extern bool reinstall_strap;

#endif /* jailbreak_h */
