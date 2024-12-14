// jailbreak.h from openpwnage

#ifndef jailbreak_h
#define jailbreak_h

bool rootify(task_t tfp0, uintptr_t kernel_base);
bool unsandbox8(mach_port_t tfp0, uint32_t kernel_base);
bool is_pmap_patch_success(task_t tfp0, uintptr_t kernel_base);
void olog(char *format, ...);

#endif /* jailbreak_h */
