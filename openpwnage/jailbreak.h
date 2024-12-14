//
//  jailbreak.h
//  openpwnage
//
//  Created by Zachary Keffaber on 4/24/22.
//

#ifndef jailbreak_h
#define jailbreak_h

bool rootify(task_t tfp0, uintptr_t kernel_base, uintptr_t kaslr_slide);
bool unsandbox8(mach_port_t tfp0, uint32_t kernel_base, uint32_t kaslr_slide);
void patch_kernel_pmap(task_t tfp0, uintptr_t kernel_base);
bool is_pmap_patch_success(task_t tfp0, uintptr_t kernel_base, uintptr_t kaslr_slide);
void olog(char *format, ...);
void pmap_unpatch(task_t tfp0);
bool remount(void);
uint64_t find_da_allproc(uint64_t ourproc, mach_port_t tfp0);
void run_cmd(char *cmd, ...);
#endif /* jailbreak_h */
