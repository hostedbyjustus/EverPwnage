#ifndef patchfinder8_h
#define patchfinder8_h

#include <stdint.h>
#include <string.h>

uint32_t find_mount8(uint32_t region, uint8_t* kdata, size_t ksize);
uint32_t find_cs_enforcement_disable_amfi8(uint32_t region, uint8_t* kdata, size_t ksize);
uint32_t find_sandbox_call_i_can_has_debugger8(uint32_t region, uint8_t* kdata, size_t ksize);
uint32_t find_vn_getpath8(uint32_t region, uint8_t* kdata, size_t ksize);
uint32_t find_memcmp8(uint32_t region, uint8_t* kdata, size_t ksize);
uint32_t find_sb_patch8(uint32_t region, uint8_t* kdata, size_t ksize);
uint32_t find_p_bootargs8(uint32_t region, uint8_t* kdata, size_t ksize);
uint32_t find_sbops(uint32_t region, uint8_t* kdata, size_t ksize);
uint32_t find_proc_enforce8(uint32_t region, uint8_t* kdata, size_t ksize);
uint32_t find_mapForIO(uint32_t region, uint8_t* kdata, size_t ksize);
uint32_t find_vm_map_enter_patch8(uint32_t region, uint8_t* kdata, size_t ksize);
uint32_t find_csops8(uint32_t region, uint8_t* kdata, size_t ksize);
uint32_t find_csops2(uint32_t region, uint8_t* kdata, size_t ksize);
uint32_t find_vm_map_protect_patch8(uint32_t region, uint8_t* kdata, size_t ksize);
uint32_t find_tfp0_patch(uint32_t region, uint8_t* kdata, size_t ksize);
uint32_t find_vm_fault_enter_patch_84(uint32_t region, uint8_t* kdata, size_t ksize);
uint32_t find_i_can_has_debugger_1(uint32_t region, uint8_t* kdata, size_t ksize);
uint32_t find_i_can_has_debugger_2(uint32_t region, uint8_t* kdata, size_t ksize);
#endif /* patchfinder8_h */
