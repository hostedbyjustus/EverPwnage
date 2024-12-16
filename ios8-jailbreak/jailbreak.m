// jailbreak.m from openpwnage

#import <Foundation/Foundation.h>
#include <mach/mach.h>
#include <sys/types.h>
#include <sys/utsname.h>
#include <UIKit/UIKit.h>
#include <sys/mount.h>
#include <spawn.h>
#include <sys/sysctl.h>
#include <sys/stat.h>
#include <copyfile.h>

#include "jailbreak.h"
#include "mac_policy_ops.h"

#import "ViewController.h"

#define UNSLID_BASE 0x80001000

void olog(char *format, ...) {
    char msg[1000];
    va_list aptr;

    va_start(aptr, format);
    vsprintf(msg, format, aptr);
    va_end(aptr);
    printf("%s",msg);
}

bool isA5orA5X(void) {
    struct utsname systemInfo;
    uname(&systemInfo);
    NSArray *A5orA5X = [NSArray arrayWithObjects:@"iPad2,1",@"iPad2,2",@"iPad2,3",@"iPad2,4",@"iPad2,5",@"iPad2,6",@"iPad2,7",@"iPad3,1",@"iPad3,2",@"iPad3,3",@"iPhone4,1",@"iPod5,1", nil];
    if([A5orA5X containsObject:[NSString stringWithCString:systemInfo.machine encoding:NSUTF8StringEncoding]]) {
        return true;
    }
    return false;
}

NSString *KernelVersion(void) {
    olog("%s\n", newkernv);
    return [NSString stringWithUTF8String:newkernv];
}

uint32_t kread_uint32(uint32_t addr, task_t tfp0) {
    vm_size_t bytesRead=0;
    uint32_t ret = 0;
    vm_read_overwrite(tfp0,addr,4,(vm_address_t)&ret,&bytesRead);
    return ret;
}

void kwrite_uint32(uint32_t addr, uint32_t value, task_t tfp0) {
    vm_write(tfp0,addr,(vm_offset_t)&value,4);
}

void kwrite_uint8(uint32_t addr, uint8_t value, task_t tfp0) {
    vm_write(tfp0,addr,(vm_offset_t)&value,1);
}

uint32_t find_kernel_pmap(uintptr_t kernel_base) {
    uint32_t pmap_addr;
    if(isA5orA5X()) {
        //A5 or A5X
        if ([[NSArray arrayWithObjects:@"2783.5.38~5", nil] containsObject:KernelVersion()]){ //8.2
            pmap_addr = 0x39411c;
        } else if ([[NSArray arrayWithObjects:@"2783.5.26~3", nil] containsObject:KernelVersion()]){ //8.1.3
            pmap_addr = 0x39211c;
        } else if ([[NSArray arrayWithObjects:@"2783.3.22~1",@"2783.3.13~4",@"2783.1.72~23",@"2783.1.72~8", nil] containsObject:KernelVersion()]){ //8.0-8.1.2
            pmap_addr = 0x39111c;
        } else { //8.3-8.4.1
            pmap_addr = 0x3a211c;
        }
    } else {
        //A6 or A6X
        if ([[NSArray arrayWithObjects:@"2783.5.38~5", nil] containsObject:KernelVersion()]){ //8.2
            pmap_addr = 0x39a11c; //for A5. For A6 offset is 0x003F6444
        } else if ([[NSArray arrayWithObjects:@"2783.5.26~3",@"2783.3.22~1",@"2783.3.13~4",@"2783.1.72~23",@"2783.1.72~8", nil] containsObject:KernelVersion()]){ //8.0-8.1.2
            pmap_addr = 0x39711c;
        } else { //8.3-8.4.1
            pmap_addr = 0x3a711c;
        }
    }
    olog("using offset 0x%08x for pmap\n",pmap_addr);
    return pmap_addr + kernel_base;
}

#define TTB_SIZE            4096
#define L1_SECT_S_BIT       (1 << 16)
#define L1_SECT_PROTO       (1 << 1) /* 0b10 */
#define L1_SECT_AP_URW      (1 << 10) | (1 << 11)
#define L1_SECT_APX         (1 << 15)
#define L1_SECT_DEFPROT     (L1_SECT_AP_URW | L1_SECT_APX)
#define L1_SECT_SORDER      (0) /* 0b00, not cacheable, strongly ordered. */
#define L1_SECT_DEFCACHE    (L1_SECT_SORDER)
#define L1_PROTO_TTE(entry) (entry | L1_SECT_S_BIT | L1_SECT_DEFPROT | L1_SECT_DEFCACHE)

uint32_t pmaps[TTB_SIZE];
int pmapscnt = 0;

void patch_kernel_pmap(task_t tfp0, uintptr_t kernel_base) {
    uint32_t kernel_pmap        = find_kernel_pmap(kernel_base);
    uint32_t kernel_pmap_store    = kread_uint32(kernel_pmap,tfp0);
    uint32_t tte_virt            = kread_uint32(kernel_pmap_store,tfp0);
    uint32_t tte_phys            = kread_uint32(kernel_pmap_store+4,tfp0);

    olog("kernel pmap store @ 0x%08x\n",
            kernel_pmap_store);
    olog("kernel pmap tte is at VA 0x%08x PA 0x%08x\n",
            tte_virt,
            tte_phys);

    /*
     *  every page is writable
     */
    uint32_t i;
    for (i = 0; i < TTB_SIZE; i++) {
        uint32_t addr   = tte_virt + (i << 2);
        uint32_t entry  = kread_uint32(addr,tfp0);
        if (entry == 0) continue;
        if ((entry & 0x3) == 1) {
            /*
             *  if the 2 lsb are 1 that means there is a second level
             *  pagetable that we need to give readwrite access to.
             *  zero bytes 0-10 to get the pagetable address
             */
            uint32_t second_level_page_addr = (entry & (~0x3ff)) - tte_phys + tte_virt;
            for (int i = 0; i < 256; i++) {
                /*
                 *  second level pagetable has 256 entries, we need to patch all
                 *  of them
                 */
                uint32_t sladdr  = second_level_page_addr+(i<<2);
                uint32_t slentry = kread_uint32(sladdr,tfp0);

                if (slentry == 0)
                    continue;

                /*
                 *  set the 9th bit to zero
                 */
                uint32_t new_entry = slentry & (~0x200);
                if (slentry != new_entry) {
                    kwrite_uint32(sladdr, new_entry,tfp0);
                    pmaps[pmapscnt++] = sladdr;
                }
            }
            continue;
        }

        if ((entry & L1_SECT_PROTO) == 2) {
            uint32_t new_entry  =  L1_PROTO_TTE(entry);
            new_entry           &= ~L1_SECT_APX;
            kwrite_uint32(addr, new_entry,tfp0);
        }
    }

    olog("every page is actually writable\n");
    usleep(100000);
}

bool is_pmap_patch_success(task_t tfp0, uintptr_t kernel_base) {
    patch_kernel_pmap(tfp0, kernel_base);

    uint32_t before = -1;
    uint32_t after = -1;

    olog("check pmap patch\n");

    before = kread_uint32(kernel_base, tfp0);
    kwrite_uint32(kernel_base, 0x41414141, tfp0);
    after = kread_uint32(kernel_base, tfp0);
    kwrite_uint32(kernel_base, before, tfp0);

    if ((before != after) && (after == 0x41414141)) {
        olog("pmap patched!\n");
    } else {
        olog("pmap patch failed\n");
        return false;
    }
    return true;
}

#include "patchfinder8.h"

extern char **environ;

void run_cmd(char *cmd, ...) {
    pid_t pid;
    va_list ap;
    char* cmd_ = NULL;

    va_start(ap, cmd);
    vasprintf(&cmd_, cmd, ap);

    char *argv[] = {"sh", "-c", cmd_, NULL};

    int status;
    olog("Run command: %s\n", cmd_);
    status = posix_spawn(&pid, "/bin/sh", NULL, NULL, argv, environ);
    if (status == 0) {
        olog("Child pid: %i\n", pid);
        do {
            if (waitpid(pid, &status, 0) != -1) {
                olog("Child status %d\n", WEXITSTATUS(status));
            } else {
                perror("waitpid");
            }
        } while (!WIFEXITED(status) && !WIFSIGNALED(status));
    } else {
        olog("posix_spawn: %s\n", strerror(status));
    }
}

void run_tar(char *cmd, ...) {
    pid_t pid;
    va_list ap;
    char* cmd_ = NULL;

    va_start(ap, cmd);
    vasprintf(&cmd_, cmd, ap);

    char *argv[] = {"/bin/tar", "-xf", cmd_, "-C", "/", "--preserve-permissions", NULL};

    int status;
    olog("Run command: %s\n", cmd_);
    status = posix_spawn(&pid, "/bin/tar", NULL, NULL, argv, environ);
    if (status == 0) {
        olog("Child pid: %i\n", pid);
        do {
            if (waitpid(pid, &status, 0) != -1) {
                olog("Child status %d\n", WEXITSTATUS(status));
            } else {
                perror("waitpid");
            }
        } while (!WIFEXITED(status) && !WIFSIGNALED(status));
    } else {
        olog("posix_spawn: %s\n", strerror(status));
    }
}

#define CHUNK_SIZE 0x800

void dump_kernel_8(mach_port_t tfp0, vm_address_t kernel_base, uint8_t *dest, size_t ksize) {
    for (vm_address_t addr = kernel_base, e = 0; addr < kernel_base + ksize; addr += CHUNK_SIZE, e += CHUNK_SIZE) {
        pointer_t buf = 0;
        vm_address_t sz = 0;
        vm_read(tfp0, addr, CHUNK_SIZE, &buf, &sz);
        if (buf == 0 || sz == 0)
            continue;
        bcopy((uint8_t *)buf, dest + e, CHUNK_SIZE);
    }
}

bool unsandbox8(mach_port_t tfp0, uint32_t kernel_base, bool untether_on) {
    olog("unsandboxing...\n");
    
    uint8_t* kdata = NULL;
    size_t ksize = 0xFFE000;
    kdata = malloc(ksize);
    dump_kernel_8(tfp0, kernel_base, kdata, ksize);
    if (!kdata) {
        olog("fuck\n");
        exit(1);
    }
    olog("now...\n");
    
    uint32_t sbopsoffset = find_sbops(kernel_base, kdata, ksize);

    olog("nuking sandbox at 0x%08lx\n", kernel_base + sbopsoffset);
    kwrite_uint32(kernel_base + sbopsoffset + offsetof(struct mac_policy_ops, mpo_vnode_check_ioctl), 0,tfp0);
    kwrite_uint32(kernel_base + sbopsoffset + offsetof(struct mac_policy_ops, mpo_vnode_check_access), 0,tfp0);
    kwrite_uint32(kernel_base + sbopsoffset + offsetof(struct mac_policy_ops, mpo_vnode_check_create), 0,tfp0);
    kwrite_uint32(kernel_base + sbopsoffset + offsetof(struct mac_policy_ops, mpo_vnode_check_chroot), 0,tfp0);
    kwrite_uint32(kernel_base + sbopsoffset + offsetof(struct mac_policy_ops, mpo_vnode_check_exchangedata), 0,tfp0);
    kwrite_uint32(kernel_base + sbopsoffset + offsetof(struct mac_policy_ops, mpo_vnode_check_deleteextattr), 0,tfp0);
    kwrite_uint32(kernel_base + sbopsoffset + offsetof(struct mac_policy_ops, mpo_vnode_notify_create), 0,tfp0);
    kwrite_uint32(kernel_base + sbopsoffset + offsetof(struct mac_policy_ops, mpo_vnode_check_listextattr), 0,tfp0);
    kwrite_uint32(kernel_base + sbopsoffset + offsetof(struct mac_policy_ops, mpo_vnode_check_open), 0,tfp0);
    kwrite_uint32(kernel_base + sbopsoffset + offsetof(struct mac_policy_ops, mpo_vnode_check_setattrlist), 0,tfp0);
    kwrite_uint32(kernel_base + sbopsoffset + offsetof(struct mac_policy_ops, mpo_vnode_check_link), 0,tfp0);
    kwrite_uint32(kernel_base + sbopsoffset + offsetof(struct mac_policy_ops, mpo_vnode_check_exec), 0,tfp0);
    kwrite_uint32(kernel_base + sbopsoffset + offsetof(struct mac_policy_ops, mpo_vnode_check_stat), 0,tfp0);
    kwrite_uint32(kernel_base + sbopsoffset + offsetof(struct mac_policy_ops, mpo_vnode_check_unlink), 0,tfp0);
    kwrite_uint32(kernel_base + sbopsoffset + offsetof(struct mac_policy_ops, mpo_vnode_check_getattrlist), 0,tfp0);
    kwrite_uint32(kernel_base + sbopsoffset + offsetof(struct mac_policy_ops, mpo_vnode_check_getextattr), 0,tfp0);
    kwrite_uint32(kernel_base + sbopsoffset + offsetof(struct mac_policy_ops, mpo_vnode_check_rename), 0,tfp0);
    kwrite_uint32(kernel_base + sbopsoffset + offsetof(struct mac_policy_ops, mpo_file_check_mmap), 0,tfp0);
    kwrite_uint32(kernel_base + sbopsoffset + offsetof(struct mac_policy_ops, mpo_cred_label_update_execve), 0,tfp0);
    kwrite_uint32(kernel_base + sbopsoffset + offsetof(struct mac_policy_ops, mpo_mount_check_stat), 0,tfp0);
    kwrite_uint32(kernel_base + sbopsoffset + offsetof(struct mac_policy_ops, mpo_proc_check_fork), 0,tfp0);
    kwrite_uint32(kernel_base + sbopsoffset + offsetof(struct mac_policy_ops, mpo_vnode_check_readlink), 0,tfp0);
    kwrite_uint32(kernel_base + sbopsoffset + offsetof(struct mac_policy_ops, mpo_vnode_check_setutimes), 0,tfp0);
    kwrite_uint32(kernel_base + sbopsoffset + offsetof(struct mac_policy_ops, mpo_vnode_check_setextattr), 0,tfp0);
    kwrite_uint32(kernel_base + sbopsoffset + offsetof(struct mac_policy_ops, mpo_vnode_check_setflags), 0,tfp0);
    kwrite_uint32(kernel_base + sbopsoffset + offsetof(struct mac_policy_ops, mpo_vnode_check_fsgetpath), 0,tfp0);
    kwrite_uint32(kernel_base + sbopsoffset + offsetof(struct mac_policy_ops, mpo_vnode_check_setmode), 0,tfp0);
    kwrite_uint32(kernel_base + sbopsoffset + offsetof(struct mac_policy_ops, mpo_vnode_check_setowner), 0,tfp0);
    kwrite_uint32(kernel_base + sbopsoffset + offsetof(struct mac_policy_ops, mpo_vnode_check_setutimes), 0,tfp0);
    kwrite_uint32(kernel_base + sbopsoffset + offsetof(struct mac_policy_ops, mpo_vnode_check_truncate), 0,tfp0);
    kwrite_uint32(kernel_base + sbopsoffset + offsetof(struct mac_policy_ops, mpo_vnode_check_getattr), 0,tfp0);
    kwrite_uint32(kernel_base + sbopsoffset + offsetof(struct mac_policy_ops, mpo_iokit_check_get_property), 0,tfp0);
    olog("nuked sandbox\n");
    olog("let's go for code exec...\n");
    
    uint32_t tfp0_patch = find_tfp0_patch(kernel_base, kdata, ksize);
    uint32_t proc_enforce8 = find_proc_enforce8(kernel_base, kdata, ksize);
    uint32_t cs_enforcement_disable_amfi = find_cs_enforcement_disable_amfi8(kernel_base, kdata, ksize);
    uint32_t PE_i_can_has_debugger_1 = find_i_can_has_debugger_1(kernel_base, kdata, ksize);
    uint32_t PE_i_can_has_debugger_2 = find_i_can_has_debugger_2(kernel_base, kdata, ksize);
    uint32_t vm_fault_enter = find_vm_fault_enter_patch_84(kernel_base, kdata, ksize);
    uint32_t vm_map_enter8 = find_vm_map_enter_patch8(kernel_base, kdata, ksize);
    uint32_t vm_map_protect8 = find_vm_map_protect_patch8(kernel_base, kdata, ksize);
    uint32_t mount_common = find_mount8(kernel_base, kdata, ksize);
    uint32_t mapForIO = find_mapForIO(kernel_base, kdata, ksize);
    uint32_t sandbox_call_i_can_has_debugger = find_sandbox_call_i_can_has_debugger8(kernel_base, kdata, ksize);
    uint32_t csops8 = find_csops8(kernel_base, kdata, ksize);
    uint32_t csops2 = find_csops2(kernel_base, kdata, ksize);

    olog("patching tfp0 at 0x%08x\n", kernel_base + tfp0_patch);
    kwrite_uint32(kernel_base + tfp0_patch, 0xbf00bf00, tfp0);

    olog("patching proc_enforce at 0x%08x\n", kernel_base + proc_enforce8);
    kwrite_uint8(kernel_base + proc_enforce8, 0, tfp0);
    
    olog("patching cs_enforcement_disable_amfi at 0x%08x\n", kernel_base + cs_enforcement_disable_amfi - 1);
    kwrite_uint8(kernel_base + cs_enforcement_disable_amfi, 1, tfp0);
    kwrite_uint8(kernel_base + cs_enforcement_disable_amfi - 4, 1, tfp0);
    
    olog("patching PE_i_can_has_debugger_1 at 0x%08x\n",PE_i_can_has_debugger_1);
    kwrite_uint32(kernel_base + PE_i_can_has_debugger_1, 1, tfp0);
    
    olog("patching PE_i_can_has_debugger_2 at 0x%08x\n",PE_i_can_has_debugger_2);
    kwrite_uint32(kernel_base + PE_i_can_has_debugger_2, 1, tfp0);

    olog("patching vm_fault_enter at 0x%08x\n", kernel_base + vm_fault_enter);
    kwrite_uint32(kernel_base + vm_fault_enter, 0x2201bf00, tfp0);

    olog("patching vm_map_enter at 0x%08x\n", kernel_base + vm_map_enter8);
    kwrite_uint32(kernel_base + vm_map_enter8, 0x4280bf00, tfp0);

    olog("patching vm_map_protect at 0x%08x\n", kernel_base + vm_map_protect8);
    kwrite_uint32(kernel_base + vm_map_protect8, 0xbf00bf00, tfp0);

    olog("patching mount at 0x%08x\n", kernel_base + mount_common);
    kwrite_uint8(kernel_base + mount_common + 1, 0xe0, tfp0);
    
    olog("patching mapForIO at 0x%08x\n", kernel_base + mapForIO);
    kwrite_uint32(kernel_base + mapForIO, 0xbf00bf00,tfp0);

    olog("patching csops at 0x%08x\n", kernel_base + csops8);
    kwrite_uint32(kernel_base + csops8, 0xbf00bf00, tfp0);

    olog("patching csops2 at 0x%08x\n", kernel_base + csops2);
    kwrite_uint8(kernel_base + csops2, 0x20, tfp0);
    
    olog("patching sandbox_call_i_can_has_debugger at 0x%08x\n", kernel_base + sandbox_call_i_can_has_debugger);
    kwrite_uint32(kernel_base + sandbox_call_i_can_has_debugger, 0xbf00bf00, tfp0);

    olog("[*] remounting rootfs\n");
    char* nmr = strdup("/dev/disk0s1s1");
    int mntr = mount("hfs", "/", MNT_UPDATE, &nmr);
    olog("remount = %d\n",mntr);
    if (mntr != 0) {
        exit(1);
    }

    sync();

    NSString *untetherPathObj = [[[NSBundle mainBundle] resourcePath]stringByAppendingString:@"/untether.tar"];
    char *untether_path = [untetherPathObj UTF8String];
    olog("untether path: %s\n",untether_path);
    
    bool InstallBootstrap = false;
    if (!((access("/.installed-openpwnage", F_OK) != -1) || (access("/.installed_everpwnage", F_OK) != -1) ||
          (access("/.installed_home_depot", F_OK) != -1) || (access("/untether", F_OK) != -1) )) {
        olog("installing bootstrap...\n");
        
        NSString *tarPathObj = [[[NSBundle mainBundle] resourcePath]stringByAppendingString:@"/tar"];
        char *tar_path = [tarPathObj UTF8String];
        olog("tar path: %s\n",tar_path);
        NSString *basebinsPathObj = [[[NSBundle mainBundle] resourcePath]stringByAppendingString:@"/bootstrap.tar"];
        char *basebins_path = [basebinsPathObj UTF8String];
        olog("bootstrap path: %s\n",basebins_path);
        NSString *launchctlPathObj = [[[NSBundle mainBundle] resourcePath]stringByAppendingString:@"/launchctl"];
        const char *launchctl_path = [launchctlPathObj UTF8String];
        olog("launchctl path: %s\n",launchctl_path);
        
        olog("copying tar\n");
        copyfile([[[NSBundle mainBundle] resourcePath]stringByAppendingString:@"/tar"].UTF8String, "/bin/tar", NULL, COPYFILE_ALL);
        
        chmod("/bin/tar", 0755);
        olog("chmod'd tar_path\n");
        olog("extracting bootstrap\n");
        run_tar("%s", basebins_path);
        
        olog("disabling stashing\n");
        run_cmd("/bin/touch /.cydia_no_stash");
        
        olog("copying launchctl\n");
        run_cmd("/bin/cp -p %s /bin/launchctl", launchctl_path);
        
        olog("fixing perms...\n");
        chmod("/bin/tar", 0755);
        chmod("/bin/launchctl", 0755);
        chmod("/private", 0777);
        chmod("/private/var", 0777);
        chmod("/private/var/mobile", 0777);
        chmod("/private/var/mobile/Library", 0777);
        chmod("/private/var/mobile/Library/Preferences", 0777);
        mkdir("/Library/LaunchDaemons", 0755);
        FILE* fp = fopen("/.installed_everpwnage", "w");
        fprintf(fp, "do **NOT** delete this file, it's important. it's how we detect if the bootstrap was installed.\n");
        fclose(fp);
        
        sync();
        
        olog("bootstrap installed\n");
        InstallBootstrap = true;
    } else {
        olog("bootstrap already installed\n");
    }

    FILE* fp = fopen("/tmp/.jailbroken", "w");
    fprintf(fp, "jailbroken.\n");
    fclose(fp);
    
    olog("allowing jailbreak apps to be shown\n");
    NSMutableDictionary *md = [[NSMutableDictionary alloc] initWithContentsOfFile:@"/var/mobile/Library/Preferences/com.apple.springboard.plist"];
        
    [md setObject:[NSNumber numberWithBool:YES] forKey:@"SBShowNonDefaultSystemApps"];
        
    [md writeToFile:@"/var/mobile/Library/Preferences/com.apple.springboard.plist" atomically:YES];
        
    olog("restarting cfprefs\n");
    run_cmd("/usr/bin/killall -9 cfprefsd &");
    
    if (InstallBootstrap){
        olog("running uicache\n");
        run_cmd("su -c uicache mobile &");
    }

    if (untether_on) {
        olog("extracting untether\n");
        run_tar("%s", untether_path);

        olog("running postinst\n");
        run_cmd("/bin/bash /private/var/tmp/postinst configure");
    }
    
    olog("loading launch daemons\n");
    run_cmd("/bin/launchctl load /Library/LaunchDaemons/*");
    run_cmd("/etc/rc.d/*");
        
    olog("respringing\n");
    run_cmd("(killall -9 backboardd) &");

    return true;
}
