//
//  jailbreak.m
//  openpwnage
//
//  Created by Zachary Keffaber on 4/24/22.
//

//big thanks to (jk maybe?) for kpmap patch, and thanks to spv for misc stuff

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
//#include <sys/kauth.h>
//#include <IOKit/IOKitLib.h>
//#include <IOKit/iokitmig.h>

#import "ViewController.h"

#define UNSLID_BASE 0x80001000

void flush_all_the_streams(void) {
    fflush(stdout);
    fflush(stderr);
}

void olog(char *format, ...) {
    //flush_all_the_streams();
    char msg[1000];//this can overflow, but eh don't care
    va_list aptr;

    va_start(aptr, format);
    vsprintf(msg, format, aptr);
    va_end(aptr);
    //printf("%s",msg);

    NSString *logTxt = [NSString stringWithUTF8String:msg];
    //NSLog(@"%@",logTxt);
    openpwnageCLog(logTxt);
    //flush_all_the_streams();
}

NSString *KernelVersion(void) {
    size_t size;
    sysctlbyname("kern.version", NULL, &size, NULL, 0);
    char *kernelVersion = malloc(size);
    sysctlbyname("kern.version", kernelVersion, &size, NULL, 0);
    olog("%s\n",kernelVersion);
    
    char *newkernv = malloc(size - 44);
    char *semicolon = strchr(kernelVersion, '~');
    int indexofsemi = (int)(semicolon - kernelVersion);
    int indexofrootxnu = indexofsemi;
    while (kernelVersion[indexofrootxnu - 1] != '-') {
        indexofrootxnu -= 1;
    }
    memcpy(newkernv, &kernelVersion[indexofrootxnu], indexofsemi - indexofrootxnu + 2);
    newkernv[indexofsemi - indexofrootxnu + 2] = '\0';
    
    return [NSString stringWithUTF8String:newkernv];
}

struct mac_policy_ops {
    uint32_t mpo_audit_check_postselect;
    uint32_t mpo_audit_check_preselect;
    uint32_t mpo_bpfdesc_label_associate;
    uint32_t mpo_bpfdesc_label_destroy;
    uint32_t mpo_bpfdesc_label_init;
    uint32_t mpo_bpfdesc_check_receive;
    uint32_t mpo_cred_check_label_update_execve;
    uint32_t mpo_cred_check_label_update;
    uint32_t mpo_cred_check_visible;
    uint32_t mpo_cred_label_associate_fork;
    uint32_t mpo_cred_label_associate_kernel;
    uint32_t mpo_cred_label_associate;
    uint32_t mpo_cred_label_associate_user;
    uint32_t mpo_cred_label_destroy;
    uint32_t mpo_cred_label_externalize_audit;
    uint32_t mpo_cred_label_externalize;
    uint32_t mpo_cred_label_init;
    uint32_t mpo_cred_label_internalize;
    uint32_t mpo_cred_label_update_execve;
    uint32_t mpo_cred_label_update;
    uint32_t mpo_devfs_label_associate_device;
    uint32_t mpo_devfs_label_associate_directory;
    uint32_t mpo_devfs_label_copy;
    uint32_t mpo_devfs_label_destroy;
    uint32_t mpo_devfs_label_init;
    uint32_t mpo_devfs_label_update;
    uint32_t mpo_file_check_change_offset;
    uint32_t mpo_file_check_create;
    uint32_t mpo_file_check_dup;
    uint32_t mpo_file_check_fcntl;
    uint32_t mpo_file_check_get_offset;
    uint32_t mpo_file_check_get;
    uint32_t mpo_file_check_inherit;
    uint32_t mpo_file_check_ioctl;
    uint32_t mpo_file_check_lock;
    uint32_t mpo_file_check_mmap_downgrade;
    uint32_t mpo_file_check_mmap;
    uint32_t mpo_file_check_receive;
    uint32_t mpo_file_check_set;
    uint32_t mpo_file_label_init;
    uint32_t mpo_file_label_destroy;
    uint32_t mpo_file_label_associate;
    uint32_t mpo_ifnet_check_label_update;
    uint32_t mpo_ifnet_check_transmit;
    uint32_t mpo_ifnet_label_associate;
    uint32_t mpo_ifnet_label_copy;
    uint32_t mpo_ifnet_label_destroy;
    uint32_t mpo_ifnet_label_externalize;
    uint32_t mpo_ifnet_label_init;
    uint32_t mpo_ifnet_label_internalize;
    uint32_t mpo_ifnet_label_update;
    uint32_t mpo_ifnet_label_recycle;
    uint32_t mpo_inpcb_check_deliver;
    uint32_t mpo_inpcb_label_associate;
    uint32_t mpo_inpcb_label_destroy;
    uint32_t mpo_inpcb_label_init;
    uint32_t mpo_inpcb_label_recycle;
    uint32_t mpo_inpcb_label_update;
    uint32_t mpo_iokit_check_device;
    uint32_t mpo_ipq_label_associate;
    uint32_t mpo_ipq_label_compare;
    uint32_t mpo_ipq_label_destroy;
    uint32_t mpo_ipq_label_init;
    uint32_t mpo_ipq_label_update;
    uint32_t mpo_file_check_library_validation;
    uint32_t mpo_vnode_notify_setacl;
    uint32_t mpo_vnode_notify_setattrlist;
    uint32_t mpo_vnode_notify_setextattr;
    uint32_t mpo_vnode_notify_setflags;
    uint32_t mpo_vnode_notify_setmode;
    uint32_t mpo_vnode_notify_setowner;
    uint32_t mpo_vnode_notify_setutimes;
    uint32_t mpo_vnode_notify_truncate;
    uint32_t mpo_mbuf_label_associate_bpfdesc;
    uint32_t mpo_mbuf_label_associate_ifnet;
    uint32_t mpo_mbuf_label_associate_inpcb;
    uint32_t mpo_mbuf_label_associate_ipq;
    uint32_t mpo_mbuf_label_associate_linklayer;
    uint32_t mpo_mbuf_label_associate_multicast_encap;
    uint32_t mpo_mbuf_label_associate_netlayer;
    uint32_t mpo_mbuf_label_associate_socket;
    uint32_t mpo_mbuf_label_copy;
    uint32_t mpo_mbuf_label_destroy;
    uint32_t mpo_mbuf_label_init;
    uint32_t mpo_mount_check_fsctl;
    uint32_t mpo_mount_check_getattr;
    uint32_t mpo_mount_check_label_update;
    uint32_t mpo_mount_check_mount;
    uint32_t mpo_mount_check_remount;
    uint32_t mpo_mount_check_setattr;
    uint32_t mpo_mount_check_stat;
    uint32_t mpo_mount_check_umount;
    uint32_t mpo_mount_label_associate;
    uint32_t mpo_mount_label_destroy;
    uint32_t mpo_mount_label_externalize;
    uint32_t mpo_mount_label_init;
    uint32_t mpo_mount_label_internalize;
    uint32_t mpo_netinet_fragment;
    uint32_t mpo_netinet_icmp_reply;
    uint32_t mpo_netinet_tcp_reply;
    uint32_t mpo_pipe_check_ioctl;
    uint32_t mpo_pipe_check_kqfilter;
    uint32_t mpo_pipe_check_label_update;
    uint32_t mpo_pipe_check_read;
    uint32_t mpo_pipe_check_select;
    uint32_t mpo_pipe_check_stat;
    uint32_t mpo_pipe_check_write;
    uint32_t mpo_pipe_label_associate;
    uint32_t mpo_pipe_label_copy;
    uint32_t mpo_pipe_label_destroy;
    uint32_t mpo_pipe_label_externalize;
    uint32_t mpo_pipe_label_init;
    uint32_t mpo_pipe_label_internalize;
    uint32_t mpo_pipe_label_update;
    uint32_t mpo_policy_destroy;
    uint32_t mpo_policy_init;
    uint32_t mpo_policy_initbsd;
    uint32_t mpo_policy_syscall;
    uint32_t mpo_system_check_sysctlbyname;
    uint32_t mpo_proc_check_inherit_ipc_ports;
    uint32_t mpo_vnode_check_rename;
    uint32_t mpo_kext_check_query;
    uint32_t mpo_iokit_check_nvram_get;
    uint32_t mpo_iokit_check_nvram_set;
    uint32_t mpo_iokit_check_nvram_delete;
    uint32_t mpo_proc_check_expose_task;
    uint32_t mpo_proc_check_set_host_special_port;
    uint32_t mpo_proc_check_set_host_exception_port;
    uint32_t mpo_exc_action_check_exception_send;
    uint32_t mpo_exc_action_label_associate;
    uint32_t mpo_exc_action_label_populate;
    uint32_t mpo_exc_action_label_destroy;
    uint32_t mpo_exc_action_label_init;
    uint32_t mpo_exc_action_label_update;
    uint32_t mpo_reserved1;
    uint32_t mpo_reserved2;
    uint32_t mpo_reserved3;
    uint32_t mpo_reserved4;
    uint32_t mpo_skywalk_flow_check_connect;
    uint32_t mpo_skywalk_flow_check_listen;
    uint32_t mpo_posixsem_check_create;
    uint32_t mpo_posixsem_check_open;
    uint32_t mpo_posixsem_check_post;
    uint32_t mpo_posixsem_check_unlink;
    uint32_t mpo_posixsem_check_wait;
    uint32_t mpo_posixsem_label_associate;
    uint32_t mpo_posixsem_label_destroy;
    uint32_t mpo_posixsem_label_init;
    uint32_t mpo_posixshm_check_create;
    uint32_t mpo_posixshm_check_mmap;
    uint32_t mpo_posixshm_check_open;
    uint32_t mpo_posixshm_check_stat;
    uint32_t mpo_posixshm_check_truncate;
    uint32_t mpo_posixshm_check_unlink;
    uint32_t mpo_posixshm_label_associate;
    uint32_t mpo_posixshm_label_destroy;
    uint32_t mpo_posixshm_label_init;
    uint32_t mpo_proc_check_debug;
    uint32_t mpo_proc_check_fork;
    uint32_t mpo_proc_check_get_task_name;
    uint32_t mpo_proc_check_get_task;
    uint32_t mpo_proc_check_getaudit;
    uint32_t mpo_proc_check_getauid;
    uint32_t mpo_proc_check_getlcid;
    uint32_t mpo_proc_check_mprotect;
    uint32_t mpo_proc_check_sched;
    uint32_t mpo_proc_check_setaudit;
    uint32_t mpo_proc_check_setauid;
    uint32_t mpo_proc_check_setlcid;
    uint32_t mpo_proc_check_signal;
    uint32_t mpo_proc_check_wait;
    uint32_t mpo_proc_label_destroy;
    uint32_t mpo_proc_label_init;
    uint32_t mpo_socket_check_accept;
    uint32_t mpo_socket_check_accepted;
    uint32_t mpo_socket_check_bind;
    uint32_t mpo_socket_check_connect;
    uint32_t mpo_socket_check_create;
    uint32_t mpo_socket_check_deliver;
    uint32_t mpo_socket_check_kqfilter;
    uint32_t mpo_socket_check_label_update;
    uint32_t mpo_socket_check_listen;
    uint32_t mpo_socket_check_receive;
    uint32_t mpo_socket_check_received;
    uint32_t mpo_socket_check_select;
    uint32_t mpo_socket_check_send;
    uint32_t mpo_socket_check_stat;
    uint32_t mpo_socket_check_setsockopt;
    uint32_t mpo_socket_check_getsockopt;
    uint32_t mpo_socket_label_associate_accept;
    uint32_t mpo_socket_label_associate;
    uint32_t mpo_socket_label_copy;
    uint32_t mpo_socket_label_destroy;
    uint32_t mpo_socket_label_externalize;
    uint32_t mpo_socket_label_init;
    uint32_t mpo_socket_label_internalize;
    uint32_t mpo_socket_label_update;
    uint32_t mpo_socketpeer_label_associate_mbuf;
    uint32_t mpo_socketpeer_label_associate_socket;
    uint32_t mpo_socketpeer_label_destroy;
    uint32_t mpo_socketpeer_label_externalize;
    uint32_t mpo_socketpeer_label_init;
    uint32_t mpo_system_check_acct;
    uint32_t mpo_system_check_audit;
    uint32_t mpo_system_check_auditctl;
    uint32_t mpo_system_check_auditon;
    uint32_t mpo_system_check_host_priv;
    uint32_t mpo_system_check_nfsd;
    uint32_t mpo_system_check_reboot;
    uint32_t mpo_system_check_settime;
    uint32_t mpo_system_check_swapoff;
    uint32_t mpo_system_check_swapon;
    uint32_t mpo_socket_check_ioctl;
    uint32_t mpo_sysvmsg_label_associate;
    uint32_t mpo_sysvmsg_label_destroy;
    uint32_t mpo_sysvmsg_label_init;
    uint32_t mpo_sysvmsg_label_recycle;
    uint32_t mpo_sysvmsq_check_enqueue;
    uint32_t mpo_sysvmsq_check_msgrcv;
    uint32_t mpo_sysvmsq_check_msgrmid;
    uint32_t mpo_sysvmsq_check_msqctl;
    uint32_t mpo_sysvmsq_check_msqget;
    uint32_t mpo_sysvmsq_check_msqrcv;
    uint32_t mpo_sysvmsq_check_msqsnd;
    uint32_t mpo_sysvmsq_label_associate;
    uint32_t mpo_sysvmsq_label_destroy;
    uint32_t mpo_sysvmsq_label_init;
    uint32_t mpo_sysvmsq_label_recycle;
    uint32_t mpo_sysvsem_check_semctl;
    uint32_t mpo_sysvsem_check_semget;
    uint32_t mpo_sysvsem_check_semop;
    uint32_t mpo_sysvsem_label_associate;
    uint32_t mpo_sysvsem_label_destroy;
    uint32_t mpo_sysvsem_label_init;
    uint32_t mpo_sysvsem_label_recycle;
    uint32_t mpo_sysvshm_check_shmat;
    uint32_t mpo_sysvshm_check_shmctl;
    uint32_t mpo_sysvshm_check_shmdt;
    uint32_t mpo_sysvshm_check_shmget;
    uint32_t mpo_sysvshm_label_associate;
    uint32_t mpo_sysvshm_label_destroy;
    uint32_t mpo_sysvshm_label_init;
    uint32_t mpo_sysvshm_label_recycle;
    uint32_t mpo_proc_notify_exit;
    uint32_t mpo_mount_check_snapshot_revert;
    uint32_t mpo_vnode_check_getattr;
    uint32_t mpo_mount_check_snapshot_create;
    uint32_t mpo_mount_check_snapshot_delete;
    uint32_t mpo_vnode_check_clone;
    uint32_t mpo_proc_check_get_cs_info;
    uint32_t mpo_proc_check_set_cs_info;
    uint32_t mpo_iokit_check_hid_control;
    uint32_t mpo_vnode_check_access;
    uint32_t mpo_vnode_check_chdir;
    uint32_t mpo_vnode_check_chroot;
    uint32_t mpo_vnode_check_create;
    uint32_t mpo_vnode_check_deleteextattr;
    uint32_t mpo_vnode_check_exchangedata;
    uint32_t mpo_vnode_check_exec;
    uint32_t mpo_vnode_check_getattrlist;
    uint32_t mpo_vnode_check_getextattr;
    uint32_t mpo_vnode_check_ioctl;
    uint32_t mpo_vnode_check_kqfilter;
    uint32_t mpo_vnode_check_label_update;
    uint32_t mpo_vnode_check_link;
    uint32_t mpo_vnode_check_listextattr;
    uint32_t mpo_vnode_check_lookup;
    uint32_t mpo_vnode_check_open;
    uint32_t mpo_vnode_check_read;
    uint32_t mpo_vnode_check_readdir;
    uint32_t mpo_vnode_check_readlink;
    uint32_t mpo_vnode_check_rename_from;
    uint32_t mpo_vnode_check_rename_to;
    uint32_t mpo_vnode_check_revoke;
    uint32_t mpo_vnode_check_select;
    uint32_t mpo_vnode_check_setattrlist;
    uint32_t mpo_vnode_check_setextattr;
    uint32_t mpo_vnode_check_setflags;
    uint32_t mpo_vnode_check_setmode;
    uint32_t mpo_vnode_check_setowner;
    uint32_t mpo_vnode_check_setutimes;
    uint32_t mpo_vnode_check_stat;
    uint32_t mpo_vnode_check_truncate;
    uint32_t mpo_vnode_check_unlink;
    uint32_t mpo_vnode_check_write;
    uint32_t mpo_vnode_label_associate_devfs;
    uint32_t mpo_vnode_label_associate_extattr;
    uint32_t mpo_vnode_label_associate_file;
    uint32_t mpo_vnode_label_associate_pipe;
    uint32_t mpo_vnode_label_associate_posixsem;
    uint32_t mpo_vnode_label_associate_posixshm;
    uint32_t mpo_vnode_label_associate_singlelabel;
    uint32_t mpo_vnode_label_associate_socket;
    uint32_t mpo_vnode_label_copy;
    uint32_t mpo_vnode_label_destroy;
    uint32_t mpo_vnode_label_externalize_audit;
    uint32_t mpo_vnode_label_externalize;
    uint32_t mpo_vnode_label_init;
    uint32_t mpo_vnode_label_internalize;
    uint32_t mpo_vnode_label_recycle;
    uint32_t mpo_vnode_label_store;
    uint32_t mpo_vnode_label_update_extattr;
    uint32_t mpo_vnode_label_update;
    uint32_t mpo_vnode_notify_create;
    uint32_t mpo_vnode_check_signature;
    uint32_t mpo_vnode_check_uipc_bind;
    uint32_t mpo_vnode_check_uipc_connect;
    uint32_t mpo_proc_check_run_cs_invalid;
    uint32_t mpo_proc_check_suspend_resume;
    uint32_t mpo_thread_userret;
    uint32_t mpo_iokit_check_set_properties;
    uint32_t mpo_system_check_chud;
    uint32_t mpo_vnode_check_searchfs;
    uint32_t mpo_priv_check;
    uint32_t mpo_priv_grant;
    uint32_t mpo_proc_check_map_anon;
    uint32_t mpo_vnode_check_fsgetpath;
    uint32_t mpo_iokit_check_open;
    uint32_t mpo_proc_check_ledger;
    uint32_t mpo_vnode_notify_rename;
    uint32_t mpo_vnode_check_setacl;
    uint32_t mpo_vnode_notify_deleteextattr;
    uint32_t mpo_system_check_kas_info;
    uint32_t mpo_vnode_check_lookup_preflight;
    uint32_t mpo_vnode_notify_open;
    uint32_t mpo_system_check_info;
    uint32_t mpo_pty_notify_grant;
    uint32_t mpo_pty_notify_close;
    uint32_t mpo_vnode_find_sigs;
    uint32_t mpo_kext_check_load;
    uint32_t mpo_kext_check_unload;
    uint32_t mpo_proc_check_proc_info;
    uint32_t mpo_vnode_notify_link;
    uint32_t mpo_iokit_check_filter_properties;
    uint32_t mpo_iokit_check_get_property;
};

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

uint32_t hardcoded_allproc(void){
    uint32_t allproc;
    struct utsname systemInfo;
    uname(&systemInfo);
    NSArray *isA5orA5X = [NSArray arrayWithObjects:@"iPad2,1",@"iPad2,2",@"iPad2,3",@"iPad2,4",@"iPad2,5",@"iPad2,6",@"iPad2,7",@"iPad3,1",@"iPad3,2",@"iPad3,3",@"iPhone4,1",@"iPod5,1", nil];
    if([isA5orA5X containsObject:[NSString stringWithCString:systemInfo.machine encoding:NSUTF8StringEncoding]]) {
        //A5 or A5X
        if ([[NSArray arrayWithObjects:@"2784.20.34~2", nil] containsObject:KernelVersion()]){ //8.3
            allproc = 0x3f480c;
            olog("using 0x3f480c\n");
        } else if ([[NSArray arrayWithObjects:@"2783.5.38~5", nil] containsObject:KernelVersion()]){ //8.2
            allproc = 0x3e6790;
            olog("using 0x3e6790\n");
        } else if ([[NSArray arrayWithObjects:@"2783.3.26~3", nil] containsObject:KernelVersion()]){ //8.1.3
            allproc = 0x3e4788;
            olog("using 0x3e4788\n");
        } else if ([[NSArray arrayWithObjects:@"2783.3.22~1", nil] containsObject:KernelVersion()]){ //8.1.2
            allproc = 0x3e3764;
            olog("using 0x3e3764\n");
        } else if ([[NSArray arrayWithObjects:@"2783.3.13~4", nil] containsObject:KernelVersion()]){ //8.1
            allproc = 0x3e3754;
            olog("using 0x3e3754\n");
        } else if ([[NSArray arrayWithObjects:@"2783.1.72~23", nil] containsObject:KernelVersion()]){ //8.0.2
            allproc = 0x3e3754;
            olog("using 0x3e3754\n");
        } else if ([[NSArray arrayWithObjects:@"2783.1.72~8", nil] containsObject:KernelVersion()]){ //8.0
            allproc = 0x3e3754;
            olog("using 0x3e3754\n");
        } else { //8.4-8.4.1
            allproc = 0x3f4810;
            olog("using 0x3f4810\n");
        }
    } else {
        //A6 or A6X
        if ([[NSArray arrayWithObjects:@"2784.20.34~2", nil] containsObject:KernelVersion()]){ //8.3
            allproc = 0x3f996c;
            olog("using 0x3f996c\n");
        } else if ([[NSArray arrayWithObjects:@"2783.5.38~5", nil] containsObject:KernelVersion()]){ //8.2
            allproc = 0x3ec8f0;
            olog("using 0x3ec8f0\n");
        } else if ([[NSArray arrayWithObjects:@"2783.3.26~3", nil] containsObject:KernelVersion()]){ //8.1.3
            allproc = 0x3e98e8;
            olog("using 0x3e98e8\n");
        } else if ([[NSArray arrayWithObjects:@"2783.3.22~1", nil] containsObject:KernelVersion()]){ //8.1.2
            allproc = 0x3e98c4;
            olog("using 0x3e98c4\n");
        } else if ([[NSArray arrayWithObjects:@"2783.3.13~4", nil] containsObject:KernelVersion()]){ //8.1
            allproc = 0x3e98b4;
            olog("using 0x3e98b4\n");
        } else if ([[NSArray arrayWithObjects:@"2783.1.72~23", nil] containsObject:KernelVersion()]){ //8.0.2
            allproc = 0x3e98b4;
            olog("using 0x3e98b4\n");
        } else if ([[NSArray arrayWithObjects:@"2783.1.72~8", nil] containsObject:KernelVersion()]){ //8.0
            allproc = 0x3e98b4;
            olog("using 0x3e98b4\n");
        } else { //8.4-8.4.1
            allproc = 0x3f9970;
            olog("using 0x3f9970\n");
        }
    }
        olog("[*] found allproc: 0x%08x\n", allproc);
        return allproc;
}

//stolen from p0laris
uint32_t find_mount_common(uint32_t region, uint8_t* kdata, size_t ksize) {
    float version_float = strtof([[[UIDevice currentDevice]systemVersion]UTF8String], 0);
    for (uint32_t i = 0; i < ksize; i++) {
        if (version_float == (float)9.3) {
            if (*(uint64_t*)&kdata[i] == 0x2501d1030f01f01b && *(uint32_t*)&kdata[i+0x8] == 0x2501e016) {
                uint32_t mount_common = i + 0x5;
                printf("[*] found mount_common: 0x%08x\n", mount_common);
                return mount_common;
            }
        } else if (version_float == (float)9.0) {
            if ((*(uint64_t*)&kdata[i] & 0x00ffffffffffffff) == 0xd4d0060f01f010) {
                uint32_t mount_common = i + 0x5;
                printf("[*] found mount_common: 0x%08x\n", mount_common);
                return mount_common;
            }
        } else {
            if (*(uint32_t*)&kdata[i] == 0x0f01f010 && *(uint8_t*)&kdata[i+0x5] == 0xd0 && *(uint32_t*)&kdata[i+0xe] == 0x0f40f010 && *(uint8_t*)&kdata[i+0x13] == 0xd0) {
                uint32_t mount_common = i + 0x5;
                printf("[*] found mount_common: 0x%08x\n", mount_common);
                return mount_common;
            }
        }
    }
    return -1;
}

uint32_t find_PE_i_can_has_debugger_1(uint32_t region, uint8_t* kdata, size_t ksize) {
    uint32_t PE_i_can_has_debugger_1;
    struct utsname systemInfo;
    uname(&systemInfo);
    NSArray *isA5orA5X = [NSArray arrayWithObjects:@"iPad2,1",@"iPad2,2",@"iPad2,3",@"iPad2,4",@"iPad2,5",@"iPad2,6",@"iPad2,7",@"iPad3,1",@"iPad3,2",@"iPad3,3",@"iPhone4,1",@"iPod5,1", nil];
    if([isA5orA5X containsObject:[NSString stringWithCString:systemInfo.machine encoding:NSUTF8StringEncoding]]) {
        //A5 or A5X
        PE_i_can_has_debugger_1 = 0x3f4dc0;
        olog("using 0x3f4dc0\n");
    } else {
        //A6 / A6X
        PE_i_can_has_debugger_1 = 0x3fa0d4; //OR 0x003fa0d4
        olog("using 0x3fa0d4\n"); //0x3f9ef0
    }
    printf("[*] found PE_i_can_has_debugger_1 at 0x%08x\n", PE_i_can_has_debugger_1);
    return PE_i_can_has_debugger_1;
}

uint32_t find_PE_i_can_has_debugger_2(uint32_t region, uint8_t* kdata, size_t ksize) {
    uint32_t PE_i_can_has_debugger_2;
    struct utsname systemInfo;
    uname(&systemInfo);
    NSArray *isA5orA5X = [NSArray arrayWithObjects:@"iPad2,1",@"iPad2,2",@"iPad2,3",@"iPad2,4",@"iPad2,5",@"iPad2,6",@"iPad2,7",@"iPad3,1",@"iPad3,2",@"iPad3,3",@"iPhone4,1",@"iPod5,1", nil];
    if([isA5orA5X containsObject:[NSString stringWithCString:systemInfo.machine encoding:NSUTF8StringEncoding]]) {
        //A5 or A5X
        PE_i_can_has_debugger_2 = 0x3f2dc0;
        olog("using 0x3f2dc0\n");
    } else {
        //A6 or A6X
        PE_i_can_has_debugger_2 = 0x3f8a1c; //0x003f8a1c
        olog("using 0x3f8a1c\n"); //0x3f7ef0
    }
    printf("[*] found PE_i_can_has_debugger_2 at 0x%08x\n", PE_i_can_has_debugger_2);
    return PE_i_can_has_debugger_2;
}

bool rootify(task_t tfp0, uintptr_t kernel_base, uintptr_t kaslr_slide){
    olog("stealing kernel creds\n");

    uint32_t proc = kread_uint32(kernel_base + hardcoded_allproc(), tfp0);
    olog("uint32_t allproc at 0x%08lx\n",kernel_base + hardcoded_allproc());

    uint32_t myproc = 0;
    uint32_t kernproc = 0;

    //thanks to Jake James for his rootlessJB writeup, plus spv. this was already in 9.3.5fun and while i can easily redo this to be my own eh I'm lazy and spv's works fine.
    if (proc != 0) {
        while ((myproc == 0) || (kernproc == 0)) {
            uint32_t kpid = kread_uint32(proc + 8, tfp0); //go to next process
            if (kpid == getpid()) {
                myproc = proc;
                olog("found myproc 0x%08x, %d\n", myproc, kpid);
            } else if (kpid == 0) {
                kernproc = proc;
                olog("found kernproc 0x%08x, %d\n", kernproc, kpid);
            }
            proc = kread_uint32(proc, tfp0);
        }
    } else {
        // fail
        return false;
    }

    uint32_t proc_ucred_offset;proc_ucred_offset = 0x8c;
    olog("using 0x8c\n");

    uint32_t kern_ucred = kread_uint32(kernproc + proc_ucred_offset, tfp0);
    olog("uint32_t kern_ucred at 0x%08x\n", kern_ucred);

    vm_write(tfp0,myproc + proc_ucred_offset,(vm_offset_t)&kern_ucred,4); //patch our ucred with kern ucred

    setuid(0);

    olog("got root\n");

    return true;

}

uint32_t find_kernel_pmap(uintptr_t kernel_base) {
    uint32_t pmap_addr;
    struct utsname systemInfo;
    uname(&systemInfo);
    NSArray *isA5orA5X = [NSArray arrayWithObjects:@"iPad2,1",@"iPad2,2",@"iPad2,3",@"iPad2,4",@"iPad2,5",@"iPad2,6",@"iPad2,7",@"iPad3,1",@"iPad3,2",@"iPad3,3",@"iPhone4,1",@"iPod5,1", nil];
    if([isA5orA5X containsObject:[NSString stringWithCString:systemInfo.machine encoding:NSUTF8StringEncoding]]) {
        //A5 or A5X
        pmap_addr = 0x003A211C;
    } else {
        //A6 or A6X
        pmap_addr = 0x3a711c;
    }
    olog("using offset 0x%08x for pmap\n",pmap_addr);
    return pmap_addr + kernel_base;
}

#define TTB_SIZE			4096
#define L1_SECT_S_BIT		(1 << 16)
#define L1_SECT_PROTO		(1 << 1)														/* 0b10 */
#define L1_SECT_AP_URW		(1 << 10) | (1 << 11)
#define L1_SECT_APX			(1 << 15)
#define L1_SECT_DEFPROT		(L1_SECT_AP_URW | L1_SECT_APX)
#define L1_SECT_SORDER		(0)																/* 0b00, not cacheable, strongly ordered. */
#define L1_SECT_DEFCACHE	(L1_SECT_SORDER)
#define L1_PROTO_TTE(entry)	(entry | L1_SECT_S_BIT | L1_SECT_DEFPROT | L1_SECT_DEFCACHE)

uint32_t pmaps[TTB_SIZE];
int pmapscnt = 0;

void patch_kernel_pmap(task_t tfp0, uintptr_t kernel_base) {
	uint32_t kernel_pmap		= find_kernel_pmap(kernel_base);
	uint32_t kernel_pmap_store	= kread_uint32(kernel_pmap,tfp0);
	uint32_t tte_virt			= kread_uint32(kernel_pmap_store,tfp0);
	uint32_t tte_phys			= kread_uint32(kernel_pmap_store+4,tfp0);

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
			new_entry		   &= ~L1_SECT_APX;
			kwrite_uint32(addr, new_entry,tfp0);
		}
	}

	olog("every page is actually writable\n");
	usleep(100000);
}

void pmap_unpatch(task_t tfp0) {
	while (pmapscnt > 0) {
		uint32_t sladdr  = pmaps[--pmapscnt];
		uint32_t slentry = kread_uint32(sladdr,tfp0);

		/*
		 *  set the 9th bit to one
		 */
		uint32_t new_entry = slentry | (0x200);
		kwrite_uint32(sladdr, new_entry,tfp0);
	}
}

bool is_pmap_patch_success(task_t tfp0, uintptr_t kernel_base, uintptr_t kaslr_slide) {

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
	olog("Run command: %s", cmd_);
	status = posix_spawn(&pid, "/bin/sh", NULL, NULL, argv, environ);
	if (status == 0) {
		olog("Child pid: %i", pid);
		do {
			if (waitpid(pid, &status, 0) != -1) {
				olog("Child status %d", WEXITSTATUS(status));
			} else {
				perror("waitpid");
			}
		} while (!WIFEXITED(status) && !WIFSIGNALED(status));
	} else {
		olog("posix_spawn: %s", strerror(status));
	}
}

bool unsandbox8(mach_port_t tfp0, uint32_t kernel_base, uint32_t kaslr_slide) {
    olog("unsandboxing...\n");
    
    uint8_t* kdata = NULL;
    size_t ksize = 0xFFE000;
    kdata = malloc(ksize);
    dump_kernel_8(kernel_base, kdata, ksize);
    if (!kdata) {
        olog("fuck\n");
        exit(42);
    }
    olog("now...\n");
    //dump_kernel
    
    uint32_t sbopsoffset = find_sbops(kernel_base, kdata, 32 * 1024 * 1024);
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
    /*olog("trying pmap patch...\n");
    if (is_pmap_patch_success(tfp0, kernel_base, kaslr_slide)) {
        olog("pmap patch success\n");
    } else {
        olog("pmap patch epic fail\n");
    }*/
    olog("let's go for code exec...\n");
    
    uint32_t proc_enforce8 = find_proc_enforce8(kernel_base, kdata, 32 * 1024 * 1024);
    olog("patching proc_enforce at 0x%08x\n",
         kernel_base + proc_enforce8);
    kwrite_uint8(kernel_base + proc_enforce8, 0, tfp0);
    
    uint32_t cs_enforcement_disable_amfi = find_cs_enforcement_disable_amfi8(kernel_base, kdata, 32 * 1024 * 1024);
    olog("patching cs_enforcement_disable_amfi at 0x%08x,0x%04x\n",
                kernel_base + cs_enforcement_disable_amfi - 1,
                0x0101); //257 //I really don't know why it's not 1
    kwrite_uint8(kernel_base + cs_enforcement_disable_amfi, 1, tfp0);
    kwrite_uint8(kernel_base + cs_enforcement_disable_amfi - 4, 1, tfp0);
    
    uint32_t PE_i_can_has_debugger_1 = find_PE_i_can_has_debugger_1(kernel_base, kdata, 32 * 1024 * 1024);
    olog("patching PE_i_can_has_debugger_1 at 0x%08x\n",PE_i_can_has_debugger_1);
    kwrite_uint32(kernel_base + PE_i_can_has_debugger_1, 1, tfp0);
    
    uint32_t PE_i_can_has_debugger_2 = find_PE_i_can_has_debugger_2(kernel_base, kdata, 32 * 1024 * 1024);
    olog("patching PE_i_can_has_debugger_2 at 0x%08x\n",PE_i_can_has_debugger_2);
    kwrite_uint32(kernel_base + PE_i_can_has_debugger_2, 1, tfp0);
    
    uint32_t mapForIO = find_mapForIO(kernel_base, kdata, 32 * 1024 * 1024);
    olog("patching mapForIO at 0x%08x\n",
         kernel_base + mapForIO);
    kwrite_uint32(kernel_base + mapForIO, 0xbf00bf00,tfp0);
    
    uint32_t sandbox_call_i_can_has_debugger = find_sandbox_call_i_can_has_debugger8(kernel_base, kdata, 32 * 1024 * 1024);
    olog("patching sandbox_call_i_can_has_debugger at 0x%08x\n",
         kernel_base + sandbox_call_i_can_has_debugger);
    kwrite_uint32(kernel_base + sandbox_call_i_can_has_debugger, 0xbf00bf00, tfp0);
    
    uint32_t vm_map_protect8 = find_vm_map_protect_patch8(kernel_base, kdata, 32 * 1024 * 1024);
    olog("patching vm_map_protect at 0x%08x\n",
         kernel_base + vm_map_protect8);
    kwrite_uint32(kernel_base + vm_map_protect8, 0xbf00bf00, tfp0);
    
    uint32_t csops8 = find_csops8(kernel_base, kdata, 32 * 1024 * 1024);
    olog("patching csops at 0x%08x\n",
         kernel_base + csops8);
    kwrite_uint32(kernel_base + csops8, 0xbf00bf00, tfp0);
    
    uint32_t csops2 = find_csops2(kernel_base, kdata, 32 * 1024 * 1024);
    olog("patching csops2 at 0x%08x\n",
         kernel_base + csops2);
    kwrite_uint8(kernel_base + csops2, 0x20, tfp0);
    
    uint32_t vm_map_enter8 = find_vm_map_enter_patch8(kernel_base, kdata, 32 * 1024 * 1024);
    olog("patching find_vm_map_enter_patch at 0x%08x\n",
         kernel_base + vm_map_enter8);
    kwrite_uint32(kernel_base + vm_map_enter8, 0x4280bf00, tfp0);

    uint32_t mount_common = 1 + find_mount8(kernel_base, kdata, 32 * 1024 * 1024);
    olog("patching mount_common at 0x%08x\n",
         kernel_base + mount_common);
    kwrite_uint8(kernel_base + mount_common, 0xe0, tfp0);
    
    olog("[*] remounting rootfs\n");
    char* nmr = strdup("/dev/disk0s1s1");
    int mntr = mount("hfs", "/", MNT_UPDATE, &nmr);
    olog("remount = %d\n",mntr);
    
    sync();
    
    bool InstallBootstrap = false;
    if (!((access("/.installed-openpwnage", F_OK) != -1) || (access("/.installed_daibutsu", F_OK) != -1) || (access("/.installed_home_depot", F_OK) != -1))) {
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
        
        olog("extracting bootstrap\n");
        olog("prepare to wait a long time. this should be obvious imo, but don't turn off your device.\n");
        chmod("/bin/tar", 0777);
        olog("chmod'd tar_path\n");
        pid_t pid;
        //char *argv_[] = {"/bin/tar", "-xf", basebins_path, "-C", "/", "--preserve-permissions", NULL};
        //posix_spawn(&pid, "/bin/tar", NULL, NULL, argv_, environ);
        //easy_spawn_bc_fuck_this("/bin/tar", argv_);
        run_cmd("/bin/tar -xf %s -C / --preserve-permissions", basebins_path);
        
        olog("disabling stashing\n");
        run_cmd("/bin/touch /.cydia_no_stash");

        
        //run_cmd("/bin/cp -p %s /bin/tar", tar_path);
        
        olog("copying launchctl\n");
        run_cmd("/bin/cp -p %s /bin/launchctl", launchctl_path);
        
        olog("fixing perms...\n");
        chmod("/bin/tar", 0755);
        chmod("/bin/launchctl", 0755);
        chmod("/private", 0755);
        chmod("/private/var", 0755);
        chmod("/private/var/mobile", 0711);
        chmod("/private/var/mobile/Library", 0711);
        chmod("/private/var/mobile/Library/Preferences", 0755);
        mkdir("/Library/LaunchDaemons", 0777);
        //chmod("/usr/libexec/cydia/cydo", 06555);
        FILE* fp = fopen("/.installed-openpwnage", "w");
        fprintf(fp, "do **NOT** delete this file, it's important. it's how we detect if the bootstrap was installed. thanks for using openpwnage! ♡zachary7829\n");
        fclose(fp);
        
        sync();
        
        olog("bootstrap installed\n");
        InstallBootstrap = true;
    } else {
        olog("bootstrap already installed\n");
    }
    
    olog("allowing jailbreak apps to be shown\n");
    NSMutableDictionary *md = [[NSMutableDictionary alloc] initWithContentsOfFile:@"/var/mobile/Library/Preferences/com.apple.springboard.plist"];
        
    [md setObject:[NSNumber numberWithBool:YES] forKey:@"SBShowNonDefaultSystemApps"];
        
    [md writeToFile:@"/var/mobile/Library/Preferences/com.apple.springboard.plist" atomically:YES];
        
    olog("restarting cfprefs\n");
    run_cmd("/usr/bin/killall -9 cfprefsd &");
    
    if (InstallBootstrap){
        olog("i spent forever trying to figure out why this wouldn't work\n");
        olog("only to look at p0laris and see that i needed to uicache this whole time :P\n");
        olog("running uicache\n");
        run_cmd("su -c uicache mobile &");
    }
    
    olog("loading launch daemons\n");
    run_cmd("/bin/launchctl load /Library/LaunchDaemons/*");
    run_cmd("/etc/rc.d/*");
        
    olog("respringing\n");
    run_cmd("(killall -9 backboardd) &");

    return true;
}
