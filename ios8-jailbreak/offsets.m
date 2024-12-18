// offsets.m from wtfis

#import <Foundation/Foundation.h>

#import <stdio.h>
#import <stdlib.h>

#import "offsets.h"
#import "jailbreak.h"

int* offsets = NULL;
uint64_t* pfaddr_arr = NULL;

// 32-bit 8.x offsets
int kstruct_offsets_8[] = {
    0x18,  // TASK_VM_MAP
    0x1c,  // TASK_NEXT
    0x20,  // TASK_PREV
    0xa4,  // TASK_ITK_SELF
    0x1a8, // TASK_ITK_SPACE
    0x1f0, // TASK_BSDINFO
    
    0x40,  // IPC_PORT_IP_RECEIVER
    0x44,  // IPC_PORT_IP_KOBJECT
    0x5c,  // IPC_PORT_IP_SRIGHTS
    
    0x8,   // BSDINFO_PID
    0x90,  // PROC_P_FD
    0x8c,  // BSDINFO_KAUTH_CRED
    
    0x0,   // FILEDESC_FD_OFILES
    
    0x8,   // FILEPROC_F_FGLOB
    
    0x28,  // FILEGLOB_FG_DATA
    
    0x10,  // PIPE_BUFFER
    
    0x18,  // IPC_SPACE_IS_TABLE
    0x10,  // IPC_ENTRY_SIZE
};

int koffset(enum kstruct_offset offset) {
    if (offsets == NULL) {
        printf("need to call offsets_init() prior to querying offsets\n");
        return 0;
    }
    return offsets[offset];
}

void offsets_init(void) {
    //if ([system_version hasPrefix:@"9.0"]) {
    //    printf("[i] offsets selected for iOS 9.0.x\n");
    //    offsets = kstruct_offsets_9_0;
    //} else if ([system_version hasPrefix:@"8"]) {
    if ([system_version hasPrefix:@"8"]) {
        printf("[i] offsets selected for iOS 8.x\n");
        offsets = kstruct_offsets_8;
    } else {
        printf("[-] iOS version not supported\n");
        exit(1);
    }
}
