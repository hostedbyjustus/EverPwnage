//
//  ViewController.m
//  ios8-jailbreak
//
//  Created by lukezgd on 12/14/24.
//  Copyright © 2024 lukezgd. All rights reserved.
//

#import "ViewController.h"

#import <sys/utsname.h>
#include <sys/sysctl.h>
#include <sys/types.h>
#include <time.h>

#import "jailbreak.h"
#import "sockpuppet.h"

@interface ViewController ()

@property (weak, nonatomic) IBOutlet UIButton *jailbreak_button;
@property (weak, nonatomic) IBOutlet UISwitch *untether_toggle;
@property (weak, nonatomic) IBOutlet UILabel *title_label;
@property (weak, nonatomic) IBOutlet UILabel *version_label;

@end

@implementation ViewController

char *newkernv;
addr_t self_port_address = 0;

- (void)viewDidLoad {
    [super viewDidLoad];
    // Do any additional setup after loading the view, typically from a nib.
    
    _title_label.text = @"EverPwnage";
    _version_label.text = @"v1.0";

    struct utsname systemInfo;
    uname(&systemInfo);

    NSString *system_machine = [NSString stringWithCString:systemInfo.machine encoding:NSUTF8StringEncoding];
    NSString *system_version = [[UIDevice currentDevice] systemVersion];

    NSLog(@"Running on %@ with iOS %@", system_machine, system_version);

    size_t size;
    sysctlbyname("kern.version", NULL, &size, NULL, 0);
    char *kernelVersion = malloc(size);
    sysctlbyname("kern.version", kernelVersion, &size, NULL, 0);
    printf("%s\n",kernelVersion);

    newkernv = malloc(size - 44);
    char *semicolon = strchr(kernelVersion, '~');
    int indexofsemi = (int)(semicolon - kernelVersion);
    int indexofrootxnu = indexofsemi;
    while (kernelVersion[indexofrootxnu - 1] != '-') {
        indexofrootxnu -= 1;
    }
    memcpy(newkernv, &kernelVersion[indexofrootxnu], indexofsemi - indexofrootxnu + 2);
    newkernv[indexofsemi - indexofrootxnu + 2] = '\0';
    printf("Kernel Version: %s\n",newkernv);

    if (![system_version hasPrefix:@"8"]) {
        _jailbreak_button.enabled = NO;
        [_jailbreak_button setTitle:@"version not supported" forState:UIControlStateDisabled];
    }
    if (UINTPTR_MAX == 0xffffffffffffffff) {
        _jailbreak_button.enabled = NO;
        [_jailbreak_button setTitle:@"64-bit not supported" forState:UIControlStateDisabled];
    }
    if (access("/.installed_daibutsu", F_OK) != -1 || access("/tmp/.jailbroken", F_OK) != -1) {
        _jailbreak_button.enabled = NO;
        [_jailbreak_button setTitle:@"jailbroken" forState:UIControlStateDisabled];
    }
    if (isA5orA5X() && ([system_version hasPrefix:@"8.0"] || [system_version hasPrefix:@"8.1"] || [system_version hasPrefix:@"8.2"])) {
        _untether_toggle.enabled = NO;
        [_untether_toggle setOn:NO];
    }
}

- (IBAction)jailbreak_pressed:(id)sender {
    printf("button pressed\n");

    _jailbreak_button.enabled = NO;
    [sender setTitle:@"jailbreaking" forState:UIControlStateDisabled];

    dispatch_async(dispatch_get_main_queue(), ^{
        [self performSelector:@selector(jailbreak) withObject:self];
    });
}

- (void)jailbreak {
    printf("jailbreak\n");
    printf("Kernel Version: %s\n",newkernv);

    mach_port_t tfp0;
    uint32_t kernel_base;
    tfp0 = exploit(&kernel_base);
    if (kernel_base == 0) {
        printf("failed to get tfp0 :(\n");
        exit(1);
    }
    printf("[*]got tfp0: 0x%x\n", tfp0);
    printf("[*]kbase=0x%08lx\n", kernel_base);

    if (is_pmap_patch_success(tfp0, kernel_base)) {
        printf("pmap patch success!\n");
    } else {
        printf("pmap patch failed :(\n");
        exit(1);
    }

    printf("time for unsandbox...\n");
    unsandbox8(tfp0, kernel_base, _untether_toggle.isOn);
}

@end
