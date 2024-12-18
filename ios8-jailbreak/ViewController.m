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

#import "jailbreak.h"
#import "sockpuppet.h"

@interface ViewController ()

@property (weak, nonatomic) IBOutlet UIButton *jailbreak_button;
@property (weak, nonatomic) IBOutlet UISwitch *untether_toggle;
@property (weak, nonatomic) IBOutlet UILabel *title_label;
@property (weak, nonatomic) IBOutlet UILabel *version_label;

@end

@implementation ViewController

NSString *system_machine;
NSString *system_version;
bool install_openssh = false;
bool reinstall_strap = false;

addr_t self_port_address = 0;

- (void)viewDidLoad {
    [super viewDidLoad];
    // Do any additional setup after loading the view, typically from a nib.
    
    _title_label.text = @"EverPwnage";
    _version_label.text = @"v1.0";

    struct utsname systemInfo;
    uname(&systemInfo);

    system_machine = [NSString stringWithCString:systemInfo.machine encoding:NSUTF8StringEncoding];
    system_version = [[UIDevice currentDevice] systemVersion];

    NSLog(@"Running on %@ with iOS %@", system_machine, system_version);

    if (!([system_version hasPrefix:@"9.0"] || [system_version hasPrefix:@"8"])) {
        _jailbreak_button.enabled = NO;
        [_jailbreak_button setTitle:@"version not supported" forState:UIControlStateDisabled];
    }

    if (access("/.installed_daibutsu", F_OK) != -1 || [system_version hasPrefix:@"9.0"]) {
        _untether_toggle.enabled = NO;
        [_untether_toggle setOn:NO];
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

    mach_port_t tfp0;
    uint32_t kernel_base;
    tfp0 = exploit(&kernel_base);
    if (tfp0 == 0) {
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

- (IBAction)showSettingsViewController:(id)sender {
    // Initialize the SettingsViewController
    UIStoryboard *storyboard = [UIStoryboard storyboardWithName:@"Main" bundle:nil];
    SettingsViewController *settingsVC = [storyboard instantiateViewControllerWithIdentifier:@"SettingsViewController"];
    settingsVC.delegate = self;

    // Check for iPad or iPhone
    if (UI_USER_INTERFACE_IDIOM() == UIUserInterfaceIdiomPad) {
        // iPad: Show as popover
        settingsVC.modalPresentationStyle = UIModalPresentationPopover;
        UIPopoverPresentationController *popover = settingsVC.popoverPresentationController;
        if (popover) {
            popover.sourceView = sender;
            popover.sourceRect = [sender bounds];
            popover.permittedArrowDirections = UIPopoverArrowDirectionAny;
            popover.delegate = settingsVC; // Assign popover delegate
        }
        [self presentViewController:settingsVC animated:YES completion:nil];
    } else {
        UINavigationController *navController = [[UINavigationController alloc] initWithRootViewController:settingsVC];
        [self presentViewController:navController animated:YES completion:nil];
    }
}

#pragma mark - SettingsViewControllerDelegate
- (void)didUpdateTogglesWithFirstToggle:(BOOL)firstToggle secondToggle:(BOOL)secondToggle {
    // Update label with toggle values
    install_openssh = firstToggle;
    reinstall_strap = secondToggle;
    NSLog([NSString stringWithFormat:@"Toggle 1: %@, Toggle 2: %@",
           firstToggle ? @"ON" : @"OFF",
           secondToggle ? @"ON" : @"OFF"]);
}

@end
