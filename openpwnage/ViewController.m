//
//  ViewController.m
//  openpwnage
//
//  Created by Zachary Keffaber on 4/20/22.
//

#import "ViewController.h"
#import <sys/utsname.h>
#include <sys/sysctl.h>
#include <sys/types.h>

#import "jailbreak.h"
#include <time.h>

#define UNSLID_BASE 0x80001000

#define UIColorFromRGB(rgbValue) [UIColor \
colorWithRed:((float)((rgbValue & 0xFF0000) >> 16))/255.0 \
green:((float)((rgbValue & 0xFF00) >> 8))/255.0 \
blue:((float)(rgbValue & 0xFF))/255.0 alpha:1.0]

@interface ViewController ()
@property (weak, nonatomic) IBOutlet UILabel *openpwnLabel;
@property (weak, nonatomic) IBOutlet UILabel *notSupportedLabel;
@property (weak, nonatomic) IBOutlet UIButton *jbButton;
//@property (weak, nonatomic) IBOutlet UITextView *consoleView;
@property (weak, nonatomic) IBOutlet UIButton *settingsButton;
-(void)openpwnageConsoleLog:(NSString*)textToLog;
@end

@implementation ViewController

@synthesize consoleView;

id param_;

static id static_consoleView = nil;
-(void)viewDidLoad {
    [super viewDidLoad];
    param_ = self;
    [self setNeedsStatusBarAppearanceUpdate];
    // Do any additional setup after loading the view.
    _jbButton.layer.cornerRadius = 5.0;
    consoleView.layer.cornerRadius = 10.0;
    struct utsname systemInfo;
    uname(&systemInfo);
    _settingsButton.hidden = 1;
    
    consoleView.text = [NSString stringWithFormat:@"[*]openpwnage running on %@ with iOS %@\n", [NSString stringWithCString:systemInfo.machine encoding:NSUTF8StringEncoding], [[UIDevice currentDevice] systemVersion]];
    [_jbButton setImage:[UIImage imageNamed:@"openpwnageB7JailbreakingButtonopenpwnageB7JailbreakingButton.png"] forState:UIControlStateHighlighted];
    [_jbButton setImage:[UIImage imageNamed:@"openpwnageB7JailbreakingButtonopenpwnageB7JailbreakingButton.png"] forState:UIControlStateSelected];
    [_jbButton setImage:[UIImage imageNamed:@"openpwnageB7JailbreakingButtonopenpwnageB7JailbreakingButton.png"] forState:UIControlStateDisabled];
    
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
        
    olog("Kernel Version: %s\n",newkernv);
    
    olog("openpwnage stage: Beta\n");
    olog("openpwnage build 10\n");
    
    //olog("olog functional!");
    
    //remember to detect free space to check that the bootstrap can be installed
    
    NSArray *supportedDevices = [NSArray arrayWithObjects:@"iPad2,1",@"iPad2,2",@"iPad2,3",@"iPad2,4",@"iPad2,5",@"iPad2,6",@"iPad2,7",@"iPad3,1",@"iPad3,2",@"iPad3,3",@"iPad3,4",@"iPad3,5",@"iPad3,6",@"iPhone4,1",@"iPhone5,1",@"iPhone5,2",@"iPhone5,3",@"iPhone5,4",@"iPod5,1", nil];
    //supports all 32bit devices on 9.0-9.3.6 (the kinfo leak works on 8.0-8.4.1 but the mach_ports_register() bug (CVE-2016-4669) doesn't), aka iPad 2, iPad Mini 1, iPad 3, iPad 4, iPhone 4S, iPhone 5, iPhone 5C, iPod Touch 5
    if([supportedDevices containsObject:[NSString stringWithCString:systemInfo.machine encoding:NSUTF8StringEncoding]]){
        NSString *kver = [NSString stringWithCString:newkernv encoding:NSUTF8StringEncoding];
        NSArray *supportedKernVers = [NSArray arrayWithObjects:@"2784.40.6~1",@"2784.30.7~3",@"2784.30.7~1",@"2784.20.34~2",@"2783.5.38~5",@"2783.3.26~3",@"2783.3.22~1",@"2783.3.13~4",@"2783.1.72~23",@"2783.1.72~8", nil];
        if (!([supportedKernVers containsObject:kver])) {
            [self openpwnageConsoleLog:@"[*]your device is supported by openpwnage, but your iOS version is not\n"];
            [self openpwnageConsoleLog:@"[*]openpwnage supports 32bit 8.4b4-10.3.4 only at the moment\n"];
            _jbButton.hidden = 1;
            consoleView.backgroundColor = UIColorFromRGB(0xF9c9c9);
        } else {
            _notSupportedLabel.hidden = 1;
        }
    } else {
        [self openpwnageConsoleLog:@"[*]your device is not supported by openpwnage\n"];
        _jbButton.hidden = 1;
        consoleView.backgroundColor = UIColorFromRGB(0xF9c9c9);
    }
}
- (IBAction)jailbreakButtonPressed:(id)sender {
    [_jbButton setImage:[UIImage imageNamed:@"openpwnageB7JailbreakingButtonopenpwnageB7JailbreakingButton.png"] forState:UIControlStateNormal];
    [_jbButton setImage:[UIImage imageNamed:@"openpwnageB7JailbreakingButtonopenpwnageB7JailbreakingButton.png"] forState:UIControlStateHighlighted];
    [_jbButton setImage:[UIImage imageNamed:@"openpwnageB7JailbreakingButtonopenpwnageB7JailbreakingButton.png"] forState:UIControlStateSelected];
    [_jbButton setImage:[UIImage imageNamed:@"openpwnageB7JailbreakingButtonopenpwnageB7JailbreakingButton.png"] forState:UIControlStateDisabled];
    _jbButton.enabled = NO;
    /*CGRect frame = _jbButton.frame;
    frame.size.height += 1;
    _jbButton.frame = frame;*/
    [_jbButton setNeedsDisplay];
    NSLog(@"button pressed");
    dispatch_async(dispatch_get_main_queue(), ^{
        [self performSelector:@selector(openpwnage) withObject:self];
    });
}

-(void)openpwnage {
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
        
    olog("Kernel Version: %s\n",newkernv);
    NSString *kver = [NSString stringWithCString:newkernv encoding:NSUTF8StringEncoding];
    if ([[NSArray arrayWithObjects:@"2784.40.6~1",@"2784.30.7~3",@"2784.30.7~1",@"2784.20.34~2",@"2783.5.38~5",@"2783.3.26~3",@"2783.3.22~1",@"2783.3.13~4",@"2783.1.72~23",@"2783.1.72~8",nil] containsObject:kver]) { //iOS 8.0-8.4.1
        olog("starting jb\n");
        //[self openpwnageConsoleLog:@"[*]aw yeah da hot sauce\n"];
        //consoleView.text = [[NSString alloc]initWithString:[consoleView.text stringByAppendingString:@"fill me with cum already\n"]];
        mach_port_t tfp0 = dajb();
        if (tfp0 == 0) {
            olog("failed to get tfp0 :(\n");
            exit(42);
        }
        //task_t tfp0 = get_kernel_task();
        olog("getting kbase again rather than using our existing one because idfk...\n");
        uint32_t kernel_base = leak_kernel_base();
        //uintptr_t kernel_base = kbase();
        olog("[*]woo kbase got... again\n");
        olog("[*]kbase=0x%08lx\n", kernel_base); //this works
        CGRect frame = consoleView.frame;
        frame.size.height -= 1;
        consoleView.frame = frame;
        [consoleView setNeedsDisplay];
        //sleep(10);
        olog("[*]calculating kaslr slide...\n");
        uint32_t kaslr_slide = kernel_base - UNSLID_BASE;
        [self openpwnageConsoleLog:[NSString stringWithFormat: @"[*]slide=0x%08x\n", kaslr_slide]];
        [self openpwnageConsoleLog:@"[*]obtaining root...\n"];
        if (rootify(tfp0, kernel_base, kaslr_slide)) {
            [self openpwnageConsoleLog:@"[*]we root baby\n"];
            if (is_pmap_patch_success(tfp0, kernel_base, kaslr_slide)) {
                olog("pmap patch success!\n");
            } else {
                olog("pmap patch no success :(\n");
            }
            olog("time for unsandbox...\n");
            unsandbox8(tfp0,kernel_base,kaslr_slide);
        } else {
            [self openpwnageConsoleLog:@"[*]root failed :(\n"];
        }
    } else {
        [self openpwnageConsoleLog:@"[*]failed to get root :(\n"];
    }
    //unpatch pmap
    [self openpwnageConsoleLog:@"[*]that's all for know. more soon (hopefully)\n"];
    //go();
}

-(void)openpwnageConsoleLog: (NSString*)textToLog {
    NSLog(@"%@", [[NSString alloc]initWithString:textToLog]);
    NSMutableString *mutableLog = [consoleView.text mutableCopy];
    
    consoleView.text = [[NSString alloc]initWithString:[mutableLog stringByAppendingString:textToLog]];
    /*dispatch_async(dispatch_get_main_queue(), ^{
        [consoleView setNeedsDisplay];
    });
    CGRect frame = consoleView.frame;
    frame.size.height += 1;
    consoleView.frame = frame;
    frame.size.height -= 1;
    consoleView.frame = frame;
    //[consoleView scrollRangeToVisible:NSMakeRange(consoleView.text.length, 0)];
    [consoleView setNeedsDisplay];
    //CGRect frame = consoleView.frame;
    frame.size.height += 1;
    consoleView.frame = frame;
    frame.size.height -= 1;
    consoleView.frame = frame;*/
    //return;
    return;
}

void openpwnageCLog(NSString* textToLog) {
    //NSLog(@"openpwnageCLog\n");a
    //NSLog(@"%@", [[NSString alloc]initWithString:textToLog]);
    /*dispatch_sync(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_BACKGROUND, 0), ^{
        [param_ openpwnageConsoleLog:textToLog];
    });*/
    [param_ openpwnageConsoleLog:textToLog];
    /*[UIView performWithoutAnimation:^{ \
        [param_ openpwnageConsoleLog:textToLog];
    }]; \*/
    /*dispatch_async(dispatch_get_main_queue(), ^{
        [param_ openpwnageConsoleLog:textToLog];
    });*/
}

@end
