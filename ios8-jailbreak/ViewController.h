//
//  ViewController.h
//  ios8-jailbreak
//
//  Created by lukezgd on 12/14/24.
//  Copyright © 2024 lukezgd. All rights reserved.
//

#import <UIKit/UIKit.h>
#import "SettingsViewController.h"
#include <mach/mach.h>

@interface ViewController : UIViewController <SettingsViewControllerDelegate>

- (IBAction)jailbreak_pressed:(id)sender;

@end

