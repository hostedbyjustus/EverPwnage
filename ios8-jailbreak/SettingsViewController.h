//
//  SettingsViewController.h
//  TestEx
//
//  Created by imac on 12/17/24.
//  Copyright © 2024 lukezgd. All rights reserved.
//

#import <UIKit/UIKit.h>

@protocol SettingsViewControllerDelegate <NSObject>

- (void)didUpdateTogglesWithFirstToggle:(BOOL)firstToggle
                           secondToggle:(BOOL)secondToggle;

@end

@interface SettingsViewController : UIViewController

@property (nonatomic, weak) id<SettingsViewControllerDelegate> delegate;

@property (weak, nonatomic) IBOutlet UISwitch *firstToggleSwitch;
@property (weak, nonatomic) IBOutlet UISwitch *secondToggleSwitch;

@end
