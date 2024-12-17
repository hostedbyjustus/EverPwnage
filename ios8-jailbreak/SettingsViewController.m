//
//  SettingsViewController.m
//  TestEx
//
//  Created by imac on 12/17/24.
//  Copyright © 2024 lukezgd. All rights reserved.
//

#import "SettingsViewController.h"

@interface SettingsViewController ()

@end

@implementation SettingsViewController

- (void)viewDidLoad {
    [super viewDidLoad];
    self.title = @"More Settings";

    // Add a Done button for iPhone only
    if (UI_USER_INTERFACE_IDIOM() == UIUserInterfaceIdiomPhone) {
        UIBarButtonItem *doneButton = [[UIBarButtonItem alloc] initWithTitle:@"Done"
                                                                       style:UIBarButtonItemStyleDone
                                                                      target:self
                                                                      action:@selector(dismissView)];
        self.navigationItem.rightBarButtonItem = doneButton;
    }
}

- (IBAction)toggleValueChanged:(id)sender {
    // Optional: Do something when toggles change
}

- (void)dismissView {
    // Notify the delegate with the toggle values
    if ([self.delegate respondsToSelector:@selector(didUpdateTogglesWithFirstToggle:secondToggle:)]) {
        [self.delegate didUpdateTogglesWithFirstToggle:self.firstToggleSwitch.isOn
                                          secondToggle:self.secondToggleSwitch.isOn];
    }

    // Dismiss the view controller
    [self dismissViewControllerAnimated:YES completion:nil];
}

#pragma mark - Popover Style
- (UIModalPresentationStyle)modalPresentationStyle {
    // Explicitly set to popover for iPad
    return UIModalPresentationPopover;
}

@end