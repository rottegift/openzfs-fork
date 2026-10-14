// SPDX-License-Identifier: BSD-3-Clause
//
//  ZetaUpdateChecker.h
//  ZetaWatch
//
//  Checks the GitHub releases for a newer OpenZFS on OS X than the loaded
//  kext, and offers it in the menu and as a notification.
//

/* CSTYLED */
#import <Cocoa/Cocoa.h>

@interface ZetaUpdateChecker : NSObject

// Adds the settings to settingsMenu and the "available" item to menu, just
// above its Quit item, then starts checking as the settings allow.
- (void)startWithMenu:(NSMenu *)menu settingsMenu:(NSMenu *)settingsMenu;

- (void)stop;

@end
