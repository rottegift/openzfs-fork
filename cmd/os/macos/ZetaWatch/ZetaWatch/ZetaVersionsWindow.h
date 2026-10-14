// SPDX-License-Identifier: BSD-3-Clause
//
//  ZetaVersionsWindow.h
//  ZetaWatch
//
//  Lists the snapshot versions of one file or folder ("ZFS versions"),
//  and opens, copies or restores them.
//

/* CSTYLED */
#import <Cocoa/Cocoa.h>

@class ZetaAuthorization;

@interface ZetaVersionsWindow : NSWindowController

// Shows the versions window for url, reusing the open one for the same
// item. Built in code, not from a nib, so the app still builds with only
// the Command Line Tools (no ibtool).
+ (void)showVersionsOf:(NSURL *)url
    authorization:(ZetaAuthorization *)authorization;

@end
