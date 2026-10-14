// SPDX-License-Identifier: BSD-3-Clause
//
//  ZetaDeletedItemsWindow.h
//  ZetaWatch
//
//  Lists what was deleted from a folder but is still in its snapshots,
//  and opens, copies or restores it.
//

/* CSTYLED */
#import <Cocoa/Cocoa.h>

@class ZetaAuthorization;

@interface ZetaDeletedItemsWindow : NSWindowController

// Shows the deleted items window for the folder at url, reusing the open
// one for the same folder.
+ (void)showDeletedItemsIn:(NSURL *)url
    authorization:(ZetaAuthorization *)authorization;

@end
