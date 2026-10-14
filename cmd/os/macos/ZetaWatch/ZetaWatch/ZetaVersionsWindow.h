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

// Paths below are passed to the file system as their UTF-8 bytes, not
// -fileSystemRepresentation, which decomposes names (NFD): on a dataset
// with normalization=none, a name stored precomposed would not be found.

// A file URL that keeps path's bytes as they are.
NSURL * ZetaFileURL(NSString * path);

// copyfile() with xattrs, resource forks and ACLs (recursively for
// folders) off the main thread; completion runs on the main thread with
// an errno. With replace, an existing target is removed first; without,
// an existing target fails with EEXIST.
void ZetaCopyItem(NSString * source, NSString * target, bool recursive,
    bool replace, void (^completion)(int err));

// Where path (within the dataset) is in snapshot ("pool/fs@snap"), under
// the dataset's mountpoint; reading it mounts that snapshot.
NSString * ZetaSnapshotPath(NSString * mountpoint, NSString * snapshot,
    NSString * path);
