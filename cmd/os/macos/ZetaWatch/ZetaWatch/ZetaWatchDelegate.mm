//
//  ZetaWatchDelegate.mm
//  ZetaWatch
//
//  Created by Gerhard Röthlin on 2015.12.20.
//  Copyright © 2015 the-color-black.net. All rights reserved.
//
//  Redistribution and use in source and binary forms, with or without modification, are permitted
//  provided that the conditions of the "3-Clause BSD" license described in the BSD.LICENSE file are met.
//  Additional licensing options are described in the README file.
//

#import "ZetaWatchDelegate.h"

#import "ZetaAuthorization.h"
#import "ZetaMainMenu.h"
#import "ZetaKeyLoader.h"
#import "ZetaQueryDialog.h"
#import "ZetaDictQueryDialog.h"
#import "ZetaConfirmDialog.h"
#import "ZetaVersionsWindow.h"
#import "ZetaDeletedItemsWindow.h"
#import "ZetaUpdateChecker.h"

#import "ZFSUtils.hpp"

#import <ServiceManagement/SMLoginItem.h>

@interface ZetaWatchDelegate ()
{
	NSStatusItem * _statusItem;
}

@property (weak) IBOutlet NSMenu * zetaMenu;
@property (weak) IBOutlet ZetaAuthorization * authorization;
@property (weak) IBOutlet ZetaMainMenu * zetaMainMenu;
@property (weak) IBOutlet ZetaKeyLoader * zetaKeyLoader;
@property (weak) IBOutlet ZetaQueryDialog * zetaQueryDialog;
@property (weak) IBOutlet ZetaConfirmDialog * zetaConfirmDialog;
@property (weak) IBOutlet ZetaPoolWatcher * poolWatcher;
@property (weak) IBOutlet NSPopover * settings;

@property (strong) ZetaDictQueryDialog * zetaNewFSDialog;
@property (strong) ZetaDictQueryDialog * zetaNewVolDialog;
@property (strong) ZetaUpdateChecker * updateChecker;

@end

@implementation ZetaWatchDelegate

- (void)applicationDidFinishLaunching:(NSNotification *)aNotification
{
	// Menu Item
	NSStatusBar * bar = [NSStatusBar systemStatusBar];
	_statusItem = [bar statusItemWithLength:NSSquareStatusItemLength];
	NSImage * zetaImage = [NSImage imageNamed:@"Zeta"];
	[zetaImage setTemplate:YES];
	_statusItem.button.image = zetaImage;
	_statusItem.menu = _zetaMenu;
	_zetaKeyLoader.statusItem = _statusItem;
	_zetaQueryDialog.statusItem = _statusItem;
	_zetaConfirmDialog.statusItem = _statusItem;
	// Dialogs
	_zetaNewFSDialog = [[ZetaDictQueryDialog alloc] initWithDialog:@"NewFS"];
	_zetaNewFSDialog.statusItem = _statusItem;
	_zetaMainMenu.zetaNewFSDialog = _zetaNewFSDialog;
	_zetaNewVolDialog = [[ZetaDictQueryDialog alloc] initWithDialog:@"NewVol"];
	_zetaNewVolDialog.statusItem = _statusItem;
	_zetaMainMenu.zetaNewVolDialog = _zetaNewVolDialog;
	// Watcher
	[[self poolWatcher] checkForChanges];
	// User Notification Center Delegate
	[[NSUserNotificationCenter defaultUserNotificationCenter] setDelegate:self];
	// Finder's Services menu: "ZFS Versions…" (NSServices in Info.plist)
	[NSApp setServicesProvider:self];
	NSUpdateDynamicServices();
	// New version check, with its settings next to "More Settings..."
	NSMenu * settingsMenu = nil;
	for (NSMenuItem * item in _zetaMenu.itemArray)
		for (NSMenuItem * sub in item.submenu.itemArray)
			if (sub.action == @selector(showSettings:))
				settingsMenu = item.submenu;
	_updateChecker = [[ZetaUpdateChecker alloc] init];
	[_updateChecker startWithMenu:_zetaMenu settingsMenu:settingsMenu];
	// Login Item
	[[NSUserDefaults standardUserDefaults] addObserver:self forKeyPath:@"startAtLogin"
											   options:NSKeyValueObservingOptionInitial
											   context:nullptr];
}

- (void)applicationWillFinishLaunching:(NSNotification *)notification
{
	// User Defaults
	[[NSUserDefaults standardUserDefaults] registerDefaults:@{
		@"autoUnlock": @YES,
		@"autoImport": @YES,
		@"allowHostIDMismatch": @NO,
		@"useKeychain": @NO,
		@"startAtLogin": @YES,
		@"keepAwakeDuringScrub": @YES,
		@"checkForUpdates": @YES,
		@"checkForPrereleases": @NO,
		@"defaultAltroot": @"/Volumes",
		@"useAltroot": @NO,
		@"searchPathOverride": @[
				@"/var/run/disk/by-serial",
				@"/var/run/disk/by-id",
		],
	}];
}

- (void)applicationWillTerminate:(NSNotification *)aNotification
{
	[[NSUserDefaults standardUserDefaults] removeObserver:self forKeyPath:@"startAtLogin"];
	[_updateChecker stop];
	[self.authorization stopHelper];
}

- (BOOL)userNotificationCenter:(NSUserNotificationCenter *)center
	 shouldPresentNotification:(NSUserNotification *)notification
{
	return YES;
}

// The update notification carries its release page.
- (void)userNotificationCenter:(NSUserNotificationCenter *)center
	   didActivateNotification:(NSUserNotification *)notification
{
	NSString * url = notification.userInfo[@"url"];
	if ([url isKindOfClass:[NSString class]])
		[[NSWorkspace sharedWorkspace] openURL:[NSURL URLWithString:url]];
}

- (void)observeValueForKeyPath:(NSString *)keyPath
					  ofObject:(id)object
						change:(NSDictionary<NSKeyValueChangeKey, id> *)change
					   context:(void *)context
{
	if ([keyPath isEqualToString:@"startAtLogin"])
	{
		bool startAtLogin = [object boolForKey:@"startAtLogin"];
		SMLoginItemSetEnabled(CFSTR("org.openzfsonosx.ZetaLoginItemHelper"), startAtLogin);
	}
}

// zetawatch://versions?path=<path> shows the ZFS versions of an item, as
// does opening a file or folder with ZetaWatch; zetawatch://deleted?path=
// shows what was deleted from a folder.
- (void)application:(NSApplication *)application openURLs:(NSArray<NSURL *> *)urls
{
	for (NSURL * url in urls)
	{
		NSURL * item = nil;
		bool deleted = false;
		if (url.isFileURL)
		{
			item = url;
		}
		else if ([url.scheme isEqualToString:@"zetawatch"] &&
			([url.host isEqualToString:@"versions"] ||
			 [url.host isEqualToString:@"deleted"]))
		{
			deleted = [url.host isEqualToString:@"deleted"];
			NSURLComponents * c = [NSURLComponents componentsWithURL:url
				resolvingAgainstBaseURL:NO];
			for (NSURLQueryItem * q in c.queryItems)
				if ([q.name isEqualToString:@"path"] && q.value.length)
					item = [NSURL fileURLWithPath:q.value];
		}
		if (item && deleted)
			[ZetaDeletedItemsWindow showDeletedItemsIn:item authorization:self.authorization];
		else if (item)
			[ZetaVersionsWindow showVersionsOf:item authorization:self.authorization];
	}
}

// Services menu "ZFS Versions…" on the files and folders selected in Finder.
- (void)showZFSVersions:(NSPasteboard *)pboard
			   userData:(NSString *)userData
				  error:(NSString **)error
{
	NSArray<NSURL *> * urls = [pboard readObjectsForClasses:@[[NSURL class]]
		options:@{NSPasteboardURLReadingFileURLsOnlyKey: @YES}];
	if (urls.count == 0)
	{
		if (error)
			*error = NSLocalizedString(@"No file or folder was selected", @"Service error");
		return;
	}
	for (NSURL * url in urls)
		[ZetaVersionsWindow showVersionsOf:url authorization:self.authorization];
}

// Services menu "ZFS Deleted Items…" on the folders selected in Finder.
- (void)showZFSDeletedItems:(NSPasteboard *)pboard
				   userData:(NSString *)userData
					  error:(NSString **)error
{
	NSArray<NSURL *> * urls = [pboard readObjectsForClasses:@[[NSURL class]]
		options:@{NSPasteboardURLReadingFileURLsOnlyKey: @YES}];
	if (urls.count == 0)
	{
		if (error)
			*error = NSLocalizedString(@"No folder was selected", @"Service error");
		return;
	}
	for (NSURL * url in urls)
		[ZetaDeletedItemsWindow showDeletedItemsIn:url authorization:self.authorization];
}

- (IBAction)showSettings:(id)sender
{
	NSView * positioningView = [_statusItem button];
	[_settings showRelativeToRect:NSMakeRect(0, 0, 0, 0)
						   ofView:positioningView preferredEdge:NSRectEdgeMinY];
}

@end
