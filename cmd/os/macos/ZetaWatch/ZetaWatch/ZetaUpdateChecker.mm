// SPDX-License-Identifier: BSD-3-Clause
//
//  ZetaUpdateChecker.mm
//  ZetaWatch
//
//  Checks the GitHub releases for a newer OpenZFS on OS X than the loaded
//  kext, and offers it in the menu and as a notification.
//

#import "ZetaUpdateChecker.h"
#import "ZetaUserNotification.h"

#include <sys/sysctl.h>

#include <cstdlib>

static NSString * const kReleasesURL =
	@"https://api.github.com/repos/openzfsonosx/openzfs-fork/releases?per_page=30";
static NSString * const kTagPrefix = @"zfs-macOS-";
static NSString * const kCheckKey = @"checkForUpdates";
static NSString * const kPrereleaseKey = @"checkForPrereleases";
static NSString * const kNotifiedKey = @"notifiedUpdateVersion";

static const NSTimeInterval kFirstCheck = 30;
static const NSTimeInterval kCheckInterval = 24 * 60 * 60;

// An OpenZFS on OS X version, as in "2.4.4rc1" (a tag), "2.4.3-rc5" (the
// kext) or "2.4.1p1". Release candidates sort before the release, and
// patch releases after it.
struct ZetaVersion
{
	long num[4] = {};
	int rank = 1;		// 0 rc, 1 release, 2 patch release
	long sub = 0;		// the rc or patch number

	explicit ZetaVersion(NSString * s)
	{
		const char * p = s.UTF8String;
		while (*p && (*p < '0' || *p > '9'))
			++p;
		for (int i = 0; i < 4 && *p >= '0' && *p <= '9'; ++i)
		{
			char * end;
			num[i] = strtol(p, &end, 10);
			p = end;
			if (*p != '.')
				break;
			++p;
		}
		if (*p == '-')
			++p;
		if (strncmp(p, "rc", 2) == 0)
		{
			rank = 0;
			sub = strtol(p + 2, nullptr, 10);
		}
		else if (*p == 'p' && p[1] >= '0' && p[1] <= '9')
		{
			rank = 2;
			sub = strtol(p + 1, nullptr, 10);
		}
	}

	bool valid() const
	{
		return num[0] != 0 || num[1] != 0 || num[2] != 0;
	}

	bool operator<(ZetaVersion const & o) const
	{
		for (int i = 0; i < 4; ++i)
			if (num[i] != o.num[i])
				return num[i] < o.num[i];
		if (rank != o.rank)
			return rank < o.rank;
		return sub < o.sub;
	}
};

// The loaded kext's version, or nil when ZFS is not loaded.
static NSString * installedVersion()
{
	char buf[128] = {};
	size_t len = sizeof(buf) - 1;
	if (sysctlbyname("zfs.kext_version", buf, &len, nullptr, 0) != 0)
		return nil;
	return [NSString stringWithUTF8String:buf];
}

// pkg_macos.sh names packages "OpenZFSonOsX-<version>-<Name>-<os>.pkg",
// with "-arm64" before ".pkg" for Apple silicon, and <os> being the major
// version, or "10.<minor>" before Big Sur.
static NSString * packageSuffix()
{
	NSOperatingSystemVersion v = NSProcessInfo.processInfo.operatingSystemVersion;
	NSString * os = v.majorVersion == 10 ?
		[NSString stringWithFormat:@"10.%ld", (long)v.minorVersion] :
		[NSString stringWithFormat:@"%ld", (long)v.majorVersion];
#if defined(__arm64__)
	return [NSString stringWithFormat:@"-%@-arm64.pkg", os];
#else
	return [NSString stringWithFormat:@"-%@.pkg", os];
#endif
}

@implementation ZetaUpdateChecker
{
	NSMenuItem * _availableItem;
	NSMenuItem * _availableSeparator;
	NSURL * _releaseURL;
	NSTimer * _timer;
	NSUInteger _generation;
}

- (void)startWithMenu:(NSMenu *)menu settingsMenu:(NSMenu *)settingsMenu
{
	_availableItem = [[NSMenuItem alloc] initWithTitle:@""
		action:@selector(openRelease:) keyEquivalent:@""];
	_availableItem.target = self;
	_availableItem.hidden = YES;
	_availableSeparator = [NSMenuItem separatorItem];
	_availableSeparator.hidden = YES;
	NSInteger quit = [menu indexOfItemWithTarget:NSApp andAction:@selector(terminate:)];
	if (quit < 0)
		quit = menu.numberOfItems;
	[menu insertItem:_availableSeparator atIndex:quit];
	[menu insertItem:_availableItem atIndex:quit];

	if (settingsMenu)
	{
		NSMenuItem * check = [[NSMenuItem alloc]
			initWithTitle:NSLocalizedString(@"Check for New Versions", @"Settings menu")
			action:@selector(toggleCheck:) keyEquivalent:@""];
		check.target = self;
		NSMenuItem * pre = [[NSMenuItem alloc]
			initWithTitle:NSLocalizedString(@"Include Pre-releases", @"Settings menu")
			action:@selector(togglePrereleases:) keyEquivalent:@""];
		pre.target = self;
		pre.indentationLevel = 1;
		// Above the separator before "More Settings...".
		NSInteger idx = settingsMenu.numberOfItems;
		for (NSInteger i = 0; i < settingsMenu.numberOfItems; ++i)
			if ([settingsMenu itemAtIndex:i].action == @selector(showSettings:))
				idx = i;
		if (idx > 0 && [settingsMenu itemAtIndex:idx - 1].isSeparatorItem)
			--idx;
		[settingsMenu insertItem:pre atIndex:idx];
		[settingsMenu insertItem:check atIndex:idx];
		[settingsMenu insertItem:[NSMenuItem separatorItem] atIndex:idx];
	}

	// The daily timer may run up to an hour late; the first check should not.
	_timer = [NSTimer scheduledTimerWithTimeInterval:kCheckInterval target:self
		selector:@selector(timerFired:) userInfo:nil repeats:YES];
	_timer.tolerance = 60 * 60;
	[self performSelector:@selector(check) withObject:nil afterDelay:kFirstCheck];
}

- (void)stop
{
	[NSObject cancelPreviousPerformRequestsWithTarget:self];
	[_timer invalidate];
	_timer = nil;
}

- (BOOL)validateMenuItem:(NSMenuItem *)item
{
	auto defaults = [NSUserDefaults standardUserDefaults];
	bool checking = [defaults boolForKey:kCheckKey];
	if (item.action == @selector(toggleCheck:))
	{
		item.state = checking ? NSControlStateValueOn : NSControlStateValueOff;
		return YES;
	}
	if (item.action == @selector(togglePrereleases:))
	{
		item.state = [defaults boolForKey:kPrereleaseKey] ?
			NSControlStateValueOn : NSControlStateValueOff;
		return checking;
	}
	return YES;
}

- (IBAction)toggleCheck:(id)sender
{
	auto defaults = [NSUserDefaults standardUserDefaults];
	[defaults setBool:![defaults boolForKey:kCheckKey] forKey:kCheckKey];
	[self check];
}

- (IBAction)togglePrereleases:(id)sender
{
	auto defaults = [NSUserDefaults standardUserDefaults];
	[defaults setBool:![defaults boolForKey:kPrereleaseKey] forKey:kPrereleaseKey];
	[self check];
}

- (IBAction)openRelease:(id)sender
{
	if (_releaseURL)
		[[NSWorkspace sharedWorkspace] openURL:_releaseURL];
}

- (void)timerFired:(NSTimer *)timer
{
	[self check];
}

- (void)showAvailable:(NSString *)version url:(NSURL *)url
{
	_releaseURL = url;
	bool show = version != nil;
	_availableItem.hidden = !show;
	_availableSeparator.hidden = !show;
	if (!show)
		return;
	_availableItem.title = [NSString stringWithFormat:
		NSLocalizedString(@"OpenZFS %@ Is Available…", @"Update menu item"),
		version];

	// Notify once per version; the menu item stays until it is installed.
	// It only counts once it was shown, so a notification dropped before
	// the user allowed them is tried again on the next check.
	auto defaults = [NSUserDefaults standardUserDefaults];
	if ([[defaults stringForKey:kNotifiedKey] isEqualToString:version])
		return;
	ZetaNotify(NSLocalizedString(@"OpenZFS Update Available",
			@"Update notification title"),
		[NSString stringWithFormat:
			NSLocalizedString(@"OpenZFS on OS X %@ is available. You have %@.",
				@"Update notification text"),
			version, installedVersion() ?: @"?"],
		url, 0, ^(BOOL shown) {
			if (shown)
				[defaults setObject:version forKey:kNotifiedKey];
		});
}

- (void)check
{
	NSUInteger generation = ++_generation;
	auto defaults = [NSUserDefaults standardUserDefaults];
	NSString * installed = installedVersion();
	if (![defaults boolForKey:kCheckKey] || !installed)
	{
		[self showAvailable:nil url:nil];
		return;
	}
	bool prereleases = [defaults boolForKey:kPrereleaseKey];
	NSString * suffix = packageSuffix();

	NSMutableURLRequest * request = [NSMutableURLRequest
		requestWithURL:[NSURL URLWithString:kReleasesURL]];
	[request setValue:@"application/vnd.github+json" forHTTPHeaderField:@"Accept"];
	[request setValue:@"ZetaWatch" forHTTPHeaderField:@"User-Agent"];
	request.cachePolicy = NSURLRequestReloadIgnoringLocalCacheData;
	NSURLSessionDataTask * task = [[NSURLSession sharedSession]
		dataTaskWithRequest:request
		completionHandler:^(NSData * data, NSURLResponse * response, NSError * error)
	{
		NSHTTPURLResponse * http = (NSHTTPURLResponse *)response;
		NSArray * releases = nil;
		if (!error && data && http.statusCode == 200)
			releases = [NSJSONSerialization JSONObjectWithData:data
				options:0 error:nullptr];
		if (![releases isKindOfClass:[NSArray class]])
			return;	// keep what is shown until a check succeeds

		// The newest release, by version, with a package for this Mac.
		ZetaVersion best(installed);
		NSString * bestVersion = nil;
		NSURL * bestURL = nil;
		for (NSDictionary * r in releases)
		{
			if (![r isKindOfClass:[NSDictionary class]] ||
				[r[@"draft"] boolValue] ||
				(!prereleases && [r[@"prerelease"] boolValue]))
				continue;
			NSString * tag = r[@"tag_name"];
			if (![tag isKindOfClass:[NSString class]] || ![tag hasPrefix:kTagPrefix])
				continue;
			ZetaVersion v(tag);
			if (!v.valid() || !(best < v))
				continue;
			bool hasPackage = false;
			for (NSDictionary * a in r[@"assets"])
				if ([a isKindOfClass:[NSDictionary class]] &&
					[a[@"name"] isKindOfClass:[NSString class]] &&
					[a[@"name"] hasSuffix:suffix])
					hasPackage = true;
			NSString * page = r[@"html_url"];
			if (!hasPackage || ![page isKindOfClass:[NSString class]])
				continue;
			best = v;
			bestVersion = [tag substringFromIndex:kTagPrefix.length];
			bestURL = [NSURL URLWithString:page];
		}
		dispatch_async(dispatch_get_main_queue(), ^{
			if (generation == self->_generation)
				[self showAvailable:bestURL ? bestVersion : nil url:bestURL];
		});
	}];
	[task resume];
}

@end
