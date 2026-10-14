// SPDX-License-Identifier: BSD-3-Clause
//
//  ZetaVersionsWindow.mm
//  ZetaWatch
//
//  Lists the snapshot versions of one file or folder ("ZFS versions"),
//  and opens, copies or restores them.
//

#import "ZetaVersionsWindow.h"

#import "ZetaAuthorization.h"
#import "ZetaDeletedItemsWindow.h"

#include <copyfile.h>
#include <removefile.h>
#include <stdio.h>
#include <sys/stat.h>
#include <unistd.h>

static NSString * const kColumnSnapshot = @"snapshot";
static NSString * const kColumnModified = @"modified";
static NSString * const kColumnAge = @"age";
static NSString * const kColumnSize = @"size";

// Open windows, one per item, so a second request brings it to the front.
static NSMutableDictionary<NSString *, ZetaVersionsWindow *> * openWindows;

@interface ZetaVersionsWindow () <NSWindowDelegate, NSTableViewDataSource, NSTableViewDelegate>
{
	NSURL * _url;
	ZetaAuthorization * _authorization;
	NSString * _mountpoint;
	NSString * _livePath;		// mountpoint + live path, nil if gone
	bool _isDirectory;
	NSArray<NSDictionary *> * _rows;	// "current" first, then versions
	NSTableView * _table;
	NSTextField * _status;
	NSButton * _openButton;
	NSButton * _copyButton;
	NSButton * _restoreButton;
	NSButton * _deletedButton;
}
@end

void ZetaCopyItem(NSString * source, NSString * target, bool recursive,
	bool replace, void (^completion)(int err))
{
	dispatch_async(dispatch_get_global_queue(QOS_CLASS_USER_INITIATED, 0), ^{
		int err = 0;
		struct stat st;
		if (replace && lstat(target.UTF8String, &st) == 0 &&
			removefile(target.UTF8String, nullptr, REMOVEFILE_RECURSIVE) != 0)
			err = errno;
		copyfile_flags_t flags = COPYFILE_ALL |
			(recursive ? COPYFILE_RECURSIVE : 0) | (replace ? 0 : COPYFILE_EXCL);
		if (err == 0 && copyfile(source.UTF8String, target.UTF8String,
			nullptr, flags) != 0)
			err = errno;
		dispatch_async(dispatch_get_main_queue(), ^{ completion(err); });
	});
}

NSURL * ZetaFileURL(NSString * path)
{
	return [NSURL fileURLWithFileSystemRepresentation:path.UTF8String
		isDirectory:NO relativeToURL:nil];
}

NSString * ZetaSnapshotPath(NSString * mountpoint, NSString * snapshot,
	NSString * path)
{
	NSString * snapName = [snapshot substringFromIndex:
		[snapshot rangeOfString:@"@"].location + 1];
	return [NSString stringWithFormat:@"%@/.zfs/snapshot/%@%@",
		[mountpoint isEqualToString:@"/"] ? @"" : mountpoint, snapName, path];
}

@implementation ZetaVersionsWindow

+ (void)showVersionsOf:(NSURL *)url
		 authorization:(ZetaAuthorization *)authorization
{
	if (!openWindows)
		openWindows = [NSMutableDictionary dictionary];
	NSString * key = url.URLByStandardizingPath.path;
	ZetaVersionsWindow * wc = openWindows[key];
	if (!wc)
	{
		wc = [[ZetaVersionsWindow alloc] initWithURL:url
									   authorization:authorization];
		openWindows[key] = wc;
	}
	[wc showWindow:nil];
	[wc.window makeKeyAndOrderFront:nil];
	// ZetaWatch is a menu bar (LSUIElement) app: bring it forward.
	[NSApp activateIgnoringOtherApps:YES];
	[wc reload];
}

- (instancetype)initWithURL:(NSURL *)url
			  authorization:(ZetaAuthorization *)authorization
{
	NSWindow * window = [[NSWindow alloc]
		initWithContentRect:NSMakeRect(0, 0, 640, 360)
				  styleMask:NSWindowStyleMaskTitled | NSWindowStyleMaskClosable |
							NSWindowStyleMaskResizable | NSWindowStyleMaskMiniaturizable
					backing:NSBackingStoreBuffered
					  defer:YES];
	self = [super initWithWindow:window];
	if (self)
	{
		_url = url.URLByStandardizingPath;
		_authorization = authorization;
		window.title = [NSString stringWithFormat:
			NSLocalizedString(@"ZFS Versions of “%@”", @"Versions window title"),
			_url.lastPathComponent];
		window.minSize = NSMakeSize(480, 240);
		window.delegate = self;
		window.releasedWhenClosed = NO;
		[self buildContent];
		[window center];
	}
	return self;
}

#pragma mark Layout

static NSTableColumn * makeColumn(NSString * ident, NSString * title,
	CGFloat width, bool alignRight)
{
	NSTableColumn * col = [[NSTableColumn alloc] initWithIdentifier:ident];
	col.title = title;
	col.width = width;
	col.minWidth = 60;
	if (alignRight)
		col.headerCell.alignment = NSTextAlignmentRight;
	return col;
}

- (void)buildContent
{
	NSView * content = self.window.contentView;

	NSTextField * header = [NSTextField labelWithString:_url.path];
	header.lineBreakMode = NSLineBreakByTruncatingMiddle;
	header.textColor = NSColor.secondaryLabelColor;
	header.translatesAutoresizingMaskIntoConstraints = NO;
	[header setContentCompressionResistancePriority:NSLayoutPriorityDefaultLow
									forOrientation:NSLayoutConstraintOrientationHorizontal];

	_table = [[NSTableView alloc] init];
	[_table addTableColumn:makeColumn(kColumnSnapshot,
		NSLocalizedString(@"Snapshot", @"Versions column"), 200, false)];
	[_table addTableColumn:makeColumn(kColumnModified,
		NSLocalizedString(@"Date Modified", @"Versions column"), 170, false)];
	[_table addTableColumn:makeColumn(kColumnAge,
		NSLocalizedString(@"Age", @"Versions column"), 110, false)];
	[_table addTableColumn:makeColumn(kColumnSize,
		NSLocalizedString(@"Size", @"Versions column"), 90, true)];
	_table.dataSource = self;
	_table.delegate = self;
	_table.usesAlternatingRowBackgroundColors = YES;
	_table.allowsMultipleSelection = NO;
	_table.target = self;
	_table.doubleAction = @selector(openVersion:);
	_table.columnAutoresizingStyle = NSTableViewFirstColumnOnlyAutoresizingStyle;

	NSScrollView * scroll = [[NSScrollView alloc] init];
	scroll.documentView = _table;
	scroll.hasVerticalScroller = YES;
	scroll.borderType = NSBezelBorder;
	scroll.translatesAutoresizingMaskIntoConstraints = NO;

	_status = [NSTextField labelWithString:
		NSLocalizedString(@"Looking for versions…", @"Versions status")];
	_status.textColor = NSColor.secondaryLabelColor;
	_status.lineBreakMode = NSLineBreakByTruncatingTail;
	[_status setContentCompressionResistancePriority:NSLayoutPriorityDefaultLow
									  forOrientation:NSLayoutConstraintOrientationHorizontal];

	_openButton = [NSButton buttonWithTitle:NSLocalizedString(@"Open", @"Versions button")
									 target:self action:@selector(openVersion:)];
	_copyButton = [NSButton buttonWithTitle:NSLocalizedString(@"Copy To…", @"Versions button")
									 target:self action:@selector(copyVersion:)];
	_restoreButton = [NSButton buttonWithTitle:NSLocalizedString(@"Restore…", @"Versions button")
										target:self action:@selector(restoreVersion:)];

	// Folders also offer what was deleted from them.
	_deletedButton = [NSButton buttonWithTitle:NSLocalizedString(@"Deleted Items…", @"Versions button")
										target:self action:@selector(showDeletedItems:)];
	NSNumber * isDir = nil;
	[_url getResourceValue:&isDir forKey:NSURLIsDirectoryKey error:nil];
	_deletedButton.hidden = ![isDir boolValue];

	NSStackView * buttons = [NSStackView stackViewWithViews:
		@[_status, _deletedButton, _openButton, _copyButton, _restoreButton]];
	buttons.orientation = NSUserInterfaceLayoutOrientationHorizontal;
	buttons.translatesAutoresizingMaskIntoConstraints = NO;

	[content addSubview:header];
	[content addSubview:scroll];
	[content addSubview:buttons];
	[NSLayoutConstraint activateConstraints:@[
		[header.topAnchor constraintEqualToAnchor:content.topAnchor constant:12],
		[header.leadingAnchor constraintEqualToAnchor:content.leadingAnchor constant:16],
		[header.trailingAnchor constraintEqualToAnchor:content.trailingAnchor constant:-16],
		[scroll.topAnchor constraintEqualToAnchor:header.bottomAnchor constant:8],
		[scroll.leadingAnchor constraintEqualToAnchor:content.leadingAnchor constant:16],
		[scroll.trailingAnchor constraintEqualToAnchor:content.trailingAnchor constant:-16],
		[buttons.topAnchor constraintEqualToAnchor:scroll.bottomAnchor constant:12],
		[buttons.leadingAnchor constraintEqualToAnchor:content.leadingAnchor constant:16],
		[buttons.trailingAnchor constraintEqualToAnchor:content.trailingAnchor constant:-16],
		[buttons.bottomAnchor constraintEqualToAnchor:content.bottomAnchor constant:-16],
	]];
	[self updateButtons];
}

#pragma mark Data

- (void)reload
{
	_status.stringValue = NSLocalizedString(@"Looking for versions…", @"Versions status");
	[_authorization fileVersions:_url withReply:^(NSError * error, NSDictionary * result)
	{
		if (error)
		{
			self->_rows = @[];
			self->_status.stringValue = error.localizedDescription;
		}
		else
		{
			[self setResult:result];
		}
		[self->_table reloadData];
		[self updateButtons];
	}];
}

static bool sameContent(NSDictionary * a, NSDictionary * b)
{
	return [a[@"size"] isEqual:b[@"size"]] && [a[@"mtime"] isEqual:b[@"mtime"]];
}

- (void)setResult:(NSDictionary *)result
{
	_mountpoint = result[@"mountpoint"];
	NSDictionary * live = result[@"live"];
	_livePath = (live && _mountpoint) ?
		[_mountpoint stringByAppendingString:live[@"path"]] : nil;
	_isDirectory = S_ISDIR([(live ?: [result[@"versions"] firstObject])[@"mode"]
		unsignedLongLongValue]);

	// Show each distinct version once, by the newest snapshot that holds
	// it; versions equal to the current one are not listed (they would
	// restore to what is already there).
	NSMutableArray * rows = [NSMutableArray array];
	if (live)
		[rows addObject:live];
	NSDictionary * previous = live;
	for (NSDictionary * v in result[@"versions"])
	{
		if (previous && sameContent(previous, v))
			continue;
		[rows addObject:v];
		previous = v;
	}
	_rows = rows;

	NSUInteger count = rows.count - (live ? 1 : 0);
	NSUInteger snapshots = [result[@"versions"] count];
	if (count == 0)
		_status.stringValue = snapshots == 0 ?
			NSLocalizedString(@"No snapshots hold this item", @"Versions status") :
			NSLocalizedString(@"Unchanged in every snapshot", @"Versions status");
	else
		_status.stringValue = [NSString stringWithFormat:
			NSLocalizedString(@"%lu earlier version(s) in %lu snapshot(s) of %@", @"Versions status"),
			(unsigned long)count, (unsigned long)snapshots, result[@"dataset"]];
}

// Where a row's content can be read: the live item, or the item inside the
// snapshot's .zfs/snapshot directory (which mounts that one snapshot).
- (NSString *)pathForRow:(NSInteger)row
{
	if (row < 0 || row >= (NSInteger)_rows.count || !_mountpoint)
		return nil;
	NSDictionary * v = _rows[row];
	NSString * snapshot = v[@"snapshot"];
	if (!snapshot)
		return _livePath;
	return ZetaSnapshotPath(_mountpoint, snapshot, v[@"path"]);
}

- (void)updateButtons
{
	NSInteger row = _table.selectedRow;
	bool haveRow = row >= 0 && [self pathForRow:row] != nil;
	bool isSnapshot = haveRow && _rows[row][@"snapshot"] != nil;
	_openButton.enabled = haveRow;
	_copyButton.enabled = haveRow;
	// Restoring a whole folder over the current one is too easy to get
	// wrong; Copy To… handles folders.
	_restoreButton.enabled = isSnapshot && !_isDirectory && _livePath != nil;
}

#pragma mark Table

- (NSInteger)numberOfRowsInTableView:(NSTableView *)tableView
{
	return _rows.count;
}

- (NSView *)tableView:(NSTableView *)tableView
   viewForTableColumn:(NSTableColumn *)column
				  row:(NSInteger)row
{
	NSTextField * cell = [tableView makeViewWithIdentifier:column.identifier owner:self];
	if (!cell)
	{
		cell = [NSTextField labelWithString:@""];
		cell.identifier = column.identifier;
		cell.lineBreakMode = NSLineBreakByTruncatingTail;
	}
	NSDictionary * v = _rows[row];
	NSString * ident = column.identifier;
	cell.alignment = NSTextAlignmentLeft;
	cell.font = [NSFont systemFontOfSize:NSFont.systemFontSize];
	if ([ident isEqualToString:kColumnSnapshot])
	{
		NSString * snapshot = v[@"snapshot"];
		if (snapshot)
		{
			cell.stringValue = [snapshot substringFromIndex:
				[snapshot rangeOfString:@"@"].location + 1];
		}
		else
		{
			cell.stringValue = NSLocalizedString(@"Current version", @"Versions row");
			cell.font = [NSFont boldSystemFontOfSize:NSFont.systemFontSize];
		}
	}
	else if ([ident isEqualToString:kColumnModified])
	{
		cell.stringValue = [NSDateFormatter localizedStringFromDate:v[@"mtime"]
			dateStyle:NSDateFormatterMediumStyle timeStyle:NSDateFormatterMediumStyle];
	}
	else if ([ident isEqualToString:kColumnAge])
	{
		NSRelativeDateTimeFormatter * f = [[NSRelativeDateTimeFormatter alloc] init];
		cell.stringValue = [f localizedStringForDate:v[@"mtime"] relativeToDate:[NSDate date]];
	}
	else if ([ident isEqualToString:kColumnSize])
	{
		cell.alignment = NSTextAlignmentRight;
		cell.stringValue = _isDirectory ?
			[NSString stringWithFormat:NSLocalizedString(@"%@ items", @"Folder entries"), v[@"size"]] :
			[NSByteCountFormatter stringFromByteCount:[v[@"size"] longLongValue]
				countStyle:NSByteCountFormatterCountStyleFile];
	}
	return cell;
}

- (void)tableViewSelectionDidChange:(NSNotification *)notification
{
	[self updateButtons];
}

#pragma mark Actions

- (void)showError:(NSString *)message detail:(NSString *)detail
{
	NSAlert * alert = [[NSAlert alloc] init];
	alert.alertStyle = NSAlertStyleWarning;
	alert.messageText = message;
	alert.informativeText = detail ?: @"";
	[alert beginSheetModalForWindow:self.window completionHandler:nil];
}

- (IBAction)openVersion:(id)sender
{
	NSString * path = [self pathForRow:_table.selectedRow];
	if (!path)
		return;
	NSURL * url = ZetaFileURL(path);
	// Folders open in Finder; files in their default app (read only,
	// as snapshots are read only).
	if (![[NSWorkspace sharedWorkspace] openURL:url])
		[self showError:NSLocalizedString(@"The version could not be opened", @"Versions error")
				 detail:path];
}

- (IBAction)copyVersion:(id)sender
{
	NSInteger row = _table.selectedRow;
	NSString * source = [self pathForRow:row];
	if (!source)
		return;
	NSSavePanel * panel = [NSSavePanel savePanel];
	NSString * base = _url.lastPathComponent.stringByDeletingPathExtension;
	NSString * ext = _url.pathExtension;
	NSString * snapshot = _rows[row][@"snapshot"];
	NSString * suffix = snapshot ?
		[snapshot substringFromIndex:[snapshot rangeOfString:@"@"].location + 1] :
		NSLocalizedString(@"copy", @"Copy suffix");
	NSString * name = [NSString stringWithFormat:@"%@ (%@)", base, suffix];
	panel.nameFieldStringValue = ext.length ? [name stringByAppendingPathExtension:ext] : name;
	panel.directoryURL = _url.URLByDeletingLastPathComponent;
	[panel beginSheetModalForWindow:self.window completionHandler:^(NSModalResponse response)
	{
		if (response != NSModalResponseOK)
			return;
		NSString * target = panel.URL.path;
		[self copyFrom:source to:target completion:^(int err)
		{
			if (err != 0)
				[self showError:NSLocalizedString(@"The version could not be copied", @"Versions error")
						 detail:[NSString stringWithUTF8String:strerror(err)]];
			else
				[[NSWorkspace sharedWorkspace] activateFileViewerSelectingURLs:@[panel.URL]];
		}];
	}];
}

// Shared with the deleted items window. NSSavePanel already confirmed any
// overwrite, so an existing target (or folder) is removed first.
- (void)copyFrom:(NSString *)source to:(NSString *)target
	  completion:(void (^)(int err))completion
{
	ZetaCopyItem(source, target, _isDirectory, true, completion);
}

- (IBAction)restoreVersion:(id)sender
{
	NSInteger row = _table.selectedRow;
	NSString * source = [self pathForRow:row];
	NSString * live = _livePath;
	if (!source || !live || !_rows[row][@"snapshot"] || _isDirectory)
		return;
	NSAlert * alert = [[NSAlert alloc] init];
	alert.messageText = [NSString stringWithFormat:
		NSLocalizedString(@"Replace “%@” with the version from %@?", @"Restore question"),
		live.lastPathComponent,
		[NSDateFormatter localizedStringFromDate:_rows[row][@"mtime"]
			dateStyle:NSDateFormatterMediumStyle timeStyle:NSDateFormatterShortStyle]];
	alert.informativeText = NSLocalizedString(
		@"The current version is replaced. It stays in any snapshot that already holds it.",
		@"Restore detail");
	[alert addButtonWithTitle:NSLocalizedString(@"Restore", @"Restore button")];
	[alert addButtonWithTitle:NSLocalizedString(@"Cancel", @"Cancel button")];
	[alert beginSheetModalForWindow:self.window completionHandler:^(NSModalResponse response)
	{
		if (response != NSAlertFirstButtonReturn)
			return;
		// Copy the old version next to the file first, so a failure to
		// read the snapshot leaves the current file alone. Then copy it
		// over the current file in place: renaming over it would make a
		// new object, which has no versions in any snapshot.
		NSString * temp = [[live stringByDeletingLastPathComponent]
			stringByAppendingPathComponent:[NSString stringWithFormat:
				@".%@.zfs-restore-%d", live.lastPathComponent, getpid()]];
		[self copyFrom:source to:temp completion:^(int err)
		{
			if (err == 0)
			{
				dispatch_async(dispatch_get_global_queue(QOS_CLASS_USER_INITIATED, 0), ^{
					int cerr = copyfile(temp.UTF8String, live.UTF8String,
						nullptr, COPYFILE_ALL) != 0 ? errno : 0;
					(void) unlink(temp.UTF8String);
					dispatch_async(dispatch_get_main_queue(), ^{
						[self restoreFinished:cerr];
					});
				});
				return;
			}
			(void) unlink(temp.UTF8String);
			[self restoreFinished:err];
		}];
	}];
}

- (IBAction)showDeletedItems:(id)sender
{
	[ZetaDeletedItemsWindow showDeletedItemsIn:_url authorization:_authorization];
}

- (void)restoreFinished:(int)err
{
	if (err != 0)
		[self showError:NSLocalizedString(@"The version could not be restored", @"Versions error")
				 detail:[NSString stringWithUTF8String:strerror(err)]];
	[self reload];
}

#pragma mark Window

- (void)windowWillClose:(NSNotification *)notification
{
	// Release this controller once its window is gone.
	dispatch_async(dispatch_get_main_queue(), ^{
		[openWindows removeObjectForKey:self->_url.path];
	});
}

@end
