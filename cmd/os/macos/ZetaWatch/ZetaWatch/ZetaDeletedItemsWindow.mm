// SPDX-License-Identifier: BSD-3-Clause
//
//  ZetaDeletedItemsWindow.mm
//  ZetaWatch
//
//  Lists what was deleted from a folder but is still in its snapshots,
//  and opens, copies or restores it.
//

#import "ZetaDeletedItemsWindow.h"

#import "ZetaAuthorization.h"
#import "ZetaVersionsWindow.h"

#include <removefile.h>
#include <stdio.h>
#include <unistd.h>

static NSString * const kColumnName = @"name";
static NSString * const kColumnSnapshot = @"snapshot";
static NSString * const kColumnModified = @"modified";
static NSString * const kColumnSize = @"size";

static NSMutableDictionary<NSString *, ZetaDeletedItemsWindow *> * openWindows;

@interface ZetaDeletedItemsWindow () <NSWindowDelegate, NSTableViewDataSource, NSTableViewDelegate>
{
	NSURL * _url;
	ZetaAuthorization * _authorization;
	NSString * _mountpoint;
	// One row per item and version: {item, version, first}, where first
	// marks an item's newest version (the row that shows its name).
	NSArray<NSDictionary *> * _rows;
	NSTableView * _table;
	NSTextField * _status;
	NSButton * _openButton;
	NSButton * _copyButton;
	NSButton * _restoreButton;
}
@end

@implementation ZetaDeletedItemsWindow

+ (void)showDeletedItemsIn:(NSURL *)url
			 authorization:(ZetaAuthorization *)authorization
{
	if (!openWindows)
		openWindows = [NSMutableDictionary dictionary];
	NSString * key = url.URLByStandardizingPath.path;
	ZetaDeletedItemsWindow * wc = openWindows[key];
	if (!wc)
	{
		wc = [[ZetaDeletedItemsWindow alloc] initWithURL:url
										  authorization:authorization];
		openWindows[key] = wc;
	}
	[wc showWindow:nil];
	[wc.window makeKeyAndOrderFront:nil];
	[NSApp activateIgnoringOtherApps:YES];
	[wc reload];
}

- (instancetype)initWithURL:(NSURL *)url
			  authorization:(ZetaAuthorization *)authorization
{
	NSWindow * window = [[NSWindow alloc]
		initWithContentRect:NSMakeRect(0, 0, 720, 400)
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
			NSLocalizedString(@"Deleted from “%@”", @"Deleted items window title"),
			_url.lastPathComponent.length ? _url.lastPathComponent : _url.path];
		window.minSize = NSMakeSize(520, 240);
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
	[_table addTableColumn:makeColumn(kColumnName,
		NSLocalizedString(@"Name", @"Deleted items column"), 220, false)];
	[_table addTableColumn:makeColumn(kColumnSnapshot,
		NSLocalizedString(@"Snapshot", @"Deleted items column"), 160, false)];
	[_table addTableColumn:makeColumn(kColumnModified,
		NSLocalizedString(@"Date Modified", @"Deleted items column"), 170, false)];
	[_table addTableColumn:makeColumn(kColumnSize,
		NSLocalizedString(@"Size", @"Deleted items column"), 90, true)];
	_table.dataSource = self;
	_table.delegate = self;
	_table.usesAlternatingRowBackgroundColors = YES;
	_table.allowsMultipleSelection = NO;
	_table.target = self;
	_table.doubleAction = @selector(openItem:);
	_table.columnAutoresizingStyle = NSTableViewFirstColumnOnlyAutoresizingStyle;

	NSScrollView * scroll = [[NSScrollView alloc] init];
	scroll.documentView = _table;
	scroll.hasVerticalScroller = YES;
	scroll.borderType = NSBezelBorder;
	scroll.translatesAutoresizingMaskIntoConstraints = NO;

	_status = [NSTextField labelWithString:@""];
	_status.textColor = NSColor.secondaryLabelColor;
	_status.lineBreakMode = NSLineBreakByTruncatingTail;
	[_status setContentCompressionResistancePriority:NSLayoutPriorityDefaultLow
									  forOrientation:NSLayoutConstraintOrientationHorizontal];

	_openButton = [NSButton buttonWithTitle:NSLocalizedString(@"Open", @"Deleted items button")
									 target:self action:@selector(openItem:)];
	_copyButton = [NSButton buttonWithTitle:NSLocalizedString(@"Copy To…", @"Deleted items button")
									 target:self action:@selector(copyItem:)];
	_restoreButton = [NSButton buttonWithTitle:NSLocalizedString(@"Restore", @"Deleted items button")
										target:self action:@selector(restoreItem:)];

	NSStackView * buttons = [NSStackView stackViewWithViews:
		@[_status, _openButton, _copyButton, _restoreButton]];
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
	_status.stringValue = NSLocalizedString(@"Searching snapshots…", @"Deleted items status");
	[_authorization deletedItems:_url withReply:^(NSError * error, NSDictionary * result)
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

- (void)setResult:(NSDictionary *)result
{
	_mountpoint = result[@"mountpoint"];
	NSMutableArray * rows = [NSMutableArray array];
	for (NSDictionary * item in result[@"items"])
	{
		bool first = true;
		for (NSDictionary * version in item[@"versions"])
		{
			[rows addObject:@{@"item": item, @"version": version, @"first": @(first)}];
			first = false;
		}
	}
	_rows = rows;
	NSUInteger count = [result[@"items"] count];
	if (count == 0)
		_status.stringValue = [NSString stringWithFormat:
			NSLocalizedString(@"Nothing deleted from this folder is in its %@ snapshot(s)", @"Deleted items status"),
			result[@"snapshots"]];
	else
		_status.stringValue = [NSString stringWithFormat:
			NSLocalizedString(@"%lu deleted item(s) in %@ snapshot(s)%@", @"Deleted items status"),
			(unsigned long)count, result[@"snapshots"],
			[result[@"truncated"] boolValue] ?
				NSLocalizedString(@" (newest only)", @"Deleted items truncated") : @""];
}

- (NSDictionary *)rowAt:(NSInteger)row
{
	return (row >= 0 && row < (NSInteger)_rows.count) ? _rows[row] : nil;
}

- (NSString *)snapshotPathForRow:(NSInteger)row
{
	NSDictionary * r = [self rowAt:row];
	if (!r || !_mountpoint)
		return nil;
	return ZetaSnapshotPath(_mountpoint, r[@"version"][@"snapshot"],
		r[@"version"][@"path"]);
}

- (void)updateButtons
{
	bool haveRow = [self snapshotPathForRow:_table.selectedRow] != nil;
	_openButton.enabled = haveRow;
	_copyButton.enabled = haveRow;
	_restoreButton.enabled = haveRow;
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
	NSDictionary * r = _rows[row];
	NSDictionary * item = r[@"item"];
	NSDictionary * v = r[@"version"];
	NSString * ident = column.identifier;
	cell.alignment = NSTextAlignmentLeft;
	cell.textColor = NSColor.labelColor;
	if ([ident isEqualToString:kColumnName])
	{
		// Older versions of the same item show its name dimmed.
		NSString * name = item[@"name"];
		if ([item[@"isDirectory"] boolValue])
			name = [name stringByAppendingString:@"/"];
		cell.stringValue = name;
		if (![r[@"first"] boolValue])
			cell.textColor = NSColor.tertiaryLabelColor;
	}
	else if ([ident isEqualToString:kColumnSnapshot])
	{
		NSString * snapshot = v[@"snapshot"];
		cell.stringValue = [snapshot substringFromIndex:
			[snapshot rangeOfString:@"@"].location + 1];
	}
	else if ([ident isEqualToString:kColumnModified])
	{
		cell.stringValue = [NSDateFormatter localizedStringFromDate:v[@"mtime"]
			dateStyle:NSDateFormatterMediumStyle timeStyle:NSDateFormatterMediumStyle];
	}
	else if ([ident isEqualToString:kColumnSize])
	{
		cell.alignment = NSTextAlignmentRight;
		cell.stringValue = [item[@"isDirectory"] boolValue] ?
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

- (IBAction)openItem:(id)sender
{
	NSString * path = [self snapshotPathForRow:_table.selectedRow];
	if (path && ![[NSWorkspace sharedWorkspace] openURL:ZetaFileURL(path)])
		[self showError:NSLocalizedString(@"The item could not be opened", @"Deleted items error")
				 detail:path];
}

- (IBAction)copyItem:(id)sender
{
	NSInteger row = _table.selectedRow;
	NSString * source = [self snapshotPathForRow:row];
	if (!source)
		return;
	NSDictionary * item = _rows[row][@"item"];
	NSSavePanel * panel = [NSSavePanel savePanel];
	panel.nameFieldStringValue = item[@"name"];
	panel.directoryURL = _url;
	[panel beginSheetModalForWindow:self.window completionHandler:^(NSModalResponse response)
	{
		if (response != NSModalResponseOK)
			return;
		ZetaCopyItem(source, panel.URL.path, [item[@"isDirectory"] boolValue], true, ^(int err)
		{
			if (err != 0)
				[self showError:NSLocalizedString(@"The item could not be copied", @"Deleted items error")
						 detail:[NSString stringWithUTF8String:strerror(err)]];
			else
				[[NSWorkspace sharedWorkspace] activateFileViewerSelectingURLs:@[panel.URL]];
		});
	}];
}

// Put the item back where it was, under its old name. Never replaces
// anything: it is copied under a temporary name, then renamed into place
// with RENAME_EXCL, which fails if the name has been taken since.
- (IBAction)restoreItem:(id)sender
{
	NSInteger row = _table.selectedRow;
	NSString * source = [self snapshotPathForRow:row];
	if (!source)
		return;
	NSDictionary * item = _rows[row][@"item"];
	NSString * target = [_url.path stringByAppendingPathComponent:item[@"name"]];
	NSString * temp = [_url.path stringByAppendingPathComponent:
		[NSString stringWithFormat:@".%@.zfs-restore-%d", item[@"name"], getpid()]];
	bool isDir = [item[@"isDirectory"] boolValue];
	ZetaCopyItem(source, temp, isDir, false, ^(int err)
	{
		if (err == 0 && renamex_np(temp.UTF8String, target.UTF8String,
			RENAME_EXCL) != 0)
			err = errno;
		if (err != 0)
		{
			(void) removefile(temp.UTF8String, nullptr, REMOVEFILE_RECURSIVE);
			[self showError:NSLocalizedString(@"The item could not be restored", @"Deleted items error")
					 detail:err == EEXIST ?
						NSLocalizedString(@"An item with that name exists again.", @"Restore exists") :
						[NSString stringWithUTF8String:strerror(err)]];
		}
		else
		{
			[[NSWorkspace sharedWorkspace] activateFileViewerSelectingURLs:
				@[ZetaFileURL(target)]];
		}
		[self reload];
	});
}

#pragma mark Window

- (void)windowWillClose:(NSNotification *)notification
{
	dispatch_async(dispatch_get_main_queue(), ^{
		[openWindows removeObjectForKey:self->_url.path];
	});
}

@end
