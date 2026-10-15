//
//  ZetaNotificationCenter.m
//  ZetaWatch
//
//  Created by cbreak on 19.08.25.
//  Copyright © 2019 the-color-black.net. All rights reserved.
//

#import "ZetaNotificationCenter.h"

#import "ZetaPoolWatcher.h"
#import "ZetaUserNotification.h"

@implementation ZetaNotification
{
}

- (id)initWithTitle:(NSString*)title
{
	if (self = [super init])
	{
		self->title = title;
	}
	return self;
}

@synthesize title;

@end

@implementation ZetaNotificationCenter
{
	NSMutableArray<ZetaNotification*> * inProgressActions;
}

- (id)init
{
	if (self = [super init])
	{
		inProgressActions = [[NSMutableArray alloc] init];
	}
	return self;
}

- (void)awakeFromNib
{
	if (self.poolWatcher)
	{
		[self.poolWatcher.delegates addObject:self];
	}
}

- (ZetaNotification*)startAction:(NSString*)title
{
	ZetaNotification * notification = [[ZetaNotification alloc] initWithTitle:title];
	[inProgressActions addObject:notification];
	return notification;
}

- (void)stopAction:(ZetaNotification*)notification
{
	[inProgressActions removeObject:notification];
}

- (void)stopAction:(ZetaNotification*)notification withError:(NSError*)error
{
	[self stopAction:notification];
}

- (void)errorDetectedInPool:(std::string const &)pool
{
	NSString * errorFormat = NSLocalizedString(@"ZFS detected an error on pool %s.", @"ZFS Pool Error Format");
	ZetaNotify(NSLocalizedString(@"ZFS Pool Error", @"ZFS Pool Error Title"),
		[NSString stringWithFormat:errorFormat, pool.c_str()], nil, 0);
}

- (void)errorDetected:(std::string const &)error
{
	NSString * errorFormat = NSLocalizedString(@"ZFS encountered an error: %s.", @"ZFS Error Format");
	ZetaNotify(NSLocalizedString(@"ZFS Error", @"ZFS Error Title"),
		[NSString stringWithFormat:errorFormat, error.c_str()], nil, 0);
}

@synthesize inProgressActions;

@end
