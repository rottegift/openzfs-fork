// SPDX-License-Identifier: BSD-3-Clause
//
//  ZetaUserNotification.mm
//  ZetaWatch
//
//  Posts notifications through UserNotifications. The older
//  NSUserNotificationCenter no longer shows anything on recent macOS.
//

#import "ZetaUserNotification.h"

void ZetaSetupNotifications(id<UNUserNotificationCenterDelegate> delegate)
{
	UNUserNotificationCenter * center = [UNUserNotificationCenter currentNotificationCenter];
	center.delegate = delegate;
	[center requestAuthorizationWithOptions:UNAuthorizationOptionAlert | UNAuthorizationOptionSound
		completionHandler:^(BOOL granted, NSError * error)
	{
		if (!granted)
			NSLog(@"ZetaWatch: notifications not allowed: %@", error);
	}];
}

void ZetaNotify(NSString * title, NSString * text, NSURL * url,
	NSTimeInterval lifetime, void (^done)(BOOL shown))
{
	UNMutableNotificationContent * content = [[UNMutableNotificationContent alloc] init];
	content.title = title;
	content.body = text ?: title;
	if (url)
		content.userInfo = @{@"url": url.absoluteString};
	NSString * identifier = [NSUUID UUID].UUIDString;
	UNNotificationRequest * request = [UNNotificationRequest
		requestWithIdentifier:identifier content:content trigger:nil];
	UNUserNotificationCenter * center = [UNUserNotificationCenter currentNotificationCenter];
	auto finish = ^(BOOL shown) {
		if (done)
			dispatch_async(dispatch_get_main_queue(), ^{ done(shown); });
	};
	// A request is accepted even when alerts are not allowed, and then
	// silently dropped, so look at the settings first.
	[center getNotificationSettingsWithCompletionHandler:^(UNNotificationSettings * settings)
	{
		if ((settings.authorizationStatus != UNAuthorizationStatusAuthorized &&
			 settings.authorizationStatus != UNAuthorizationStatusProvisional) ||
			settings.alertSetting == UNNotificationSettingDisabled)
		{
			NSLog(@"ZetaWatch: notifications not allowed (status %ld, alerts %ld), "
				"dropped \"%@\"", (long)settings.authorizationStatus,
				(long)settings.alertSetting, title);
			finish(NO);
			return;
		}
		[center addNotificationRequest:request withCompletionHandler:^(NSError * error)
		{
			if (error)
				NSLog(@"ZetaWatch: notification \"%@\" not shown: %@", title, error);
			finish(error == nil);
		}];
	}];
	if (lifetime > 0)
	{
		dispatch_after(dispatch_time(DISPATCH_TIME_NOW,
			(int64_t)(lifetime * NSEC_PER_SEC)), dispatch_get_main_queue(), ^{
			[center removeDeliveredNotificationsWithIdentifiers:@[identifier]];
		});
	}
}

void ZetaOpenNotificationURL(UNNotification * notification)
{
	NSString * url = notification.request.content.userInfo[@"url"];
	if ([url isKindOfClass:[NSString class]])
		[[NSWorkspace sharedWorkspace] openURL:[NSURL URLWithString:url]];
}
