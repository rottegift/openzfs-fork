// SPDX-License-Identifier: BSD-3-Clause
//
//  ZetaUserNotification.h
//  ZetaWatch
//
//  Posts notifications through UserNotifications. The older
//  NSUserNotificationCenter no longer shows anything on recent macOS.
//

/* CSTYLED */
#import <Cocoa/Cocoa.h>
/* CSTYLED */
#import <UserNotifications/UserNotifications.h>

// Asks once for permission to notify, and makes delegate the center's
// delegate, so notifications show while ZetaWatch is active and clicking
// one opens its URL.
/* CSTYLED */
void ZetaSetupNotifications(id<UNUserNotificationCenterDelegate> delegate);

// Shows a notification. Clicking it opens url, when given. With a lifetime
// above zero it is removed from Notification Center after that many seconds.
// done, when given, is called on the main queue with whether it was shown:
// it is not while the user has not allowed ZetaWatch's notifications.
void ZetaNotify(NSString * title, NSString * text, NSURL * url,
    NSTimeInterval lifetime, void (^done)(BOOL shown) = nil);

// Opens the URL a notification carries, if any.
void ZetaOpenNotificationURL(UNNotification * notification);
