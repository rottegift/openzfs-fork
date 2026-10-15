//
//  ZetaCommanderBase.mm
//  ZetaWatch
//
//  Created by cbreak on 19.06.02.
//  Copyright © 2019 the-color-black.net. All rights reserved.
//

#import "ZetaCommanderBase.h"
#import "ZetaUserNotification.h"

@implementation ZetaCommanderBase

- (void)notifySuccessWithTitle:(NSString*)title text:(NSString*)text
{
	ZetaNotify(title, text, nil, 10);
}

- (void)notifyErrorFromHelper:(NSError*)error
{
	NSString * errorFormat = NSLocalizedString(@"%@.", @"Helper Error notification Format");
	ZetaNotify(NSLocalizedString(@"ZetaWatch Error", @"Helper Error notification Title"),
		[NSString stringWithFormat:errorFormat, [error localizedDescription]], nil, 0);
}

- (IBAction)copyRepresentedObject:(id)sender
{
	NSPasteboard * pb = [NSPasteboard generalPasteboard];
	[pb clearContents];
	[pb writeObjects:@[[sender representedObject]]];
}

@end
