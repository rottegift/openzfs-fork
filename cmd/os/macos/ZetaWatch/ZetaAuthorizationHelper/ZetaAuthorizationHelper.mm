//
//  ZetaAuthorizationHelper.m
//  ZetaAuthorizationHelper
//
//  Created by cbreak on 18.01.01.
//  Copyright © 2018 the-color-black.net. All rights reserved.
//

#import "ZetaAuthorizationHelper.h"
#import "ZetaAuthorizationHelperProtocol.h"

#import "CommonAuthorization.h"

#include "ZFSUtils.hpp"
#include "ZetaCPPUtils.hpp"

extern "C"
{
#include <libzfs.h>
}

#include <sys/mount.h>
#include <sys/stat.h>
#include <fcntl.h>

#include <algorithm>

@interface ZetaAuthorizationHelper () <NSXPCListenerDelegate, ZetaAuthorizationHelperProtocol>
{
	bool shouldRun;
}

@property (atomic, strong, readwrite) NSXPCListener * listener;

@end

NSMutableArray<NSString*> * toArray(std::vector<std::string> const & strings)
{
	NSMutableArray<NSString*> * array = [[NSMutableArray<NSString*> alloc] initWithCapacity:strings.size()];
	for (auto const & s : strings)
	{
		[array addObject:[NSString stringWithUTF8String:s.c_str()]];
	}
	return array;
}

std::vector<std::string> fromArray(NSArray<NSString*> * array)
{
	std::vector<std::string> vec;
	for (NSString * string in array)
	{
		vec.push_back([string UTF8String]);
	}
	return vec;
}

@implementation ZetaAuthorizationHelper

- (id)init
{
	self = [super init];
	if (self != nil)
	{
		shouldRun = true;
		// Set up our XPC listener to handle requests on our Mach service.
		self->_listener = [[NSXPCListener alloc] initWithMachServiceName:kHelperToolMachServiceName];
		self->_listener.delegate = self;
	}
	return self;
}

- (void)run
{
	// Tell the XPC listener to start processing requests.
	[self.listener resume];
	// Run the run loop until it's time to terminate.
	bool runLoopSuccess = true;
	while (shouldRun && runLoopSuccess)
	{
		runLoopSuccess = [[NSRunLoop mainRunLoop]
			runMode:NSDefaultRunLoopMode
			beforeDate:[NSDate distantFuture]];
	}
}

- (void)stop
{
	shouldRun = false;
	[self.listener invalidate];
	// Stop the run loop
	CFRunLoopStop(CFRunLoopGetMain());
}

- (BOOL)listener:(NSXPCListener *)listener shouldAcceptNewConnection:(NSXPCConnection *)newConnection
{
	assert(listener == self.listener);
	assert(newConnection != nil);

	newConnection.exportedInterface = [NSXPCInterface interfaceWithProtocol:@protocol(ZetaAuthorizationHelperProtocol)];
	newConnection.exportedObject = self;
	[newConnection resume];

	return YES;
}

NSError * checkAuthorization(NSData * authData, SEL command)
{
	NSError * error = nil;
	AuthorizationRef authRef = NULL;

	assert(command != nil);

	// First check that authData looks reasonable.
	error = nil;
	if ((authData == nil) || ([authData length] != sizeof(AuthorizationExternalForm)))
	{
		error = [NSError errorWithDomain:NSOSStatusErrorDomain code:paramErr userInfo:nil];
		return error;
	}

	// Create an authorization ref from that the external form data contained within.
	auto extForm = static_cast<const AuthorizationExternalForm *>([authData bytes]);
	OSStatus err = AuthorizationCreateFromExternalForm(extForm, &authRef);

	// Authorize the right associated with the command.
	if (err == errAuthorizationSuccess)
	{
		AuthorizationItem oneRight = { NULL, 0, NULL, 0 };
		AuthorizationRights rights   = { 1, &oneRight };

		auto right = [CommonAuthorization authorizationRightForCommand:command];
		if (!right)
		{
			error = [NSError errorWithDomain:NSOSStatusErrorDomain code:paramErr userInfo:nil];
			return error;
		}

		oneRight.name = [right UTF8String];

		err = AuthorizationCopyRights(authRef, &rights, NULL,
			kAuthorizationFlagExtendRights | kAuthorizationFlagInteractionAllowed,
			NULL);
	}
	if (err != errAuthorizationSuccess)
	{
		error = [NSError errorWithDomain:NSOSStatusErrorDomain code:err userInfo:nil];
	}

	if (authRef != NULL)
	{
		OSStatus junk = AuthorizationFree(authRef, 0);
		assert(junk == errAuthorizationSuccess);
	}

	return error;
}

- (void)getVersionWithReply:(void (^)(NSError * error, NSString *))reply
{
	reply(nil, [[NSBundle mainBundle] objectForInfoDictionaryKey:@"CFBundleVersion"]);
}

// Checks authorization, and handles c++ exceptions by forwarding them to the
// caller.
template<typename C, typename R>
void processWithExceptionForwarding(NSData * authData, SEL command,
									R reply, C callable)
{
	NSError * error = checkAuthorization(authData, command);
	if (error)
	{
		reply(error);
		return;
	}
	try
	{
		callable();
	}
	catch (std::exception const & e)
	{
		reply([NSError errorWithDomain:@"ZFSException" code:-1 userInfo:@{NSLocalizedDescriptionKey: [NSString stringWithUTF8String:e.what()]}]);
	}
}

- (void)stopHelperWithAuthorization:(NSData *)authData
						  withReply:(void (^)(NSError *))reply
{
	processWithExceptionForwarding(authData, _cmd, reply, [=]()
	{
		// Acknowledge receipt of stop request, performed asyncronously
		reply(nullptr);
		[self stop];
	});
}

- (void)importPools:(NSDictionary *)importData authorization:(NSData *)authData
		  withReply:(void (^)(NSError *))reply
{
	processWithExceptionForwarding(authData, _cmd, reply, [=]()
	{
		std::vector<std::string> failures;
		NSNumber * pool = [importData objectForKey:@"poolGUID"];
		zfs::LibZFSHandle::ImportProps props;
		if (id ar = [importData objectForKey:@"altroot"])
			props.altroot.assign([ar UTF8String]);
		if (id aidm = [importData objectForKey:@"allowHostIDMismatch"])
			props.allowHostIDMismatch = [aidm boolValue];
		if (id auh = [importData objectForKey:@"allowUnhealthy"])
			props.allowUnhealthy = [auh boolValue];
		if (id ro = [importData objectForKey:@"readOnly"])
			props.readOnly = [ro boolValue];
		if (id spo = [importData objectForKey:@"searchPathOverride"])
			props.searchPathOverride = fromArray(spo);
		std::vector<zfs::ZPool> importedPools;
		zfs::LibZFSHandle zfs;
		if (pool != nil)
		{
			importedPools.emplace_back(zfs.import([pool unsignedLongLongValue], props));
		}
		else
		{
			importedPools = zfs.importAllPools(props);
		}
		if (failures.empty())
		{
			reply(nullptr);
		}
		else
		{
			NSDictionary * userInfo = @{
				NSLocalizedDescriptionKey: [NSString stringWithUTF8String:
					formatForHumans(failures).c_str()]
			};
			reply([NSError errorWithDomain:@"ZFSError" code:-1 userInfo:userInfo]);
		}
	});
}

- (void)importablePools:(NSDictionary *)importData
		  authorization:(NSData *)authData
			  withReply:(void (^)(NSError *, NSArray *))reply
{
	NSError * error = checkAuthorization(authData, _cmd);
	if (error)
	{
		reply(error, nullptr);
		return;
	}
	try
	{
		zfs::LibZFSHandle zfs;
		std::vector<std::string> searchPathOverride;
		if (id spo = [importData objectForKey:@"searchPathOverride"])
			searchPathOverride = fromArray(spo);
		auto pools = zfs.importablePools(searchPathOverride);
		NSMutableArray * poolsArray = [[NSMutableArray alloc] initWithCapacity:pools.size()];
		for (auto const & pool : pools)
		{
			NSString * name = [NSString stringWithUTF8String:pool.name.c_str()];
			NSNumber * guid = [NSNumber numberWithUnsignedLongLong:pool.guid];
			NSNumber * status = [NSNumber numberWithUnsignedLongLong:pool.status];
			NSMutableArray<NSString*> * deviceArray = toArray(pool.devices);
			NSDictionary * poolDict =
			@{@"name": name, @"guid": guid, @"status": status, @"devices": deviceArray};
			[poolsArray addObject:poolDict];
		}
		reply(nullptr, poolsArray);
	}
	catch (std::exception const & e)
	{
		reply([NSError errorWithDomain:@"ZFSException" code:-1 userInfo:@{NSLocalizedDescriptionKey: [NSString stringWithUTF8String:e.what()]}], nullptr);
	}
}

- (void)exportPools:(NSDictionary *)exportData authorization:(NSData *)authData withReply:(void(^)(NSError * error))reply
{
	processWithExceptionForwarding(authData, _cmd, reply, [=]()
	{
		NSString * poolName = [exportData objectForKey:@"pool"];
		bool force = false;
		if (id o = [exportData objectForKey:@"force"])
			force = [o boolValue];
		if (!poolName)
		{
			reply([NSError errorWithDomain:@"ZFSArgError" code:-1 userInfo:@{NSLocalizedDescriptionKey: @"Missing Arguments"}]);
			return;
		}
		zfs::LibZFSHandle zfs;
		auto pool = zfs.pool(std::string(poolName.UTF8String));
		// Export Pool
		pool.exportPool(force);
		reply(nullptr);
	});
}

- (void)mountFilesystems:(NSDictionary *)mountData authorization:(NSData *)authData
			   withReply:(void (^)(NSError *))reply
{
	processWithExceptionForwarding(authData, _cmd, reply, [=]()
	{
		NSString * fsName = [mountData objectForKey:@"filesystem"];
		bool recursive = false;
		if (id o = [mountData objectForKey:@"recursive"])
			recursive = [o boolValue];
		if (!fsName)
		{
			reply([NSError errorWithDomain:@"ZFSArgError" code:-1 userInfo:@{NSLocalizedDescriptionKey: @"Missing Arguments"}]);
			return;
		}
		zfs::LibZFSHandle zfs;
		auto fs = zfs.filesystem([fsName UTF8String]);
		int ret = 0;
		if (recursive)
			ret = fs.mountRecursive();
		else
			ret = fs.mount();
		if (ret == 0)
		{
			reply(nullptr);
		}
		else
		{
			NSDictionary * userInfo = @{
				NSLocalizedDescriptionKey: [NSString stringWithUTF8String:
					zfs.lastError().c_str()]
			};
			reply([NSError errorWithDomain:@"ZFSError" code:-1 userInfo:userInfo]);
		}
	});
}

- (void)unmountFilesystems:(NSDictionary *)mountData authorization:(NSData *)authData
				 withReply:(void (^)(NSError *))reply
{
	processWithExceptionForwarding(authData, _cmd, reply, [=]()
	{
		NSString * fsName = [mountData objectForKey:@"filesystem"];
		bool force = false;
		if (id o = [mountData objectForKey:@"force"])
			force = [o boolValue];
		bool recursive = false;
		if (id o = [mountData objectForKey:@"recursive"])
			recursive = [o boolValue];
		if (!fsName)
		{
			reply([NSError errorWithDomain:@"ZFSArgError" code:-1 userInfo:@{NSLocalizedDescriptionKey: @"Missing Arguments"}]);
			return;
		}
		zfs::LibZFSHandle zfs;
		auto fs = zfs.filesystem([fsName UTF8String]);
		int ret = 0;
		if (recursive)
			ret = fs.unmountRecursive(force);
		else
			ret = fs.unmount();
		if (ret == 0)
		{
			reply(nullptr);
		}
		else
		{
			NSDictionary * userInfo = @{
				NSLocalizedDescriptionKey: [NSString stringWithUTF8String:
					zfs.lastError().c_str()]
			};
			reply([NSError errorWithDomain:@"ZFSError" code:-1 userInfo:userInfo]);
		}
	});
}

- (void)snapshotFilesystem:(NSDictionary *)fsData authorization:(NSData *)authData withReply:(void(^)(NSError * error))reply
{
	processWithExceptionForwarding(authData, _cmd, reply, [=]()
	{
		NSString * fsName = [fsData objectForKey:@"filesystem"];
		NSString * snapName = [fsData objectForKey:@"snapshot"];
		bool recursive = false;
		if (id o = [fsData objectForKey:@"recursive"])
			recursive = [o boolValue];
		if (!fsName || !snapName)
		{
			reply([NSError errorWithDomain:@"ZFSArgError" code:-1 userInfo:@{NSLocalizedDescriptionKey: @"Missing Arguments"}]);
			return;
		}
		zfs::LibZFSHandle zfs;
		auto fs = zfs.filesystem([fsName UTF8String]);
		auto ret = fs.snapshot([snapName UTF8String], recursive);
		if (ret == 0)
		{
			reply(nullptr);
		}
		else
		{
			NSDictionary * userInfo = @{
				NSLocalizedDescriptionKey: [NSString stringWithUTF8String:zfs.lastError().c_str()]
			};
			reply([NSError errorWithDomain:@"ZFSError" code:-1 userInfo:userInfo]);
		}
	});
}

- (void)rollbackFilesystem:(NSDictionary *)fsData authorization:(NSData *)authData withReply:(void(^)(NSError * error))reply
{
	processWithExceptionForwarding(authData, _cmd, reply, [=]()
	{
		NSString * snapName = [fsData objectForKey:@"snapshot"];
		bool force = false;
		if (id o = [fsData objectForKey:@"force"])
			force = [o boolValue];
		if (!snapName)
		{
			reply([NSError errorWithDomain:@"ZFSArgError" code:-1 userInfo:@{NSLocalizedDescriptionKey: @"Missing Arguments"}]);
			return;
		}
		zfs::LibZFSHandle zfs;
		auto snap = zfs.filesystem([snapName UTF8String]);
		auto res = snap.rollback(force);
		if (res == 0)
		{
			reply(nullptr);
		}
		else
		{
			NSDictionary * userInfo = @{
				NSLocalizedDescriptionKey: [NSString stringWithUTF8String:zfs.lastError().c_str()]
			};
			reply([NSError errorWithDomain:@"ZFSError" code:-1 userInfo:userInfo]);
		}
	});
}

- (void)cloneSnapshot:(NSDictionary *)fsData authorization:(NSData *)authData withReply:(void(^)(NSError * error))reply
{
	processWithExceptionForwarding(authData, _cmd, reply, [=]()
	{
		NSString * snapName = [fsData objectForKey:@"snapshot"];
		NSString * newFSName = [fsData objectForKey:@"newFilesystem"];
		if (!snapName || !newFSName)
		{
			reply([NSError errorWithDomain:@"ZFSArgError" code:-1 userInfo:@{NSLocalizedDescriptionKey: @"Missing Arguments"}]);
			return;
		}
		zfs::LibZFSHandle zfs;
		std::string newFSNameStr = [newFSName UTF8String];
		auto snap = zfs.filesystem([snapName UTF8String]);
		if (snap.clone(newFSNameStr) == 0)
		{
			auto newFS = zfs.filesystem(newFSNameStr);
			if (newFS.mount() == 0)
			{
				reply(nullptr);
				return;
			}
		}
		NSDictionary * userInfo = @{
			NSLocalizedDescriptionKey: [NSString stringWithUTF8String:zfs.lastError().c_str()]
		};
		reply([NSError errorWithDomain:@"ZFSError" code:-1 userInfo:userInfo]);
	});
}

- (void)createFilesystem:(NSDictionary *)fsData authorization:(NSData *)authData withReply:(void(^)(NSError * error))reply
{
	processWithExceptionForwarding(authData, _cmd, reply, [=]()
	{
		NSString * newFSName = [fsData objectForKey:@"filesystem"];
		NSString * mountpoint = [fsData objectForKey:@"mountpoint"];
		if (!newFSName)
		{
			reply([NSError errorWithDomain:@"ZFSArgError" code:-1 userInfo:@{NSLocalizedDescriptionKey: @"Missing Arguments"}]);
			return;
		}
		zfs::LibZFSHandle zfs;
		std::string newFSNameStr = [newFSName UTF8String];
		std::string mountpointStr = mountpoint ? [mountpoint UTF8String] : "";
		if (zfs.createFilesystem(newFSNameStr, mountpointStr) == 0)
		{
			auto newFS = zfs.filesystem(newFSNameStr);
			if (newFS.mount() == 0)
			{
				reply(nullptr);
				return;
			}
		}
		NSDictionary * userInfo = @{
			NSLocalizedDescriptionKey: [NSString stringWithUTF8String:zfs.lastError().c_str()]
		};
		reply([NSError errorWithDomain:@"ZFSError" code:-1 userInfo:userInfo]);
	});
}

- (void)createVolume:(NSDictionary *)fsData authorization:(NSData *)authData withReply:(void(^)(NSError * error))reply
{
	processWithExceptionForwarding(authData, _cmd, reply, [=]()
	{
		NSString * newFSName = [fsData objectForKey:@"filesystem"];
		NSNumber * size = [fsData objectForKey:@"size"];
		NSNumber * blocksize = [fsData objectForKey:@"blocksize"];
		if (!newFSName || size == nullptr)
		{
			reply([NSError errorWithDomain:@"ZFSArgError" code:-1 userInfo:@{NSLocalizedDescriptionKey: @"Missing Arguments"}]);
			return;
		}
		zfs::LibZFSHandle zfs;
		std::string newFSNameStr = [newFSName UTF8String];
		auto s = [size unsignedLongLongValue];
		auto bs = blocksize != nullptr ? [blocksize unsignedLongLongValue] : 0;
		if (zfs.createVolume(newFSNameStr, s, bs) == 0)
		{
			reply(nullptr);
			return;
		}
		NSDictionary * userInfo = @{
			NSLocalizedDescriptionKey: [NSString stringWithUTF8String:zfs.lastError().c_str()]
		};
		reply([NSError errorWithDomain:@"ZFSError" code:-1 userInfo:userInfo]);
	});
}

- (void)destroy:(NSDictionary *)fsData authorization:(NSData *)authData withReply:(void(^)(NSError * error))reply
{
	processWithExceptionForwarding(authData, _cmd, reply, [=]()
	{
		NSString * fsName = [fsData objectForKey:@"filesystem"];
		bool recursive = false;
		if (id o = [fsData objectForKey:@"recursive"])
			recursive = [o boolValue];
		bool force = false;
		if (id o = [fsData objectForKey:@"force"])
			force = [o boolValue];
		if (!fsName)
		{
			reply([NSError errorWithDomain:@"ZFSArgError" code:-1 userInfo:@{NSLocalizedDescriptionKey: @"Missing Arguments"}]);
			return;
		}
		zfs::LibZFSHandle zfs;
		auto fs = zfs.filesystem([fsName UTF8String]);
		int ret = 0;
		if (recursive)
		{
			ret = fs.destroyRecursive(force);
		}
		else
		{
			auto dependents = fs.dependents();
			if (dependents.empty())
			{
				ret = fs.destroy(force);
			}
			else
			{
				NSDictionary * userInfo = @{
					NSLocalizedDescriptionKey: @"Filesystem has Dependents"
				};
				reply([NSError errorWithDomain:@"ZFSError" code:-1 userInfo:userInfo]);
				return;
			}
		}
		if (ret == 0)
		{
			reply(nullptr);
		}
		else
		{
			NSDictionary * userInfo = @{
				NSLocalizedDescriptionKey: [NSString stringWithUTF8String:zfs.lastError().c_str()]
			};
			reply([NSError errorWithDomain:@"ZFSError" code:-1 userInfo:userInfo]);
		}
	});
}

- (void)loadKeyForFilesystem:(NSDictionary *)loadData authorization:(NSData *)authData withReply:(void(^)(NSError * error))reply
{
	processWithExceptionForwarding(authData, _cmd, reply, [=]()
	{
		NSString * fsName = [loadData objectForKey:@"filesystem"];
		NSString * key = [loadData objectForKey:@"key"];
		if (!fsName)
		{
			reply([NSError errorWithDomain:@"ZFSArgError" code:-1 userInfo:@{NSLocalizedDescriptionKey: @"Missing Arguments"}]);
			return;
		}
		zfs::LibZFSHandle zfs;
		auto fs = zfs.filesystem([fsName UTF8String]);
		int ret = 0;
		if (key)
		{
			ret = fs.loadKey([key UTF8String]);
		}
		else if (fs.keyLocation() == zfs::ZFileSystem::KeyLocation::uri)
		{
			ret = fs.loadKeyFile();
		}
		else
		{
			reply([NSError errorWithDomain:@"ZFSKeyError" code:-1 userInfo:@{NSLocalizedDescriptionKey: @"Missing Key"}]);
			return;
		}
		if (ret)
		{
			NSDictionary * userInfo = @{
				NSLocalizedDescriptionKey: [NSString stringWithUTF8String:zfs.lastError().c_str()]
			};
			reply([NSError errorWithDomain:@"ZFSKeyError" code:-1 userInfo:userInfo]);
			return;
		}
		// Encryption Root Filesystem and contained filesystems recursively
		ret = fs.automountRecursive();
		if (ret)
		{
			NSDictionary * userInfo = @{
				NSLocalizedDescriptionKey: [NSString stringWithUTF8String:zfs.lastError().c_str()]
			};
			reply([NSError errorWithDomain:@"ZFSError" code:-1 userInfo:userInfo]);
		}
		reply(nullptr);
	});
}

- (void)unloadKeyForFilesystem:(NSDictionary *)unloadData authorization:(NSData *)authData withReply:(void(^)(NSError * error))reply
{
	processWithExceptionForwarding(authData, _cmd, reply, [=]()
	{
		NSString * fsName = [unloadData objectForKey:@"filesystem"];
		if (!fsName)
		{
			reply([NSError errorWithDomain:@"ZFSArgError" code:-1 userInfo:@{NSLocalizedDescriptionKey: @"Missing Arguments"}]);
			return;
		}
		zfs::LibZFSHandle zfs;
		auto fs = zfs.filesystem([fsName UTF8String]);
		auto ret = fs.unloadKey();
		if (ret == 0)
		{
			reply(nullptr);
		}
		else
		{
			NSDictionary * userInfo = @{
				NSLocalizedDescriptionKey: [NSString stringWithUTF8String:
					zfs.lastError().c_str()]
			};
			reply([NSError errorWithDomain:@"ZFSError" code:-1 userInfo:userInfo]);
		}
	});
}

- (void)scrubPool:(NSDictionary *)poolData authorization:(NSData *)authData
		withReply:(void (^)(NSError *))reply
{
	processWithExceptionForwarding(authData, _cmd, reply, [=]()
	{
		NSString * poolName = [poolData objectForKey:@"pool"];
		NSString * command = [poolData objectForKey:@"command"];
		if (!poolName)
		{
			reply([NSError errorWithDomain:@"ZFSArgError" code:-1 userInfo:@{NSLocalizedDescriptionKey: @"Missing Arguments"}]);
			return;
		}
		zfs::LibZFSHandle zfs;
		auto pool = zfs.pool(std::string(poolName.UTF8String));
		if (command)
		{
			if ([command isEqualToString:@"stop"])
				pool.scrubStop();
			else if ([command isEqualToString:@"pause"])
				pool.scrubPause();
			// No other commands are supported
			else
				reply([NSError errorWithDomain:@"ZFSArgError" code:-1 userInfo:@{NSLocalizedDescriptionKey: @"Invalid Scrub Command"}]);
		}
		else
		{
			pool.scrub();
		}
		reply(nullptr);
	});
}

// Mirrors INO_XNUTOZFS() in include/os/macos/zfs/sys/zfs_context_os.h: the
// dataset root is reported as inode 2, and objects 0-15 are moved to the top.
static const uint64_t kInoRoot = 2;
static const uint64_t kInoMap = static_cast<uint64_t>(-16);

// Searched by deletedItems:, newest first, like the Windows port.
static const size_t kDeletedMaxSnapshots = 512;
static const size_t kDeletedMaxObjects = 20000;

static NSError * versionsError(int code, NSString * what)
{
	return [NSError errorWithDomain:NSPOSIXErrorDomain code:code
		userInfo:@{NSLocalizedDescriptionKey: what}];
}

static NSString * toNS(std::string const & s)
{
	return [[NSString alloc] initWithBytes:s.data() length:s.size()
		encoding:NSUTF8StringEncoding] ?: @"?";
}

static NSDictionary * versionDict(zfs_obj_version_t const & v,
	char const * path, char const * snapshot)
{
	NSMutableDictionary * d = [@{
		@"path": toNS(path),
		@"size": @(v.zov_size),
		@"mtime": [NSDate dateWithTimeIntervalSince1970:
			v.zov_mtime[0] + v.zov_mtime[1] / 1e9],
		@"mode": @(v.zov_mode),
		@"gen": @(v.zov_gen),
	} mutableCopy];
	if (snapshot)
		d[@"snapshot"] = toNS(snapshot);
	return d;
}

static int collectSnapshotName(zfs_handle_t * zhp, void * arg)
{
	auto names = static_cast<std::vector<std::string> *>(arg);
	names->emplace_back(zfs_get_name(zhp));
	zfs_close(zhp);
	return 0;
}

// What a descriptor passed by the app refers to.
struct ZetaItem
{
	struct stat st;
	uint64_t obj;			// ZFS object number, 0 for a dataset root
	std::string reference;		// dataset or snapshot it is on
	std::string dataset;		// reference without any @snapshot
	std::string mountpoint;		// where dataset is mounted
	std::string path;		// fd's path, from F_GETPATH
};

// Check a descriptor from the app and find its dataset. No authorization
// is asked for: holding the item open for reading is the proof that the
// caller may see it. O_EXEC/O_SEARCH descriptors have an access mode of
// O_RDONLY (0), so they are refused explicitly.
static NSError * resolveItem(libzfs_handle_t * hdl, int fd, ZetaItem & item)
{
	int flags = fcntl(fd, F_GETFL);
	if (flags == -1 ||
		((flags & O_ACCMODE) != O_RDONLY && (flags & O_ACCMODE) != O_RDWR) ||
		(flags & (O_EXEC | O_EVTONLY)) != 0)
		return versionsError(EBADF, @"The item must be open for reading");
	struct statfs sfs, msfs;
	char path[MAXPATHLEN];
	if (fstat(fd, &item.st) != 0 || fstatfs(fd, &sfs) != 0 ||
		fcntl(fd, F_GETPATH, path) != 0)
		return versionsError(errno, @"Cannot stat the item");
	item.path = path;
	item.obj = item.st.st_ino;
	if (item.obj == kInoRoot)
		item.obj = 0;
	else if (item.obj >= kInoMap)
		item.obj -= kInoMap;

	// The mount point must still be the mount the descriptor lives on.
	if (statfs(sfs.f_mntonname, &msfs) != 0 ||
		memcmp(&msfs.f_fsid, &sfs.f_fsid, sizeof (sfs.f_fsid)) != 0)
		return versionsError(ENOENT, @"The item's file system has moved");

	// Datasets and snapshots mount with their name as the device; a
	// pool's root dataset may mount as /dev/diskN, which libzfs maps back
	// to the dataset (zfs_path_to_zhandle() only opens filesystems, so it
	// cannot be used for snapshot mounts).
	if (sfs.f_mntfromname[0] != '/' &&
		strcmp(sfs.f_fstypename, "zfs") == 0 &&
		zfs_dataset_exists(hdl, sfs.f_mntfromname,
			static_cast<zfs_type_t>(ZFS_TYPE_FILESYSTEM | ZFS_TYPE_SNAPSHOT)))
	{
		item.reference = sfs.f_mntfromname;
	}
	else if (zfs_handle_t * mzhp = zfs_path_to_zhandle(hdl,
		sfs.f_mntonname, ZFS_TYPE_FILESYSTEM))
	{
		item.reference = zfs_get_name(mzhp);
		zfs_close(mzhp);
	}
	else
	{
		return versionsError(EINVAL, @"The item is not on a ZFS file system");
	}
	item.dataset = item.reference.substr(0, item.reference.find('@'));

	zfs_handle_t * zhp = zfs_open(hdl, item.dataset.c_str(), ZFS_TYPE_FILESYSTEM);
	if (zhp == nullptr)
		return versionsError(ENOENT, @"Cannot open the file system");
	char * where = nullptr;
	if (zfs_is_mounted(zhp, &where) && where != nullptr)
		item.mountpoint = where;
	free(where);
	zfs_close(zhp);
	return nil;
}

static std::vector<std::string> snapshotsOf(libzfs_handle_t * hdl,
	std::string const & dataset)
{
	std::vector<std::string> snapshots;	// oldest first
	if (zfs_handle_t * zhp = zfs_open(hdl, dataset.c_str(), ZFS_TYPE_FILESYSTEM))
	{
		(void) zfs_iter_snapshots_sorted_v2(zhp, 0, collectSnapshotName,
			&snapshots, 0, 0);
		zfs_close(zhp);
	}
	return snapshots;
}

static NSError * exceptionError(std::exception const & e)
{
	return [NSError errorWithDomain:@"ZFSException" code:-1
		userInfo:@{NSLocalizedDescriptionKey: [NSString stringWithUTF8String:e.what()]}];
}

- (void)fileVersions:(NSFileHandle *)file
		   withReply:(void (^)(NSError *, NSDictionary *))reply
{
	try
	{
		zfs::LibZFSHandle zfs;
		libzfs_handle_t * hdl = zfs.handle();
		ZetaItem item;
		if (NSError * error = resolveItem(hdl, file.fileDescriptor, item))
		{
			reply(error, nullptr);
			return;
		}
		if (item.obj == 0)
		{
			reply(versionsError(ENOTSUP,
				@"Versions of a file system's top folder are not supported yet"), nullptr);
			return;
		}

		// The version on the descriptor's dataset or snapshot is the
		// reference the others must match (same gen).
		char path[MAXPATHLEN];
		zfs_obj_version_t ref, v;
		int err = zfs_get_obj_version(hdl, item.reference.c_str(), item.obj,
			&ref, path, sizeof (path));
		if (err != 0)
		{
			reply(versionsError(err, @"Cannot look up the item"), nullptr);
			return;
		}

		NSMutableDictionary * result = [NSMutableDictionary dictionary];
		result[@"dataset"] = toNS(item.dataset);
		if (!item.mountpoint.empty())
			result[@"mountpoint"] = toNS(item.mountpoint);
		if (zfs_get_obj_version(hdl, item.dataset.c_str(), item.obj, &v,
			path, sizeof (path)) == 0 && v.zov_gen == ref.zov_gen)
			result[@"live"] = versionDict(v, path, nullptr);

		auto snapshots = snapshotsOf(hdl, item.dataset);
		NSMutableArray * versions = [NSMutableArray array];
		for (auto s = snapshots.rbegin(); s != snapshots.rend(); ++s)
		{
			// ENOENT: the object did not exist yet, or no longer.
			// A different gen: the object number was reused by
			// another file.
			if (zfs_get_obj_version(hdl, s->c_str(), item.obj, &v, path,
				sizeof (path)) != 0 || v.zov_gen != ref.zov_gen)
				continue;
			[versions addObject:versionDict(v, path, s->c_str())];
		}
		result[@"versions"] = versions;
		reply(nullptr, result);
	}
	catch (std::exception const & e)
	{
		reply(exceptionError(e), nullptr);
	}
}

// Undo stream_bytes() in libzfs_diff.c: "\ooo" (4 octal digits) for any
// byte that is not printable, a space or a backslash.
static std::string unmangle(char const * s)
{
	std::string out;
	while (*s)
	{
		if (s[0] == '\\' && s[1] >= '0' && s[1] <= '7' &&
			s[2] >= '0' && s[2] <= '7' && s[3] >= '0' && s[3] <= '7' &&
			s[4] >= '0' && s[4] <= '7')
		{
			out += static_cast<char>(strtoul(std::string(s + 1, 4).c_str(),
				nullptr, 8));
			s += 5;
		}
		else
		{
			out += *s++;
		}
	}
	return out;
}

// An object removed from the directory between two snapshots.
struct ZetaRemoved
{
	uint64_t obj;
	std::string name;
	bool isDirectory;
	size_t lastSnapshot;	// newest snapshot known to hold it
};

/*
 * Run "zfs diff -HF" with object numbers from one snapshot to the next
 * (or to the live dataset), and note the objects removed from dir
 * ("" for the dataset root, else "/a/b"). Returns 0 if the diff ran.
 */
static int diffRemovals(zfs_handle_t * zhp, std::string const & from,
	std::string const & to, std::string const & mountpoint,
	std::string const & dir, size_t snapshot, std::vector<ZetaRemoved> & removed)
{
	char tmpl[] = "/var/tmp/zeta-diff.XXXXXX";
	int fd = mkstemp(tmpl);
	if (fd < 0)
		return -1;
	(void) unlink(tmpl);
	// zfs_show_diffs() closes the descriptor it is given.
	int rc = zfs_show_diffs(zhp, dup(fd), from.c_str(), to.c_str(),
		ZFS_DIFF_PARSEABLE | ZFS_DIFF_CLASSIFY | ZFS_DIFF_OBJNUM);
	FILE * fp = rc == 0 ? fdopen(fd, "r") : nullptr;
	if (fp == nullptr)
	{
		(void) close(fd);
		return rc != 0 ? rc : -1;
	}
	rewind(fp);
	// "/" mounts print paths without a prefix, see get_mountpoint().
	std::string prefix = mountpoint == "/" ? "" : mountpoint;
	char * line = nullptr;
	size_t cap = 0;
	ssize_t len;
	while ((len = getline(&line, &cap, fp)) > 0)
	{
		// <obj> TAB <change> TAB <type> TAB <path>; mangled, so the
		// fields hold no tabs or newlines themselves.
		if (line[len - 1] == '\n')
			line[len - 1] = '\0';
		char * fields[4];
		char * p = line;
		int n = 0;
		while (n < 4 && p != nullptr)
		{
			fields[n++] = p;
			if ((p = strchr(p, '\t')) != nullptr)
				*p++ = '\0';
		}
		if (n < 4 || strcmp(fields[1], "-") != 0)
			continue;
		std::string path = unmangle(fields[3]);
		if (path.compare(0, prefix.size(), prefix) != 0)
			continue;
		path.erase(0, prefix.size());
		size_t slash = path.rfind('/');
		if (slash == std::string::npos || path.compare(0, slash, dir) != 0 ||
			slash != dir.size() || slash + 1 == path.size())
			continue;
		std::string name = path.substr(slash + 1);
		uint64_t obj = strtoull(fields[0], nullptr, 10);
		auto it = std::find_if(removed.begin(), removed.end(),
			[&](ZetaRemoved const & r) { return r.obj == obj && r.name == name; });
		if (it != removed.end())
			it->lastSnapshot = snapshot;
		else if (removed.size() < kDeletedMaxObjects)
			removed.push_back({obj, name, fields[2][0] == '/', snapshot});
	}
	free(line);
	fclose(fp);
	return 0;
}

- (void)deletedItems:(NSFileHandle *)directory
		   withReply:(void (^)(NSError *, NSDictionary *))reply
{
	try
	{
		zfs::LibZFSHandle zfs;
		libzfs_handle_t * hdl = zfs.handle();
		ZetaItem item;
		int dirfd = directory.fileDescriptor;
		if (NSError * error = resolveItem(hdl, dirfd, item))
		{
			reply(error, nullptr);
			return;
		}
		if (!S_ISDIR(item.st.st_mode))
		{
			reply(versionsError(ENOTDIR, @"The item is not a folder"), nullptr);
			return;
		}
		if (item.reference != item.dataset)
		{
			reply(versionsError(ENOTSUP,
				@"Deleted items can only be listed for a folder on the live file system"), nullptr);
			return;
		}
		// The folder's path within the dataset, from the descriptor.
		std::string const & mnt = item.mountpoint;
		std::string dir;
		if (mnt.empty() || item.path.compare(0, mnt.size(), mnt) != 0 ||
			(item.path.size() > mnt.size() && item.path[mnt.size()] != '/' && mnt != "/"))
		{
			reply(versionsError(ENOENT, @"The folder is not under its file system's mount point"), nullptr);
			return;
		}
		dir = mnt == "/" ? item.path : item.path.substr(mnt.size());
		if (dir == "/")
			dir.clear();

		auto snapshots = snapshotsOf(hdl, item.dataset);
		size_t first = snapshots.size() > kDeletedMaxSnapshots ?
			snapshots.size() - kDeletedMaxSnapshots : 0;

		// No snapshot is mounted: diffs name the objects removed from
		// the folder, and OBJ_TO_STATS gives their versions.
		std::vector<ZetaRemoved> removed;
		zfs_handle_t * zhp = zfs_open(hdl, item.dataset.c_str(), ZFS_TYPE_FILESYSTEM);
		if (zhp == nullptr)
		{
			reply(versionsError(ENOENT, @"Cannot open the file system"), nullptr);
			return;
		}
		size_t failed = 0;
		for (size_t i = first; i < snapshots.size(); ++i)
		{
			std::string const & to = i + 1 < snapshots.size() ?
				snapshots[i + 1] : item.dataset;
			if (diffRemovals(zhp, snapshots[i], to, mnt, dir, i, removed) != 0)
				failed++;
		}
		zfs_close(zhp);
		if (failed > 0 && failed == snapshots.size() - first)
		{
			reply(versionsError(EIO, @"zfs diff failed on this file system"), nullptr);
			return;
		}

		// Name -> versions; one name can be several deleted objects.
		NSMutableDictionary<NSString *, NSMutableDictionary *> * byName =
			[NSMutableDictionary dictionary];
		for (auto const & r : removed)
		{
			// Names that exist again are not deleted.
			struct stat st;
			if (fstatat(dirfd, r.name.c_str(), &st, AT_SYMLINK_NOFOLLOW) == 0)
				continue;
			char path[MAXPATHLEN];
			zfs_obj_version_t ref, v, prev = {};
			if (zfs_get_obj_version(hdl, snapshots[r.lastSnapshot].c_str(),
				r.obj, &ref, path, sizeof (path)) != 0)
				continue;
			NSString * name = toNS(r.name);
			NSMutableDictionary * entry = byName[name];
			if (!entry)
			{
				entry = [@{@"name": name, @"isDirectory": @(r.isDirectory),
					@"versions": [NSMutableArray array]} mutableCopy];
				byName[name] = entry;
			}
			// Newest first; each distinct version once, by the newest
			// snapshot that holds it.
			bool havePrev = false;
			for (size_t s = r.lastSnapshot + 1; s-- > first; )
			{
				if (zfs_get_obj_version(hdl, snapshots[s].c_str(), r.obj,
					&v, path, sizeof (path)) != 0 || v.zov_gen != ref.zov_gen)
					continue;
				if (havePrev && v.zov_size == prev.zov_size &&
					v.zov_mtime[0] == prev.zov_mtime[0] &&
					v.zov_mtime[1] == prev.zov_mtime[1])
					continue;
				NSMutableDictionary * vd = [versionDict(v, path,
					snapshots[s].c_str()) mutableCopy];
				vd[@"index"] = @(s);
				[entry[@"versions"] addObject:vd];
				prev = v;
				havePrev = true;
			}
		}

		NSMutableArray * items = [NSMutableArray array];
		for (NSMutableDictionary * entry in byName.allValues)
		{
			[entry[@"versions"] sortUsingDescriptors:@[
				[NSSortDescriptor sortDescriptorWithKey:@"index" ascending:NO]]];
			if ([entry[@"versions"] count] > 0)
				[items addObject:entry];
		}
		[items sortUsingComparator:^NSComparisonResult(NSDictionary * a, NSDictionary * b) {
			return [a[@"name"] localizedStandardCompare:b[@"name"]];
		}];
		reply(nullptr, @{
			@"dataset": toNS(item.dataset),
			@"mountpoint": toNS(mnt),
			@"folder": toNS(dir.empty() ? "/" : dir),
			@"snapshots": @(snapshots.size() - first),
			@"truncated": @(first > 0),
			@"items": items,
		});
	}
	catch (std::exception const & e)
	{
		reply(exceptionError(e), nullptr);
	}
}

@end
