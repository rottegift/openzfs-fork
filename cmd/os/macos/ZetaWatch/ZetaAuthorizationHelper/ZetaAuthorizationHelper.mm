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

static NSError * versionsError(int code, NSString * what)
{
	return [NSError errorWithDomain:NSPOSIXErrorDomain code:code
		userInfo:@{NSLocalizedDescriptionKey: what}];
}

static NSDictionary * versionDict(zfs_obj_version_t const & v,
	char const * path, char const * snapshot)
{
	NSMutableDictionary * d = [@{
		@"path": [NSString stringWithUTF8String:path],
		@"size": @(v.zov_size),
		@"mtime": [NSDate dateWithTimeIntervalSince1970:
			v.zov_mtime[0] + v.zov_mtime[1] / 1e9],
		@"mode": @(v.zov_mode),
		@"gen": @(v.zov_gen),
	} mutableCopy];
	if (snapshot)
		d[@"snapshot"] = [NSString stringWithUTF8String:snapshot];
	return d;
}

static int collectSnapshotName(zfs_handle_t * zhp, void * arg)
{
	auto names = static_cast<std::vector<std::string> *>(arg);
	names->emplace_back(zfs_get_name(zhp));
	zfs_close(zhp);
	return 0;
}

- (void)fileVersions:(NSFileHandle *)file
		   withReply:(void (^)(NSError *, NSDictionary *))reply
{
	// No authorization check: holding the item open for reading is the
	// proof that the caller may see it. O_EXEC/O_SEARCH descriptors have
	// an access mode of O_RDONLY (0), so they are refused explicitly.
	int fd = file.fileDescriptor;
	int flags = fcntl(fd, F_GETFL);
	if (flags == -1 ||
		((flags & O_ACCMODE) != O_RDONLY && (flags & O_ACCMODE) != O_RDWR) ||
		(flags & (O_EXEC | O_EVTONLY)) != 0)
	{
		reply(versionsError(EBADF, @"The item must be open for reading"), nullptr);
		return;
	}
	struct stat st;
	struct statfs sfs, msfs;
	if (fstat(fd, &st) != 0 || fstatfs(fd, &sfs) != 0)
	{
		reply(versionsError(errno, @"Cannot stat the item"), nullptr);
		return;
	}
	uint64_t obj = st.st_ino;
	if (obj == kInoRoot)
	{
		reply(versionsError(ENOTSUP,
			@"Versions of a file system's top folder are not supported yet"), nullptr);
		return;
	}
	if (obj >= kInoMap)
		obj -= kInoMap;

	// The mount point must still be the mount the descriptor lives on.
	if (statfs(sfs.f_mntonname, &msfs) != 0 ||
		memcmp(&msfs.f_fsid, &sfs.f_fsid, sizeof (sfs.f_fsid)) != 0)
	{
		reply(versionsError(ENOENT, @"The item's file system has moved"), nullptr);
		return;
	}

	try
	{
		zfs::LibZFSHandle zfs;
		libzfs_handle_t * hdl = zfs.handle();
		// The dataset (or snapshot) the descriptor is on: its version of
		// the object is the reference the others must match (same gen).
		// Datasets and snapshots mount with their name as the device; a
		// pool's root dataset may mount as /dev/diskN, which libzfs maps
		// back to the dataset (zfs_path_to_zhandle() only opens
		// filesystems, so it cannot be used for snapshot mounts).
		std::string reference;
		if (sfs.f_mntfromname[0] != '/' &&
			strcmp(sfs.f_fstypename, "zfs") == 0 &&
			zfs_dataset_exists(hdl, sfs.f_mntfromname,
				static_cast<zfs_type_t>(ZFS_TYPE_FILESYSTEM | ZFS_TYPE_SNAPSHOT)))
		{
			reference = sfs.f_mntfromname;
		}
		else if (zfs_handle_t * mzhp = zfs_path_to_zhandle(hdl,
			sfs.f_mntonname, ZFS_TYPE_FILESYSTEM))
		{
			reference = zfs_get_name(mzhp);
			zfs_close(mzhp);
		}
		else
		{
			reply(versionsError(EINVAL, @"The item is not on a ZFS file system"), nullptr);
			return;
		}
		std::string dataset = reference.substr(0, reference.find('@'));
		zfs_handle_t * zhp = zfs_open(hdl, dataset.c_str(), ZFS_TYPE_FILESYSTEM);
		if (zhp == nullptr)
		{
			reply(versionsError(ENOENT, @"Cannot open the file system"), nullptr);
			return;
		}

		char path[MAXPATHLEN];
		zfs_obj_version_t ref, v;
		int err = zfs_get_obj_version(hdl, reference.c_str(), obj, &ref,
			path, sizeof (path));
		if (err != 0)
		{
			zfs_close(zhp);
			reply(versionsError(err, @"Cannot look up the item"), nullptr);
			return;
		}

		NSMutableDictionary * result = [NSMutableDictionary dictionary];
		result[@"dataset"] = [NSString stringWithUTF8String:dataset.c_str()];
		char * where = nullptr;
		if (zfs_is_mounted(zhp, &where) && where != nullptr)
			result[@"mountpoint"] = [NSString stringWithUTF8String:where];
		free(where);

		if (zfs_get_obj_version(hdl, dataset.c_str(), obj, &v, path,
			sizeof (path)) == 0 && v.zov_gen == ref.zov_gen)
			result[@"live"] = versionDict(v, path, nullptr);

		std::vector<std::string> snapshots;
		(void) zfs_iter_snapshots_sorted_v2(zhp, 0, collectSnapshotName,
			&snapshots, 0, 0);
		zfs_close(zhp);

		NSMutableArray * versions = [NSMutableArray array];
		for (auto s = snapshots.rbegin(); s != snapshots.rend(); ++s)
		{
			// ENOENT: the object did not exist yet, or no longer.
			// A different gen: the object number was reused by
			// another file.
			if (zfs_get_obj_version(hdl, s->c_str(), obj, &v, path,
				sizeof (path)) != 0 || v.zov_gen != ref.zov_gen)
				continue;
			[versions addObject:versionDict(v, path, s->c_str())];
		}
		result[@"versions"] = versions;
		reply(nullptr, result);
	}
	catch (std::exception const & e)
	{
		reply([NSError errorWithDomain:@"ZFSException" code:-1 userInfo:@{NSLocalizedDescriptionKey: [NSString stringWithUTF8String:e.what()]}], nullptr);
	}
}

@end
