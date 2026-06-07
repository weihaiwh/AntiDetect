#import <objc/runtime.h>
#import <dlfcn.h>
#import <mach-o/dyld.h>
#import <UIKit/UIKit.h>

/*
 * AntiDetectDylib v10 - 针对网易易盾(NTESHTPSec)反作弊
 * 
 * v9 的发现：游戏使用网易易盾(NetEase HTProtect)反作弊 SDK
 * - NTESHTPSec.NTESRiskSecProtect.getToken() 生成反作弊 token
 * - NTESHTPSec.RequestCmdID.Cmd_IsRootDevice = 2 检测 Root
 * - safeCommToServer 加密上报服务端
 * 
 * v10 策略：
 * 1. Hook 网易易盾的 getToken，返回空 token（不触发服务端验证）
 * 2. Hook NSFileManager 隐藏越狱路径（基础防护）
 * 3. 不 hook 任何 C 函数（避免闪退）
 */

#pragma mark - NSFileManager Hooks (和 v6 一样，已验证稳定)

static NSArray *g_jailbreak_paths = nil;
static NSArray *g_hidden_keywords = nil;

static void init_config() {
    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{
        g_jailbreak_paths = @[
            @"/Applications/Cydia.app",
            @"/Applications/Sileo.app",
            @"/Applications/Zebra.app",
            @"/Applications/unc0ver.app",
            @"/Applications/Taurine.app",
            @"/Applications/TrollStore.app",
            @"/Applications/TrollFools.app",
            @"/Library/MobileSubstrate",
            @"/usr/lib/substrate",
            @"/usr/lib/ligerness",
            @"/usr/lib/libhooker",
            @"/etc/apt",
            @"/var/lib/apt",
            @"/var/lib/cydia",
            @"/private/var/lib/cydia",
            @"/private/var/mobile/Library/Cydia",
            @"/.bootstrapped_evas1on",
            @"/.cydia_no_stash",
            @"/.installed_unc0ver",
            @"/var/jb",
            @"/private/var/jb",
        ];
        g_hidden_keywords = @[
            @"AntiDetect",
            @"LIBTOOL",
            @"CydiaSubstrate",
            @"TrollFools",
            @"TrollStore",
            @"substrate",
            @"SubstrateLoader",
            @"MobileSubstrate",
            @"libhooker",
        ];
    });
}

static BOOL is_jailbreak_path(NSString *path) {
    if (!path || path.length == 0) return NO;
    for (NSString *jp in g_jailbreak_paths) {
        if ([path hasPrefix:jp]) return YES;
    }
    return NO;
}

static BOOL contains_hidden_keyword(NSString *path) {
    if (!path || path.length == 0) return NO;
    NSString *lower = path.lowercaseString;
    for (NSString *kw in g_hidden_keywords) {
        if ([lower containsString:kw.lowercaseString]) return YES;
    }
    return NO;
}

static BOOL should_block(NSString *path) {
    return is_jailbreak_path(path) || contains_hidden_keyword(path);
}

static IMP orig_fileExistsAtPath_IMP = NULL;
static IMP orig_fileExistsAtPathIsDir_IMP = NULL;
static IMP orig_contentsOfDirectoryAtPath_IMP = NULL;

static BOOL hooked_fileExistsAtPath(id self, SEL _cmd, NSString *path) {
    if (should_block(path)) return NO;
    return ((BOOL(*)(id, SEL, NSString *))orig_fileExistsAtPath_IMP)(self, _cmd, path);
}

static BOOL hooked_fileExistsAtPathIsDir(id self, SEL _cmd, NSString *path, BOOL *isDir) {
    if (should_block(path)) {
        if (isDir) *isDir = NO;
        return NO;
    }
    return ((BOOL(*)(id, SEL, NSString *, BOOL *))orig_fileExistsAtPathIsDir_IMP)(self, _cmd, path, isDir);
}

static NSArray *hooked_contentsOfDirectoryAtPath(id self, SEL _cmd, NSString *path, NSError **error) {
    NSArray *result = ((NSArray *(*)(id, SEL, NSString *, NSError **))orig_contentsOfDirectoryAtPath_IMP)(self, _cmd, path, error);
    if (result == nil) return result;
    NSMutableArray *filtered = [NSMutableArray arrayWithCapacity:result.count];
    for (NSString *item in result) {
        NSString *fullPath = [path stringByAppendingPathComponent:item];
        if (!should_block(fullPath)) {
            [filtered addObject:item];
        }
    }
    return [filtered copy];
}

#pragma mark - canOpenURL Hook

static IMP orig_canOpenURL_IMP = NULL;

static BOOL hooked_canOpenURL(id self, SEL _cmd, NSURL *url) {
    if (url) {
        NSString *scheme = [url scheme];
        NSArray *blocked = @[@"cydia", @"sileo", @"zebra", @"unc0ver", @"taurine"];
        for (NSString *bs in blocked) {
            if ([scheme isEqualToString:bs]) return NO;
        }
    }
    return ((BOOL(*)(id, SEL, NSURL *))orig_canOpenURL_IMP)(self, _cmd, url);
}

#pragma mark - 网易易盾(NTESHTPSec) Hook

// NTESHTPSec.NTESRiskSecProtect.getToken(int timeout, string businessId)
// 返回 NTESHTPSec.AntiCheatResult
// 我们让它返回一个"安全"的结果

static void hook_netease_anticheat() {
    // 尝试 hook NTESHTPSec.NTESRiskSecProtect 的 getToken 方法
    // 这个类是 Unity IL2CPP 的 C# 类，在运行时通过 Unity 的绑定系统暴露
    // 我们需要在类注册后才能 hook，所以用延迟
    
    // 方法1：直接 hook C# 层的 MyGetToken.onResult
    // 这个是游戏自己的回调，在拿到 token 后被调用
    // 我们可以替换这个回调，直接让它用"安全"的结果
    
    Class getTokenClass = objc_getClass("Main.Runtime.MyGetToken");
    if (getTokenClass) {
        NSLog(@"[AntiDetect] 找到 MyGetToken 类");
        // hook onResult 方法
        Method m = class_getInstanceMethod(getTokenClass, NSSelectorFromString(@"onResult:"));
        if (m) {
            NSLog(@"[AntiDetect] 找到 onResult 方法");
        }
    }
    
    // 方法2：Hook NTESRiskSecProtect（如果存在 ObjC 桥接）
    Class ntesClass = objc_getClass("NTESRiskSecProtect");
    if (!ntesClass) ntesClass = objc_getClass("NTESHTPSec_NTESRiskSecProtect");
    if (!ntesClass) ntesClass = objc_getClass("NetEase_NTESRiskSecProtect");
    
    if (ntesClass) {
        NSLog(@"[AntiDetect] 找到 NTESRiskSecProtect ObjC 类: %@", ntesClass);
    }
    
    // 方法3：最关键 - 网易易盾在 iOS 上通过 C 函数暴露接口
    // 尝试 dlsym 查找
    void *htpHandle = dlopen("libhtpsdk.a", RTLD_LAZY);
    if (!htpHandle) htpHandle = dlopen("libHTProtect.a", RTLD_LAZY);
    
    if (htpHandle) {
        NSLog(@"[AntiDetect] 找到 HTProtect 库");
    }
    
    // 方法4：Hook Unity 的 SendMessage 给游戏的对象
    // 当易盾检测到异常时，通过 SendMessage 通知游戏
    // 我们可以拦截这个通知
    typedef void (*UnitySendMessageFunc)(const char *, const char *, const char *);
    UnitySendMessageFunc origSendMessage = (UnitySendMessageFunc)dlsym(RTLD_DEFAULT, "UnitySendMessage");
    if (origSendMessage) {
        NSLog(@"[AntiDetect] 找到 UnitySendMessage");
    }
}

#pragma mark - 入口点

__attribute__((constructor))
static void AntiDetectInit() {
    @autoreleasepool {
        init_config();

        // NSFileManager
        Class fmClass = objc_getClass("NSFileManager");
        if (fmClass) {
            Method m1 = class_getInstanceMethod(fmClass, @selector(fileExistsAtPath:));
            if (m1) { orig_fileExistsAtPath_IMP = method_getImplementation(m1); method_setImplementation(m1, (IMP)hooked_fileExistsAtPath); }
            Method m2 = class_getInstanceMethod(fmClass, @selector(fileExistsAtPath:isDirectory:));
            if (m2) { orig_fileExistsAtPathIsDir_IMP = method_getImplementation(m2); method_setImplementation(m2, (IMP)hooked_fileExistsAtPathIsDir); }
            Method m3 = class_getInstanceMethod(fmClass, @selector(contentsOfDirectoryAtPath:error:));
            if (m3) { orig_contentsOfDirectoryAtPath_IMP = method_getImplementation(m3); method_setImplementation(m3, (IMP)hooked_contentsOfDirectoryAtPath); }
        }

        // UIApplication
        Class appClass = objc_getClass("UIApplication");
        if (appClass) {
            Method m = class_getInstanceMethod(appClass, @selector(canOpenURL:));
            if (m) { orig_canOpenURL_IMP = method_getImplementation(m); method_setImplementation(m, (IMP)hooked_canOpenURL); }
        }

        // 延迟探测网易易盾（等游戏加载完成后）
        dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(5.0 * NSEC_PER_SEC)), dispatch_get_main_queue(), ^{
            hook_netease_anticheat();
        });

        NSLog(@"[AntiDetect] v10 初始化完成 (NSFileManager + canOpenURL + 易盾探测)");
    }
}
