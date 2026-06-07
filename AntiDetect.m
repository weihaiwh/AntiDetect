#import <objc/runtime.h>
#import <dlfcn.h>
#import <mach-o/dyld.h>
#import <mach-o/dyld_images.h>
#import <mach/mach.h>
#import <mach/task_info.h>
#import <UIKit/UIKit.h>
#import <string.h>
#import <stdlib.h>

/*
 * AntiDetectDylib v20 - 基于Shadow源码重写
 *
 * 完全模仿Shadow 3.7.6的"动态库"hook实现：
 *   1. 维护一个安全dylib列表（_shdw_dyld_collection）
 *   2. Hook _dyld_image_count → 返回安全dylib数量
 *   3. Hook _dyld_get_image_name → 返回安全dylib名称
 *   4. Hook _dyld_get_image_header → 返回安全dylib header
 *   5. Hook _dyld_get_image_vmaddr_slide → 返回安全dylib slide
 *   6. Hook task_info → 修改TASK_DYLD_INFO中的count
 *   7. Hook dladdr → 伪装被隐藏的dylib为游戏主程序
 *
 * 和Shadow的区别：
 *   - 不需要isCallerTweak()（我们只有游戏进程，没有tweak调用者）
 *   - 不需要ruleset系统（硬编码越狱路径判断）
 *   - 不需要配置界面（默认全部开启）
 *   - 不需要环境变量/文件系统hook（只做动态库隐藏）
 *
 * 和之前版本的关键区别：
 *   - v18/v19: 只hook _dyld_get_image_name返回空 → count和name不一致 → 卡死
 *   - v20: 同时hook count/name/header/slide，保持列表一致性 → 不会卡死
 */

#pragma mark - CydiaSubstrate

typedef void (*MSHookFunction_t)(void *symbol, void *replace, void **result);
static MSHookFunction_t g_MSHookFunction = NULL;

static BOOL load_MSHookFunction() {
    if (g_MSHookFunction) return YES;
    g_MSHookFunction = (MSHookFunction_t)dlsym(RTLD_DEFAULT, "MSHookFunction");
    if (g_MSHookFunction) return YES;
    void *h = dlopen("@executable_path/Frameworks/CydiaSubstrate.framework/CydiaSubstrate", RTLD_LAZY);
    if (!h) h = dlopen("/usr/lib/libsubstrate.dylib", RTLD_LAZY);
    if (h) g_MSHookFunction = (MSHookFunction_t)dlsym(h, "MSHookFunction");
    return (g_MSHookFunction != NULL);
}

#pragma mark - 安全dylib集合

// 模仿Shadow的 _shdw_dyld_collection
// 存储所有"安全"的dylib信息
static NSMutableArray *g_safe_dylib_collection = nil;

// 需要隐藏的dylib路径关键词
static NSArray *g_hide_keywords = nil;

// 游戏主程序路径（用于dladdr伪装）
static const char *g_main_exec_path = NULL;

static BOOL should_hide_dylib_path(const char *path) {
    if (!path) return NO;
    NSString *nsPath = [NSString stringWithUTF8String:path];

    // 系统路径始终安全
    if ([nsPath hasPrefix:@"/System/"]) return NO;
    if ([nsPath hasPrefix:@"/Developer/"]) return NO;
    if ([nsPath hasPrefix:@"/usr/lib/system/"]) return NO;

    // 游戏自身路径安全
    if (g_main_exec_path && strncmp(path, g_main_exec_path, strlen(g_main_exec_path)) == 0) return NO;

    // 检查是否在游戏app bundle内
    if ([nsPath containsString:@"/Application/"] && ![nsPath containsString:@"/Applications/"]) {
        // 在/var/containers/Bundle/Application/下的app bundle内部，安全
        // 但要排除越狱app
        for (NSString *kw in g_hide_keywords) {
            if ([nsPath containsString:kw]) return YES;
        }
        return NO;
    }

    // /usr/lib 下的，只隐藏含关键词的
    if ([nsPath hasPrefix:@"/usr/lib/"]) {
        for (NSString *kw in g_hide_keywords) {
            if ([nsPath containsString:kw]) return YES;
        }
        return NO;
    }

    // 其他路径：检查关键词
    for (NSString *kw in g_hide_keywords) {
        if ([nsPath containsString:kw]) return YES;
    }

    // 越狱特有路径
    static NSArray *jb_prefixes = nil;
    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{
        jb_prefixes = @[
            @"/var/jb/", @"/private/var/jb/",
            @"/Library/MobileSubstrate", @"/etc/apt",
            @"/var/lib/apt", @"/var/lib/cydia",
            @"/Applications/Cydia.app", @"/Applications/Sileo.app",
            @"/Applications/Zebra.app", @"/Applications/unc0ver.app",
            @"/Applications/Taurine.app", @"/Applications/TrollStore.app",
            @"/Applications/TrollFools.app",
        ];
    });

    for (NSString *prefix in jb_prefixes) {
        if ([nsPath hasPrefix:prefix]) return YES;
    }

    return NO;
}

#pragma mark - 构建安全dylib集合

static void build_safe_dylib_collection() {
    g_safe_dylib_collection = [NSMutableArray new];
    g_hide_keywords = @[
        @"CydiaSubstrate", @"SubstrateLoader", @"MobileSubstrate",
        @"TrollFools", @"TrollStore", @"AntiDetect",
        @"LIBTOOL", @"libhooker", @"substrate",
        @"Shadow", @"libSandy", @"RootBridge",
        @"HookKit", @"PreferenceLoader",
    ];

    // 获取游戏主程序路径（第一个image通常是主程序）
    // 找到在 /Application/ 下但不是 /Applications/ 的路径
    for (uint32_t i = 0; i < _dyld_image_count(); i++) {
        const char *name = _dyld_get_image_name(i);
        if (name && strstr(name, "/Application/") && !strstr(name, "/Applications/")) {
            // 这是app bundle内的路径
            if (!strstr(name, ".dylib") && !strstr(name, ".framework/")) {
                // 这是主程序
                g_main_exec_path = strdup(name);
                break;
            }
        }
    }
    if (!g_main_exec_path) {
        // 回退：用_dyld_get_image_name(0)
        const char *name = _dyld_get_image_name(0);
        if (name) g_main_exec_path = strdup(name);
    }

    NSLog(@"[AntiDetect] 主程序路径: %s", g_main_exec_path ? g_main_exec_path : "未知");

    // 遍历所有已加载的dylib，只保留安全的
    uint32_t total = _dyld_image_count();
    int hidden = 0;

    for (uint32_t i = 0; i < total; i++) {
        const char *name = _dyld_get_image_name(i);
        if (should_hide_dylib_path(name)) {
            hidden++;
            NSLog(@"[AntiDetect] 隐藏: %s", name);
        } else {
            const struct mach_header *header = _dyld_get_image_header(i);
            intptr_t slide = _dyld_get_image_vmaddr_slide(i);

            NSDictionary *dylibInfo = @{
                @"name": [NSString stringWithUTF8String:name],
                @"mach_header": [NSValue valueWithPointer:header],
                @"slide": [NSValue valueWithPointer:(void *)slide],
            };
            [g_safe_dylib_collection addObject:dylibInfo];
        }
    }

    NSLog(@"[AntiDetect] dylib集合构建完成: 总数%d, 隐藏%d, 安全%lu",
          total, hidden, (unsigned long)g_safe_dylib_collection.count);
}

#pragma mark - dyld函数Hook

static uint32_t (*orig_dyld_image_count)(void) = NULL;
static const char *(*orig_dyld_get_image_name)(uint32_t) = NULL;
static const struct mach_header *(*orig_dyld_get_image_header)(uint32_t) = NULL;
static intptr_t (*orig_dyld_get_image_vmaddr_slide)(uint32_t) = NULL;

static uint32_t hook_dyld_image_count(void) {
    return (uint32_t)[g_safe_dylib_collection count];
}

static const char *hook_dyld_get_image_name(uint32_t index) {
    if (index < [g_safe_dylib_collection count]) {
        return [g_safe_dylib_collection[index][@"name"] fileSystemRepresentation];
    }
    return NULL;
}

static const struct mach_header *hook_dyld_get_image_header(uint32_t index) {
    if (index < [g_safe_dylib_collection count]) {
        return (struct mach_header *)[g_safe_dylib_collection[index][@"mach_header"] pointerValue];
    }
    return NULL;
}

static intptr_t hook_dyld_get_image_vmaddr_slide(uint32_t index) {
    if (index < [g_safe_dylib_collection count]) {
        return (intptr_t)[g_safe_dylib_collection[index][@"slide"] pointerValue];
    }
    return 0;
}

#pragma mark - task_info Hook（修改TASK_DYLD_INFO）

static kern_return_t (*orig_task_info)(task_name_t, task_flavor_t, task_info_t, mach_msg_type_number_t *) = NULL;

static kern_return_t hook_task_info(task_name_t target_task, task_flavor_t flavor,
                                     task_info_t task_info_out, mach_msg_type_number_t *task_info_outCnt) {
    kern_return_t result = orig_task_info(target_task, flavor, task_info_out, task_info_outCnt);

    if (flavor == TASK_DYLD_INFO && result == KERN_SUCCESS) {
        struct task_dyld_info *info = (struct task_dyld_info *)task_info_out;
        if (info && info->all_image_info_addr) {
            struct dyld_all_image_infos *dyld_info = (struct dyld_all_image_infos *)info->all_image_info_addr;
            // 修改为安全dylib的数量
            dyld_info->infoArrayCount = (uint32_t)[g_safe_dylib_collection count];
            dyld_info->uuidArrayCount = (uint32_t)[g_safe_dylib_collection count];
        }
    }

    return result;
}

#pragma mark - dladdr Hook（伪装被隐藏的dylib）

static int (*orig_dladdr)(const void *, Dl_info *) = NULL;

static int hook_dladdr(const void *addr, Dl_info *info) {
    int ret = orig_dladdr(addr, info);

    if (ret && info && info->dli_fname) {
        // 检查这个dylib是否应该被隐藏
        if (should_hide_dylib_path(info->dli_fname)) {
            // 伪装为游戏主程序（和Shadow的做法一致）
            if (g_main_exec_path) {
                info->dli_fname = g_main_exec_path;
            }
            info->dli_sname = NULL;
        }
    }

    return ret;
}

#pragma mark - ObjC Hook（NSFileManager基础 + canOpenURL + 弹窗拦截）

static NSArray *g_jb_paths_ns = nil;
static NSArray *g_hide_kw_ns = nil;

static BOOL should_block_ns(NSString *path) {
    if (!path || path.length == 0) return NO;
    for (NSString *jp in g_jb_paths_ns) {
        if ([path hasPrefix:jp]) return YES;
    }
    NSString *lower = path.lowercaseString;
    for (NSString *kw in g_hide_kw_ns) {
        if ([lower containsString:kw.lowercaseString]) return YES;
    }
    return NO;
}

static IMP orig_fileExistsAtPath_IMP = NULL;
static IMP orig_fileExistsAtPathIsDir_IMP = NULL;
static IMP orig_contentsOfDirectoryAtPath_IMP = NULL;
static IMP orig_canOpenURL_IMP = NULL;
static IMP orig_presentViewController_IMP = NULL;

static BOOL hooked_fileExistsAtPath(id self, SEL _cmd, NSString *path) {
    if (should_block_ns(path)) return NO;
    return ((BOOL(*)(id, SEL, NSString *))orig_fileExistsAtPath_IMP)(self, _cmd, path);
}

static BOOL hooked_fileExistsAtPathIsDir(id self, SEL _cmd, NSString *path, BOOL *isDir) {
    if (should_block_ns(path)) { if (isDir) *isDir = NO; return NO; }
    return ((BOOL(*)(id, SEL, NSString *, BOOL *))orig_fileExistsAtPathIsDir_IMP)(self, _cmd, path, isDir);
}

static NSArray *hooked_contentsOfDirectoryAtPath(id self, SEL _cmd, NSString *path, NSError **error) {
    NSArray *result = ((NSArray *(*)(id, SEL, NSString *, NSError **))orig_contentsOfDirectoryAtPath_IMP)(self, _cmd, path, error);
    if (!result) return result;
    NSMutableArray *filtered = [NSMutableArray arrayWithCapacity:result.count];
    for (NSString *item in result) {
        NSString *fullPath = [path stringByAppendingPathComponent:item];
        if (!should_block_ns(fullPath)) [filtered addObject:item];
    }
    return [filtered copy];
}

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

static void hooked_presentViewController(id self, SEL _cmd, UIViewController *vc, BOOL animated, id completion) {
    if ([vc isKindOfClass:[UIAlertController class]]) {
        UIAlertController *alert = (UIAlertController *)vc;
        NSString *combined = [NSString stringWithFormat:@"%@%@", alert.title ?: @"", alert.message ?: @""];
        if ([combined containsString:@"环境异常"] || [combined containsString:@"800180933"] || [combined containsString:@"QQ公众号"]) {
            NSLog(@"[AntiDetect] 拦截弹窗");
            return;
        }
    }
    ((void(*)(id, SEL, UIViewController *, BOOL, id))orig_presentViewController_IMP)(self, _cmd, vc, animated, completion);
}

#pragma mark - 安装dyld Hook

static void install_dyld_hooks() {
    NSLog(@"[AntiDetect] 安装dyld Hook...");
    if (!load_MSHookFunction()) {
        NSLog(@"[AntiDetect] MSHookFunction不可用");
        return;
    }

    // 先构建安全dylib集合（必须在hook之前，因为hook后会改变_dyld_image_count等）
    build_safe_dylib_collection();

    // Hook所有dyld相关函数（和Shadow完全一致）
    g_MSHookFunction((void *)_dyld_image_count, (void *)hook_dyld_image_count, (void **)&orig_dyld_image_count);
    g_MSHookFunction((void *)_dyld_get_image_name, (void *)hook_dyld_get_image_name, (void **)&orig_dyld_get_image_name);
    g_MSHookFunction((void *)_dyld_get_image_header, (void *)hook_dyld_get_image_header, (void **)&orig_dyld_get_image_header);
    g_MSHookFunction((void *)_dyld_get_image_vmaddr_slide, (void *)hook_dyld_get_image_vmaddr_slide, (void **)&orig_dyld_get_image_vmaddr_slide);

    // Hook task_info（修改TASK_DYLD_INFO）
    g_MSHookFunction((void *)task_info, (void *)hook_task_info, (void **)&orig_task_info);

    // Hook dladdr（伪装被隐藏的dylib）
    g_MSHookFunction((void *)dladdr, (void *)hook_dladdr, (void **)&orig_dladdr);

    NSLog(@"[AntiDetect] ★ dyld Hook全部安装完成 ★");
}

#pragma mark - 入口点

__attribute__((constructor))
static void AntiDetectInit() {
    @autoreleasepool {
        g_jb_paths_ns = @[
            @"/Applications/Cydia.app", @"/Applications/Sileo.app",
            @"/Applications/Zebra.app", @"/Applications/unc0ver.app",
            @"/Applications/Taurine.app", @"/Applications/TrollStore.app",
            @"/Applications/TrollFools.app", @"/Library/MobileSubstrate",
            @"/usr/lib/substrate", @"/usr/lib/ligerness",
            @"/usr/lib/libhooker", @"/etc/apt", @"/var/lib/apt",
            @"/var/lib/cydia", @"/private/var/lib/cydia",
            @"/private/var/mobile/Library/Cydia", @"/.bootstrapped_evas1on",
            @"/.cydia_no_stash", @"/.installed_unc0ver",
            @"/var/jb", @"/private/var/jb",
        ];
        g_hide_kw_ns = @[
            @"AntiDetect", @"LIBTOOL", @"CydiaSubstrate",
            @"TrollFools", @"TrollStore", @"substrate",
            @"SubstrateLoader", @"MobileSubstrate", @"libhooker",
        ];

        NSLog(@"[AntiDetect] v20 初始化（基于Shadow源码重写）...");

        // ===== ObjC Hook（constructor中立即执行，稳定）=====
        Class fmClass = objc_getClass("NSFileManager");
        if (fmClass) {
            Method m1 = class_getInstanceMethod(fmClass, @selector(fileExistsAtPath:));
            if (m1) { orig_fileExistsAtPath_IMP = method_getImplementation(m1); method_setImplementation(m1, (IMP)hooked_fileExistsAtPath); }
            Method m2 = class_getInstanceMethod(fmClass, @selector(fileExistsAtPath:isDirectory:));
            if (m2) { orig_fileExistsAtPathIsDir_IMP = method_getImplementation(m2); method_setImplementation(m2, (IMP)hooked_fileExistsAtPathIsDir); }
            Method m3 = class_getInstanceMethod(fmClass, @selector(contentsOfDirectoryAtPath:error:));
            if (m3) { orig_contentsOfDirectoryAtPath_IMP = method_getImplementation(m3); method_setImplementation(m3, (IMP)hooked_contentsOfDirectoryAtPath); }
        }

        Class appClass = objc_getClass("UIApplication");
        if (appClass) {
            Method m = class_getInstanceMethod(appClass, @selector(canOpenURL:));
            if (m) { orig_canOpenURL_IMP = method_getImplementation(m); method_setImplementation(m, (IMP)hooked_canOpenURL); }
        }

        Class vcClass = objc_getClass("UIViewController");
        if (vcClass) {
            Method m = class_getInstanceMethod(vcClass, @selector(presentViewController:animated:completion:));
            if (m) { orig_presentViewController_IMP = method_getImplementation(m); method_setImplementation(m, (IMP)hooked_presentViewController); }
        }

        // ===== dyld Hook（延迟1秒，模仿Shadow的方式安装）=====
        dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(1.0 * NSEC_PER_SEC)), dispatch_get_main_queue(), ^{
            install_dyld_hooks();
        });

        NSLog(@"[AntiDetect] v20 ObjC完成，+1s安装dyld全套Hook");
    }
}
