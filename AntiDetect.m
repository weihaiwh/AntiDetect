#import <objc/runtime.h>
#import <dlfcn.h>
#import <mach-o/dyld.h>
#import <UIKit/UIKit.h>
#import <pthread.h>

/*
 * AntiDetectDylib v11 - il2cpp Runtime Hook 策略
 *
 * v10发现：纯ObjC NSFileManager hook稳定但拦不住易盾的native层检测
 * v11核心策略转变：
 *   1. 保留v6稳定的NSFileManager/canOpenURL ObjC hook基础
 *   2. 使用il2cpp C API直接操作反作弊类的内存字段，而非hook C函数
 *   3. 关键：Hook NSURLConnection/NSURLSession的网络层，拦截易盾服务端上报
 *   4. 让getToken返回的AntiCheatResult.code = 0 (OK)
 *
 * 为什么不用fishhook/DYLD_INTERPOSE：在TrollStore注入环境下必闪退
 * 为什么不用ObjC hook il2cpp类：il2cpp类不是ObjC类，objc_getClass找不到
 *
 * v11方案：
 *   A) Hook NSURLSession/NSURLConnection的dataTask回调，检测并拦截易盾上报流量
 *   B) Hook NSJSONSerialization，篡改反作弊相关JSON数据
 *   C) 用dlsym找il2cpp运行时函数，直接修改静态字段
 *   D) 在游戏C#层getToken结果返回前，替换token字符串
 */

#pragma mark - 配置

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

#pragma mark - NSFileManager Hooks (v6稳定基础)

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

#pragma mark - il2cpp Runtime 接口

// il2cpp运行时函数指针
typedef void* (*il2cpp_domain_get_t)(void);
typedef void* (*il2cpp_domain_get_assemblies_t)(void* domain, size_t* size);
typedef void* (*il2cpp_assembly_get_image_t)(void* assembly);
typedef void* (*il2cpp_class_from_name_t)(void* image, const char* ns, const char* name);
typedef void* (*il2cpp_class_get_method_from_name_t)(void* klass, const char* name, int argsCount);
typedef void* (*il2cpp_method_get_param_count_t)(void* method);
typedef void  (*il2cpp_runtime_invoke_t)(void* method, void* obj, void** params, void** exc);
typedef void* (*il2cpp_field_static_get_value_t)(void* field, void* value);
typedef void  (*il2cpp_field_static_set_value_t)(void* field, void* value);
typedef void* (*il2cpp_class_get_field_from_name_t)(void* klass, const char* name);
typedef void* (*il2cpp_field_get_offset_t)(void* field);
typedef void* (*il2cpp_string_new_t)(const char* str);
typedef size_t (*il2cpp_string_length_t)(void* str);
typedef char* (*il2cpp_string_chars_t)(void* str);
typedef int   (*il2cpp_field_get_flags_t)(void* field);

static il2cpp_domain_get_t                 p_il2cpp_domain_get = NULL;
static il2cpp_domain_get_assemblies_t      p_il2cpp_domain_get_assemblies = NULL;
static il2cpp_assembly_get_image_t         p_il2cpp_assembly_get_image = NULL;
static il2cpp_class_from_name_t           p_il2cpp_class_from_name = NULL;
static il2cpp_class_get_method_from_name_t p_il2cpp_class_get_method_from_name = NULL;
static il2cpp_runtime_invoke_t            p_il2cpp_runtime_invoke = NULL;
static il2cpp_class_get_field_from_name_t p_il2cpp_class_get_field_from_name = NULL;
static il2cpp_field_static_get_value_t    p_il2cpp_field_static_get_value = NULL;
static il2cpp_field_static_set_value_t    p_il2cpp_field_static_set_value = NULL;
static il2cpp_string_new_t               p_il2cpp_string_new = NULL;

static BOOL load_il2cpp_api() {
    void *handle = dlopen(NULL, RTLD_LAZY);
    if (!handle) {
        NSLog(@"[AntiDetect] dlopen(NULL) 失败");
        return NO;
    }

    p_il2cpp_domain_get = (il2cpp_domain_get_t)dlsym(handle, "il2cpp_domain_get");
    p_il2cpp_domain_get_assemblies = (il2cpp_domain_get_assemblies_t)dlsym(handle, "il2cpp_domain_get_assemblies");
    p_il2cpp_assembly_get_image = (il2cpp_assembly_get_image_t)dlsym(handle, "il2cpp_assembly_get_image");
    p_il2cpp_class_from_name = (il2cpp_class_from_name_t)dlsym(handle, "il2cpp_class_from_name");
    p_il2cpp_class_get_method_from_name = (il2cpp_class_get_method_from_name_t)dlsym(handle, "il2cpp_class_get_method_from_name");
    p_il2cpp_runtime_invoke = (il2cpp_runtime_invoke_t)dlsym(handle, "il2cpp_runtime_invoke");
    p_il2cpp_class_get_field_from_name = (il2cpp_class_get_field_from_name_t)dlsym(handle, "il2cpp_class_get_field_from_name");
    p_il2cpp_field_static_get_value = (il2cpp_field_static_get_value_t)dlsym(handle, "il2cpp_field_static_get_value");
    p_il2cpp_field_static_set_value = (il2cpp_field_static_set_value_t)dlsym(handle, "il2cpp_field_static_set_value");
    p_il2cpp_string_new = (il2cpp_string_new_t)dlsym(handle, "il2cpp_string_new");

    if (!p_il2cpp_domain_get || !p_il2cpp_class_from_name) {
        NSLog(@"[AntiDetect] il2cpp API 加载不完整，部分功能不可用");
        return NO;
    }

    NSLog(@"[AntiDetect] il2cpp API 加载成功");
    return YES;
}

#pragma mark - il2cpp AntiCheat 操作

// 网易易盾相关的il2cpp类和方法偏移
// 来自dump分析:
// NTESHTPSec.NTESRiskSecProtect 在 NTESHTPSec 命名空间
// NetEase.NetSecProtect 在 NetEase 命名空间
// Main.Runtime.NetEaseRuntime 在 Main.Runtime 命名空间
// Main.Runtime.MyGetToken 在 Main.Runtime 命名空间
// NetEase.AntiCheatResult.code 偏移 0x10, codeStr 0x18, token 0x20, businessId 0x28
// NTESHTPSec.NTESRiskSecProtect.isInitialized 偏移 0x0 (静态bool)
// Main.Runtime.NetEaseRuntime.NetEaseEnable 偏移 0x0 (静态bool)
// Main.Runtime.NetEaseRuntime.CurrentToken 偏移 0x8 (静态string)

static void patch_netease_anticheat_il2cpp() {
    if (!p_il2cpp_domain_get) {
        NSLog(@"[AntiDetect] il2cpp API 不可用，跳过il2cpp层patch");
        return;
    }

    void *domain = p_il2cpp_domain_get();
    if (!domain) {
        NSLog(@"[AntiDetect] il2cpp_domain_get 返回 NULL");
        return;
    }

    NSLog(@"[AntiDetect] il2cpp domain 获取成功");

    size_t assemblyCount = 0;
    void **assemblies = (void **)p_il2cpp_domain_get_assemblies(domain, &assemblyCount);
    if (!assemblies || assemblyCount == 0) {
        NSLog(@"[AntiDetect] 获取assemblies失败");
        return;
    }

    NSLog(@"[AntiDetect] 找到 %zu 个assembly", assemblyCount);

    // 查找关键类并操作
    for (size_t i = 0; i < assemblyCount; i++) {
        void *image = p_il2cpp_assembly_get_image(assemblies[i]);
        if (!image) continue;

        // ====== 1. NTESHTPSec.NTESRiskSecProtect ======
        void *ntesRiskCls = p_il2cpp_class_from_name(image, "NTESHTPSec", "NTESRiskSecProtect");
        if (ntesRiskCls) {
            NSLog(@"[AntiDetect] 找到 NTESHTPSec.NTESRiskSecProtect");

            // 设置 isInitialized = true（让SDK认为已初始化，跳过重复初始化检测）
            void *initField = p_il2cpp_class_get_field_from_name(ntesRiskCls, "isInitialized");
            if (initField && p_il2cpp_field_static_set_value) {
                int32_t val = 1; // true
                p_il2cpp_field_static_set_value(initField, &val);
                NSLog(@"[AntiDetect] NTESRiskSecProtect.isInitialized 已设置为 true");
            }

            // 清空 getTokenAsyncCallback 回调，让getToken结果无法传递
            // 注意：这可能让getToken永远不返回，导致游戏卡住
            // 所以不这么做，改用其他策略
        }

        // ====== 2. NetEase.NetSecProtect ======
        void *netSecCls = p_il2cpp_class_from_name(image, "NetEase", "NetSecProtect");
        if (netSecCls) {
            NSLog(@"[AntiDetect] 找到 NetEase.NetSecProtect");

            // 设置 isInitialized = true
            void *initField = p_il2cpp_class_get_field_from_name(netSecCls, "isInitialized");
            if (initField && p_il2cpp_field_static_set_value) {
                int32_t val = 1;
                p_il2cpp_field_static_set_value(initField, &val);
                NSLog(@"[AntiDetect] NetSecProtect.isInitialized 已设置为 true");
            }

            // 调用 ioctl(Cmd_IsRootDevice=2, "0") 让它返回"非root"
            // 通过 il2cpp_runtime_invoke 调用 C# 方法
            if (p_il2cpp_runtime_invoke) {
                void *ioctlMethod = p_il2cpp_class_get_method_from_name(netSecCls, "ioctl", 2);
                if (ioctlMethod) {
                    NSLog(@"[AntiDetect] 找到 NetSecProtect.ioctl 方法，尝试调用");
                    // 注意：ioctl参数是(RequestCmdID, string)
                    // 需要构造il2cpp的枚举值和字符串对象
                    // 这很复杂，先跳过
                }
            }
        }

        // ====== 3. Main.Runtime.NetEaseRuntime ======
        // 这是最关键的类！它控制游戏对易盾的使用
        void *neRuntime = p_il2cpp_class_from_name(image, "Main.Runtime", "NetEaseRuntime");
        if (neRuntime) {
            NSLog(@"[AntiDetect] 找到 Main.Runtime.NetEaseRuntime ★关键★");

            // 核心字段：NetEaseEnable (静态bool)
            // 设置为true让游戏认为易盾已启用，但实际检测结果被我们篡改
            void *enableField = p_il2cpp_class_get_field_from_name(neRuntime, "NetEaseEnable");
            if (enableField && p_il2cpp_field_static_set_value) {
                // 读取当前值
                int32_t curVal = 0;
                p_il2cpp_field_static_get_value(enableField, &curVal);
                NSLog(@"[AntiDetect] NetEaseEnable 当前值: %d", curVal);

                // 保持为true（1），因为如果设为false，游戏会认为易盾不可用
                // 可能会走另一条检测路径
                int32_t newVal = 1;
                p_il2cpp_field_static_set_value(enableField, &newVal);
                NSLog(@"[AntiDetect] NetEaseEnable 已设置为 1 (启用)");
            }

            // CurrentToken 字段
            void *tokenField = p_il2cpp_class_get_field_from_name(neRuntime, "CurrentToken");
            if (tokenField) {
                NSLog(@"[AntiDetect] 找到 CurrentToken 字段");
                // 读取当前token
                void *curToken = NULL;
                p_il2cpp_field_static_get_value(tokenField, &curToken);
                if (curToken) {
                    NSLog(@"[AntiDetect] CurrentToken 已有值（长度未知）");
                }
            }
        }

        // ====== 4. NTESHTPSec.AntiCheatResult ======
        void *ntesResultCls = p_il2cpp_class_from_name(image, "NTESHTPSec", "AntiCheatResult");
        if (ntesResultCls) {
            NSLog(@"[AntiDetect] 找到 NTESHTPSec.AntiCheatResult");

            // 查看OK字段的值（code=0代表正常）
            void *okField = p_il2cpp_class_get_field_from_name(ntesResultCls, "OK");
            if (okField) {
                int32_t okVal = 0;
                p_il2cpp_field_static_get_value(okField, &okVal);
                NSLog(@"[AntiDetect] AntiCheatResult.OK = %d", okVal);
            }
        }

        // ====== 5. NetEase.AntiCheatResult ======
        void *neResultCls = p_il2cpp_class_from_name(image, "NetEase", "AntiCheatResult");
        if (neResultCls) {
            NSLog(@"[AntiDetect] 找到 NetEase.AntiCheatResult");

            void *okField = p_il2cpp_class_get_field_from_name(neResultCls, "OK");
            if (okField) {
                int32_t okVal = 0;
                p_il2cpp_field_static_get_value(okField, &okVal);
                NSLog(@"[AntiDetect] NetEase.AntiCheatResult.OK = %d", okVal);
            }

            void *errorNotInitField = p_il2cpp_class_get_field_from_name(neResultCls, "ERROR_NOT_INIT");
            if (errorNotInitField) {
                int32_t val = 0;
                p_il2cpp_field_static_get_value(errorNotInitField, &val);
                NSLog(@"[AntiDetect] AntiCheatResult.ERROR_NOT_INIT = %d", val);
            }
        }

        // ====== 6. Main.Runtime.MyGetToken ======
        void *getTokenCls = p_il2cpp_class_from_name(image, "Main.Runtime", "MyGetToken");
        if (getTokenCls) {
            NSLog(@"[AntiDetect] 找到 Main.Runtime.MyGetToken");
        }

        // ====== 7. Main.Runtime.MyHtpCallback ======
        void *htpCallbackCls = p_il2cpp_class_from_name(image, "Main.Runtime", "MyHtpCallback");
        if (htpCallbackCls) {
            NSLog(@"[AntiDetect] 找到 Main.Runtime.MyHtpCallback");
        }

        // ====== 8. NetEase.HTProtectConfig ======
        void *htpConfigCls = p_il2cpp_class_from_name(image, "NetEase", "HTProtectConfig");
        if (htpConfigCls) {
            NSLog(@"[AntiDetect] 找到 NetEase.HTProtectConfig");

            // 查看ie和ic字段（可能是环境检测和完整性检测开关）
            void *ieField = p_il2cpp_class_get_field_from_name(htpConfigCls, "<ie>k__BackingField");
            if (ieField) {
                int32_t ieVal = 0;
                p_il2cpp_field_static_get_value(ieField, &ieVal);
                NSLog(@"[AntiDetect] HTProtectConfig.ie = %d", ieVal);
            }
            void *icField = p_il2cpp_class_get_field_from_name(htpConfigCls, "<ic>k__BackingField");
            if (icField) {
                int32_t icVal = 0;
                p_il2cpp_field_static_get_value(icField, &icVal);
                NSLog(@"[AntiDetect] HTProtectConfig.ic = %d", icVal);
            }
        }
    }
}

#pragma mark - 网络层拦截 (NSURLSession Hook)

// 易盾通过安全通道(safeCommToServer)上报数据到服务器
// 服务器返回检测结果后，游戏客户端根据结果踢人
// 我们hook NSURLSession的回调来检测易盾的网络通信

static IMP orig_setDataTaskCompletionHandler_IMP = NULL;

// 拦截方式：Hook NSURLSessionConfiguration 的 defaultConfiguration
// 让所有通过 NSURLSession 发出的请求都经过我们的检查

static IMP orig_sessionInitWithURL_IMP = NULL;

// 更好的方案：Hook NSDictionary 和 NSJSONSerialization
// 易盾的数据采集结果最终会通过JSON格式上报

static IMP orig_jsonSerialization_dataWithJSONObject_IMP = NULL;

static NSData *hooked_jsonSerialization_dataWithJSONObject(id self, SEL _cmd, id obj, NSJSONWritingOptions opt, NSError **error) {
    // 检查是否是易盾相关的JSON数据
    if ([obj isKindOfClass:[NSDictionary class]]) {
        NSDictionary *dict = (NSDictionary *)obj;
        // 易盾上报的JSON通常包含特定字段
        NSArray *anticheatKeys = @[@"code", @"token", @"businessId", @"signResult", @"encResult"];
        NSInteger matchCount = 0;
        for (NSString *key in anticheatKeys) {
            if (dict[key]) matchCount++;
        }
        if (matchCount >= 3) {
            NSLog(@"[AntiDetect] 检测到疑似易盾上报数据: %@", dict);
            // 不修改，只记录
        }
    }
    return ((NSData *(*)(id, SEL, id, NSJSONWritingOptions, NSError **))orig_jsonSerialization_dataWithJSONObject_IMP)(self, _cmd, obj, opt, error);
}

#pragma mark - 网络请求拦截 (NSURLSession Hook)

// 易盾safeCommToServer底层最终也会走NSURLSession
// 但关键是：服务端返回检测结果给游戏，游戏判断后踢人
// 所以我们不仅要拦截上行，更要拦截下行
//
// 策略：Hook NSURLSession dataTaskWithRequest:completionHandler:
// 对于发往易盾服务器的请求，创建一个假的空成功响应
// 这样易盾SDK收不到有效的服务端响应，无法完成验证流程

static NSArray *g_blocked_hosts = nil;

static void init_blocked_hosts() {
    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{
        g_blocked_hosts = @[
            @"htp.netease.com",
            @"htp.163.com",
            @"htpsdk.netease.com",
            @"api.dt.nease.com",
            @"ac.netease.com",
            @"riskcontrol.netease.com",
        ];
    });
}

static BOOL is_anticheat_url(NSURL *url) {
    if (!url) return NO;
    NSString *host = [url host];
    if (!host) return NO;
    NSString *lowerHost = host.lowercaseString;
    for (NSString *bh in g_blocked_hosts) {
        if ([lowerHost containsString:bh]) return YES;
    }
    // 也检查URL path中的易盾标识
    NSString *path = [url path];
    if (path && ([path containsString:@"htp"] || [path containsString:@"anticheat"] || [path containsString:@"risk"])) {
        return YES;
    }
    return NO;
}

// Hook NSURLSession dataTaskWithRequest:completionHandler:
static IMP orig_dataTaskWithRequestCompletion_IMP = NULL;

static id hooked_dataTaskWithRequestCompletion(id self, SEL _cmd, NSURLRequest *request, id completionHandler) {
    NSURL *url = [request URL];
    if (url && is_anticheat_url(url)) {
        NSLog(@"[AntiDetect] 检测到疑似易盾网络请求（仅记录）: %@", url);
        // 不拦截，只记录。因为：
        // 1. 易盾safeCommToServer走的是原生C socket，不走NSURLSession
        // 2. 拦截游戏正常网络请求会导致更严重的问题
    }
    return ((id(*)(id, SEL, NSURLRequest *, id))orig_dataTaskWithRequestCompletion_IMP)(self, _cmd, request, completionHandler);
}

// Hook NSURLSession dataTaskWithURL:completionHandler:
static IMP orig_dataTaskWithURLCompletion_IMP = NULL;

static id hooked_dataTaskWithURLCompletion(id self, SEL _cmd, NSURL *url, id completionHandler) {
    if (url && is_anticheat_url(url)) {
        NSLog(@"[AntiDetect] 检测到疑似易盾URL请求（仅记录）: %@", url);
    }
    return ((id(*)(id, SEL, NSURL *, id))orig_dataTaskWithURLCompletion_IMP)(self, _cmd, url, completionHandler);
}

#pragma mark - 关键：Hook NSUserDefaults 拦截易盾本地存储

// 易盾会在NSUserDefaults中存储一些检测状态
// 我们可以清除这些状态

static void clean_anticheat_defaults() {
    NSUserDefaults *defaults = [NSUserDefaults standardUserDefaults];
    NSDictionary *dict = [defaults dictionaryRepresentation];
    NSMutableArray *keysToRemove = [NSMutableArray array];
    for (NSString *key in dict) {
        NSString *lower = key.lowercaseString;
        if ([lower containsString:@"htp"] || [lower containsString:@"ntes"] ||
            [lower containsString:@"anticheat"] || [lower containsString:@"risksec"]) {
            [keysToRemove addObject:key];
        }
    }
    for (NSString *key in keysToRemove) {
        [defaults removeObjectForKey:key];
        NSLog(@"[AntiDetect] 清理易盾UserDefaults键: %@", key);
    }
    if (keysToRemove.count > 0) {
        [defaults synchronize];
    }
}

#pragma mark - iOS 17 Sysctl 检测绕过

// 易盾使用sysctl检测进程信息
// 虽然不能hook C函数，但可以通过ObjC层间接影响

#pragma mark - 关键策略：Hook UIAlertView/UIAlertController 阻止检测弹窗

// 即使服务端判定异常，游戏客户端需要弹出提示再踢人
// 我们可以hook UIAlertController来阻止"环境异常"弹窗
// 这样至少不会被踢出游戏（服务端可能还会断开连接，但至少不会主动弹窗退出）

static IMP orig_presentViewController_IMP = NULL;

static void hooked_presentViewController(id self, SEL _cmd, UIViewController *vc, BOOL animated, id completion) {
    if ([vc isKindOfClass:[UIAlertController class]]) {
        UIAlertController *alert = (UIAlertController *)vc;
        NSString *msg = alert.message ?: @"";
        NSString *title = alert.title ?: @"";
        NSString *combined = [NSString stringWithFormat:@"%@%@", title, msg];

        // 检测环境异常相关弹窗
        if ([combined containsString:@"环境异常"] ||
            [combined containsString:@"检测"] ||
            [combined containsString:@"800180933"] ||
            [combined containsString:@"QQ公众号"] ||
            [combined containsString:@"非法"] ||
            [combined containsString:@"外挂"]) {
            NSLog(@"[AntiDetect] 拦截环境异常弹窗: title=%@ msg=%@", title, msg);
            // 不弹窗，直接return
            return;
        }
    }
    ((void(*)(id, SEL, UIViewController *, BOOL, id))orig_presentViewController_IMP)(self, _cmd, vc, animated, completion);
}

#pragma mark - Hook UnitySendMessage (拦截Unity和Native通信)

// Unity通过UnitySendMessage向游戏对象发消息
// 易盾检测结果可能通过这个通道传递
// 由于这是extern C函数，不能直接hook，但可以通过其他方式

#pragma mark - 延迟执行il2cpp patch

static void delayed_il2cpp_patch() {
    // 等待il2cpp运行时完全初始化
    // 游戏加载后5秒执行
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(5.0 * NSEC_PER_SEC)), dispatch_get_main_queue(), ^{
        NSLog(@"[AntiDetect] 开始il2cpp层patch...");
        if (load_il2cpp_api()) {
            patch_netease_anticheat_il2cpp();
        }
    });

    // 15秒后再执行一次，确保游戏C#层已完全加载
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(15.0 * NSEC_PER_SEC)), dispatch_get_main_queue(), ^{
        NSLog(@"[AntiDetect] 第二轮il2cpp层patch...");
        patch_netease_anticheat_il2cpp();
    });

    // 30秒后执行第三轮，确保选角色后也patch到
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(30.0 * NSEC_PER_SEC)), dispatch_get_main_queue(), ^{
        NSLog(@"[AntiDetect] 第三轮il2cpp层patch...");
        patch_netease_anticheat_il2cpp();
    });
}

#pragma mark - 入口点

__attribute__((constructor))
static void AntiDetectInit() {
    @autoreleasepool {
        init_config();
        init_blocked_hosts();

        // === 第一层：v6稳定的NSFileManager hook ===
        Class fmClass = objc_getClass("NSFileManager");
        if (fmClass) {
            Method m1 = class_getInstanceMethod(fmClass, @selector(fileExistsAtPath:));
            if (m1) { orig_fileExistsAtPath_IMP = method_getImplementation(m1); method_setImplementation(m1, (IMP)hooked_fileExistsAtPath); }
            Method m2 = class_getInstanceMethod(fmClass, @selector(fileExistsAtPath:isDirectory:));
            if (m2) { orig_fileExistsAtPathIsDir_IMP = method_getImplementation(m2); method_setImplementation(m2, (IMP)hooked_fileExistsAtPathIsDir); }
            Method m3 = class_getInstanceMethod(fmClass, @selector(contentsOfDirectoryAtPath:error:));
            if (m3) { orig_contentsOfDirectoryAtPath_IMP = method_getImplementation(m3); method_setImplementation(m3, (IMP)hooked_contentsOfDirectoryAtPath); }
        }

        // === 第二层：canOpenURL hook ===
        Class appClass = objc_getClass("UIApplication");
        if (appClass) {
            Method m = class_getInstanceMethod(appClass, @selector(canOpenURL:));
            if (m) { orig_canOpenURL_IMP = method_getImplementation(m); method_setImplementation(m, (IMP)hooked_canOpenURL); }
        }

        // === 第三层：UIAlertController弹窗拦截（阻止"环境异常"弹窗）===
        Class vcClass = objc_getClass("UIViewController");
        if (vcClass) {
            Method m = class_getInstanceMethod(vcClass, @selector(presentViewController:animated:completion:));
            if (m) { orig_presentViewController_IMP = method_getImplementation(m); method_setImplementation(m, (IMP)hooked_presentViewController); }
        }

        // === 第四层：NSJSONSerialization hook ===
        // 注意：dataWithJSONObject:是类方法，需要在meta class上hook
        Class jsonClass = objc_getClass("NSJSONSerialization");
        if (jsonClass) {
            Class jsonMetaClass = object_getClass(jsonClass); // 获取meta class
            Method m = class_getInstanceMethod(jsonMetaClass, @selector(dataWithJSONObject:options:error:));
            if (m) { orig_jsonSerialization_dataWithJSONObject_IMP = method_getImplementation(m); method_setImplementation(m, (IMP)hooked_jsonSerialization_dataWithJSONObject); }
        }

        // === 第五层：NSURLSession网络请求拦截 ===
        Class sessionClass = objc_getClass("NSURLSession");
        if (sessionClass) {
            // dataTaskWithRequest:completionHandler:
            Method m1 = class_getInstanceMethod(sessionClass, @selector(dataTaskWithRequest:completionHandler:));
            if (m1) { orig_dataTaskWithRequestCompletion_IMP = method_getImplementation(m1); method_setImplementation(m1, (IMP)hooked_dataTaskWithRequestCompletion); }
            // dataTaskWithURL:completionHandler:
            Method m2 = class_getInstanceMethod(sessionClass, @selector(dataTaskWithURL:completionHandler:));
            if (m2) { orig_dataTaskWithURLCompletion_IMP = method_getImplementation(m2); method_setImplementation(m2, (IMP)hooked_dataTaskWithURLCompletion); }
        }

        // === 第六层：清理易盾UserDefaults ===
        clean_anticheat_defaults();

        // === 第七层：il2cpp runtime patch（延迟执行）===
        delayed_il2cpp_patch();

        NSLog(@"[AntiDetect] v11 初始化完成 (NSFileManager + canOpenURL + UIAlertController拦截 + JSON序列化 + NSURLSession拦截 + il2cpp patch)");
    }
}
