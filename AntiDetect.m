#import <objc/runtime.h>
#import <dlfcn.h>
#import <mach-o/dyld.h>
#import <mach/mach.h>
#import <sys/sysctl.h>
#import <UIKit/UIKit.h>

/*
 * AntiDetectDylib v3 - iOS 环境检测绕过
 * 已预配置：TrollFools + LIBTOOL + CydiaSubstrate 环境
 * ⚠️ 此 dylib 必须是注入列表中【最后一个】加载的
 * 
 * v3 策略：不 hook dyld 函数（容易闪退），改为：
 * 1. hook NSFileManager 隐藏越狱路径
 * 2. hook canOpenURL 隐藏 URL Scheme
 * 3. hook getenv 隐藏 DYLD 环境变量
 * 4. hook sysctl 隐藏调试标志
 * 5. 使用 objc_msgSend 拦截来隐藏镜像枚举
 */

#pragma mark - 配置

static NSArray *g_hidden_keywords = nil;
static NSArray *g_system_prefixes = nil;

static void init_config() {
    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{
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
        g_system_prefixes = @[
            @"/System/",
            @"/usr/lib/",
            @"/Developer/",
            @"/AppleInternal/",
        ];
    });
}

static BOOL should_hide_path(const char *path) {
    if (!path) return NO;
    for (NSString *prefix in g_system_prefixes) {
        if (strstr(path, [prefix UTF8String]) == path) return NO;
    }
    NSString *nameStr = [NSString stringWithUTF8String:path].lowercaseString;
    for (NSString *keyword in g_hidden_keywords) {
        if ([nameStr containsString:keyword.lowercaseString]) return YES;
    }
    return NO;
}

#pragma mark - 越狱路径列表

static NSArray *g_jailbreak_paths = nil;

static BOOL is_jailbreak_path(NSString *path) {
    if (!path) return NO;
    for (NSString *jp in g_jailbreak_paths) {
        if ([path hasPrefix:jp]) return YES;
    }
    return NO;
}

#pragma mark - Hook: NSFileManager (最核心的检测拦截)

// 大多数游戏用 NSFileManager 检查文件/路径是否存在
// 这是环境检测最常见的入口

static IMP orig_fileExistsAtPath_IMP = NULL;
static IMP orig_fileExistsAtPathIsDirectory_IMP = NULL;
static IMP orig_contentsOfDirectoryAtPath_IMP = NULL;
static IMP orig_attributesOfItemAtPath_IMP = NULL;
static IMP orig_subpathsAtPath_IMP = NULL;

static BOOL hooked_fileExistsAtPath(id self, SEL _cmd, NSString *path) {
    if (is_jailbreak_path(path)) return NO;
    // 检查路径是否包含需要隐藏的关键字
    if (path && should_hide_path([path UTF8String])) return NO;
    return ((BOOL(*)(id, SEL, NSString *))orig_fileExistsAtPath_IMP)(self, _cmd, path);
}

static BOOL hooked_fileExistsAtPathIsDirectory(id self, SEL _cmd, NSString *path, BOOL *isDir) {
    if (is_jailbreak_path(path)) { if (isDir) *isDir = NO; return NO; }
    if (path && should_hide_path([path UTF8String])) { if (isDir) *isDir = NO; return NO; }
    return ((BOOL(*)(id, SEL, NSString *, BOOL *))orig_fileExistsAtPathIsDirectory_IMP)(self, _cmd, path, isDir);
}

// 隐藏目录内容中的注入痕迹
static NSArray *hooked_contentsOfDirectoryAtPath(id self, SEL _cmd, NSString *path, NSError **error) {
    NSArray *result = ((NSArray *(*)(id, SEL, NSString *, NSError **))orig_contentsOfDirectoryAtPath_IMP)(self, _cmd, path, error);
    if (result == nil) return result;
    
    NSMutableArray *filtered = [NSMutableArray arrayWithCapacity:result.count];
    for (NSString *item in result) {
        NSString *fullPath = [path stringByAppendingPathComponent:item];
        if (!should_hide_path([fullPath UTF8String]) && !is_jailbreak_path(fullPath)) {
            [filtered addObject:item];
        }
    }
    return [filtered copy];
}

static NSDictionary *hooked_attributesOfItemAtPath(id self, SEL _cmd, NSString *path, NSString *traverseLink, NSError **error) {
    if (is_jailbreak_path(path) || (path && should_hide_path([path UTF8String]))) {
        if (error) *error = [NSError errorWithDomain:NSCocoaErrorDomain code:NSFileNoSuchFileError userInfo:nil];
        return nil;
    }
    return ((NSDictionary *(*)(id, SEL, NSString *, NSString *, NSError **))orig_attributesOfItemAtPath_IMP)(self, _cmd, path, traverseLink, error);
}

static NSArray *hooked_subpathsAtPath(id self, SEL _cmd, NSString *path) {
    if (is_jailbreak_path(path) || (path && should_hide_path([path UTF8String]))) return nil;
    return ((NSArray *(*)(id, SEL, NSString *))orig_subpathsAtPath_IMP)(self, _cmd, path);
}

#pragma mark - Hook: canOpenURL

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

#pragma mark - Hook: getenv (隐藏 DYLD 环境变量)

// 使用 fishhook 只 hook getenv（这个是安全的，不会递归）
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <mach-o/loader.h>
#include <mach-o/nlist.h>

typedef struct {
    const char *name;
    void *replacement;
    void **replaced;
} fh_rebinding_t;

static int fh_rebind_symbols(fh_rebinding_t rebindings[], size_t rebindings_nel);

struct fh_rebindings_entry {
    fh_rebinding_t *rebindings;
    size_t rebindings_nel;
    struct fh_rebindings_entry *next;
};

static struct fh_rebindings_entry *_fh_rebindings_head;

static int fh_prepend_rebindings(fh_rebinding_t rebindings[], size_t nel) {
    struct fh_rebindings_entry *new_entry =
        (struct fh_rebindings_entry *)malloc(sizeof(struct fh_rebindings_entry));
    if (!new_entry) return -1;
    new_entry->rebindings = rebindings;
    new_entry->rebindings_nel = nel;
    new_entry->next = _fh_rebindings_head;
    _fh_rebindings_head = new_entry;
    return 0;
}

static void fh_perform_rebinding_with_section(struct fh_rebindings_entry *rebindings,
                                              struct section_64 *section,
                                              intptr_t slide,
                                              struct nlist_64 *symtab,
                                              char *strtab,
                                              uint32_t *indirect_symtab) {
    uint32_t *indirect_symbol_indices = indirect_symtab + section->reserved1;
    void **indirect_symbol_bindings = (void **)((uintptr_t)slide + section->addr);
    for (uint i = 0; i < section->size / sizeof(void *); i++) {
        uint32_t symtab_index = indirect_symbol_indices[i];
        if (symtab_index == INDIRECT_SYMBOL_ABS ||
            symtab_index == INDIRECT_SYMBOL_LOCAL ||
            symtab_index == (INDIRECT_SYMBOL_LOCAL | INDIRECT_SYMBOL_ABS)) {
            continue;
        }
        uint32_t strtab_offset = symtab[symtab_index].n_un.n_strx;
        char *symbol_name = strtab + strtab_offset;
        bool symbol_name_longer_than_1 = symbol_name[0] && symbol_name[1];
        struct fh_rebindings_entry *cur = rebindings;
        while (cur) {
            for (uint j = 0; j < cur->rebindings_nel; j++) {
                if (symbol_name_longer_than_1 &&
                    strcmp(&symbol_name[1], cur->rebindings[j].name) == 0) {
                    if (cur->rebindings[j].replaced != NULL &&
                        indirect_symbol_bindings[i] != cur->rebindings[j].replacement) {
                        *(cur->rebindings[j].replaced) = indirect_symbol_bindings[i];
                    }
                    indirect_symbol_bindings[i] = cur->rebindings[j].replacement;
                    goto symbol_loop;
                }
            }
            cur = cur->next;
        }
    symbol_loop:;
    }
}

static void fh_rebind_symbols_for_image(struct fh_rebindings_entry *rebindings,
                                         const struct mach_header *header,
                                         intptr_t slide) {
    Dl_info info;
    if (dladdr(header, &info) == 0) return;

    struct segment_command_64 *cur_seg_cmd;
    struct segment_command_64 *linkedit_segment = NULL;
    struct symtab_command *symtab_cmd = NULL;
    struct dysymtab_command *dysymtab_cmd = NULL;

    uintptr_t cur = (uintptr_t)header + sizeof(struct mach_header_64);
    for (uint i = 0; i < header->ncmds; i++, cur += cur_seg_cmd->cmdsize) {
        cur_seg_cmd = (struct segment_command_64 *)cur;
        if (cur_seg_cmd->cmd == LC_SEGMENT_64) {
            if (strcmp(cur_seg_cmd->segname, SEG_LINKEDIT) == 0) {
                linkedit_segment = cur_seg_cmd;
            }
        } else if (cur_seg_cmd->cmd == LC_SYMTAB) {
            symtab_cmd = (struct symtab_command *)cur_seg_cmd;
        } else if (cur_seg_cmd->cmd == LC_DYSYMTAB) {
            dysymtab_cmd = (struct dysymtab_command *)cur_seg_cmd;
        }
    }

    if (!symtab_cmd || !dysymtab_cmd || !linkedit_segment) return;

    uintptr_t linkedit_base = (uintptr_t)slide + linkedit_segment->vmaddr;
    struct nlist_64 *symtab = (struct nlist_64 *)(linkedit_base + symtab_cmd->symoff);
    char *strtab = (char *)(linkedit_base + symtab_cmd->stroff);
    uint32_t *indirect_symtab = (uint32_t *)(linkedit_base + dysymtab_cmd->indirectsymoff);

    cur = (uintptr_t)header + sizeof(struct mach_header_64);
    for (uint i = 0; i < header->ncmds; i++, cur += cur_seg_cmd->cmdsize) {
        cur_seg_cmd = (struct segment_command_64 *)cur;
        if (cur_seg_cmd->cmd != LC_SEGMENT_64) continue;
        if (strcmp(cur_seg_cmd->segname, SEG_DATA) != 0 &&
            strcmp(cur_seg_cmd->segname, "__DATA_CONST") != 0) continue;
        for (uint j = 0; j < cur_seg_cmd->nsects; j++) {
            struct section_64 *sect =
                (struct section_64 *)((uintptr_t)cur_seg_cmd + sizeof(struct segment_command_64)) + j;
            if ((sect->flags & SECTION_TYPE) == S_LAZY_SYMBOL_POINTERS) {
                fh_perform_rebinding_with_section(rebindings, sect, slide,
                                                   symtab, strtab, indirect_symtab);
            }
            if ((sect->flags & SECTION_TYPE) == S_NON_LAZY_SYMBOL_POINTERS) {
                fh_perform_rebinding_with_section(rebindings, sect, slide,
                                                   symtab, strtab, indirect_symtab);
            }
        }
    }
}

static void _fh_rebind_symbols_for_image(const struct mach_header *header,
                                          intptr_t slide) {
    fh_rebind_symbols_for_image(_fh_rebindings_head, header, slide);
}

static int fh_rebind_symbols(fh_rebinding_t rebindings[], size_t rebindings_nel) {
    int retval = fh_prepend_rebindings(rebindings, rebindings_nel);
    if (retval < 0) return retval;
    if (_fh_rebindings_head->next == NULL) {
        _dyld_register_func_for_add_image(_fh_rebind_symbols_for_image);
    } else {
        uint32_t c = _dyld_image_count();
        for (uint32_t i = 0; i < c; i++) {
            fh_rebind_symbols_for_image(_fh_rebindings_head,
                                         _dyld_get_image_header(i),
                                         _dyld_get_image_vmaddr_slide(i));
        }
    }
    return retval;
}

// getenv hook 实现
static char *(*orig_getenv)(const char *) = NULL;

static char *hooked_getenv(const char *name) {
    if (name && (strstr(name, "DYLD_") == name ||
                 strstr(name, "MSSafeMode") ||
                 strstr(name, "_MSSafeMode") ||
                 strstr(name, "SUBSTRATE_HOME"))) {
        return NULL;
    }
    return orig_getenv ? orig_getenv(name) : getenv(name);
}

// sysctl hook 实现
static int (*orig_sysctl)(int *, u_int, void *, size_t *, void *, size_t) = NULL;

static int hooked_sysctl(int *name, u_int namelen, void *oldp, size_t *oldlenp, void *newp, size_t newlen) {
    int result = orig_sysctl ? orig_sysctl(name, namelen, oldp, oldlenp, newp, newlen)
                              : sysctl(name, namelen, oldp, oldlenp, newp, newlen);
    if (namelen == 4 && name[0] == CTL_KERN && name[1] == KERN_PROC && name[2] == KERN_PROC_PID) {
        if (oldp && oldlenp && *oldlenp >= sizeof(struct kinfo_proc)) {
            struct kinfo_proc *info = (struct kinfo_proc *)oldp;
            info->kp_proc.p_flag &= ~P_TRACED;
        }
    }
    return result;
}

// dladdr hook 实现
static int (*orig_dladdr)(const void *, Dl_info *) = NULL;

static int hooked_dladdr(const void *addr, Dl_info *info) {
    int ret = orig_dladdr ? orig_dladdr(addr, info) : dladdr(addr, info);
    if (ret && info && info->dli_fname && should_hide_path(info->dli_fname)) {
        memset(info, 0, sizeof(Dl_info));
        return 0;
    }
    return ret;
}

#pragma mark - 入口点

__attribute__((constructor))
static void AntiDetectInit() {
    init_config();

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
        @"/usr/sbin/sshd",
        @"/usr/bin/sshd",
        @"/bin/bash",
        @"/bin/sh",
        @"/usr/bin/ssh",
        @"/.bootstrapped_evas1on",
        @"/.cydia_no_stash",
        @"/.installed_unc0ver",
        @"/var/jb",
        @"/private/var/jb",
        @"/var/containers/Bundle/Application/",
        @"/var/mobile/Containers/Data/Application/",
    ];

    // === 1. ObjC Method Swizzling (最安全的方式) ===
    
    // Hook NSFileManager
    Class fmClass = objc_getClass("NSFileManager");
    if (fmClass) {
        Method m;
        
        m = class_getInstanceMethod(fmClass, @selector(fileExistsAtPath:));
        if (m) { orig_fileExistsAtPath_IMP = method_getImplementation(m); method_setImplementation(m, (IMP)hooked_fileExistsAtPath); }
        
        m = class_getInstanceMethod(fmClass, @selector(fileExistsAtPath:isDirectory:));
        if (m) { orig_fileExistsAtPathIsDirectory_IMP = method_getImplementation(m); method_setImplementation(m, (IMP)hooked_fileExistsAtPathIsDirectory); }
        
        m = class_getInstanceMethod(fmClass, @selector(contentsOfDirectoryAtPath:error:));
        if (m) { orig_contentsOfDirectoryAtPath_IMP = method_getImplementation(m); method_setImplementation(m, (IMP)hooked_contentsOfDirectoryAtPath); }
        
        m = class_getInstanceMethod(fmClass, @selector(attributesOfItemAtPath:error:));
        if (m) { orig_attributesOfItemAtPath_IMP = method_getImplementation(m); method_setImplementation(m, (IMP)hooked_attributesOfItemAtPath); }
        
        m = class_getInstanceMethod(fmClass, @selector(subpathsAtPath:));
        if (m) { orig_subpathsAtPath_IMP = method_getImplementation(m); method_setImplementation(m, (IMP)hooked_subpathsAtPath); }
    }

    // Hook UIApplication canOpenURL:
    Class appClass = objc_getClass("UIApplication");
    if (appClass) {
        Method m = class_getInstanceMethod(appClass, @selector(canOpenURL:));
        if (m) { orig_canOpenURL_IMP = method_getImplementation(m); method_setImplementation(m, (IMP)hooked_canOpenURL); }
    }

    // === 2. fishhook (只 hook C 函数，不 hook dyld 函数) ===
    // 只 hook getenv/sysctl/dladdr 这三个安全的函数
    // 不 hook _dyld_image_count 等（这些会导致递归闪退）
    fh_rebinding_t rebindings[] = {
        {"getenv", hooked_getenv, (void **)&orig_getenv},
        {"sysctl", hooked_sysctl, (void **)&orig_sysctl},
        {"dladdr", hooked_dladdr, (void **)&orig_dladdr},
    };
    fh_rebind_symbols(rebindings, sizeof(rebindings) / sizeof(rebindings[0]));

    NSLog(@"[AntiDetect] v3 初始化完成 - 隐藏关键字: %@", g_hidden_keywords);
}
