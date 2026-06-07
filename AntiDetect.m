#import <objc/runtime.h>
#import <dlfcn.h>
#import <mach-o/dyld.h>
#import <UIKit/UIKit.h>
#import <sys/stat.h>
#import <unistd.h>

/*
 * AntiDetectDylib v7 - 增加 C 层文件检测拦截
 * 
 * v6: 游戏能打开，但选角色后环境异常闪退
 * 原因: 游戏用 stat()/access() 等 C 函数检测，不走 NSFileManager
 * v7: 在 v6 基础上增加 stat/access/fopen 的 C 层 hook
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

// C 路径检查（高性能，不用 NSString）
static BOOL c_should_block(const char *path) {
    if (!path) return NO;
    
    // 越狱路径前缀检查
    static const char *jb_prefixes[] = {
        "/Applications/Cydia.app",
        "/Applications/Sileo.app",
        "/Applications/Zebra.app",
        "/Applications/unc0ver.app",
        "/Applications/Taurine.app",
        "/Applications/TrollStore.app",
        "/Applications/TrollFools.app",
        "/Library/MobileSubstrate",
        "/usr/lib/substrate",
        "/usr/lib/ligerness",
        "/usr/lib/libhooker",
        "/etc/apt",
        "/var/lib/apt",
        "/var/lib/cydia",
        "/private/var/lib/cydia",
        "/private/var/mobile/Library/Cydia",
        "/.bootstrapped_evas1on",
        "/.cydia_no_stash",
        "/.installed_unc0ver",
        "/var/jb",
        "/private/var/jb",
        NULL
    };
    
    for (int i = 0; jb_prefixes[i]; i++) {
        if (strncmp(path, jb_prefixes[i], strlen(jb_prefixes[i])) == 0) return YES;
    }
    
    // 关键字检查（大小写不敏感）
    static const char *keywords[] = {
        "antidetect", "libtool", "cydiasubstrate", "trollfools",
        "trollstore", "substrate", "substituteloader", "mobilesubstrate",
        "libhooker", NULL
    };
    
    // 简单的小写转换检查
    const char *p = path;
    while (*p) {
        char c = *p;
        if (c >= 'A' && c <= 'Z') c += 32;
        for (int i = 0; keywords[i]; i++) {
            const char *kw = keywords[i];
            const char *pp = p;
            BOOL match = YES;
            while (*kw) {
                char pc = *pp;
                if (pc >= 'A' && pc <= 'Z') pc += 32;
                if (pc != *kw) { match = NO; break; }
                pp++; kw++;
            }
            if (match) return YES;
        }
        p++;
    }
    
    return NO;
}

#pragma mark - NSFileManager Hooks

static IMP orig_fileExistsAtPath_IMP = NULL;
static IMP orig_fileExistsAtPathIsDir_IMP = NULL;

static BOOL hooked_fileExistsAtPath(id self, SEL _cmd, NSString *path) {
    if (is_jailbreak_path(path) || contains_hidden_keyword(path)) return NO;
    return ((BOOL(*)(id, SEL, NSString *))orig_fileExistsAtPath_IMP)(self, _cmd, path);
}

static BOOL hooked_fileExistsAtPathIsDir(id self, SEL _cmd, NSString *path, BOOL *isDir) {
    if (is_jailbreak_path(path) || contains_hidden_keyword(path)) {
        if (isDir) *isDir = NO;
        return NO;
    }
    return ((BOOL(*)(id, SEL, NSString *, BOOL *))orig_fileExistsAtPathIsDir_IMP)(self, _cmd, path, isDir);
}

#pragma mark - fishhook (只 hook stat/access/fopen，安全的 C 函数)

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
    struct fh_rebindings_entry *new_entry = (struct fh_rebindings_entry *)malloc(sizeof(struct fh_rebindings_entry));
    if (!new_entry) return -1;
    new_entry->rebindings = rebindings;
    new_entry->rebindings_nel = nel;
    new_entry->next = _fh_rebindings_head;
    _fh_rebindings_head = new_entry;
    return 0;
}

static void fh_perform_rebinding_with_section(struct fh_rebindings_entry *rebindings,
                                              struct section_64 *section, intptr_t slide,
                                              struct nlist_64 *symtab, char *strtab,
                                              uint32_t *indirect_symtab) {
    uint32_t *indirect_symbol_indices = indirect_symtab + section->reserved1;
    void **indirect_symbol_bindings = (void **)((uintptr_t)slide + section->addr);
    for (uint i = 0; i < section->size / sizeof(void *); i++) {
        uint32_t symtab_index = indirect_symbol_indices[i];
        if (symtab_index == INDIRECT_SYMBOL_ABS || symtab_index == INDIRECT_SYMBOL_LOCAL ||
            symtab_index == (INDIRECT_SYMBOL_LOCAL | INDIRECT_SYMBOL_ABS)) continue;
        uint32_t strtab_offset = symtab[symtab_index].n_un.n_strx;
        char *symbol_name = strtab + strtab_offset;
        bool symbol_name_longer_than_1 = symbol_name[0] && symbol_name[1];
        struct fh_rebindings_entry *cur = rebindings;
        while (cur) {
            for (uint j = 0; j < cur->rebindings_nel; j++) {
                if (symbol_name_longer_than_1 && strcmp(&symbol_name[1], cur->rebindings[j].name) == 0) {
                    if (cur->rebindings[j].replaced != NULL && indirect_symbol_bindings[i] != cur->rebindings[j].replacement)
                        *(cur->rebindings[j].replaced) = indirect_symbol_bindings[i];
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
                                         const struct mach_header *header, intptr_t slide) {
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
            if (strcmp(cur_seg_cmd->segname, SEG_LINKEDIT) == 0) linkedit_segment = cur_seg_cmd;
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
        if (strcmp(cur_seg_cmd->segname, SEG_DATA) != 0 && strcmp(cur_seg_cmd->segname, "__DATA_CONST") != 0) continue;
        for (uint j = 0; j < cur_seg_cmd->nsects; j++) {
            struct section_64 *sect = (struct section_64 *)((uintptr_t)cur_seg_cmd + sizeof(struct segment_command_64)) + j;
            if ((sect->flags & SECTION_TYPE) == S_LAZY_SYMBOL_POINTERS)
                fh_perform_rebinding_with_section(rebindings, sect, slide, symtab, strtab, indirect_symtab);
            if ((sect->flags & SECTION_TYPE) == S_NON_LAZY_SYMBOL_POINTERS)
                fh_perform_rebinding_with_section(rebindings, sect, slide, symtab, strtab, indirect_symtab);
        }
    }
}

static void _fh_rebind_symbols_for_image(const struct mach_header *header, intptr_t slide) {
    fh_rebind_symbols_for_image(_fh_rebindings_head, header, slide);
}

static int fh_rebind_symbols(fh_rebinding_t rebindings[], size_t rebindings_nel) {
    int retval = fh_prepend_rebindings(rebindings, rebindings_nel);
    if (retval < 0) return retval;
    if (_fh_rebindings_head->next == NULL) {
        _dyld_register_func_for_add_image(_fh_rebind_symbols_for_image);
    } else {
        uint32_t c = _dyld_image_count();
        for (uint32_t i = 0; i < c; i++)
            fh_rebind_symbols_for_image(_fh_rebindings_head, _dyld_get_image_header(i), _dyld_get_image_vmaddr_slide(i));
    }
    return retval;
}

#pragma mark - C 函数 Hooks

// stat hook
static int (*orig_stat)(const char *, struct stat *) = NULL;

static int hooked_stat(const char *path, struct stat *buf) {
    if (c_should_block(path)) {
        errno = ENOENT;
        return -1;
    }
    return orig_stat(path, buf);
}

// stat64 hook (iOS 可能用这个变体)
static int (*orig_stat64)(const char *, struct stat64 *) = NULL;

static int hooked_stat64(const char *path, struct stat64 *buf) {
    if (c_should_block(path)) {
        errno = ENOENT;
        return -1;
    }
    return orig_stat64(path, buf);
}

// lstat hook
static int (*orig_lstat)(const char *, struct stat *) = NULL;

static int hooked_lstat(const char *path, struct stat *buf) {
    if (c_should_block(path)) {
        errno = ENOENT;
        return -1;
    }
    return orig_lstat(path, buf);
}

// access hook
static int (*orig_access)(const char *, int) = NULL;

static int hooked_access(const char *path, int mode) {
    if (c_should_block(path)) {
        errno = ENOENT;
        return -1;
    }
    return orig_access(path, mode);
}

// fopen hook
static void *(*orig_fopen)(const char *, const char *) = NULL;

static void *hooked_fopen(const char *path, const char *mode) {
    if (c_should_block(path)) {
        return NULL;
    }
    return orig_fopen(path, mode);
}

// opendir hook (检测目录是否存在)
static void *(*orig_opendir)(const char *) = NULL;

static void *hooked_opendir(const char *path) {
    if (c_should_block(path)) {
        return NULL;
    }
    return orig_opendir(path);
}

// dladdr hook (反查 dylib 来源)
static int (*orig_dladdr)(const void *, Dl_info *) = NULL;

static int hooked_dladdr(const void *addr, Dl_info *info) {
    int ret = orig_dladdr(addr, info);
    if (ret && info && info->dli_fname && c_should_block(info->dli_fname)) {
        memset(info, 0, sizeof(Dl_info));
        return 0;
    }
    return ret;
}

#pragma mark - 入口点

__attribute__((constructor))
static void AntiDetectInit() {
    @autoreleasepool {
        init_config();

        // NSFileManager swizzle
        Class fmClass = objc_getClass("NSFileManager");
        if (fmClass) {
            Method m1 = class_getInstanceMethod(fmClass, @selector(fileExistsAtPath:));
            if (m1) { orig_fileExistsAtPath_IMP = method_getImplementation(m1); method_setImplementation(m1, (IMP)hooked_fileExistsAtPath); }
            Method m2 = class_getInstanceMethod(fmClass, @selector(fileExistsAtPath:isDirectory:));
            if (m2) { orig_fileExistsAtPathIsDir_IMP = method_getImplementation(m2); method_setImplementation(m2, (IMP)hooked_fileExistsAtPathIsDir); }
        }

        // fishhook: 只 hook 文件检查相关 C 函数
        fh_rebinding_t rebindings[] = {
            {"stat", hooked_stat, (void **)&orig_stat},
            {"stat64", hooked_stat64, (void **)&orig_stat64},
            {"lstat", hooked_lstat, (void **)&orig_lstat},
            {"access", hooked_access, (void **)&orig_access},
            {"fopen", hooked_fopen, (void **)&orig_fopen},
            {"opendir", hooked_opendir, (void **)&orig_opendir},
            {"dladdr", hooked_dladdr, (void **)&orig_dladdr},
        };
        fh_rebind_symbols(rebindings, sizeof(rebindings) / sizeof(rebindings[0]));

        NSLog(@"[AntiDetect] v7 初始化完成 - NSFileManager + C层文件检测拦截");
    }
}
