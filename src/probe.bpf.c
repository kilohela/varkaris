// kprobe 程序：捕获 n_tty_write 的写入内容并送入 ring buffer。
// CO-RE 编译（clang -target bpf -g -O2），结构体偏移在加载时由内核 BTF 解析。
#define __TARGET_ARCH_x86
#include <stddef.h>
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

char LICENSE[] SEC("license") = "GPL";

// 只定义用到的字段，preserve_access_index 让 clang 生成 CO-RE 重定位。
struct tty_struct {
    struct tty_driver *driver;
    int index;
} __attribute__((preserve_access_index));

struct tty_driver {
    int major;
    int minor_start;
} __attribute__((preserve_access_index));

// x86_64 pt_regs，字段偏移由 CO-RE 从内核 BTF 解析。
// 注意：内核视图字段名是 ax/cx/dx/si/di（asm/ptrace.h），
// 不是用户态视图的 rax/rcx/rdx/rsi/rdi。
struct pt_regs {
    __u64 r15;
    __u64 r14;
    __u64 r13;
    __u64 r12;
    __u64 rbp;
    __u64 rbx;
    __u64 r11;
    __u64 r10;
    __u64 r9;
    __u64 r8;
    __u64 ax;
    __u64 cx;
    __u64 dx;
    __u64 si;
    __u64 di;
    __u64 orig_ax;
    __u64 ip;
    __u64 cs;
    __u64 flags;
    __u64 sp;
    __u64 ss;
} __attribute__((preserve_access_index));

// 目标 tty 的设备号（rdev major/minor，statx 原样写入）。
struct target_dev_value {
    __u32 major;
    __u32 minor;
};

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct target_dev_value);
} target_dev SEC(".maps");

// 输出事件。
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 20);
} events SEC(".maps");

#define MAX_COPY 4096

struct event {
    __u32 len;
    __u8 data[MAX_COPY];
};

SEC("kprobe/n_tty_write")
int capture_tty_write(struct pt_regs *ctx)
{
    // n_tty_write(struct tty_struct *tty, struct file *file, const u8 *buf, size_t nr)
    // 直接读内核 pt_regs 字段（CO-RE 解析偏移），不依赖 PT_REGS_PARM 宏。
    struct tty_struct *tty = (struct tty_struct *)ctx->di;
    const unsigned char *buf = (const unsigned char *)ctx->dx;
    size_t nr = ctx->cx;

    __u32 key = 0;
    struct target_dev_value *target = bpf_map_lookup_elem(&target_dev, &key);

    if (!target)
        return 0;
    if (nr == 0)
        return 0;

    // 按设备号过滤：major 来自 tty->driver->major；minor 不能直接比 tty->index，
    // 物理 tty 驱动带 minor_start（如 ttyS0: minor_start=40, index=0 → minor 40；
    // /dev/console: minor_start=1, index=0 → minor 1），pty 的 minor_start 为 0。
    if (BPF_CORE_READ(tty, driver, major) != target->major)
        return 0;
    if (BPF_CORE_READ(tty, driver, minor_start) + BPF_CORE_READ(tty, index) != target->minor)
        return 0;

    __u32 len = nr < MAX_COPY ? (__u32)nr : MAX_COPY;
    struct event *e = bpf_ringbuf_reserve(&events, sizeof(struct event), 0);
    if (!e)
        return 0;
    e->len = len;
    if (bpf_probe_read_kernel(e->data, len, buf))
        e->len = 0;
    bpf_ringbuf_submit(e, 0);
    return 0;
}
