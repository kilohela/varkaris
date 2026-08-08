// fentry 程序：捕获 n_tty_write 的写入内容并送入 ring buffer。
// CO-RE 编译（clang -target bpf -g -O2）：参数由 BPF_PROG 宏按 BTF 签名
// 直接获取（不再读 pt_regs），结构体字段偏移在加载时由内核 BTF 解析。
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

// 输出事件。16MB：容纳约 4000 个 4KB 事件（单次 chafa 6.7MB 图
// ≈ 3300 个事件），传输全程缓冲，即使消费稍慢也不丢。
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 24);
} events SEC(".maps");

// 单次 n_tty_write 的最大长度：tty 写路径（iterate_tty_write）把用户
// 写入分块后调用 n_tty_write，默认 chunk=2048，TTY_NO_WRITE_SPLIT 时
// 才 65536（物理 console 不设该标志，实测事件均为 2048）。
// 事件固定大小（bpf_ringbuf_reserve 的 size 必须是编译期常量），
// 4096 覆盖默认 chunk 并留余量。
#define MAX_COPY 4096

struct event {
    __u32 len;
    __u8 data[MAX_COPY];
};

// fexit 挂 n_tty_write：fentry 捕获的是"请求写入量"nr，但物理 console
// 输出慢导致 n_tty_write 部分写，iterate_tty_write 会退回重试——同一
// 数据多次进入 n_tty_write，按 nr 捕获会重复数倍（实测 6.7MB vs
// chafa 实际输出 1.96MB）。
// 这里显式读取 fexit ctx（避免 BPF_PROG 宏展开歧义）：
// ctx[0]=tty, ctx[1]=file, ctx[2]=buf, ctx[3]=nr, ctx[4]=ret(实际写入量)。
// 读 buf[0..ret] 即真实输出数据（fexit 在函数返回前触发，write_buf
// 尚未被下一次 copy_from_iter 覆盖）。
SEC("fexit/n_tty_write")
int capture_tty_write_exit(unsigned long long *ctx)
{
    struct tty_struct *tty = (struct tty_struct *)(void *)ctx[0];
    const unsigned char *buf = (const unsigned char *)(void *)ctx[2];
    long ret = (long)ctx[4];

    __u32 key = 0;
    struct target_dev_value *target = bpf_map_lookup_elem(&target_dev, &key);

    if (!target)
        return 0;
    if (ret <= 0)
        return 0;

    // 按设备号过滤：major 来自 tty->driver->major；minor 不能直接比 tty->index，
    // 物理 tty 驱动带 minor_start（如 ttyS0: minor_start=40, index=0 → minor 40；
    // /dev/console: minor_start=1, index=0 → minor 1），pty 的 minor_start 为 0。
    if (BPF_CORE_READ(tty, driver, major) != target->major)
        return 0;
    if (BPF_CORE_READ(tty, driver, minor_start) + BPF_CORE_READ(tty, index) != target->minor)
        return 0;

    // 单事件提交实际写入的数据（ret <= nr <= 2048 默认 chunk）。
    __u32 len = ret < MAX_COPY ? (__u32)ret : MAX_COPY;
    struct event *e = bpf_ringbuf_reserve(&events, sizeof(struct event), 0);
    if (!e)
        return 0;
    e->len = len;
    if (bpf_probe_read_kernel(e->data, len, buf))
        e->len = 0;
    bpf_ringbuf_submit(e, 0);
    return 0;
}
