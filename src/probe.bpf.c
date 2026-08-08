// fexit program: captures the content written by n_tty_write into a ring buffer.
// CO-RE compilation (clang -target bpf -g -O2): arguments come straight from
// the kernel BTF (no pt_regs access), struct field offsets are resolved at load
// time from the kernel BTF.
#define __TARGET_ARCH_x86
#include <stddef.h>
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

char LICENSE[] SEC("license") = "GPL";

// Only the fields we use; preserve_access_index makes clang emit CO-RE
// relocations.
struct tty_struct {
    struct tty_driver *driver;
    int index;
} __attribute__((preserve_access_index));

struct tty_driver {
    int major;
    int minor_start;
} __attribute__((preserve_access_index));

// Device number of the target tty (rdev major/minor, written as-is from statx).
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

// Output events. 16MB: holds ~4000 4KB events (a single chafa 6.7MB image is
// ~3300 events), buffering the whole transfer even if consumption is slow.
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 24);
} events SEC(".maps");

// Maximum length of a single n_tty_write: the tty write path
// (iterate_tty_write) chunks user writes before calling n_tty_write, with a
// default chunk of 2048 (65536 only with TTY_NO_WRITE_SPLIT; physical consoles
// don't set it — observed events are all 2048).
// The event is fixed-size (bpf_ringbuf_reserve's size must be a compile-time
// constant); 4096 covers the default chunk with headroom.
#define MAX_COPY 4096

struct event {
    __u32 len;
    __u8 data[MAX_COPY];
};

// fexit on n_tty_write: fentry captures the *requested* amount nr, but a slow
// physical console makes n_tty_write write partially; iterate_tty_write then
// retries, so the same data enters n_tty_write multiple times and capturing
// nr would multiply it (observed 6.7MB vs chafa's actual 1.96MB output).
// We read the fexit ctx explicitly (to avoid BPF_PROG macro expansion
// ambiguity):
// ctx[0]=tty, ctx[1]=file, ctx[2]=buf, ctx[3]=nr, ctx[4]=ret (bytes actually
// written). Reading buf[0..ret] gives the real output data (fexit triggers
// before the function returns, so write_buf is not yet overwritten by the next
// copy_from_iter).
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

    // Filter by device number: major comes from tty->driver->major; minor can't
    // be compared directly to tty->index because physical tty drivers carry a
    // minor_start (e.g. ttyS0: minor_start=40, index=0 -> minor 40;
    // /dev/console: minor_start=1, index=0 -> minor 1); pty minor_start is 0.
    if (BPF_CORE_READ(tty, driver, major) != target->major)
        return 0;
    if (BPF_CORE_READ(tty, driver, minor_start) + BPF_CORE_READ(tty, index) != target->minor)
        return 0;

    // Submit the actually written data per event (ret <= nr <= 2048 default chunk).
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
