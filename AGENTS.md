# AGENTS.md

## Zig usage principles

1. **Implement in small verifiable steps, confirm with the user before moving
   on**. Don't roll out large changes at once; complete one small verifiable
   step, explain it, and wait for confirmation before the next one.

2. **Terminal / syscall-related APIs must be verified against the stdlib
   source before writing code**. This project uses Zig 0.16, whose stdlib API
   differs greatly from older conventions. Don't write from memory or older
   versions; check the signatures and behavior in source code first.

3. **When hardware/kernel behavior is uncertain, verify empirically before
   implementing**. For example, kernel struct field names (BTF), device number
   semantics, tty behavior — confirm from actual sources such as kernel BTF,
   `/sys`, `stat`, avoiding speculation.

4. **Build cache must be sensitive to input changes**: when `build.zig`
   compiles external source files (e.g. clang-compiled BPF programs), inputs
   must be registered with `addFileArg`, otherwise the cache won't
   invalidate and stale artifacts get installed.

## Project overview

- Terminal pass-through (mirror): TIOCSTI input injection + eBPF capture of
  `n_tty_write` output, Zig userspace + BPF program compiled with C/clang
  (CO-RE, `SEC("fentry/n_tty_write")` auto-attach).
- `src/filter.zig`: selective filtering of mirrored output (built-in minimal
  VT sequence state machine, drops query/negotiation sequences) + kitty
  keyboard event decoding on the input side; tested with `zig build test`.
- Prefix key Ctrl+6 (0x1e), `x` exits (tmux-style).
