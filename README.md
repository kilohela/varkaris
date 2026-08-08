# varkaris — Terminal pass-through mirror

Mirrors the output of a controlled terminal (physical tty or pty) to your own
terminal in real time, and injects your keystrokes into the controlled
terminal. **This project runs on x86-64 Linux only**.

## How it works

- **Output capture**: eBPF `fexit/n_tty_write` grabs data at the point of
  generation
- **Input injection**: the `TIOCSTI` ioctl forges keystrokes into the
  controlled tty's input queue (requires root)
- **Filtering**: a minimal VT sequence state machine drops query/negotiation
  sequences (kitty keyboard protocol, mouse tracking, OSC queries, kitty
  graphics `q=` queries, etc.) so your terminal's responses are not injected
  back into the controlled tty causing duplicates or malformed input; kitty
  graphics image data passes through verbatim, like sixel

## Building

Dependencies: Zig 0.16, clang (to compile the BPF program), libbpf, kernel BTF
(CO-RE).

```sh
zig build
zig build test   # filter unit tests
```

The artifact `zig-out/bin/varkaris` is a single binary (the BPF object is
embedded via `@embedFile`).

## Usage

```sh
sudo zig-out/bin/varkaris /dev/tty1                           # interactive: mirror + keystroke injection
sudo zig-out/bin/varkaris /dev/pts/3 -c "chafa /tmp/img.png"  # non-interactive: inject command, mirror for 5s, exit
```

- The first argument is the controlled terminal's **slave path** (`/dev/pts/N`
  or a physical tty)
- Press `Ctrl+6` then `x` to exit interactive mode.

## Known limitations

- **May drop output**: the controlled terminal's emulator holds the pty master;
  this tool can only observe as a third party at the kernel level. The capture
  point (`n_tty_write`) sits at the point of generation, so events can be
  dropped when the ring is full, and the captured content differs from what
  the emulator sees when OPOST is enabled
- **No input echo in raw mode**: keystroke echo is generated internally by the
  line discipline (`echo_buf` → driver `write`) and never passes through
  `n_tty_write`, so it cannot be captured
- **No winsize sync**: the controlled side renders at its own column width;
  layouts (image sizes, wrapping) may misalign when widths differ
- **No protocol negotiation with the controlling terminal**: varkaris does not
  probe or negotiate the controlling terminal's protocol support; it assumes
  the controlling terminal's rendering and other capabilities match the
  controlled side. Terminal capability query sequences (e.g. `q=`) are dropped
  by the filter. If the controlling terminal does not support kitty graphics,
  image APC sequences become garbage text or invisible content, and there is
  no fallback
- TIOCSTI is deprecated and requires root

