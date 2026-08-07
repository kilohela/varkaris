# AGENTS.md

## Zig 使用原则

1. **逐步小步实现，每步确认后再继续**。不要一次铺开大改动；先完成一个可验证的小步骤，向用户说明并等待确认，再进入下一步。

2. **Terminal / 系统调用相关 API 必须先查 stdlib 源码确认再写**。本项目使用 Zig 0.16，stdlib API 与传统写法差异大（如 `std.ArrayList` 的 allocator 参数化、union 字面量语法等），不要凭记忆或旧版本经验写；动手前先看 `/usr/lib/zig/std/` 下的源码确认签名与行为。

3. **硬件/内核行为不确定时，先做实证验证再实现**。例如内核结构体字段名（BTF）、设备号语义、tty 行为等，优先从内核 BTF、`/sys`、`stat` 等实际来源确认，避免臆测。

4. **构建产物缓存感知输入变化**：`build.zig` 中编译外部源文件（如 clang 编译 BPF 程序）必须用 `addFileArg` 注册输入，否则缓存不失效、装出旧产物。

## 项目速览

- 终端透传（镜像）：TIOCSTI 注入输入 + eBPF kprobe 捕获 `n_tty_write` 输出，Zig 用户态 + C/clang 编译的 BPF 程序（CO-RE）。
- `src/vt/` 是从 ghostty 移植的 VT 解析器（Parser.zig + parse_table.zig + 极简 osc stub），测试用 `zig build test`。
- `src/filter.zig`：镜像输出选择性过滤（丢弃查询/协商序列）+ 输入侧 kitty 键盘事件解码。
- 前缀键 Ctrl+6（0x1e），`x` 退出（tmux 式）。
