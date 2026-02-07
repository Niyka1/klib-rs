# klib-rs

`klib-rs` is a Rust library developed and used for my **Windows kernel-mode** projects.  
It serves as a shared foundation to avoid rewriting common low-level components, and I decided to make it public as it may be useful to others.

The library mainly provides bindings and utilities around Windows kernel APIs, along with a few practical abstractions for low-level Rust development.

---

## Features

### Windows Kernel Headers Exposure

`klib-rs` exposes functions and structures from the following Windows kernel headers:

- `wdm.h`
- `ntddk.h`
- `ntifs.h`

Access to these APIs is controlled via **Cargo features**, allowing fine-grained control over what is included:

```toml
[dependencies]
klib-rs = { version = "*", features = ["ntifs"] }
```

### Inline Hooking

`klib-rs` includes an **inline hooking** implementation designed for Windows kernel-mode environments.

It allows intercepting kernel functions in a controlled manner while remaining compatible with Rust constraints and kernel execution rules.

Example usage:

```rust
use klib_rs::khook::Hook;
let hook = match Hook::set_hook(target_function as _, my_random_hook as *const () as u64, false) {
    Ok(o) => o,
    Err(e) => todo!(),
};
```
