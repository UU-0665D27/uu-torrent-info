use seccomp::{Action, Compare, Context, Op, Rule};
const SYSCALLS: &[&str] = &[
    "statx",
    "fstat",
    "read",
    "openat",
    "rt_sigreturn",
    "rt_sigaction",
    "rt_sigreturn",
    "rt_sigprocmask",
    "close",
    "mmap",
    "tgkill",
    "getpid",
    "gettid",
    "writev",
    "futex",
    "munmap",
    "sigaltstack",
    "exit_group",
    "write",
    "brk",
];
pub fn appl_seccomp() {
    let mut ctx = Context::default(Action::Errno(13)).unwrap();

    for syscall in SYSCALLS {
        if let Some(nr) = resolve_syscall(syscall) {
            let cmp = Compare::arg(0).with(0).using(Op::MaskedEq).build().unwrap();
            let rule = Rule::new(nr as usize, cmp, Action::Allow);
            let _ = ctx.add_rule(rule);
        }
    }
    ctx.load().unwrap();
}
pub fn resolve_syscall(name: &str) -> Option<i32> {
    let c_name = std::ffi::CString::new(name).ok()?;
    let nr = unsafe { seccomp_sys::seccomp_syscall_resolve_name(c_name.as_ptr()) };
    if nr == seccomp_sys::__NR_SCMP_ERROR {
        None
    } else {
        Some(nr)
    }
}
