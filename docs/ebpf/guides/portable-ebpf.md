# Shipping Portable eBPF-powered Applications

Several kinds of portability:

* Across library versions: libc
* Across kernel versions: v5, v6
* Across architectures: amd64, arm64
* Across little and big endian

Especially important for tracing style programs which need to access kernel
internal data structures.

* Entry poit:
  * bpf2go has `-target` to make this easy.
  * Missing: bpf2go should ship libbpf headers.

* Differences in types: CO-RE
  * Missing: how can `bpf2go` create portable vmlinux.h based on BTF?

* Differences in configuration


---

If you followed the [getting started](./getting-started.md) guide you may have
noticed that bpf2go generates two sets of files:

- `*_bpfel.o` and `*_bpfel.go`
- `*_bpfeb.o` and `*_bpfeb.go`

These files contain build tags that instruct the compiler to choose the correct
implementation based on the [endianness] of the CPU architecture you are compiling
for. This means that the XDP packet counter program will work on amd64, arm64,
s390x, and so on out of the box.

bpf2go can do this because the XDP hook has a stable API: the way an XDP program
is invoked is the same across all kernel versions.
The same isn't true for eBPF programs which derive their power from being able to
inspect kernel memory very freely. Such tracing programs not only have to take
endianness into account, they also have to be adjusted for differences in
architectures, major kernel versions and even individual kernel configurations.

!! note ""
  Of course your Go code itself has to be portable as well. Here is a guide which
  covers the main pitfalls.

## A small kprobe example

Let's take a look at a very simple kprobe which has one goal: print the path of
any binary executed on the system.

{{ c_example('kprobe_simple', title='kprobe_execve.c') }}

From the `SEC` macro we can infer that the example attaches a `kprobe` to a
function called `sys_execve`, which is the implementation
of the `execve` syscall in the kernel. It only receives a single argument
`struct pt_regs *` which it passes to a function `fill_pathname`, along with a
temporary buffer. From its signature we can tell that `fill_pathname` extracts
the path of the binary to be executed from `struct pt_regs` and copies it into `dst`.
This is the first point at which we run into portability problems.

## Portability across architectures

By looking at the [sys_execve source] we know that the path of the file to be
executed is in the first argument to the function:

```C
SYSCALL_DEFINE3(execve,
		const char __user *, filename,
		const char __user *const __user *, argv,
		const char __user *const __user *, envp)
```

But how do we extract the first argument from the `struct pt_regs` context passed
to kprobes?
It turns out that the answer to this depends on the CPU architecture of the system.
Let's take a look at [pt_regs on amd64] and on [user_pt_regs on arm64]:

```C
// amd64
struct pt_regs {
	unsigned long r15;
	unsigned long r14;
	unsigned long r13;
	unsigned long r12;
// remainder omitted
};

// arm64 - even the name is different!
struct user_pt_regs {
	__u64		regs[31];
	__u64		sp;
	__u64		pc;
	__u64		pstate;
};
```

There is no overlap between the two architectures at all! The fields are all
different and even the types are named differently.
Luckily there is a way to abstract these differences away. Here is the implementation
of `fill_filename` from earlier:

{{ c_example('fill_filename_def', title='kprobe_execve.c') }}

We can extract the nth argument using `PT_REGS_PARMn()` macro defined in `bpf_tracing.h`,
in our example `PT_REGS_PARM1(ctx)` corresponds to `const char __user *, filename`.

It's possible to simplify the example even more by using the `BPF_KPROBE` macro:

{{ c_example('kprobe_macro_def', title='kprobe_execve.c') }}

Instead of manually calling `PT_REGS_PARMn()` we pass the names and types of the
function arguments to the macro.

Here is the Go code needed to execute the kprobe:

TODO: Collapse the file somehow?
{{ go_example('portable_ebpf_main', title='main.go') }}

TODO: What about BPF_KSYSCALL? https://github.com/libbpf/libbpf/blob/56069cda7897afdd0ae2478825845c7a7308c878/src/bpf_tracing.h#L667

## Portability across major kernel versions

CO-RE
* using `__attribute((preserve_access_index))`
* using flavours
* using `vmlinux.h`

TODO: Read up on the existing CORE stuff from andrii.

## Portability across configurations

* CONFIG_HZ, etc.
* presence of functions using ksym (not working yet?)



OLD:

Both sets of .go files contain a `//go:embed` statement that slurps the contents
of the respective .o files into a byte slice at compile time. The result is a
standalone Go application binary that can be deployed to a target machine
without any of the .o files included. To further reduce runtime dependencies,
add `CGO_ENABLED=0` to `go build` and your application won't depend on libc.
(assuming none of your other dependencies require cgo)

Moreover, because both eBPF objects and Go scaffolding are generated for both
big- and little-endian architectures, cross-compiling your Go application is as
simple as setting the right `GOARCH` value at compile time.

Pulling it all together, for building an eBPF-powered Go application for a
Raspberry Pi running a 64-bit Linux distribution:

```shell-session
CGO_ENABLED=0 GOARCH=arm64 go build
```

### Compile Once - Run Everywhere?

Since we can generate a standalone binary and deploy it to any system, does that
mean tools built using {{ proj }} will magically work anywhere? Unfortunately,
no, not really.

The kernel's internal data structures change as the kernel progresses in
development, just like any other software. Differences in compile-time
configuration affect data structures and the presence of certain kernel symbols.
This means that, even when using the exact same kernel release, no two Linux
distributions will be the same when it comes to data layout.

This is problematic for authors that want to ship a single binary to their users
and expect it to work across multiple distributions and kernel versions. In
response to this, the term *Compile Once - Run Everywhere* was coined to
describe the collection of techniques employed to achieve universal
interoperability for eBPF. This technique relies on type information encoded in
BPF Type Format (BTF) to be shipped with the kernel so memory accesses can be
adjusted right before loading the eBPF program into the kernel.

Alternatively, you may opt for shipping a full LLVM compiler toolchain along
with your application and recompiling the eBPF C against Linux kernel headers
present on the target machine. This approach is out of scope of the {{ proj }}
documentation.

[endianness]: https://en.wikipedia.org/wiki/Endianness
[pt_regs on amd64]: https://elixir.bootlin.com/linux/v6.5.7/source/arch/x86/include/uapi/asm/ptrace.h#L44
[user_pt_regs on arm64]: https://elixir.bootlin.com/linux/v6.5.7/source/arch/arm64/include/uapi/asm/ptrace.h#L88
[sys_execve source]: https://elixir.bootlin.com/linux/v6.5.7/source/fs/exec.c#L2108
