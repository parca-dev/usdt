// Kernel types, BPF helpers, and architecture definitions for USDT programs.

#ifndef USDT_KERNEL_H
#define USDT_KERNEL_H

// Map bpf2go __TARGET_ARCH_* defines to the standard architecture macros.
// bpf2go compiles with "-target bpf" and only defines these.
#if defined(__TARGET_ARCH_x86) && !defined(__x86_64__)
  #define __x86_64__  1
  #define __x86_64    1
#endif
#if defined(__TARGET_ARCH_arm64) && !defined(__aarch64__)
  #define __aarch64__ 1
#endif

// ---------------------------------------------------------------------------
// Integer types
// ---------------------------------------------------------------------------

typedef signed char s8;
typedef unsigned char u8;
typedef signed short s16;
typedef unsigned short u16;
typedef signed int s32;
typedef unsigned int u32;
typedef signed long long s64;
typedef unsigned long long u64;

typedef __SIZE_TYPE__ uintptr_t;
typedef __SIZE_TYPE__ size_t;

_Static_assert(sizeof(s8) == 1, "bad s8 size");
_Static_assert(sizeof(u8) == 1, "bad u8 size");
_Static_assert(sizeof(s16) == 2, "bad s16 size");
_Static_assert(sizeof(u16) == 2, "bad u16 size");
_Static_assert(sizeof(s32) == 4, "bad s32 size");
_Static_assert(sizeof(u32) == 4, "bad u32 size");
_Static_assert(sizeof(s64) == 8, "bad s64 size");
_Static_assert(sizeof(u64) == 8, "bad u64 size");

#if __STDC_VERSION__ < 202311L
typedef _Bool bool;
  #ifndef __bool_true_false_are_defined
    #define true                          1
    #define false                         0
    #define __bool_true_false_are_defined 1
  #endif
#endif

#ifndef NULL
  #define NULL ((void *)0)
#endif

// ---------------------------------------------------------------------------
// pt_regs — arch/{x86,arm64}/include/asm/ptrace.h
// ---------------------------------------------------------------------------

#if defined(__x86_64) || defined(__x86_64__)
struct pt_regs {
  unsigned long r15;
  unsigned long r14;
  unsigned long r13;
  unsigned long r12;
  unsigned long bp;
  unsigned long bx;
  unsigned long r11;
  unsigned long r10;
  unsigned long r9;
  unsigned long r8;
  unsigned long ax;
  unsigned long cx;
  unsigned long dx;
  unsigned long si;
  unsigned long di;
  unsigned long orig_ax;
  unsigned long ip;
  unsigned long cs;
  unsigned long flags;
  unsigned long sp;
  unsigned long ss;
};
#elif defined(__aarch64__)
struct pt_regs {
  u64 regs[31];
  u64 sp;
  u64 pc;
  u64 pstate;
  u64 orig_x0;
  s32 syscallno;
  u32 unused2;
};
#else
  #error "Unsupported architecture"
#endif

// ---------------------------------------------------------------------------
// BPF constants
// ---------------------------------------------------------------------------

enum {
  BPF_ANY     = 0,
  BPF_NOEXIST = 1,
  BPF_EXIST   = 2,
  BPF_F_LOCK  = 4,
};

enum bpf_map_type {
  BPF_MAP_TYPE_UNSPEC,
  BPF_MAP_TYPE_HASH,
  BPF_MAP_TYPE_ARRAY,
  BPF_MAP_TYPE_PROG_ARRAY,
  BPF_MAP_TYPE_PERF_EVENT_ARRAY,
};

// BPF helper function IDs used by USDT.
#define BPF_FUNC_map_lookup_elem       1
#define BPF_FUNC_map_update_elem       2
#define BPF_FUNC_map_delete_elem       3
#define BPF_FUNC_trace_printk          6
#define BPF_FUNC_probe_read_user       112
#define BPF_FUNC_probe_read_kernel     113
#define BPF_FUNC_get_attach_cookie     174

// ---------------------------------------------------------------------------
// BPF macros and helper declarations
// ---------------------------------------------------------------------------

#define UNUSED __attribute__((unused))

// BTF-style map definition macros (from tools/lib/bpf/bpf_helpers.h)
#define __uint(name, val)  int(*name)[val]
#define __type(name, val)  typeof(val) *name
#define __array(name, val) typeof(val) *name[]

#define SEC(name)                                                              \
  _Pragma("GCC diagnostic push")                                              \
  _Pragma("GCC diagnostic ignored \"-Wignored-attributes\"")                  \
    __attribute__((section(name), used))                                       \
  _Pragma("GCC diagnostic pop")

#define EBPF_INLINE __attribute__((__always_inline__))

// BPF helper function pointers
static void *(*bpf_map_lookup_elem)(void *map, void *key) =
  (void *)BPF_FUNC_map_lookup_elem;
static int (*bpf_map_update_elem)(void *map, void *key, void *value,
                                   u64 flags) =
  (void *)BPF_FUNC_map_update_elem;
static int (*bpf_map_delete_elem)(void *map, void *key) =
  (void *)BPF_FUNC_map_delete_elem;

__attribute__((format(printf, 1, 3)))
static int (*bpf_trace_printk)(const char *fmt, int fmt_size, ...) =
  (void *)BPF_FUNC_trace_printk;

static long (*bpf_probe_read_user)(void *dst, int size,
                                    const void *unsafe_ptr) =
  (void *)BPF_FUNC_probe_read_user;
static long (*bpf_probe_read_kernel)(void *dst, int size,
                                      const void *unsafe_ptr) =
  (void *)BPF_FUNC_probe_read_kernel;
static long (*bpf_get_attach_cookie)(void *ctx) =
  (void *)BPF_FUNC_get_attach_cookie;

// ---------------------------------------------------------------------------
// Debug helpers
// ---------------------------------------------------------------------------

#define printt(fmt, ...)                                                       \
  ({                                                                           \
    const char ____fmt[] = fmt "\n";                                           \
    bpf_trace_printk(____fmt, sizeof(____fmt), ##__VA_ARGS__);                 \
  })

// DEBUG_PRINT requires a `with_debug_output` variable declared by the
// consumer.  Define USDT_NO_DEBUG_PRINT before including to disable.
#ifndef USDT_NO_DEBUG_PRINT
  #ifndef USDT_DEBUG_OUTPUT_VAR_DECLARED
    extern u32 with_debug_output;
    #define USDT_DEBUG_OUTPUT_VAR_DECLARED
  #endif
  #define DEBUG_PRINT(fmt, ...)                                                \
    ({                                                                         \
      if (__builtin_expect(with_debug_output, 0)) {                            \
        printt(fmt, ##__VA_ARGS__);                                            \
      }                                                                        \
    })
#else
  #define DEBUG_PRINT(fmt, ...) ({})
#endif

#define MIN(a, b) (((a) < (b)) ? (a) : (b))

#endif // USDT_KERNEL_H
