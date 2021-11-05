/* Unicorn Emulator Engine */
/* By Nguyen Anh Quynh <aquynh@gmail.com>, 2015-2017 */
/* This file is released under LGPL2.
   See COPYING.LGPL2 in root directory for more details
*/

#ifndef QNICORN_ENGINE_H
#define QNICORN_ENGINE_H

#ifdef __cplusplus
extern "C" {
#endif

#include "platform.h"
#include <stdarg.h>

#if defined(QNICORN_HAS_OSXKERNEL)
#include <libkern/libkern.h>
#else
#include <stdlib.h>
#include <stdio.h>
#endif

struct qc_struct;
typedef struct qc_struct qc_engine;

typedef size_t qc_hook;

#include "m68k.h"
#include "x86.h"
#include "arm.h"
#include "arm64.h"
#include "mips.h"
#include "sparc.h"
#include "ppc.h"
#include "riscv.h"

#ifdef __GNUC__
#define DEFAULT_VISIBILITY __attribute__((visibility("default")))
#else
#define DEFAULT_VISIBILITY
#endif

#ifdef _MSC_VER
#pragma warning(disable : 4201)
#pragma warning(disable : 4100)
#ifdef UNICORN_SHARED
#define UNICORN_EXPORT __declspec(dllexport)
#else // defined(UNICORN_STATIC)
#define UNICORN_EXPORT
#endif
#else
#ifdef __GNUC__
#define UNICORN_EXPORT __attribute__((visibility("default")))
#else
#define UNICORN_EXPORT
#endif
#endif

#ifdef __GNUC__
#define UNICORN_DEPRECATED __attribute__((deprecated))
#elif defined(_MSC_VER)
#define UNICORN_DEPRECATED __declspec(deprecated)
#else
#pragma message(                                                               \
    "WARNING: You need to implement UNICORN_DEPRECATED for this compiler")
#define UNICORN_DEPRECATED
#endif

// Unicorn API version
#define QC_API_MAJOR 2
#define QC_API_MINOR 0

// Unicorn package version
#define QC_VERSION_MAJOR QC_API_MAJOR
#define QC_VERSION_MINOR QC_API_MINOR
#define QC_VERSION_EXTRA 0

/*
  Macro to create combined version which can be compared to
  result of qc_version() API.
*/
#define QC_MAKE_VERSION(major, minor) ((major << 8) + minor)

// Scales to calculate timeout on microsecond unit
// 1 second = 1000,000 microseconds
#define QC_SECOND_SCALE 1000000
// 1 milisecond = 1000 nanoseconds
#define QC_MILISECOND_SCALE 1000

// Architecture type
typedef enum qc_arch {
    QC_ARCH_ARM = 1, // ARM architecture (including Thumb, Thumb-2)
    QC_ARCH_ARM64,   // ARM-64, also called AArch64
    QC_ARCH_MIPS,    // Mips architecture
    QC_ARCH_X86,     // X86 architecture (including x86 & x86-64)
    QC_ARCH_PPC,     // PowerPC architecture
    QC_ARCH_SPARC,   // Sparc architecture
    QC_ARCH_M68K,    // M68K architecture
    QC_ARCH_RISCV,   // RISCV architecture
    QC_ARCH_MAX,
} qc_arch;

// Mode type
typedef enum qc_mode {
    QC_MODE_LITTLE_ENDIAN = 0,    // little-endian mode (default mode)
    QC_MODE_BIG_ENDIAN = 1 << 30, // big-endian mode

    // arm / arm64
    QC_MODE_ARM = 0,        // ARM mode
    QC_MODE_THUMB = 1 << 4, // THUMB mode (including Thumb-2)
    // Depreciated, use QC_ARM_CPU_* with qc_ctl instead.
    QC_MODE_MCLASS = 1 << 5, // ARM's Cortex-M series.
    QC_MODE_V8 = 1 << 6, // ARMv8 A32 encodings for ARM (currently unsupported)

    // arm (32bit) cpu types
    // Depreciated, use QC_ARM_CPU_* with qc_ctl instead.
    QC_MODE_ARM926 = 1 << 7,  // ARM926 CPU type
    QC_MODE_ARM946 = 1 << 8,  // ARM946 CPU type
    QC_MODE_ARM1176 = 1 << 9, // ARM1176 CPU type

    // mips
    QC_MODE_MICRO = 1 << 4,    // MicroMips mode (currently unsupported)
    QC_MODE_MIPS3 = 1 << 5,    // Mips III ISA (currently unsupported)
    QC_MODE_MIPS32R6 = 1 << 6, // Mips32r6 ISA (currently unsupported)
    QC_MODE_MIPS32 = 1 << 2,   // Mips32 ISA
    QC_MODE_MIPS64 = 1 << 3,   // Mips64 ISA

    // x86 / x64
    QC_MODE_16 = 1 << 1, // 16-bit mode
    QC_MODE_32 = 1 << 2, // 32-bit mode
    QC_MODE_64 = 1 << 3, // 64-bit mode

    // ppc
    QC_MODE_PPC32 = 1 << 2, // 32-bit mode
    QC_MODE_PPC64 = 1 << 3, // 64-bit mode (currently unsupported)
    QC_MODE_QPX =
        1 << 4, // Quad Processing eXtensions mode (currently unsupported)

    // sparc
    QC_MODE_SPARC32 = 1 << 2, // 32-bit mode
    QC_MODE_SPARC64 = 1 << 3, // 64-bit mode
    QC_MODE_V9 = 1 << 4,      // SparcV9 mode (currently unsupported)

    // riscv
    QC_MODE_RISCV32 = 1 << 2, // 32-bit mode
    QC_MODE_RISCV64 = 1 << 3, // 64-bit mode

    // m68k
} qc_mode;

// All type of errors encountered by Unicorn API.
// These are values returned by qc_errno()
typedef enum qc_err {
    QC_ERR_OK = 0,         // No error: everything was fine
    QC_ERR_NOMEM,          // Out-Of-Memory error: qc_open(), qc_emulate()
    QC_ERR_ARCH,           // Unsupported architecture: qc_open()
    QC_ERR_HANDLE,         // Invalid handle
    QC_ERR_MODE,           // Invalid/unsupported mode: qc_open()
    QC_ERR_VERSION,        // Unsupported version (bindings)
    QC_ERR_READ_UNMAPPED,  // Quit emulation due to READ on unmapped memory:
                           // qc_emu_start()
    QC_ERR_WRITE_UNMAPPED, // Quit emulation due to WRITE on unmapped memory:
                           // qc_emu_start()
    QC_ERR_FETCH_UNMAPPED, // Quit emulation due to FETCH on unmapped memory:
                           // qc_emu_start()
    QC_ERR_HOOK,           // Invalid hook type: qc_hook_add()
    QC_ERR_INSN_INVALID,   // Quit emulation due to invalid instruction:
                           // qc_emu_start()
    QC_ERR_MAP,            // Invalid memory mapping: qc_mem_map()
    QC_ERR_WRITE_PROT,     // Quit emulation due to QC_MEM_WRITE_PROT violation:
                           // qc_emu_start()
    QC_ERR_READ_PROT,      // Quit emulation due to QC_MEM_READ_PROT violation:
                           // qc_emu_start()
    QC_ERR_FETCH_PROT,     // Quit emulation due to QC_MEM_FETCH_PROT violation:
                           // qc_emu_start()
    QC_ERR_ARG, // Inavalid argument provided to qc_xxx function (See specific
                // function API)
    QC_ERR_READ_UNALIGNED,  // Unaligned read
    QC_ERR_WRITE_UNALIGNED, // Unaligned write
    QC_ERR_FETCH_UNALIGNED, // Unaligned fetch
    QC_ERR_HOOK_EXIST,      // hook for this event already existed
    QC_ERR_RESOURCE,        // Insufficient resource: qc_emu_start()
    QC_ERR_EXCEPTION,       // Unhandled CPU exception
} qc_err;

/*
  Callback function for tracing code (QC_HOOK_CODE & QC_HOOK_BLOCK)

  @address: address where the code is being executed
  @size: size of machine instruction(s) being executed, or 0 when size is
  unknown
  @user_data: user data passed to tracing APIs.
*/
typedef void (*qc_cb_hookcode_t)(qc_engine *uc, uint64_t address, uint32_t size,
                                 void *user_data);

/*
  Callback function for tracing interrupts (for qc_hook_intr())

  @intno: interrupt number
  @user_data: user data passed to tracing APIs.
*/
typedef void (*qc_cb_hookintr_t)(qc_engine *uc, uint32_t intno,
                                 void *user_data);

/*
  Callback function for tracing invalid instructions

  @user_data: user data passed to tracing APIs.

  @return: return true to continue, or false to stop program (due to invalid
  instruction).
*/
typedef bool (*qc_cb_hookinsn_invalid_t)(qc_engine *uc, void *user_data);

/*
  Callback function for tracing IN instruction of X86

  @port: port number
  @size: data size (1/2/4) to be read from this port
  @user_data: user data passed to tracing APIs.
*/
typedef uint32_t (*qc_cb_insn_in_t)(qc_engine *uc, uint32_t port, int size,
                                    void *user_data);

/*
  Callback function for OUT instruction of X86

  @port: port number
  @size: data size (1/2/4) to be written to this port
  @value: data value to be written to this port
*/
typedef void (*qc_cb_insn_out_t)(qc_engine *uc, uint32_t port, int size,
                                 uint32_t value, void *user_data);

// Represent a TranslationBlock.
typedef struct qc_tb {
    uint64_t pc;
    uint16_t icount;
    uint16_t size;
} qc_tb;

/*
  Callback function for new edges between translation blocks.

  @cur_tb: Current TB which is to be generated.
  @prev_tb: The previous TB.
*/
typedef void (*qc_hook_edge_gen_t)(qc_engine *uc, qc_tb *cur_tb, qc_tb *prev_tb,
                                   void *user_data);

/*
  Callback function for tcg opcodes that fits in two arguments.

  @address: Current pc.
  @arg1: The first argument.
  @arg2: The second argument.
*/
typedef void (*qc_hook_tcg_op_2)(qc_engine *uc, uint64_t address, uint64_t arg1,
                                 uint64_t arg2, void *user_data);

typedef qc_hook_tcg_op_2 qc_hook_tcg_sub;

/*
  Callback function for MMIO read

  @offset: offset to the base address of the IO memory.
  @size: data size to read
  @user_data: user data passed to qc_mmio_map()
*/
typedef uint64_t (*qc_cb_mmio_read_t)(qc_engine *uc, uint64_t offset,
                                      unsigned size, void *user_data);

/*
  Callback function for MMIO write

  @offset: offset to the base address of the IO memory.
  @size: data size to write
  @value: data value to be written
  @user_data: user data passed to qc_mmio_map()
*/
typedef void (*qc_cb_mmio_write_t)(qc_engine *uc, uint64_t offset,
                                   unsigned size, uint64_t value,
                                   void *user_data);

// All type of memory accesses for QC_HOOK_MEM_*
typedef enum qc_mem_type {
    QC_MEM_READ = 16,      // Memory is read from
    QC_MEM_WRITE,          // Memory is written to
    QC_MEM_FETCH,          // Memory is fetched
    QC_MEM_READ_UNMAPPED,  // Unmapped memory is read from
    QC_MEM_WRITE_UNMAPPED, // Unmapped memory is written to
    QC_MEM_FETCH_UNMAPPED, // Unmapped memory is fetched
    QC_MEM_WRITE_PROT,     // Write to write protected, but mapped, memory
    QC_MEM_READ_PROT,      // Read from read protected, but mapped, memory
    QC_MEM_FETCH_PROT,     // Fetch from non-executable, but mapped, memory
    QC_MEM_READ_AFTER,     // Memory is read from (successful access)
} qc_mem_type;

// These are all op codes we support to hook for QC_HOOK_TCG_OP_CODE.
// Be cautious since it may bring much more overhead than QC_HOOK_CODE without
// proper flags.
// TODO: Tracing QC_TCG_OP_CALL should be interesting.
typedef enum qc_tcg_op_code {
    QC_TCG_OP_SUB = 0, // Both sub_i32 and sub_i64
} qc_tcg_op_code;

// These are extra flags to be paired with qc_tcg_op_code which is helpful to
// instrument in some certain cases.
typedef enum qc_tcg_op_flag {
    // Only instrument opcode if it would set cc_dst, i.e. cmp instruction.
    QC_TCG_OP_FLAG_CMP = 1 << 0,
    // Only instrument opcode which is directly translated.
    // i.e. x86 sub/subc -> tcg sub_i32/64
    QC_TCG_OP_FLAG_DIRECT = 1 << 1
} qc_tcg_op_flag;

// All type of hooks for qc_hook_add() API.
typedef enum qc_hook_type {
    // Hook all interrupt/syscall events
    QC_HOOK_INTR = 1 << 0,
    // Hook a particular instruction - only a very small subset of instructions
    // supported here
    QC_HOOK_INSN = 1 << 1,
    // Hook a range of code
    QC_HOOK_CODE = 1 << 2,
    // Hook basic blocks
    QC_HOOK_BLOCK = 1 << 3,
    // Hook for memory read on unmapped memory
    QC_HOOK_MEM_READ_UNMAPPED = 1 << 4,
    // Hook for invalid memory write events
    QC_HOOK_MEM_WRITE_UNMAPPED = 1 << 5,
    // Hook for invalid memory fetch for execution events
    QC_HOOK_MEM_FETCH_UNMAPPED = 1 << 6,
    // Hook for memory read on read-protected memory
    QC_HOOK_MEM_READ_PROT = 1 << 7,
    // Hook for memory write on write-protected memory
    QC_HOOK_MEM_WRITE_PROT = 1 << 8,
    // Hook for memory fetch on non-executable memory
    QC_HOOK_MEM_FETCH_PROT = 1 << 9,
    // Hook memory read events.
    QC_HOOK_MEM_READ = 1 << 10,
    // Hook memory write events.
    QC_HOOK_MEM_WRITE = 1 << 11,
    // Hook memory fetch for execution events
    QC_HOOK_MEM_FETCH = 1 << 12,
    // Hook memory read events, but only successful access.
    // The callback will be triggered after successful read.
    QC_HOOK_MEM_READ_AFTER = 1 << 13,
    // Hook invalid instructions exceptions.
    QC_HOOK_INSN_INVALID = 1 << 14,
    // Hook on new edge generation. Could be useful in program analysis.
    //
    // NOTE: This is different from QC_HOOK_BLOCK in 2 ways:
    //       1. The hook is called before executing code.
    //       2. The hook is only called when generation is triggered.
    QC_HOOK_EDGE_GENERATED = 1 << 15,
    // Hook on specific tcg op code. The usage of this hook is similar to
    // QC_HOOK_INSN.
    QC_HOOK_TCG_OPCODE = 1 << 16,
} qc_hook_type;

// Hook type for all events of unmapped memory access
#define QC_HOOK_MEM_UNMAPPED                                                   \
    (QC_HOOK_MEM_READ_UNMAPPED + QC_HOOK_MEM_WRITE_UNMAPPED +                  \
     QC_HOOK_MEM_FETCH_UNMAPPED)
// Hook type for all events of illegal protected memory access
#define QC_HOOK_MEM_PROT                                                       \
    (QC_HOOK_MEM_READ_PROT + QC_HOOK_MEM_WRITE_PROT + QC_HOOK_MEM_FETCH_PROT)
// Hook type for all events of illegal read memory access
#define QC_HOOK_MEM_READ_INVALID                                               \
    (QC_HOOK_MEM_READ_PROT + QC_HOOK_MEM_READ_UNMAPPED)
// Hook type for all events of illegal write memory access
#define QC_HOOK_MEM_WRITE_INVALID                                              \
    (QC_HOOK_MEM_WRITE_PROT + QC_HOOK_MEM_WRITE_UNMAPPED)
// Hook type for all events of illegal fetch memory access
#define QC_HOOK_MEM_FETCH_INVALID                                              \
    (QC_HOOK_MEM_FETCH_PROT + QC_HOOK_MEM_FETCH_UNMAPPED)
// Hook type for all events of illegal memory access
#define QC_HOOK_MEM_INVALID (QC_HOOK_MEM_UNMAPPED + QC_HOOK_MEM_PROT)
// Hook type for all events of valid memory access
// NOTE: QC_HOOK_MEM_READ is triggered before QC_HOOK_MEM_READ_PROT and
// QC_HOOK_MEM_READ_UNMAPPED, so
//       this hook may technically trigger on some invalid reads.
#define QC_HOOK_MEM_VALID                                                      \
    (QC_HOOK_MEM_READ + QC_HOOK_MEM_WRITE + QC_HOOK_MEM_FETCH)

/*
  Callback function for hooking memory (READ, WRITE & FETCH)

  @type: this memory is being READ, or WRITE
  @address: address where the code is being executed
  @size: size of data being read or written
  @value: value of data being written to memory, or irrelevant if type = READ.
  @user_data: user data passed to tracing APIs
*/
typedef void (*qc_cb_hookmem_t)(qc_engine *uc, qc_mem_type type,
                                uint64_t address, int size, int64_t value,
                                void *user_data);

/*
  Callback function for handling invalid memory access events (UNMAPPED and
    PROT events)

  @type: this memory is being READ, or WRITE
  @address: address where the code is being executed
  @size: size of data being read or written
  @value: value of data being written to memory, or irrelevant if type = READ.
  @user_data: user data passed to tracing APIs

  @return: return true to continue, or false to stop program (due to invalid
  memory). NOTE: returning true to continue execution will only work if the
  accessed memory is made accessible with the correct permissions during the
  hook.

           In the event of a QC_MEM_READ_UNMAPPED or QC_MEM_WRITE_UNMAPPED
  callback, the memory should be qc_mem_map()-ed with the correct permissions,
  and the instruction will then read or write to the address as it was supposed
  to.

           In the event of a QC_MEM_FETCH_UNMAPPED callback, the memory can be
  mapped in as executable, in which case execution will resume from the fetched
  address. The instruction pointer may be written to in order to change where
  execution resumes, but the fetch must succeed if execution is to resume.
*/
typedef bool (*qc_cb_eventmem_t)(qc_engine *uc, qc_mem_type type,
                                 uint64_t address, int size, int64_t value,
                                 void *user_data);

/*
  Memory region mapped by qc_mem_map() and qc_mem_map_ptr()
  Retrieve the list of memory regions with qc_mem_regions()
*/
typedef struct qc_mem_region {
    uint64_t begin; // begin address of the region (inclusive)
    uint64_t end;   // end address of the region (inclusive)
    uint32_t perms; // memory permissions of the region
} qc_mem_region;

// All type of queries for qc_query() API.
typedef enum qc_query_type {
    // Dynamically query current hardware mode.
    QC_QUERY_MODE = 1,
    QC_QUERY_PAGE_SIZE, // query pagesize of engine
    QC_QUERY_ARCH, // query architecture of engine (for ARM to query Thumb mode)
    QC_QUERY_TIMEOUT, // query if emulation stops due to timeout (indicated if
                      // result = True)
} qc_query_type;

// The implementation of qc_ctl is like what Linux ioctl does but slightly
// different.
//
// A qc_control_type passed to qc_ctl is constructed as:
//
//    R/W       NR       Reserved     Type
//  [      ] [      ]  [         ] [       ]
//  31    30 29     26 25       16 15      0
//
//  @R/W: Whether the operation is a read or write access.
//  @NR: Number of arguments.
//  @Reserved: Should be zero, reserved for future extension.
//  @Type: Taken from qc_control_type enum.
//
// See the helper macros below.

// No input and output arguments.
#define QC_CTL_IO_NONE (0)
// Only input arguments for a write operation.
#define QC_CTL_IO_WRITE (1)
// Only output arguments for a read operation.
#define QC_CTL_IO_READ (2)
// The arguments include both input and output arugments.
#define QC_CTL_IO_READ_WRITE (QC_CTL_IO_WRITE | QC_CTL_IO_READ)

#define QC_CTL(type, nr, rw) ((type) | ((nr) << 26) | ((rw) << 30))
#define QC_CTL_NONE(type, nr) QC_CTL(type, nr, QC_CTL_IO_NONE)
#define QC_CTL_READ(type, nr) QC_CTL(type, nr, QC_CTL_IO_READ)
#define QC_CTL_WRITE(type, nr) QC_CTL(type, nr, QC_CTL_IO_WRITE)
#define QC_CTL_READ_WRITE(type, nr) QC_CTL(type, nr, QC_CTL_IO_READ_WRITE)

// All type of controls for qc_ctl API.
// The controls are organized in a tree level.
// If a control don't have `Set` or `Get` for @args, it means it's r/o or w/o.
typedef enum qc_control_type {
    // Current mode.
    // Read: @args = (int*)
    QC_CTL_QC_MODE = 0,
    // Curent page size.
    // Write: @args = (uint32_t)
    // Read: @args = (uint32_t*)
    QC_CTL_QC_PAGE_SIZE,
    // Current arch.
    // Read: @args = (int*)
    QC_CTL_QC_ARCH,
    // Current timeout.
    // Read: @args = (uint64_t*)
    QC_CTL_QC_TIMEOUT,
    // Enable multiple exits.
    // Without this control, reading/setting exits won't work.
    // This is for API backward compatibility.
    // Write: @args = (int)
    QC_CTL_QC_USE_EXITS,
    // The number of current exits.
    // Read: @args = (size_t*)
    QC_CTL_QC_EXITS_CNT,
    // Current exits.
    // Write: @args = (uint64_t* exits, size_t len)
    //        @len = QC_CTL_QC_EXITS_CNT
    // Read: @args = (uint64_t* exits, size_t len)
    //       @len = QC_CTL_QC_EXITS_CNT
    QC_CTL_QC_EXITS,

    // Set the cpu model of uc.
    // Note this option can only be set before any Unicorn
    // API is called except for qc_open.
    // Write: @args = (int)
    // Read:  @args = (int*)
    QC_CTL_CPU_MODEL,
    // Request a tb cache at a specific address
    // Read: @args = (uint64_t, qc_tb*)
    QC_CTL_TB_REQUEST_CACHE,
    // Invalidate a tb cache at a specific address
    // Write: @args = (uint64_t)
    QC_CTL_TB_REMOVE_CACHE

} qc_control_type;

#define qc_ctl_get_mode(uc, mode)                                              \
    qc_ctl(uc, QC_CTL_READ(QC_CTL_QC_MODE, 1), (mode))
#define qc_ctl_get_page_size(uc, ptr)                                          \
    qc_ctl(uc, QC_CTL_READ(QC_CTL_QC_PAGE_SIZE, 1), (ptr))
#define qc_ctl_set_page_size(uc, page_size)                                    \
    qc_ctl(uc, QC_CTL_WRITE(QC_CTL_QC_PAGE_SIZE, 1), (page_size))
#define qc_ctl_get_arch(uc, arch)                                              \
    qc_ctl(uc, QC_CTL_READ(QC_CTL_QC_ARCH, 1), (arch))
#define qc_ctl_get_timeout(uc, ptr)                                            \
    qc_ctl(uc, QC_CTL_READ(QC_CTL_QC_TIMEOUT, 1), (ptr))
#define qc_ctl_exits_enabled(uc, enabled)                                      \
    qc_ctl(uc, QC_CTL_WRITE(QC_CTL_QC_USE_EXITS, 1), (enabled))
#define qc_ctl_get_exits_cnt(uc, ptr)                                          \
    qc_ctl(uc, QC_CTL_READ(QC_CTL_QC_EXITS_CNT, 1), (ptr))
#define qc_ctl_get_exits(uc, buffer, len)                                      \
    qc_ctl(uc, QC_CTL_READ(QC_CTL_QC_EXITS, 2), (buffer), (len))
#define qc_ctl_set_exits(uc, buffer, len)                                      \
    qc_ctl(uc, QC_CTL_WRITE(QC_CTL_QC_EXITS, 2), (buffer), (len))
#define qc_ctl_get_cpu_model(uc, model)                                        \
    qc_ctl(uc, QC_CTL_READ(QC_CTL_CPU_MODEL, 1), (model))
#define qc_ctl_set_cpu_model(uc, model)                                        \
    qc_ctl(uc, QC_CTL_WRITE(QC_CTL_CPU_MODEL, 1), (model))
#define qc_ctl_remove_cache(uc, address)                                       \
    qc_ctl(uc, QC_CTL_WRITE(QC_CTL_TB_REMOVE_CACHE, 1), (address))
#define qc_ctl_request_cache(uc, address, tb)                                  \
    qc_ctl(uc, QC_CTL_READ_WRITE(QC_CTL_TB_REQUEST_CACHE, 2), (address), (tb))

// Opaque storage for CPU context, used with qc_context_*()
struct qc_context;
typedef struct qc_context qc_context;

/*
 Return combined API version & major and minor version numbers.

 @major: major number of API version
 @minor: minor number of API version

 @return hexical number as (major << 8 | minor), which encodes both
     major & minor versions.
     NOTE: This returned value can be compared with version number made
     with macro QC_MAKE_VERSION

 For example, second API version would return 1 in @major, and 1 in @minor
 The return value would be 0x0101

 NOTE: if you only care about returned value, but not major and minor values,
 set both @major & @minor arguments to NULL.
*/
UNICORN_EXPORT
unsigned int qc_version(unsigned int *major, unsigned int *minor);

/*
 Determine if the given architecture is supported by this library.

 @arch: architecture type (QC_ARCH_*)

 @return True if this library supports the given arch.
*/
UNICORN_EXPORT
bool qc_arch_supported(qc_arch arch);

/*
 Create new instance of unicorn engine.

 @arch: architecture type (QC_ARCH_*)
 @mode: hardware mode. This is combined of QC_MODE_*
 @uc: pointer to qc_engine, which will be updated at return time

 @return QC_ERR_OK on success, or other value on failure (refer to qc_err enum
   for detailed error).
*/
UNICORN_EXPORT
qc_err qc_open(qc_arch arch, qc_mode mode, qc_engine **uc);

/*
 Close a Unicorn engine instance.
 NOTE: this must be called only when there is no longer any
 usage of @uc. This API releases some of @uc's cached memory, thus
 any use of the Unicorn API with @uc after it has been closed may
 crash your application. After this, @uc is invalid, and is no
 longer usable.

 @uc: pointer to a handle returned by qc_open()

 @return QC_ERR_OK on success, or other value on failure (refer to qc_err enum
   for detailed error).
*/
UNICORN_EXPORT
qc_err qc_close(qc_engine *uc);

/*
 Query internal status of engine.

 @uc: handle returned by qc_open()
 @type: query type. See qc_query_type

 @result: save the internal status queried

 @return: error code of qc_err enum type (QC_ERR_*, see above)
*/
UNICORN_EXPORT
qc_err qc_query(qc_engine *uc, qc_query_type type, size_t *result);

/*
 Control internal states of engine.

 Also see qc_ctl_* macro helpers for easy use.

 @uc: handle returned by qc_open()
 @control: the control type.
 @args: See qc_control_type for details about variadic arguments.

 @return: error code of qc_err enum type (QC_ERR_*, see above)
*/
UNICORN_EXPORT
qc_err qc_ctl(qc_engine *uc, qc_control_type control, ...);

/*
 Report the last error number when some API function fails.
 Like glibc's errno, qc_errno might not retain its old value once accessed.

 @uc: handle returned by qc_open()

 @return: error code of qc_err enum type (QC_ERR_*, see above)
*/
UNICORN_EXPORT
qc_err qc_errno(qc_engine *uc);

/*
 Return a string describing given error code.

 @code: error code (see QC_ERR_* above)

 @return: returns a pointer to a string that describes the error code
   passed in the argument @code
 */
UNICORN_EXPORT
const char *qc_strerror(qc_err code);

/*
 Write to register.

 @uc: handle returned by qc_open()
 @regid:  register ID that is to be modified.
 @value:  pointer to the value that will set to register @regid

 @return QC_ERR_OK on success, or other value on failure (refer to qc_err enum
   for detailed error).
*/
UNICORN_EXPORT
qc_err qc_reg_write(qc_engine *uc, int regid, const void *value);

/*
 Read register value.

 @uc: handle returned by qc_open()
 @regid:  register ID that is to be retrieved.
 @value:  pointer to a variable storing the register value.

 @return QC_ERR_OK on success, or other value on failure (refer to qc_err enum
   for detailed error).
*/
UNICORN_EXPORT
qc_err qc_reg_read(qc_engine *uc, int regid, void *value);

/*
 Write multiple register values.

 @uc: handle returned by qc_open()
 @rges:  array of register IDs to store
 @value: pointer to array of register values
 @count: length of both *regs and *vals

 @return QC_ERR_OK on success, or other value on failure (refer to qc_err enum
   for detailed error).
*/
UNICORN_EXPORT
qc_err qc_reg_write_batch(qc_engine *uc, int *regs, void *const *vals,
                          int count);

/*
 Read multiple register values.

 @uc: handle returned by qc_open()
 @rges:  array of register IDs to retrieve
 @value: pointer to array of values to hold registers
 @count: length of both *regs and *vals

 @return QC_ERR_OK on success, or other value on failure (refer to qc_err enum
   for detailed error).
*/
UNICORN_EXPORT
qc_err qc_reg_read_batch(qc_engine *uc, int *regs, void **vals, int count);

/*
 Write to a range of bytes in memory.

 @uc: handle returned by qc_open()
 @address: starting memory address of bytes to set.
 @bytes:   pointer to a variable containing data to be written to memory.
 @size:   size of memory to write to.

 NOTE: @bytes must be big enough to contain @size bytes.

 @return QC_ERR_OK on success, or other value on failure (refer to qc_err enum
   for detailed error).
*/
UNICORN_EXPORT
qc_err qc_mem_write(qc_engine *uc, uint64_t address, const void *bytes,
                    size_t size);

/*
 Read a range of bytes in memory.

 @uc: handle returned by qc_open()
 @address: starting memory address of bytes to get.
 @bytes:   pointer to a variable containing data copied from memory.
 @size:   size of memory to read.

 NOTE: @bytes must be big enough to contain @size bytes.

 @return QC_ERR_OK on success, or other value on failure (refer to qc_err enum
   for detailed error).
*/
UNICORN_EXPORT
qc_err qc_mem_read(qc_engine *uc, uint64_t address, void *bytes, size_t size);

/*
 Emulate machine code in a specific duration of time.

 @uc: handle returned by qc_open()
 @begin: address where emulation starts
 @until: address where emulation stops (i.e. when this address is hit)
 @timeout: duration to emulate the code (in microseconds). When this value is 0,
        we will emulate the code in infinite time, until the code is finished.
 @count: the number of instructions to be emulated. When this value is 0,
        we will emulate all the code available, until the code is finished.

 NOTE: The internal states of the engine is guranteed to be correct if and only
       if qc_emu_start returns without any errors or errors have been handled in
       the callbacks.

 @return QC_ERR_OK on success, or other value on failure (refer to qc_err enum
   for detailed error).
*/
UNICORN_EXPORT
qc_err qc_emu_start(qc_engine *uc, uint64_t begin, uint64_t until,
                    uint64_t timeout, size_t count);

/*
 Stop emulation (which was started by qc_emu_start() API.
 This is typically called from callback functions registered via tracing APIs.

 @uc: handle returned by qc_open()

 @return QC_ERR_OK on success, or other value on failure (refer to qc_err enum
   for detailed error).
*/
UNICORN_EXPORT
qc_err qc_emu_stop(qc_engine *uc);

/*
 Register callback for a hook event.
 The callback will be run when the hook event is hit.

 @uc: handle returned by qc_open()
 @hh: hook handle returned from this registration. To be used in qc_hook_del()
 API
 @type: hook type, refer to qc_hook_type enum
 @callback: callback to be run when instruction is hit
 @user_data: user-defined data. This will be passed to callback function in its
      last argument @user_data
 @begin: start address of the area where the callback is in effect (inclusive)
 @end: end address of the area where the callback is in effect (inclusive)
   NOTE 1: the callback is called only if related address is in range [@begin,
 @end] NOTE 2: if @begin > @end, callback is called whenever this hook type is
 triggered
 @...: variable arguments (depending on @type)
   NOTE: if @type = QC_HOOK_INSN, this is the instruction ID.
         currently, only x86 in, out, syscall, sysenter, cpuid are supported.
   NOTE: if @type = QC_HOOK_TCG_OPCODE, arguments are @opcode and @flags. See
 @qc_tcg_op_code and @qc_tcg_op_flag for details.

 @return QC_ERR_OK on success, or other value on failure (refer to qc_err enum
   for detailed error).
*/
UNICORN_EXPORT
qc_err qc_hook_add(qc_engine *uc, qc_hook *hh, int type, void *callback,
                   void *user_data, uint64_t begin, uint64_t end, ...);

/*
 Unregister (remove) a hook callback.
 This API removes the hook callback registered by qc_hook_add().
 NOTE: this should be called only when you no longer want to trace.
 After this, @hh is invalid, and no longer usable.

 @uc: handle returned by qc_open()
 @hh: handle returned by qc_hook_add()

 @return QC_ERR_OK on success, or other value on failure (refer to qc_err enum
   for detailed error).
*/
UNICORN_EXPORT
qc_err qc_hook_del(qc_engine *uc, qc_hook hh);

typedef enum qc_prot {
    QC_PROT_NONE = 0,
    QC_PROT_READ = 1,
    QC_PROT_WRITE = 2,
    QC_PROT_EXEC = 4,
    QC_PROT_ALL = 7,
} qc_prot;

/*
 Map memory in for emulation.
 This API adds a memory region that can be used by emulation.

 @uc: handle returned by qc_open()
 @address: starting address of the new memory region to be mapped in.
    This address must be aligned to 4KB, or this will return with QC_ERR_ARG
 error.
 @size: size of the new memory region to be mapped in.
    This size must be a multiple of 4KB, or this will return with QC_ERR_ARG
 error.
 @perms: Permissions for the newly mapped region.
    This must be some combination of QC_PROT_READ | QC_PROT_WRITE |
 QC_PROT_EXEC, or this will return with QC_ERR_ARG error.

 @return QC_ERR_OK on success, or other value on failure (refer to qc_err enum
   for detailed error).
*/
UNICORN_EXPORT
qc_err qc_mem_map(qc_engine *uc, uint64_t address, size_t size, uint32_t perms);

/*
 Map existing host memory in for emulation.
 This API adds a memory region that can be used by emulation.

 @uc: handle returned by qc_open()
 @address: starting address of the new memory region to be mapped in.
    This address must be aligned to 4KB, or this will return with QC_ERR_ARG
 error.
 @size: size of the new memory region to be mapped in.
    This size must be a multiple of 4KB, or this will return with QC_ERR_ARG
 error.
 @perms: Permissions for the newly mapped region.
    This must be some combination of QC_PROT_READ | QC_PROT_WRITE |
 QC_PROT_EXEC, or this will return with QC_ERR_ARG error.
 @ptr: pointer to host memory backing the newly mapped memory. This host memory
 is expected to be an equal or larger size than provided, and be mapped with at
    least PROT_READ | PROT_WRITE. If it is not, the resulting behavior is
 undefined.

 @return QC_ERR_OK on success, or other value on failure (refer to qc_err enum
   for detailed error).
*/
UNICORN_EXPORT
qc_err qc_mem_map_ptr(qc_engine *uc, uint64_t address, size_t size,
                      uint32_t perms, void *ptr);

/*
 Map MMIO in for emulation.
 This API adds a MMIO region that can be used by emulation.

 @uc: handle returned by qc_open()
 @address: starting address of the new MMIO region to be mapped in.
   This address must be aligned to 4KB, or this will return with QC_ERR_ARG
 error.
 @size: size of the new MMIO region to be mapped in.
   This size must be multiple of 4KB, or this will return with QC_ERR_ARG error.
 @read_cb: function for handling reads from this MMIO region.
 @user_data_read: user-defined data. This will be passed to @read_cb function in
 its last argument @user_data
 @write_cb: function for handling writes to this MMIO region.
 @user_data_write: user-defined data. This will be passed to @write_cb function
 in its last argument @user_data
 @return QC_ERR_OK on success, or other value on failure (refer to qc_err enum
   for detailed error).
 */
UNICORN_EXPORT
qc_err qc_mmio_map(qc_engine *uc, uint64_t address, size_t size,
                   qc_cb_mmio_read_t read_cb, void *user_data_read,
                   qc_cb_mmio_write_t write_cb, void *user_data_write);

/*
 Unmap a region of emulation memory.
 This API deletes a memory mapping from the emulation memory space.

 @uc: handle returned by qc_open()
 @address: starting address of the memory region to be unmapped.
    This address must be aligned to 4KB, or this will return with QC_ERR_ARG
 error.
 @size: size of the memory region to be modified.
    This size must be a multiple of 4KB, or this will return with QC_ERR_ARG
 error.

 @return QC_ERR_OK on success, or other value on failure (refer to qc_err enum
   for detailed error).
*/
UNICORN_EXPORT
qc_err qc_mem_unmap(qc_engine *uc, uint64_t address, size_t size);

/*
 Set memory permissions for emulation memory.
 This API changes permissions on an existing memory region.

 @uc: handle returned by qc_open()
 @address: starting address of the memory region to be modified.
    This address must be aligned to 4KB, or this will return with QC_ERR_ARG
 error.
 @size: size of the memory region to be modified.
    This size must be a multiple of 4KB, or this will return with QC_ERR_ARG
 error.
 @perms: New permissions for the mapped region.
    This must be some combination of QC_PROT_READ | QC_PROT_WRITE |
 QC_PROT_EXEC, or this will return with QC_ERR_ARG error.

 @return QC_ERR_OK on success, or other value on failure (refer to qc_err enum
   for detailed error).
*/
UNICORN_EXPORT
qc_err qc_mem_protect(qc_engine *uc, uint64_t address, size_t size,
                      uint32_t perms);

/*
 Retrieve all memory regions mapped by qc_mem_map() and qc_mem_map_ptr()
 This API allocates memory for @regions, and user must free this memory later
 by qc_free() to avoid leaking memory.
 NOTE: memory regions may be split by qc_mem_unmap()

 @uc: handle returned by qc_open()
 @regions: pointer to an array of qc_mem_region struct. This is allocated by
   Unicorn, and must be freed by user later with qc_free()
 @count: pointer to number of struct qc_mem_region contained in @regions

 @return QC_ERR_OK on success, or other value on failure (refer to qc_err enum
   for detailed error).
*/
UNICORN_EXPORT
qc_err qc_mem_regions(qc_engine *uc, qc_mem_region **regions, uint32_t *count);

/*
 Allocate a region that can be used with qc_context_{save,restore} to perform
 quick save/rollback of the CPU context, which includes registers and some
 internal metadata. Contexts may not be shared across engine instances with
 differing arches or modes.

 @uc: handle returned by qc_open()
 @context: pointer to a qc_context*. This will be updated with the pointer to
   the new context on successful return of this function.
   Later, this allocated memory must be freed with qc_context_free().

 @return QC_ERR_OK on success, or other value on failure (refer to qc_err enum
   for detailed error).
*/
UNICORN_EXPORT
qc_err qc_context_alloc(qc_engine *uc, qc_context **context);

/*
 Free the memory allocated by qc_mem_regions.
 WARNING: After Unicorn 1.0.1rc5, the memory allocated by qc_context_alloc
 should be freed by qc_context_free(). Calling qc_free() may still work, but
 the result is **undefined**.

 @mem: memory allocated by qc_mem_regions (returned in *regions).

 @return QC_ERR_OK on success, or other value on failure (refer to qc_err enum
   for detailed error).
*/
UNICORN_EXPORT
qc_err qc_free(void *mem);

/*
 Save a copy of the internal CPU context.
 This API should be used to efficiently make or update a saved copy of the
 internal CPU state.

 @uc: handle returned by qc_open()
 @context: handle returned by qc_context_alloc()

 @return QC_ERR_OK on success, or other value on failure (refer to qc_err enum
   for detailed error).
*/
UNICORN_EXPORT
qc_err qc_context_save(qc_engine *uc, qc_context *context);

/*
 Write value to a register of a context.

 @ctx: handle returned by qc_context_alloc()
 @regid:  register ID that is to be modified.
 @value:  pointer to the value that will set to register @regid

 @return QC_ERR_OK on success, or other value on failure (refer to qc_err enum
   for detailed error).
*/
UNICORN_EXPORT
qc_err qc_context_reg_write(qc_context *ctx, int regid, const void *value);

/*
 Read register value from a context.

 @ctx: handle returned by qc_context_alloc()
 @regid:  register ID that is to be retrieved.
 @value:  pointer to a variable storing the register value.

 @return QC_ERR_OK on success, or other value on failure (refer to qc_err enum
   for detailed error).
*/
UNICORN_EXPORT
qc_err qc_context_reg_read(qc_context *ctx, int regid, void *value);

/*
 Write multiple register values to registers of a context.

 @ctx: handle returned by qc_context_alloc()
 @regs:  array of register IDs to store
 @value: pointer to array of register values
 @count: length of both *regs and *vals

 @return QC_ERR_OK on success, or other value on failure (refer to qc_err enum
   for detailed error).
*/
UNICORN_EXPORT
qc_err qc_context_reg_write_batch(qc_context *ctx, int *regs, void *const *vals,
                                  int count);

/*
 Read multiple register values from a context.

 @ctx: handle returned by qc_context_alloc()
 @regs:  array of register IDs to retrieve
 @value: pointer to array of values to hold registers
 @count: length of both *regs and *vals

 @return QC_ERR_OK on success, or other value on failure (refer to qc_err enum
   for detailed error).
*/
UNICORN_EXPORT
qc_err qc_context_reg_read_batch(qc_context *ctx, int *regs, void **vals,
                                 int count);

/*
 Restore the current CPU context from a saved copy.
 This API should be used to roll the CPU context back to a previous
 state saved by qc_context_save().

 @uc: handle returned by qc_open()
 @context: handle returned by qc_context_alloc that has been used with
 qc_context_save

 @return QC_ERR_OK on success, or other value on failure (refer to qc_err enum
   for detailed error).
*/
UNICORN_EXPORT
qc_err qc_context_restore(qc_engine *uc, qc_context *context);

/*
  Return the size needed to store the cpu context. Can be used to allocate a
  buffer to contain the cpu context and directly call qc_context_save.

  @uc: handle returned by qc_open()

  @return the size for needed to store the cpu context as as size_t.
*/
UNICORN_EXPORT
size_t qc_context_size(qc_engine *uc);

/*
  Free the context allocated by qc_context_alloc().

  @context: handle returned by qc_context_alloc()

  @return QC_ERR_OK on success, or other value on failure (refer to qc_err enum
   for detailed error).
*/
UNICORN_EXPORT
qc_err qc_context_free(qc_context *context);

#ifdef __cplusplus
}
#endif

#endif
