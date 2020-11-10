/**
 * @file cmdenv.c
 * @brief Load command line from virtual machine, if any
 *
 * @copyright Copyright (c) 2020 SiFive, Inc
 * @copyright SPDX-License-Identifier: MIT
 *
 */

#include <stdint.h>
#include <metal/machine/platform.h>
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wdocumentation"
#pragma clang diagnostic ignored "-Wunused-parameter"
#pragma clang diagnostic ignored "-Wmissing-variable-declarations"
#pragma clang diagnostic ignored "-Wdocumentation-unknown-command"
#include <metal/machine.h>
#pragma clang diagnostic pop

static char _cmdline_str[0x100u];
static const char * _cmdline_argv[16u];
static int _cmdline_argc;

#ifndef ARRAY_SIZE
#define ARRAY_SIZE(_a_) (sizeof(_a_)/sizeof((_a_)[0]))
#endif // ARRAY_SIZE

#ifndef ELFNAME
#define ELFNAME "test"
#endif

/** Dummy structure to return values in registers a0/a1 */
struct stack_return
{
    uintptr_t sr_argc; /**< a0: argc */
    uintptr_t sr_argv; /**< a1: argv */
};

struct stack_return load_cmdline(void);

struct stack_return load_cmdline(void)
{
    _cmdline_argc = 0;
    _cmdline_argv[_cmdline_argc++] = ELFNAME;

#ifdef __METAL_DT_SHUTDOWN_HANDLE
    // Query VM peripheral for an optional command line
    unsigned long base;
    base = __metal_driver_sifive_test0_base(__METAL_DT_SHUTDOWN_HANDLE);
    // Initialize the query
    __METAL_ACCESS_ONCE((__metal_io_u32 *)(base + 0x100)) = 0x6c63;

    char * ptr = _cmdline_str;
    char last = '\0';
    const char * first = NULL;
    _cmdline_argv[_cmdline_argc] = ptr;

    // retrieve the command line if any, and slit it into an argv array
    while ( (ptr-_cmdline_str < (int)sizeof(_cmdline_str)) &&
            (_cmdline_argc < (int)ARRAY_SIZE(_cmdline_argv)) ) {
        *ptr = (char)__METAL_ACCESS_ONCE((__metal_io_u32 *)(base + 0x100));
        if ( ! *ptr ) {
            break;
        }
        if ( *ptr == ' ' ) {
            if ( last != ' ' && first ) {
                *ptr ='\0';
                _cmdline_argv[_cmdline_argc++] = first;
                first = NULL;
            }
        } else if ( ! first ) {
            first = ptr;
        }
        last = *ptr;
        ptr++;
    }
    if ( first ) {
        _cmdline_argv[_cmdline_argc++] = first;
    }
#endif // __METAL_DT_SHUTDOWN_HANDLE

    struct stack_return sr = {
        .sr_argc = (uintptr_t)_cmdline_argc, /* a0 */
        .sr_argv = (uintptr_t)_cmdline_argv, /* a1 */
    };

    return sr;
}
