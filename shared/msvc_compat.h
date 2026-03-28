#ifndef MSVC_COMPAT_H
#define MSVC_COMPAT_H

#ifdef _MSC_VER
#include <stddef.h>
#include <stdint.h>

/* Handle GCC attributes */
#define __attribute__(x)
#define __builtin_expect(x, y) (x)
#define __inline inline
#define __thread __declspec(thread)

/* libsodium specific macros usually in config.h */
#ifndef SODIUM_STATIC
#define SODIUM_STATIC 1
#endif

#ifndef SODIUM_EXPORT
#define SODIUM_EXPORT
#endif

#ifndef SODIUM_SIZE_MAX
#ifdef SIZE_MAX
#define SODIUM_SIZE_MAX SIZE_MAX
#else
#define SODIUM_SIZE_MAX ((size_t)-1)
#endif
#endif

#ifndef SODIUM_MIN
#define SODIUM_MIN(A, B) ((A) < (B) ? (A) : (B))
#endif

#ifndef SODIUM_MAX
#define SODIUM_MAX(A, B) ((A) > (B) ? (A) : (B))
#endif

/* MSVC-specific warning suppressions */
#pragma warning(disable: 4244) /* type conversion, possible loss of data */
#pragma warning(disable: 4267) /* conversion from 'size_t' to 'int' */
#pragma warning(disable: 4018) /* signed/unsigned mismatch */
#pragma warning(disable: 4146) /* unary minus operator applied to unsigned type */

#endif

#endif
