#ifndef SODIUM_EXPORT_H
#define SODIUM_EXPORT_H

#ifndef SODIUM_EXPORT
#  if defined(_WIN32)
#    ifdef SODIUM_DLL_EXPORT
#      define SODIUM_EXPORT __declspec(dllexport)
#    else
#      define SODIUM_EXPORT __declspec(dllimport)
#    endif
#  else
#    define SODIUM_EXPORT
#  endif
#endif

#ifndef SODIUM_EXPORT_WEAK
#  define SODIUM_EXPORT_WEAK SODIUM_EXPORT
#endif

#ifndef CRYPTO_ALIGN
#  if defined(__GNUC__) || defined(__clang__)
#    define CRYPTO_ALIGN(x) __attribute__((aligned(x)))
#  elif defined(_MSC_VER)
#    define CRYPTO_ALIGN(x) __declspec(align(x))
#  else
#    define CRYPTO_ALIGN(x)
#  endif
#endif

#endif
