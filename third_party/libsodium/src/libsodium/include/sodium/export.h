
#ifndef sodium_export_H
#define sodium_export_H

#ifndef SODIUM_EXPORT
#  if defined(_WIN32)
#    ifdef BUILDING_SODIUM
#      define SODIUM_EXPORT __declspec(dllexport)
#    else
#      define SODIUM_EXPORT __declspec(dllimport)
#    endif
#  else
#    if defined(__GNUC__) && __GNUC__ >= 4
#      define SODIUM_EXPORT __attribute__ ((visibility ("default")))
#    else
#      define SODIUM_EXPORT
#    endif
#  endif
#endif

#ifndef SODIUM_EXPORT_STATIC
#  define SODIUM_EXPORT_STATIC SODIUM_EXPORT
#endif

#endif
