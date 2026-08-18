/*
 * RNA2 Package Manager & Memory Engine (rna2_pm)
 * C/C++ Foreign Function Interface (FFI) Header
 * Developed by SmartAscent Labs
 * Copyright (c) SmartAscent Labs. All rights reserved.
 */

#ifndef RNA2_PM_H
#define RNA2_PM_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#if defined(_WIN32) || defined(__CYGWIN__)
  #ifdef RNA2_PM_EXPORTS
    #define RNA2_API __declspec(dllexport)
  #else
    #define RNA2_API __declspec(dllimport)
  #endif
#else
  #if __GNUC__ >= 4
    #define RNA2_API __attribute__ ((visibility ("default")))
  #else
    #define RNA2_API
  #endif
#endif

/* Progress Callback Function Prototype */
typedef void (*rna2_progress_cb)(uint64_t bytes_processed, uint64_t total_bytes, const char* current_file);

/* Status / Return Codes */
typedef enum {
    RNA2_SUCCESS = 0,
    RNA2_ERROR_INVALID_PARAM = -1,
    RNA2_ERROR_ENCRYPTION_FAILED = -2,
    RNA2_ERROR_DECRYPTION_FAILED = -3,
    RNA2_ERROR_IO_FAILURE = -4,
    RNA2_ERROR_MEMORY_ALLOCATION = -5
} rna2_status_t;

RNA2_API int32_t rna2_pack_directory(
    const char* dir_path,
    const char* output_file,
    const char* passphrase
);

RNA2_API int32_t rna2_pack_directory_with_progress(
    const char* dir_path,
    const char* output_file,
    const char* passphrase,
    rna2_progress_cb callback
);

RNA2_API int32_t rna2_unpack_directory(
    const char* package_file,
    const char* target_dir,
    const char* passphrase
);

RNA2_API int32_t rna2_unpack_directory_with_progress(
    const char* package_file,
    const char* target_dir,
    const char* passphrase,
    rna2_progress_cb callback
);

#ifdef __cplusplus
}
#endif

#endif /* RNA2_PM_H */
