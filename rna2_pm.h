/*
 * RNA2 Package Manager & Memory Engine (rna2_pm)
 * C/C++ Foreign Function Interface (FFI) Header
 * Developed by SmartAscent Labs
 * Copyright (c) SmartAscent Labs. All rights reserved.
 */

#ifndef RNA2_PM_H
#define RNA2_PM_H

#include <stddef.h>
#include <stdint.t.h>

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

/* Status / Return Codes */
typedef enum {
    RNA2_SUCCESS = 0,
    RNA2_ERROR_INVALID_PARAM = -1,
    RNA2_ERROR_ENCRYPTION_FAILED = -2,
    RNA2_ERROR_DECRYPTION_FAILED = -3,
    RNA2_ERROR_IO_FAILURE = -4,
    RNA2_ERROR_MEMORY_ALLOCATION = -5
} rna2_status_t;

/**
 * Packs a directory into an encrypted RNA2 container archive.
 * 
 * @param dir_path Path to target input directory.
 * @param output_file Path for destination .rna2 archive file.
 * @param passphrase Null-terminated passphrase string for encryption.
 * @return RNA2_SUCCESS (0) on success, or appropriate error code.
 */
RNA2_API int32_t rna2_pack_directory(
    const char* dir_path,
    const char* output_file,
    const char* passphrase
);

/**
 * Unpacks an encrypted RNA2 container archive into a target directory.
 * 
 * @param package_file Path to input .rna2 archive file.
 * @param target_dir Path to target destination directory.
 * @param passphrase Null-terminated passphrase string for decryption.
 * @return RNA2_SUCCESS (0) on success, or appropriate error code.
 */
RNA2_API int32_t rna2_unpack_directory(
    const char* package_file,
    const char* target_dir,
    const char* passphrase
);

#ifdef __cplusplus
}
#endif

#endif /* RNA2_PM_H */
