#pragma once

#include <stdint.h>


#ifdef SJEJHHUTIL_BUILD_DLL
#ifdef SJEJHHUTIL_EXPORTS
#define SJEJHHUTIL_API __declspec(dllexport)
#else
#define SJEJHHUTIL_API __declspec(dllimport)
#endif
#else
#define SJEJHHUTIL_API extern
#endif // 

#ifdef __cplusplus
extern "C" {
#endif // __cplusplus

    int SJEJHHUTIL_API sjejhh_encrypt_stream(const char* data, size_t inputLength, char* out, size_t outLength, const char* keyData, uint32_t keyLength);
    int SJEJHHUTIL_API sjejhh_encrypt_file(const wchar_t* input_filePath, const wchar_t* output_filePath, const char* keyData, uint32_t keyLength);

    /*
     * sugar
    */
    int SJEJHHUTIL_API sjejhh_decrypt_stream(const char* data, size_t inputLength, char* out, size_t outLength, const char* keyData, uint32_t keyLength);
    int SJEJHHUTIL_API sjejhh_decrypt_file(const wchar_t* input_filePath, const wchar_t* output_filePath, const char* keyData, uint32_t keyLength);




#ifdef __cplusplus
}
#endif // __cplusplus
