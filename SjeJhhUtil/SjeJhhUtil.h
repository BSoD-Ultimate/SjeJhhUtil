/* 
 * SJEJhhUtil - encode/decode SJE.JHH files locates in 
 * Tetris Online Poland(TOP) client.
 *
 * Code here is inspired by Wojtek's tool used to pack/unpack "SJE.JHH" files
 * locates in Tetris Online Poland client.
 * 
 * The implementation is partly based on disassembling Wojtek's work of 
 * "Encrypt.exe" and "SjeJhhTool.exe"
 * 
 * Thanks for Wojtek's help.
*/
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

    /*
     * sjejhh_encrypt_stream
     * 
     * Encrypt plain data in memory into the encrypted TOP client-compatible format.
     * 
     * Parameters: 
     * 
     * data:        plain data needs to be encrypted.
     * inputLength: plain data size.
     * out:         pointer to a part of memory which receives the encrypted data.
     * outLength:   output memory buffer length.
     * keyData:     the binary-formatted key used in encryption.
     * keyLength:   length of encryption key data. 
     *
     * When calling this function. A encryption key in binary-format is required.
     * The parameter "keyLength" should not be zero. Otherwise, the encryption 
     * will fail.
     * When encryption succeeded, the function returns 0.
     * When encryption failed, the return value is -1.
     * When parameter "outLength"'s value is 0, or the encrypted data requires more
     * space than parameter "outLength" assigned, the return value will be the minimum 
     * size of memory space required to hold the encrypted data. Which helps user to 
     * allocate enough memory space to store the encrypted result.
    */
    int SJEJHHUTIL_API sjejhh_encrypt_stream(
        const char* data,
        size_t inputLength,
        char* out,
        size_t outLength,
        const char* keyData,
        uint32_t keyLength
    );

    /*
     * sjejhh_encrypt_file
     * 
     * Encrypt a plain data file into the TOP-Client-accepted encrypted format. 
     * The encrypted file will be saved in the path points to "output_file_path".
     * 
     * Parameters:
     *
     * input_filePath:  path points to the source file.
     * output_filePath: the path where the encrypted file will be saved.
     * keyData:         the binary-formatted key used in encryption.
     * keyLength:       length of encryption key data.
     * 
     * A encryption key in binary-format is required. The parameter "keyLength"
     * should not be zero. Otherwise, the encryption will fail.
     * When encryption succeeded, the function returns 1.
     * When encryption failed, the return value is 0.
     * 
    */
    int SJEJHHUTIL_API sjejhh_encrypt_file(const wchar_t* input_filePath, const wchar_t* output_filePath, const char* keyData, uint32_t keyLength);

    /*
     * Sugar method of sjejhh_encrypt_stream & sjejhh_encrypt_file. :D
     * 
     * CAUTION: Functionality of the following two functions may be altered later.
     * 
     * The way of encryption used in TOP client results in plain data again
     * when a piece of encrypted data is encrypted again. In short:
     * 
     * Encrypt(Encrypt(plain data)) = plain data.
     * 
     * So decryption functions here is just an alias of encryption functions. Just for 
     * distinguishing when they are used with "encrypt" methods. :D
    */
    int SJEJHHUTIL_API sjejhh_decrypt_stream(const char* data, size_t inputLength, char* out, size_t outLength, const char* keyData, uint32_t keyLength);
    int SJEJHHUTIL_API sjejhh_decrypt_file(const wchar_t* input_filePath, const wchar_t* output_filePath, const char* keyData, uint32_t keyLength);




#ifdef __cplusplus
}
#endif // __cplusplus
