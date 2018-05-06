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
 * Thanks for Wojtek's work help.
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
#endif 

#ifdef __cplusplus
extern "C" {
#endif // __cplusplus

    /*
     * sjejhh_encrypt_data
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
    SJEJHHUTIL_API int sjejhh_encrypt_data(
        const char* data,
        size_t inputLength,
        char* out,
        size_t outLength,
        const char* keyData,
        uint32_t keyLength
    );

    /*
    * sjejhh_encrypt_stream_data
    *
    * Encrypt data assembled in stream into the encrypted TOP client-compatible format.
    *
    * Parameters:
    *
    * data:        plain data needs to be encrypted.
    * inputLength: plain data size.
    * out:         pointer to a part of memory which receives the encrypted data.
    * outLength:   output memory buffer length.
    * keyData:     the binary-formatted key used in encryption.
    * keyLength:   length of encryption key data.
    * streamEnd:   whether the data going to be encrypted is the end of the whole stream data.
    *
    * behaves same when parameter "streamEnd" is set true. When encrypting stream data, 
    * set "streamEnd" false until the last piece of data is going to be encrypted.
    */
    //SJEJHHUTIL_API int sjejhh_encrypt_stream_data(
    //    const char* data,
    //    size_t inputLength,
    //    char* out,
    //    size_t outLength,
    //    const char* keyData,
    //    uint32_t keyLength,
    //    int streamEnd
    //);

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
    SJEJHHUTIL_API int sjejhh_encrypt_file(
        const wchar_t* input_filePath,
        const wchar_t* output_filePath,
        const char* keyData,
        uint32_t keyLength
    );

    /*
     * Sugar of encryption methods. :D
     * 
     * CAUTION: Functionality of the following two functions may be altered later.
     * 
     * The way of encryption(RC4) used in TOP client results in plain data again
     * when a piece of encrypted data is encrypted again. In short:
     * 
     * Encrypt(Encrypt(plain data)) = plain data.
     * 
     * So decryption functions here is just an alias of encryption functions. Just for 
     * distinguishing when they are used together with "encrypt" methods. :P
    */

    /*
     * alias of function sjejhh_encrypt_data.
    */
    SJEJHHUTIL_API int sjejhh_decrypt_data(
        const char* data,
        size_t inputLength,
        char* out,
        size_t outLength,
        const char* keyData,
        uint32_t keyLength
    );

    /*
    * alias of function sjejhh_encrypt_stream_data.
    */
    //SJEJHHUTIL_API int sjejhh_decrypt_stream_data(
    //    const char* data,
    //    size_t inputLength,
    //    char* out,
    //    size_t outLength,
    //    const char* keyData,
    //    uint32_t keyLength,
    //    int streamEnd
    //);

    /*
     * alias of function sjejhh_encrypt_file.
    */
    SJEJHHUTIL_API int sjejhh_decrypt_file(
        const wchar_t* input_filePath,
        const wchar_t* output_filePath,
        const char* keyData, 
        uint32_t keyLength
    );


    /*
     * functions used to unpack a "SJE.JHH" archive.
    */
    typedef enum _sjejhh_unpack_error_code
    {
        SJEJHH_UNPACK_OK = 0,
        SJEJHH_UNPACK_END_OF_LIST_OF_FILE,
        SJEJHH_UNPACK_ERRNO,
        SJEJHH_UNPACK_EOF,
        SJEJHH_UNPACK_INVALIDARG,
        SJEJHH_UNPACK_INTERNALERROR,

    }sjejhh_unpack_error_code;

    typedef struct sjejhh_unpack_context sjejhh_unpack_context;

    typedef struct _sjejhh_unpack_global_info
    {
        // "SJE.JHH" file path
        const wchar_t* archiveFilePath;
        size_t archiveFilePathLength;

        // internal folder identifier
        const char* internalFolderName;
        size_t internalFolderNameLength;

        size_t archiveFileSize;   // file size
        size_t fileCount;         // total file count
        size_t currentFileIndex;  // current file index
    }sjejhh_unpack_global_info;

    typedef struct _sjejhh_unpack_current_file_info
    {
        size_t currentIndex;

        const char* filename;
        size_t filenameLength;

        size_t fileOffset;
        size_t fileLength;
        int isEncrypted;
    }sjejhh_unpack_current_file_info;

    SJEJHHUTIL_API sjejhh_unpack_context* sjejhh_unpack_open(const wchar_t* filePath);

    SJEJHHUTIL_API int sjejhh_unpack_get_global_info(
        sjejhh_unpack_context* pArchive,
        sjejhh_unpack_global_info* pGlobalInfo
    );

    SJEJHHUTIL_API int sjejhh_unpack_get_current_file_info(
        sjejhh_unpack_context* pArchive,
        sjejhh_unpack_current_file_info* pCurrentFileInfo
    );

    SJEJHHUTIL_API int sjejhh_unpack_read_current_file(
        sjejhh_unpack_context* pArchive,
        char* readBuf,
        size_t bufLength, 
        size_t* bytesRead,
        size_t* bytesRemaining
    );

    SJEJHHUTIL_API int sjejhh_unpack_decrypt_read_data(
        sjejhh_unpack_context* pArchive,
        const char* inData,
        size_t inLength,
        char* outBuf,
        size_t outLength
    );

    SJEJHHUTIL_API void sjejhh_unpack_reset_decrypt_context(sjejhh_unpack_context* pArchive);

    SJEJHHUTIL_API int sjejhh_unpack_seek_to_begin(sjejhh_unpack_context* pArchive);

    SJEJHHUTIL_API int sjejhh_unpack_reset_file_pointer(sjejhh_unpack_context* pArchive);

    SJEJHHUTIL_API int sjejhh_unpack_goto_next_file(sjejhh_unpack_context* pArchive);


    SJEJHHUTIL_API int sjejhh_unpack_close(sjejhh_unpack_context* pArchive);

    /*
    * functions used to pack a "SJE.JHH" archive
    */
    typedef struct sjejhh_pack_context sjejhh_pack_context;

#ifdef __cplusplus
}
#endif // __cplusplus
