// SjeJhhUtil.cpp : Defines the exported functions for the DLL application.
//

#include "stdafx.h"
#include "SjeJhhUtil.h"

#include "CryptUtil.h"

#include <sstream>
#include <experimental/filesystem>

namespace filesystem = std::experimental::filesystem;

using namespace SjeJhhUtil;

class FileHandle
{
public:
    FileHandle(const std::wstring& filename, const std::wstring& mode)
        : m_filePath(filename)
        , m_openMode(mode)
        , m_fileHandle(NULL)
    {
        m_fileHandle = _wfopen(m_filePath.c_str(), mode.c_str());
        int error = errno;
        assert(m_fileHandle);

        if (!m_fileHandle)
        {
            std::ostringstream ss;
            ss << "Could not open file \"" << m_filePath << "\" ! errorCode = " << error;
            throw std::runtime_error(ss.str());
        }
    }
    ~FileHandle()
    {
        fclose(m_fileHandle);
    }

    FILE* Get() const
    {
        return m_fileHandle;
    }

    FileHandle(const FileHandle&) = delete;
    FileHandle& operator=(const FileHandle&) = delete;
private:
    filesystem::path m_filePath;
    std::wstring m_openMode;
    FILE* m_fileHandle;
};

static std::unique_ptr<CCryptKey> CreateCryptKey(CCryptContext& context, const char* keyData, size_t keyLength)
{
    std::unique_ptr<CCryptKey> pKey(new CCryptKey());
    CCryptKeyHash hash(context.Get(), CALG_MD5);
    if (!CryptHashData(hash.Get(), (const BYTE*)keyData, keyLength, 0))
    {
        int error = GetLastError();
        return nullptr;
    }

    if (!CryptDeriveKey(context.Get(), CALG_RC4, hash.Get(), CRYPT_CREATE_SALT, &(*pKey.get())))
    {
        int error = GetLastError();
        return nullptr;
    }

    return pKey;
}

static std::unique_ptr<CCryptKey> CreateCryptKeyFromEnvironment(CCryptContext& context, std::unique_ptr<char[]>& keyData, size_t& keyLen)
{
    std::unique_ptr<CCryptKey> randomKey(new CCryptKey());
    if (!CryptGenKey(context.Get(), CALG_RC4, CRYPT_CREATE_SALT | CRYPT_EXPORTABLE, &(*randomKey)))
    {
        int error = GetLastError();
        return nullptr;
    }
    CCryptKey userKey;
    if (!CryptGetUserKey(context.Get(), 1, &userKey))
    {
        int error = GetLastError();
        if (error != NTE_NO_KEY)
        {
            return nullptr;
        }
        else
        {
            if (!CryptGenKey(context.Get(), ALG_SID_DES, CRYPT_EXPORTABLE, &userKey))
            {
                int error = GetLastError();
                return nullptr;
            }
        }
    }

    // export the keyData
    // get key length
    DWORD keyDataLen = 0;
    if (!CryptExportKey(randomKey->get(), userKey.get(), SIMPLEBLOB, 0, 0, &keyDataLen))
    {
        int error = GetLastError();
        return nullptr;
    }

    keyData.reset(new char[keyDataLen]());
    keyLen = keyDataLen;
    // get key data
    if (!CryptExportKey(randomKey->get(), userKey.get(), SIMPLEBLOB, 0, (BYTE*)keyData.get(), &keyDataLen))
    {
        int error = GetLastError();
        return nullptr;
    }

    return randomKey;
}

int SJEJHHUTIL_API sjejhh_encrypt_stream(const char* data, size_t inputLength, char* out, size_t outLength, const char* keyData, uint32_t keyLength)
{
    assert(keyData && (keyLength > 0));

    if (!keyData && (keyLength > 0))
    {
        return 0;
    }

    std::unique_ptr<char[]> keyBuf(new char[keyLength]());
    memcpy_s(keyBuf.get(), keyLength, keyData, keyLength);
    uint32_t keyBufLen = keyLength;

    CCryptContext cryptContext;

    std::unique_ptr<CCryptKey> keyHandle = CreateCryptKey(cryptContext, keyBuf.get(), keyBufLen);

    //if (!CryptEncrypt(keyHandle->get(), 0, encryptComplete, 0, (BYTE*)buf.get(), (DWORD*)&bytesRead, encryptBufLen))
    //{
    //    int error = GetLastError();
    //    return 0;
    //    throw std::runtime_error(util::generate_errorMsg("Error during CryptEncrypt!", error));
    //}

    return 1;
}

int SJEJHHUTIL_API sjejhh_encrypt_file(const wchar_t* input_filePath, const wchar_t* output_filePath, const char* keyData, uint32_t keyLength)
{
    try
    {
        FileHandle inputFileHandle(input_filePath, L"rb");
        FileHandle outputFileHandle(output_filePath, L"wb");

        CCryptContext cryptContext;

        std::unique_ptr<CCryptKey> keyHandle;
        bool keyAssignedFromArg = keyData && (keyLength > 0);

        std::unique_ptr<char[]> keyBuf;
        uint32_t keyBufLen = keyLength;

        if (keyAssignedFromArg)
        {
            keyBuf.reset(new char[keyLength]());
            memcpy_s(keyBuf.get(), keyBufLen, keyData, keyLength);
            keyHandle = CreateCryptKey(cryptContext, keyBuf.get(), keyBufLen);
        }
        else
        {
            keyHandle = CreateCryptKeyFromEnvironment(cryptContext, keyBuf, keyBufLen);
        }

        if (!keyHandle)
        {
            throw std::runtime_error("Error while creating the key handle!");
        }

        // write key generated from user environment to file as header
        if (!keyAssignedFromArg)
        {
            bool writeKeyLenSuccess = fwrite(&keyBufLen, 1, sizeof(keyBufLen), outputFileHandle.Get()) == sizeof(keyBufLen);
            bool writeKeySuccess = fwrite(keyBuf.get(), 1, keyBufLen, outputFileHandle.Get()) == keyBufLen;
            if (!(writeKeyLenSuccess && writeKeySuccess))
            {
                throw std::runtime_error("Write file header failed!");
            }
        }

        static const int encryptChunkLen = 1000;
        static const int encryptBufLen = encryptChunkLen + 8;
        std::unique_ptr<char[]> plainTextBuf(new char[encryptBufLen]());

        // encrypt the file
        bool encryptComplete = false;
        size_t bytesRead = 0;
        while (true)
        {
            bytesRead = fread(plainTextBuf.get(), 1, encryptChunkLen, inputFileHandle.Get());

            if (bytesRead < encryptChunkLen)
                encryptComplete = true;

            if (!CryptEncrypt(keyHandle->get(), 0, encryptComplete, 0, (BYTE*)plainTextBuf.get(), (DWORD*)&bytesRead, encryptBufLen))
            {
                int error = GetLastError();
                throw std::runtime_error(util::generate_errorMsg("Error during CryptEncrypt!", error));
            }

            size_t bytesWrite = fwrite(plainTextBuf.get(), 1, bytesRead, outputFileHandle.Get());
            if (bytesWrite < bytesRead)
            {
                int error = errno;
                throw std::runtime_error(util::generate_errorMsg("Error writing cipherText!", error));
            }

            if (encryptComplete)
            {
                break;
            }
        }

        return 1;
    }
    catch (const std::exception& e)
    {
        return 0;
    }


}

int SJEJHHUTIL_API sjejhh_decrypt_stream(const char* data, size_t inputLength, char* out, size_t outLength, const char* keyData, uint32_t keyLength)
{
    return 0;
}

int SJEJHHUTIL_API sjejhh_decrypt_file(const wchar_t* input_filePath, const wchar_t* output_filePath, const char* keyData, uint32_t keyLength)
{
    return 0;
}


//char sub_10610B0(const WCHAR *a1, const WCHAR *lpFileName, WORD *a3)
//{
//    const WCHAR *v3; // esi@1
//    HANDLE v4; // ebx@1
//    int v5; // ST18_4@5
//    int v6; // eax@14
//    int v7; // eax@18
//    int v8; // eax@21
//    DWORD(__stdcall *v10)(); // ebp@28
//    int v11; // ST18_4@29
//    int v12; // ST18_4@30
//    int v13; // ST18_4@31
//    BYTE *v14; // edi@36
//    int v15; // ST18_4@40
//    int v16; // ST18_4@43
//    int v17; // ST18_4@47
//    void *v18; // edi@49
//    char v19; // bl@50
//    int v20; // ST18_4@58
//    int v21; // ST18_4@59
//    int v22; // ST18_4@60
//    int v23; // ST18_4@62
//    int v24; // ST18_4@63
//    int v25; // ST18_4@64
//    int v26; // ST18_4@65
//    int v27; // ST18_4@66
//    DWORD v28; // ebp@67
//    FILE *v29; // eax@67
//    FILE *v30; // eax@67
//    FILE *v31; // eax@67
//    char v32; // [sp+13h] [bp-25h]@1
//    HCRYPTPROV phProv; // [sp+14h] [bp-24h]@1
//    HCRYPTKEY phUserKey; // [sp+18h] [bp-20h]@1
//    DWORD NumberOfBytesWritten; // [sp+1Ch] [bp-1Ch]@45
//    HCRYPTKEY hKey; // [sp+20h] [bp-18h]@1
//    DWORD pdwDataLen; // [sp+24h] [bp-14h]@35
//    HANDLE hFile; // [sp+28h] [bp-10h]@2
//    HCRYPTHASH hHash; // [sp+2Ch] [bp-Ch]@1
//    HANDLE hObject; // [sp+30h] [bp-8h]@1
//    void *Memory; // [sp+34h] [bp-4h]@1
//
//    v3 = a1;
//    v32 = 0;
//    v4 = (HANDLE)-1;
//    phProv = 0;
//    hKey = 0;
//    phUserKey = 0;
//    hHash = 0;
//    Memory = 0;
//    hObject = CreateFileW(a1, 0x80000000, 0, 0, 3u, 0x80u, 0);
//    if (hObject != (HANDLE)-1)
//    {
//        wprintf(L"The source plaintext file, %s, is open. \n", v3);
//        hFile = CreateFileW(lpFileName, 0x40000000u, 0, 0, 2u, 0x80u, 0);
//        if (hFile == (HANDLE)-1)
//        {
//            v27 = GetLastError();
//            sub_1061630((int)L"Error opening destination file!\n", v27);
//            goto LABEL_6;
//        }
//        wprintf(L"The destination file, %s, is open. \n", lpFileName);
//        if (!CryptAcquireContextW(&phProv, 0, L"Microsoft Base Cryptographic Provider v1.0", 1u, 0)
//            && !CryptAcquireContextW(&phProv, 0, L"Microsoft Base Cryptographic Provider v1.0", 1u, 8u))
//        {
//            v5 = GetLastError();
//            sub_1061630((int)L"Error during CryptAcquireContext!\n", v5);
//            goto LABEL_6;
//        }
//        wprintf(L"A cryptographic provider has been acquired. \n");
//        if (a3 && *a3)
//        {
//            if (!CryptCreateHash(phProv, 0x8003u, 0, 0, &hHash))
//            {
//                v13 = GetLastError();
//                sub_1061630((int)L"Error during CryptCreateHash!\n", v13);
//                goto LABEL_6;
//            }
//            wprintf(L"A hash object has been created. \n");
//            if (!CryptHashData(hHash, &pbData, strlen((const char *)&pbData), 0))
//            {
//                v12 = GetLastError();
//                sub_1061630((int)L"Error during CryptHashData. \n", v12);
//                goto LABEL_6;
//            }
//            wprintf(L"The password has been added to the hash. \n");
//            if (!CryptDeriveKey(phProv, 0x6801u, hHash, 4u, &hKey))
//            {
//                v11 = GetLastError();
//                sub_1061630((int)L"Error during CryptDeriveKey!\n", v11);
//                goto LABEL_6;
//            }
//            wprintf(L"An encryption key is derived from the password hash. \n");
//            v10 = GetLastError;
//        }
//        else
//        {
//            if (!CryptGenKey(phProv, 0x6801u, 5u, &hKey))
//            {
//                v26 = GetLastError();
//                sub_1061630((int)L"Error during CryptGenKey. \n", v26);
//                goto LABEL_6;
//            }
//            wprintf(L"A session key has been created. \n");
//            if (CryptGetUserKey(phProv, 1u, &phUserKey))
//            {
//                wprintf(L"The user public key has been retrieved. \n");
//                v10 = GetLastError;
//            }
//            else
//            {
//                v10 = GetLastError;
//                if (GetLastError() != 0x8009000D)
//                {
//                    v25 = GetLastError();
//                    sub_1061630((int)L"User public key is not available and may not exist.\n", v25);
//                    goto LABEL_6;
//                }
//                if (!CryptGenKey(phProv, 1u, 1u, &phUserKey))
//                {
//                    v16 = GetLastError();
//                    sub_1061630((int)L"Could not create a user public key.\n", v16);
//                    goto LABEL_6;
//                }
//            }
//            if (!CryptExportKey(hKey, phUserKey, 1u, 0, 0, &pdwDataLen))
//            {
//                v24 = v10();
//                sub_1061630((int)L"Error computing BLOB length! \n", v24);
//                goto LABEL_6;
//            }
//            wprintf(L"The key BLOB is %d bytes long. \n", pdwDataLen);
//            v14 = (BYTE *)malloc(pdwDataLen);
//            if (!v14)
//                goto LABEL_61;
//            wprintf(L"Memory is allocated for the key BLOB. \n");
//            if (!CryptExportKey(hKey, phUserKey, 1u, 0, v14, &pdwDataLen))
//            {
//                v23 = v10();
//                sub_1061630((int)L"Error during CryptExportKey!\n", v23);
//                goto LABEL_6;
//            }
//            wprintf(L"The key has been exported. \n");
//            if (phUserKey)
//            {
//                if (!CryptDestroyKey(phUserKey))
//                {
//                    v15 = v10();
//                    sub_1061630((int)L"Error during CryptDestroyKey.\n", v15);
//                    goto LABEL_6;
//                }
//                phUserKey = 0;
//            }
//            if (!WriteFile(hFile, &pdwDataLen, 4u, &NumberOfBytesWritten, 0)
//                || (wprintf(L"A file header has been written. \n"), !WriteFile(hFile, v14, pdwDataLen, &NumberOfBytesWritten, 0)))
//            {
//                v17 = v10();
//                sub_1061630((int)L"Error writing header.\n", v17);
//                goto LABEL_6;
//            }
//            wprintf(L"The key BLOB has been written to the file. \n");
//            free(v14);
//        }
//        v18 = malloc(0x3F0u);
//        Memory = v18;
//        if (v18)
//        {
//            wprintf(L"Memory has been allocated for the buffer. \n");
//            v19 = 0;
//            while (1)
//            {
//                if (!ReadFile(hObject, v18, 0x3E8u, &NumberOfBytesWritten, 0))
//                {
//                    v20 = v10();
//                    sub_1061630((int)L"Error reading plaintext!\n", v20);
//                    goto LABEL_6;
//                }
//                if (NumberOfBytesWritten < 0x3E8)
//                    v19 = 1;
//                if (!CryptEncrypt(hKey, 0, (unsigned __int8)v19, 0, (BYTE *)v18, &NumberOfBytesWritten, 0x3F0u))
//                {
//                    v21 = v10();
//                    sub_1061630((int)L"Error during CryptEncrypt. \n", v21);
//                    goto LABEL_6;
//                }
//                if (!WriteFile(hFile, v18, NumberOfBytesWritten, &NumberOfBytesWritten, 0))
//                    break;
//                if (v19)
//                {
//                    v32 = 1;
//                    goto LABEL_6;
//                }
//            }
//            v22 = v10();
//            sub_1061630((int)L"Error writing ciphertext.\n", v22);
//        LABEL_6:
//            v4 = hFile;
//            if (!hObject)
//                goto LABEL_8;
//            goto LABEL_7;
//        }
//    LABEL_61:
//        sub_1061630((int)L"Out of memory. \n", -2147024882);
//        goto LABEL_6;
//    }
//    v28 = GetLastError();
//    v29 = _iob_func();
//    fwprintf(v29 + 2, L"An error occurred in the program. \n");
//    v30 = _iob_func();
//    fwprintf(v30 + 2, L"%s\n", L"Error opening source plaintext file!\n");
//    v31 = _iob_func();
//    fwprintf(v31 + 2, L"Error number %x.\n", v28);
//LABEL_7:
//    CloseHandle(hObject);
//LABEL_8:
//    if (v4)
//        CloseHandle(v4);
//    if (Memory)
//        free(Memory);
//    if (hHash)
//    {
//        if (!CryptDestroyHash(hHash))
//        {
//            v6 = GetLastError();
//            sub_1061630((int)L"Error during CryptDestroyHash.\n", v6);
//        }
//        hHash = 0;
//    }
//    if (hKey && !CryptDestroyKey(hKey))
//    {
//        v7 = GetLastError();
//        sub_1061630((int)L"Error during CryptDestroyKey!\n", v7);
//    }
//    if (phProv && !CryptReleaseContext(phProv, 0))
//    {
//        v8 = GetLastError();
//        sub_1061630((int)L"Error during CryptReleaseContext!\n", v8);
//    }
//    return v32;
//}