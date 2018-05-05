﻿// SjeJhhUtil.cpp : Defines the exported functions for the DLL application.
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

static std::unique_ptr<CCryptKey> GenerateCryptKeyFromHash(CCryptContext& context, const char* keyData, uint32_t keyLength)
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

static std::unique_ptr<CCryptKey> GenerateCryptKeyFromEnvironment(CCryptContext& context, std::unique_ptr<char[]>& keyData, uint32_t& keyLen)
{
    std::unique_ptr<CCryptKey> randomKey(new CCryptKey());
    if (!CryptGenKey(context.Get(), CALG_RC4, CRYPT_CREATE_SALT | CRYPT_EXPORTABLE, &(*randomKey)))
    {
        int error = GetLastError();
        return nullptr;
    }
    CCryptKey userKey;
    if (!CryptGetUserKey(context.Get(), AT_KEYEXCHANGE, &userKey))
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

static std::unique_ptr<CCryptKey> GenerateCryptKeyFromImportedData(CCryptContext& context, char* keyData, uint32_t keyLen)
{
    CCryptKey userKey;
    if (!CryptGetUserKey(context.Get(), AT_KEYEXCHANGE, &userKey))
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

    std::unique_ptr<CCryptKey> importedKey(new CCryptKey());

    std::unique_ptr<char[]> importedKeyDataBuf(new char[keyLen]());

    char* keyDataField = importedKeyDataBuf.get();
    memcpy_s(keyDataField, keyLen, keyData, keyLen);

    if (!CryptImportKey(context.Get(), (BYTE*)importedKeyDataBuf.get(), keyLen, userKey.get(), CRYPT_EXPORTABLE, &(*importedKey)))
    {
        DWORD error = GetLastError();
        return nullptr;
    }


    return importedKey;
}

int SJEJHHUTIL_API sjejhh_encrypt_stream(const char* data, size_t inputLength, char* out, size_t outLength, const char* keyData, uint32_t keyLength)
{
    assert(keyData && (keyLength > 0));

    if (!keyData && (keyLength > 0))
    {
        return -1;
    }

    std::unique_ptr<char[]> keyBuf(new char[keyLength]());
    memcpy_s(keyBuf.get(), keyLength, keyData, keyLength);
    uint32_t keyBufLen = keyLength;

    CCryptContext cryptContext;

    std::unique_ptr<CCryptKey> keyHandle = GenerateCryptKeyFromHash(cryptContext, keyBuf.get(), keyBufLen);

    size_t encryptedDataLen = inputLength;

    // calculate encrypted data length
    if (!CryptEncrypt(keyHandle->get(), 0, TRUE, 0, 0, (DWORD*)&encryptedDataLen, 0))
    {
        int error = GetLastError();
        return -1;
    }

    if (encryptedDataLen > outLength || outLength == 0)
    {
        return encryptedDataLen;
    }

    memcpy_s(out, outLength, data, inputLength);

    if (!CryptEncrypt(keyHandle->get(), 0, TRUE, 0, (BYTE*)out, (DWORD*)&encryptedDataLen, outLength))
    {
        int error = GetLastError();
        return -1;
    }

    return 0;
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
            keyHandle = GenerateCryptKeyFromHash(cryptContext, keyBuf.get(), keyBufLen);
        }
        else
        {
            assert(false);
            return 0;
            //keyHandle = GenerateCryptKeyFromEnvironment(cryptContext, keyBuf, keyBufLen);
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
        std::unique_ptr<char[]> plainDataBuf(new char[encryptBufLen]());

        // encrypt the file
        bool encryptComplete = false;
        size_t bytesRead = 0;
        while (true)
        {
            bytesRead = fread(plainDataBuf.get(), 1, encryptChunkLen, inputFileHandle.Get());

            if (bytesRead < encryptChunkLen)
                encryptComplete = true;

            if (!CryptEncrypt(keyHandle->get(), 0, encryptComplete, 0, (BYTE*)plainDataBuf.get(), (DWORD*)&bytesRead, encryptBufLen))
            {
                int error = GetLastError();
                throw std::runtime_error(util::generate_errorMsg("Error during CryptEncrypt!", error));
            }


            size_t bytesWrite = fwrite(plainDataBuf.get(), 1, bytesRead, outputFileHandle.Get());
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
    return sjejhh_encrypt_stream(data, inputLength, out, outLength, keyData, keyLength);
}

int SJEJHHUTIL_API sjejhh_decrypt_file(const wchar_t* input_filePath, const wchar_t* output_filePath, const char* keyData, uint32_t keyLength)
{
    bool keyAssignedFromArg = keyData && (keyLength > 0);
    if (keyAssignedFromArg)
    {
        return sjejhh_encrypt_file(input_filePath, output_filePath, keyData, keyLength);
    }
    else
    {
        assert(false);
        return 0;
    }

    // not consider the circumstance that uses the key generated from user environment to encrypt the file now :(

    // key is not specified
    // regard file is encrypted by the key generated from user environment, read the key from userdata
    //try
    //{
    //    FileHandle inputFileHandle(input_filePath, L"rb");
    //    FileHandle outputFileHandle(output_filePath, L"wb");

    //    CCryptContext cryptContext;

    //    std::unique_ptr<CCryptKey> keyHandle;

    //    std::unique_ptr<char[]> keyBuf;
    //    uint32_t keyBufLen = 0;

    //    // read key from file
    //    if (fread(&keyBufLen, 1, sizeof(keyBufLen), inputFileHandle.Get()) < sizeof(keyBufLen))
    //    {
    //        // read key length failed
    //        return 0;
    //    }
    //    keyBuf.reset(new char[keyBufLen]());
    //    if (fread(keyBuf.get(), 1, keyBufLen, inputFileHandle.Get()) < keyBufLen)
    //    {
    //        // read key failed
    //        return 0;
    //    }

    //    keyHandle = GenerateCryptKeyFromImportedData(cryptContext, keyBuf.get(), keyBufLen);

    //    if (!keyHandle)
    //    {
    //        throw std::runtime_error("Error while creating the key handle!");
    //    }

    //    static const int encryptChunkLen = 1000;
    //    static const int encryptBufLen = encryptChunkLen + 8;
    //    std::unique_ptr<char[]> plainDataBuf(new char[encryptBufLen]());

    //    // encrypt the file
    //    bool encryptComplete = false;
    //    size_t bytesRead = 0;
    //    while (true)
    //    {
    //        bytesRead = fread(plainDataBuf.get(), 1, encryptChunkLen, inputFileHandle.Get());

    //        if (bytesRead < encryptChunkLen)
    //            encryptComplete = true;

    //        if (!CryptDecrypt(keyHandle->get(), 0, encryptComplete, 0, (BYTE*)plainDataBuf.get(), (DWORD*)&bytesRead))
    //        {
    //            int error = GetLastError();
    //            throw std::runtime_error(util::generate_errorMsg("Error during CryptDecrypt!", error));
    //        }


    //        size_t bytesWrite = fwrite(plainDataBuf.get(), 1, bytesRead, outputFileHandle.Get());
    //        if (bytesWrite < bytesRead)
    //        {
    //            int error = errno;
    //            throw std::runtime_error(util::generate_errorMsg("Error writing cipherText!", error));
    //        }

    //        if (encryptComplete)
    //        {
    //            break;
    //        }
    //    }

    //    return 1;
    //}
    //catch (const std::exception& e)
    //{
    //    return 0;
    //}

    //return 0;
}

