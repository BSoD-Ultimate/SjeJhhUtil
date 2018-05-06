// SjeJhhUtil.cpp : Defines the exported functions for the DLL application.
//

#include "stdafx.h"
#include "SjeJhhUtil.h"

#include "CryptUtil.h"

#include <sstream>

using namespace SjeJhhUtil;

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

static int DoEncryptMemoryStream(const char* data, size_t inputLength, char* out, size_t outLength, const char* keyData, uint32_t keyLength, bool bEndOfData = true)
{
    std::unique_ptr<char[]> keyBuf(new char[keyLength]());
    memcpy_s(keyBuf.get(), keyLength, keyData, keyLength);
    uint32_t keyBufLen = keyLength;

    CCryptContext cryptContext;

    std::unique_ptr<CCryptKey> keyHandle = GenerateCryptKeyFromHash(cryptContext, keyBuf.get(), keyBufLen);

    size_t encryptedDataLen = inputLength;

    // calculate encrypted data length
    if (!CryptEncrypt(keyHandle->get(), 0, bEndOfData ? TRUE : FALSE, 0, 0, (DWORD*)&encryptedDataLen, 0))
    {
        int error = GetLastError();
        return -1;
    }

    if (encryptedDataLen > outLength || outLength == 0)
    {
        return encryptedDataLen;
    }

    memcpy_s(out, outLength, data, inputLength);

    if (!CryptEncrypt(keyHandle->get(), 0, bEndOfData ? TRUE : FALSE, 0, (BYTE*)out, (DWORD*)&encryptedDataLen, outLength))
    {
        int error = GetLastError();
        return -1;
    }

    return 0;
}

// RC4 algorithm, encrypt = decrypt
static int DoDecryptMemoryStream(const char* data, size_t inputLength, char* out, size_t outLength, const char* keyData, uint32_t keyLength, bool bEndOfData = true)
{
    return DoEncryptMemoryStream(data, inputLength, out, outLength, keyData, keyLength, bEndOfData);
}

SJEJHHUTIL_API int sjejhh_encrypt_data(const char* data, size_t inputLength, char* out, size_t outLength, const char* keyData, uint32_t keyLength)
{
    assert(keyData && (keyLength > 0));

    if (!keyData && (keyLength > 0))
    {
        return -1;
    }

    return DoEncryptMemoryStream(data, inputLength, out, outLength, keyData, keyLength);
}

SJEJHHUTIL_API int sjejhh_encrypt_file(const wchar_t* input_filePath, const wchar_t* output_filePath, const char* keyData, uint32_t keyLength)
{
    try
    {
        util::FileHandle inputFileHandle(input_filePath, L"rb");
        util::FileHandle outputFileHandle(output_filePath, L"wb");

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

        // not consider the circumstance that uses the key generated from user environment to encrypt the file now :(
        // write key generated from user environment to file as header
        //if (!keyAssignedFromArg)
        //{
        //    bool writeKeyLenSuccess = fwrite(&keyBufLen, 1, sizeof(keyBufLen), outputFileHandle.Get()) == sizeof(keyBufLen);
        //    bool writeKeySuccess = fwrite(keyBuf.get(), 1, keyBufLen, outputFileHandle.Get()) == keyBufLen;
        //    if (!(writeKeyLenSuccess && writeKeySuccess))
        //    {
        //        throw std::runtime_error("Write file header failed!");
        //    }
        //}

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

SJEJHHUTIL_API int sjejhh_decrypt_data(const char* data, size_t inputLength, char* out, size_t outLength, const char* keyData, uint32_t keyLength)
{
    return sjejhh_encrypt_data(data, inputLength, out, outLength, keyData, keyLength);
}

SJEJHHUTIL_API int sjejhh_decrypt_file(const wchar_t* input_filePath, const wchar_t* output_filePath, const char* keyData, uint32_t keyLength)
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
}

/* *********************************************************************************
 * "SJE.JHH" file packing / unpacking
 * 
 * *********************************************************************************
*/

static const std::string indexCryptKey = "1111";
static const std::string encryptedFileCryptKey = "TOJ";

static bool IsStringStartsWith(const std::string& src, const std::string& match)
{
    return src.substr(0, match.length()) == match;
}

static bool IsStringEndsWith(const std::string& src, const std::string& match)
{
    std::string sub = src.substr(src.length() - match.length(), match.length());
    return sub == match;
}

static bool IsFileNeedToBeEncrypted(const std::string& folderIdentifier, const std::string& filename)
{
    if (IsStringStartsWith(folderIdentifier, "config") ||
        (IsStringEndsWith(filename, ".lua") && IsStringStartsWith(folderIdentifier, "ai")))
    {
        return true;
    }
    if (IsStringEndsWith(filename, ".uis"))
    {
        return IsStringStartsWith(folderIdentifier, "ui");
    }
    return false;
}

struct StringBlobHeader
{
    uint32_t stringDataLength; // string data length, including '\0'
};
struct StringBlob
{
    StringBlobHeader header;
    char stringData[1];
};

struct FileInfoBlob
{
    uint32_t filedataOffset;
    uint32_t filedataLength;
};

/* *********************************************************************************
 * Unpack SJE.JHH files
 * 
 * *********************************************************************************
*/

struct SJEJHHFileInfo
{
    std::string filename;
    size_t fileOffset;
    size_t fileLength;
    bool isEncrypted;

    SJEJHHFileInfo()
        : fileOffset(0)
        , fileLength(0)
        , isEncrypted(false)
    {
    }
};

// index data
struct SJEJHHIndexData
{
    std::string internalFolderIdentifier;
    std::vector<std::shared_ptr<SJEJHHFileInfo>> fileIndexes;
};

struct sjejhh_unpack_context
{
    filesystem::path filename;
    util::FileHandle fileHandle;

    size_t fileSize;

    SJEJHHIndexData fileIndexData;

    size_t currentIndex;

    sjejhh_unpack_context(const wchar_t* filePath)
        : filename(filePath)
        , fileHandle(filePath, L"rb")
        , fileSize(filesystem::file_size(filePath))
        , currentIndex(0)
    {
        ParseSJEJHHFileIndexInfo();
        SeekToBegin();
    }


public:
    int GetGlobalInfo(sjejhh_unpack_global_info* pGlobalInfo);
    int GetCurrentFileInfo(sjejhh_unpack_current_file_info* pCurrentFileInfo);
    int ReadCurrentFileData(char* readBuf, size_t bufLength, size_t* bytesRead, size_t* bytesRemaining);

    int SeekToBegin();
    int ResetFilePointer();
    int GotoNextFile();

    void ResetCryptContext();
    int DecryptEncryptedData(const char* inBuf, size_t inBufLength, char* out, size_t outBufLen);

private:
    void ParseSJEJHHFileIndexInfo();


private:
    CCryptContext m_cryptContext;

    std::unique_ptr<CCryptKey> m_pIndexCryptKey;
    std::unique_ptr<CCryptKey> m_pEncryptedFileKey;
};


int sjejhh_unpack_context::GetGlobalInfo(sjejhh_unpack_global_info* pGlobalInfo)
{
    pGlobalInfo->archiveFilePath = filename.c_str();
    pGlobalInfo->archiveFilePathLength = filename.string().length();

    pGlobalInfo->internalFolderName = fileIndexData.internalFolderIdentifier.c_str();
    pGlobalInfo->internalFolderNameLength = fileIndexData.internalFolderIdentifier.length();

    pGlobalInfo->archiveFileSize = fileSize;
    pGlobalInfo->fileCount = fileIndexData.fileIndexes.size();
    pGlobalInfo->currentFileIndex = currentIndex;

    return 0;
}

int sjejhh_unpack_context::GetCurrentFileInfo(sjejhh_unpack_current_file_info* pCurrentFileInfo)
{
    if (currentIndex < fileIndexData.fileIndexes.size())
    {
        pCurrentFileInfo->currentIndex = currentIndex;

        auto currentIndexData = fileIndexData.fileIndexes[currentIndex];

        pCurrentFileInfo->filename = currentIndexData->filename.c_str();
        pCurrentFileInfo->filenameLength = currentIndexData->filename.length();

        pCurrentFileInfo->fileOffset = currentIndexData->fileOffset;
        pCurrentFileInfo->fileLength = currentIndexData->fileLength;
        pCurrentFileInfo->isEncrypted = currentIndexData->isEncrypted; 

        return 0;
    }
    else
    {
        pCurrentFileInfo->currentIndex = currentIndex;
        pCurrentFileInfo->filename = NULL;
        pCurrentFileInfo->filenameLength = 0;

        pCurrentFileInfo->fileOffset = 0;
        pCurrentFileInfo->fileLength = 0;
        pCurrentFileInfo->isEncrypted = false;

        return SJEJHH_UNPACK_END_OF_LIST_OF_FILE;
    }
}

int sjejhh_unpack_context::ReadCurrentFileData(char* readBuf, size_t bufLength, size_t* bytesRead, size_t* bytesRemaining)
{
    if (currentIndex < fileIndexData.fileIndexes.size())
    {
        auto currentIndexData = fileIndexData.fileIndexes[currentIndex];

        assert(currentIndexData);
        if (!currentIndexData)
        {
            return SJEJHH_UNPACK_INTERNALERROR;
        }

        // calcuate how many bytes are available for read
        uint32_t fileEndOffset = currentIndexData->fileOffset + currentIndexData->fileLength;
        uint32_t curOffset = ftell(fileHandle.Get());

        int32_t bytesRemain = fileEndOffset - curOffset;

        bool isEnd = bufLength >= bytesRemain;

        size_t bytesToRead = isEnd ? bytesRemain : bufLength;

        if (bytesToRead == 0)
        {
            return SJEJHH_UNPACK_EOF;
        }

        std::unique_ptr<char[]> tempBuf(new char[bytesToRead]);

        if (!(fread(tempBuf.get(), 1, bytesToRead, fileHandle.Get()) == bytesToRead))
        {
            return SJEJHH_UNPACK_ERRNO;
        }

        bytesRemain -= bytesToRead;

        memcpy_s(readBuf, bufLength, tempBuf.get(), bytesToRead);
        *bytesRead = bytesToRead;
        *bytesRemaining = bytesRemain;
        return 0;
    }
    else
    {
        return SJEJHH_UNPACK_END_OF_LIST_OF_FILE;
    }
}

int sjejhh_unpack_context::SeekToBegin()
{
    int oldIndex = currentIndex;
    currentIndex = 0;

    if (currentIndex < fileIndexData.fileIndexes.size())
    {
        auto currentIndexData = fileIndexData.fileIndexes[0];
        assert(currentIndexData);
        if (!currentIndexData)
        {
            int currentIndex = oldIndex;
            return SJEJHH_UNPACK_INTERNALERROR;
        }

        ResetCryptContext();
        fseek(fileHandle.Get(), currentIndexData->fileOffset, SEEK_SET);
        return 0;
    }
    else
    {
        // no files in a "SJE.JHH" archive
        return SJEJHH_UNPACK_END_OF_LIST_OF_FILE;
    }

}

int sjejhh_unpack_context::ResetFilePointer()
{
    if (currentIndex < fileIndexData.fileIndexes.size())
    {
        ResetCryptContext();
        fseek(fileHandle.Get(), fileIndexData.fileIndexes[currentIndex]->fileOffset, SEEK_SET);
        return 0;
    }
    else
    {
        // the end of the cursor, resetting the file pointer has no significance when the cursor
        // reaches the end of the index (the cursor does not point to any file indexes).
        return SJEJHH_UNPACK_END_OF_LIST_OF_FILE;
    }

}

int sjejhh_unpack_context::GotoNextFile()
{
    int oldIndex = currentIndex;

    if (currentIndex + 1 < fileIndexData.fileIndexes.size())
    {
        currentIndex++;
        auto currentIndexData = fileIndexData.fileIndexes[currentIndex];
        assert(currentIndexData);
        if (!currentIndexData)
        {
            currentIndex = oldIndex;
            return SJEJHH_UNPACK_INTERNALERROR;
        }

        ResetCryptContext();
        fseek(fileHandle.Get(), currentIndexData->fileOffset, SEEK_SET);
        return 0;
    }
    else if (currentIndex == fileIndexData.fileIndexes.size() - 1)
    {
        // go to the end cursor
        currentIndex++;
        return 0;
    }
    else
    {
        // the end cursor
        return SJEJHH_UNPACK_END_OF_LIST_OF_FILE;
    }
}

void sjejhh_unpack_context::ResetCryptContext()
{
    m_pIndexCryptKey = GenerateCryptKeyFromHash(m_cryptContext, indexCryptKey.c_str(), indexCryptKey.length());
    m_pEncryptedFileKey = GenerateCryptKeyFromHash(m_cryptContext, encryptedFileCryptKey.c_str(), encryptedFileCryptKey.length());
}

int sjejhh_unpack_context::DecryptEncryptedData(const char* inBuf, size_t inBufLength, char* out, size_t outBufLen)
{
    size_t encryptedDataLen = inBufLength;

    // Tetris Online Poland client has mistakenly used the cryptography API here :(
    // Typically according to MSDN documentation, the parameter "Final" should be set "TRUE"
    // when encrypting the last chunk of data.

    // We have to follow the error here to get the same result. :( 
    // Then the encryption key must be destroyed and re-created manually to reset context 
    // which the key contains. :( See the method "ResetCryptContext" for detail.

    // calculate encrypted data length
    if (!CryptEncrypt(m_pEncryptedFileKey->get(), 0, FALSE, 0, 0, (DWORD*)&encryptedDataLen, 0))
    {
        int error = GetLastError();
        return -1;
    }

    if (encryptedDataLen > outBufLen || outBufLen == 0)
    {
        return encryptedDataLen;
    }

    memcpy_s(out, outBufLen, inBuf, inBufLength);

    if (!CryptEncrypt(m_pEncryptedFileKey->get(), 0, FALSE, 0, (BYTE*)out, (DWORD*)&encryptedDataLen, outBufLen))
    {
        int error = GetLastError();
        return -1;
    }

    return 0;
}

void sjejhh_unpack_context::ParseSJEJHHFileIndexInfo()
{
    int32_t indexFileOffset = 0;
    int32_t indexFileLength = 0;
    if (!(fread(&indexFileOffset, 1, sizeof(indexFileOffset), fileHandle.Get()) == sizeof(indexFileOffset) && 
        fread(&indexFileLength, 1, sizeof(indexFileLength), fileHandle.Get()) == sizeof(indexFileLength)))
    {
        throw std::runtime_error("Unable to read index file offset in the archive file!");
    }

    std::unique_ptr<char[]> indexData(new char[indexFileLength]);
    fseek(fileHandle.Get(), indexFileOffset, SEEK_SET);
    if (!(fread(indexData.get(), 1, indexFileLength, fileHandle.Get()) == indexFileLength))
    {
        throw std::runtime_error("Unable to read index data!");
    }

    // decrypt the index data
    std::unique_ptr<char[]> decryptedIndexData;

    int decryptLength = sjejhh_decrypt_data(indexData.get(), indexFileLength, NULL, 0, indexCryptKey.c_str(), indexCryptKey.length());
    decryptedIndexData.reset(new char[decryptLength]);
    sjejhh_decrypt_data(indexData.get(), indexFileLength, decryptedIndexData.get(), decryptLength, indexCryptKey.c_str(), indexCryptKey.length());

    /*
     * read the index data
    */
    char* indexDataReader = decryptedIndexData.get();

    uint32_t fileCount = *(uint32_t*)(indexDataReader);
    indexDataReader += sizeof(uint32_t);

    // internal folder identifier
    StringBlob* internalFolderName = (StringBlob*)indexDataReader;
    this->fileIndexData.internalFolderIdentifier.assign(internalFolderName->stringData, internalFolderName->header.stringDataLength - 1);
    indexDataReader += sizeof(StringBlobHeader) + internalFolderName->header.stringDataLength;

    // parse file name/offset/length
    for (size_t i = 0; i < fileCount; i++)
    {
        std::shared_ptr<SJEJHHFileInfo> pFileInfo = std::make_shared<SJEJHHFileInfo>();

        // file name
        StringBlob* filenameData = (StringBlob*)indexDataReader;
        pFileInfo->filename.assign(filenameData->stringData, filenameData->header.stringDataLength - 1);
        indexDataReader += sizeof(StringBlobHeader) + filenameData->header.stringDataLength;

        // file offset 
        uint32_t fileOffset = *(uint32_t*)(indexDataReader);
        indexDataReader += sizeof(uint32_t);
        pFileInfo->fileOffset = fileOffset;

        // file length
        uint32_t fileLength = *(uint32_t*)(indexDataReader);
        indexDataReader += sizeof(uint32_t);
        pFileInfo->fileLength = fileLength;

        // encrypted?
        pFileInfo->isEncrypted = IsFileNeedToBeEncrypted(fileIndexData.internalFolderIdentifier, pFileInfo->filename);

        this->fileIndexData.fileIndexes.emplace_back(pFileInfo);
    }
}

SJEJHHUTIL_API sjejhh_unpack_context* sjejhh_unpack_open(const wchar_t * filePath)
{
    try
    {
        std::unique_ptr<sjejhh_unpack_context> pFile(new sjejhh_unpack_context(filePath));
        return pFile.release();
    }
    catch (const std::runtime_error& e)
    {
        return nullptr;
    }
}

SJEJHHUTIL_API int sjejhh_unpack_get_global_info(sjejhh_unpack_context* pArchive, sjejhh_unpack_global_info* pGlobalInfo)
{
    return pArchive->GetGlobalInfo(pGlobalInfo);
}

SJEJHHUTIL_API int sjejhh_unpack_get_current_file_info(sjejhh_unpack_context* pArchive, sjejhh_unpack_current_file_info* pCurrentFileInfo)
{
    return pArchive->GetCurrentFileInfo(pCurrentFileInfo);
}

SJEJHHUTIL_API int sjejhh_unpack_read_current_file(sjejhh_unpack_context* pArchive, char* readBuf, size_t bufLength, size_t* bytesRead, size_t* bytesRemaining)
{
    return pArchive->ReadCurrentFileData(readBuf, bufLength, bytesRead, bytesRemaining);
}

SJEJHHUTIL_API int sjejhh_unpack_decrypt_read_data(sjejhh_unpack_context* pArchive, const char* inData, size_t inLength, char* outBuf, size_t outLength)
{
    return pArchive->DecryptEncryptedData(inData, inLength, outBuf, outLength);
}

SJEJHHUTIL_API void sjejhh_unpack_reset_decrypt_context(sjejhh_unpack_context * pArchive)
{
    pArchive->ResetCryptContext();
}

SJEJHHUTIL_API int sjejhh_unpack_seek_to_begin(sjejhh_unpack_context* pArchive)
{
    return pArchive->SeekToBegin();
}

SJEJHHUTIL_API int sjejhh_unpack_reset_file_pointer(sjejhh_unpack_context* pArchive)
{
    return pArchive->ResetFilePointer();
}

SJEJHHUTIL_API int sjejhh_unpack_goto_next_file(sjejhh_unpack_context* pArchive)
{
    return pArchive->GotoNextFile();
}

SJEJHHUTIL_API int sjejhh_unpack_close(sjejhh_unpack_context* pArchive)
{
    delete pArchive;
    return 0;
}


