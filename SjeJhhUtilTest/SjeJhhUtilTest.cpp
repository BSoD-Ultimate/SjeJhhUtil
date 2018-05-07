// SjeJhhUtilTest.cpp : Defines the entry point for the console application.
//

#include "stdafx.h"

#include <cstring>
#include <string>
#include <memory>

#include "SjeJhhUtil.h"

#include <experimental/filesystem>

namespace filesystem = std::experimental::filesystem;

const char testData[] = 
"[SYSTEM]\r\n"
"CLIENT_VERSION = 3000 ;odd(QA) even(REAL)\r\n"
"SERVER_TYPE = 1 ;0:QA 1:REAL\r\n"
"\r\n"
"[UI]\r\n"
"DEFAULT_FONT_NAME = DEFAULT\r\n"
"CHAT_FONT_COLOR = 255 255 255 255\r\n"
"FONT_CHAT_INDEX = 2\r\n"
"NOTICE_FONT_COLOR = 0 255 0 255\r\n"
"DEFAULT_CURSOR_FILE_NAME = UI\\cursor.dds\r\n"
"COLORKEY = 255 0 255 255\r\n\r\n";



bool CreateDirectoryWithSubdir(const std::wstring& dir)
{
    wchar_t separator = filesystem::path::preferred_separator;

    std::wstring tempDir(dir);

    auto AddDirSeparator = [](std::wstring& dirString) -> std::wstring
    {
        if (dirString.empty())
            return L"";
        if (dirString[dirString.length() - 1] != filesystem::path::preferred_separator)
            dirString.push_back(filesystem::path::preferred_separator);
        return dirString;
    };
    AddDirSeparator(tempDir);

    std::vector<std::wstring> dirs;		
    std::wstring temp;	
    std::wstring baseDir = tempDir;
    for (int i = 0; i < baseDir.length(); i++) {
        if (baseDir[i] != separator) {
            temp += tempDir[i];
        }
        else
        {
            dirs.push_back(temp);
            temp += separator;
        }
    }

    for (std::vector<std::wstring>::const_iterator iter = dirs.begin(); iter != dirs.end(); ++iter)
    {
        if ((*iter).empty()) {
            continue;
        }
        if (!filesystem::exists(*iter))
        {
            try
            {
                filesystem::create_directory(*iter);
            }
            catch (const filesystem::filesystem_error& e)
            {
                e.code();
                return false;
            }
        }
    }

    return true;
}

static void testUnpackSJEJHHArchive(const wchar_t* filePath)
{
    filesystem::path archivePath = filePath;

    sjejhh_unpack_context* pArchive = sjejhh_unpack_open(filePath);

    // get global info
    sjejhh_unpack_global_info gi = { 0 };
    sjejhh_unpack_get_global_info(pArchive, &gi);

    filesystem::path extractDir = archivePath.parent_path();
    extractDir /= std::string(gi.internalFolderName, gi.internalFolderNameLength);

    CreateDirectoryWithSubdir(extractDir);

    for (size_t i = 0; i < gi.fileCount; i++)
    {
        sjejhh_unpack_file_info curFileInfo = { 0 };
        sjejhh_unpack_get_current_file_info(pArchive, &curFileInfo);

        filesystem::path extractFileName = extractDir;
        extractFileName /= std::string(curFileInfo.filename, curFileInfo.filenameLength);
        FILE* fp = _wfopen(extractFileName.c_str(), L"wb");

        const size_t bufSize = 1000;
        std::unique_ptr<char[]> readBuf(new char[bufSize]);
        size_t readBytes = 0;
        size_t bytesRemaining = 0;

        while (sjejhh_unpack_read_current_file(pArchive, readBuf.get(), bufSize, &readBytes, &bytesRemaining) != SJEJHH_UNPACK_EOF)
        {
            if (!curFileInfo.isEncrypted)
            {
                fwrite(readBuf.get(), 1, readBytes, fp);
            }
            else
            {
                bool isEnd = bytesRemaining == 0;

                int decryptLength = sjejhh_unpack_decrypt_read_data(pArchive, readBuf.get(), readBytes, NULL, 0);
                std::unique_ptr<char[]> decryptedData(new char[decryptLength]);
                sjejhh_unpack_decrypt_read_data(pArchive, readBuf.get(), readBytes, decryptedData.get(), decryptLength);
                fwrite(decryptedData.get(), 1, decryptLength, fp);
                fflush(fp);
            }
        }

        fclose(fp);

        sjejhh_unpack_goto_next_file(pArchive);

    }

    sjejhh_unpack_close(pArchive);
}

static void testPackSJEJHHArchive(const char* internalFolderName, const wchar_t* saveFilename)
{

}

int main(int argc, char** argv)
{
    // test encrypting & decrypting memory data
    int length = sjejhh_encrypt_data(testData, strlen(testData), NULL, 0, "TOJ", 3);
    std::unique_ptr<char[]> encryptedData(new char[length]);
    sjejhh_encrypt_data(testData, strlen(testData), encryptedData.get(), length, "TOJ", 3);

    int decryptLength = sjejhh_decrypt_data(encryptedData.get(), length, NULL, 0, "TOJ", 3);
    std::unique_ptr<char[]> decryptedData(new char[decryptLength]);
    sjejhh_decrypt_data(encryptedData.get(), length, decryptedData.get(), decryptLength, "TOJ", 3);

    // test encrypting & decrypting a file using the key passed from arguments
    sjejhh_encrypt_file(L"testdata/config.ini", L"testdata/config_encrypted.ini", "TOJ", 3);
    sjejhh_decrypt_file(L"testdata/config_encrypted.ini", L"testdata/config_encrypted_decrypted.ini", "TOJ", 3);

    // test unpacking "SJE.JHH" archives
    testUnpackSJEJHHArchive(L"testdata/SJE.JHH-config");
    testUnpackSJEJHHArchive(L"testdata/SJE.JHH-ui");
    testUnpackSJEJHHArchive(L"testdata/SJE.JHH-skin-multi-default");

    // test packing "SJE.JHH" archives
    return 0;
}

