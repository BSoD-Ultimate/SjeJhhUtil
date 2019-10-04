#pragma once

#if _MSC_VER < 1920
#include <experimental/filesystem>
namespace filesystem = std::experimental::filesystem;
#else
#include <filesystem>
namespace filesystem = std::filesystem;
#endif // _MSC_VER < 1920


namespace SjeJhhUtil
{
    namespace util
    {
        std::string generate_errorMsg(const char * msg, int errorCode);

        class FileHandle
        {
        public:
            FileHandle(const std::wstring& filename, const std::wstring& mode);
            ~FileHandle();

            FILE* Get() const;

            FileHandle(const FileHandle&) = delete;
            FileHandle& operator=(const FileHandle&) = delete;
        private:
            filesystem::path m_filePath;
            std::wstring m_openMode;
            FILE* m_fileHandle;
        };
    }
}
