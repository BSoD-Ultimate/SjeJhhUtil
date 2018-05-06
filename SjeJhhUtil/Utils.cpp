#include "stdafx.h"
#include "Utils.h"

#include <sstream>

namespace SjeJhhUtil
{
    namespace util
    {
        std::string generate_errorMsg(const char* msg, int errorCode)
        {
            std::ostringstream ss;
            ss << msg << " error=" << errorCode;
            return ss.str();
        }

        FileHandle::FileHandle(const std::wstring& filename, const std::wstring& mode)
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
        FileHandle::~FileHandle()
        {
            fclose(m_fileHandle);
        }

        FILE* FileHandle::Get() const
        {
            return m_fileHandle;
        }

    }
}