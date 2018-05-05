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

    }
}