cmake_minimum_required(VERSION 3.14.0)

option(SJEJHHUTIL_BUILD_AS_DLL "build the library as DLL" ON)

if(SJEJHHUTIL_BUILD_AS_DLL)
  set(SJEJHH_LIB_TYPE SHARED)
else()
  set(SJEJHH_LIB_TYPE STATIC)
endif()

set(SJEJHH_INCLUDES
  include/SjeJhhUtil.h 
)
set(SJEJHH_SRC
  src/stdafx.h 
  src/stdafx.cpp 
  src/targetver.h 
  src/CryptUtil.h
  src/CryptUtil.cpp 
  src/Utils.h 
  src/Utils.cpp 
  src/SjejhhUtil.cpp 
)

set(SJEJHH_RESOURCE_FILES
  resource/resource.h 
  resource/SjeJhhUtil.rc 
)

add_library(SjeJhhUtil ${SJEJHH_LIB_TYPE}
  ${SJEJHH_INCLUDES}
  ${SJEJHH_SRC}
  ${SJEJHH_RESOURCE_FILES}
)

target_include_directories(SjeJhhUtil
  PRIVATE
  "${CMAKE_CURRENT_SOURCE_DIR}/include"
  "${CMAKE_CURRENT_SOURCE_DIR}/src"
  "${CMAKE_CURRENT_SOURCE_DIR}/resource"
)

target_compile_definitions(SjeJhhUtil
  PUBLIC
    $<$<BOOL:${SJEJHHUTIL_BUILD_AS_DLL}>:SJEJHHUTIL_BUILD_DLL>
  PRIVATE 
    UNICODE
    _UNICODE
    SJEJHHUTIL_EXPORTS
    _WINDOWS
)