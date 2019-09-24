cmake_minimum_required(VERSION 3.14.0)

add_executable(SjeJhhUtilTest
  stdafx.h 
  stdafx.cpp 
  targetver.h 
  SjeJhhUtilTest.cpp 
)

target_include_directories(SjeJhhUtilTest
  PRIVATE
    "${CMAKE_CURRENT_SOURCE_DIR}/../SjeJhhUtil/include"
)

target_link_libraries(SjeJhhUtilTest
  SjeJhhUtil 
)