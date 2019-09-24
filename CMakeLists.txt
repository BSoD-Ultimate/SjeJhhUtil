cmake_minimum_required(VERSION 3.14.0)

project(SjeJhhUtil)

add_subdirectory(SjeJhhUtil)
add_subdirectory(SjeJhhUtilTest)

set(INSTALL_FILE_LIST
  "$<TARGET_FILE:SjeJhhUtilTest>"
)

file(GLOB INSTALL_TESTDATA_LIST 
  "${CMAKE_CURRENT_SOURCE_DIR}/SjeJhhUtilTest/testdata/*"
)

get_target_property(target_type SjeJhhUtil TYPE)
if(NOT target_type STREQUAL "STATIC_LIBRARY")
  list(APPEND INSTALL_FILE_LIST "$<TARGET_FILE:SjeJhhUtil>")
endif()

# install executable
install(
  FILES
    ${INSTALL_FILE_LIST}
  DESTINATION 
    "${CMAKE_INSTALL_PREFIX}"
  COMPONENT publish
)

# install test files
install(
  FILES
    ${INSTALL_TESTDATA_LIST}
  DESTINATION 
    "${CMAKE_INSTALL_PREFIX}/testdata"
  COMPONENT publish
)

