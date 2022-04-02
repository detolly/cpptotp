# The contents of this file have been placed into the public domain; see the
# file COPYING for more details.

cmake_minimum_required (VERSION 3.10)
project (CppOtp)

set (CMAKE_CXX_STANDARD 20)

# the static library
add_library(cppotp STATIC
	src/libcppotp/bytes.cpp
	src/libcppotp/otp.cpp
	src/libcppotp/sha1.cpp
)

set(CPPOTP_INCLUDE_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/src)
target_include_directories(cppotp PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/src)

# the binary
