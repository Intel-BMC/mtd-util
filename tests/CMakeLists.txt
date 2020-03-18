#
# MIT License
#
# Copyright (c) 2017 Intel Corporation
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in
# all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
# THE SOFTWARE.
#

project(intel-fw-update-tests CXX)

set(CMAKE_CXX_STANDARD 14)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

###############
# CMake options
cmake_minimum_required(VERSION 2.8)

###############
# C++ options
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wall -std=c++14")
include_directories(${CMAKE_CURRENT_SOURCE_DIR})
include_directories(${CMAKE_CURRENT_SOURCE_DIR}/sysroot/include)

###############
# import Boost
find_package(Boost REQUIRED COMPONENTS iostreams)
add_definitions(-DBOOST_ERROR_CODE_HEADER_ONLY)
add_definitions(-DBOOST_SYSTEM_NO_DEPRECATED)
add_definitions(-DBOOST_ALL_NO_LIB)
find_package(Boost REQUIRED)
include_directories(${Boost_INCLUDE_DIRS})
link_directories(${Boost_LIBRARY_DIRS})

###############
# import OpenSSL (crypto)
find_package(PkgConfig REQUIRED)
pkg_check_modules(Crypto crypto)
include_directories(${Crypto_INCLUDE_DIRS})
link_directories(${Crypto_LIBRARY_DIRS})

##############
# import GTest
find_package(GTest REQUIRED)
include_directories(${GTEST_INCLUDE_DIRS})

##############
# Tests
enable_testing()

# mtd-tests
add_executable(mtd-tests "mtd-tests.cpp" "../debug.cpp" "../mtd.cpp" "../pfr.cpp")
target_link_libraries(mtd-tests Boost::iostreams)
target_link_libraries(mtd-tests ${GTEST_BOTH_LIBRARIES} gmock)
target_link_libraries(mtd-tests pthread)
add_test(mtd-tests mtd-tests "--gtest_output=xml:${test_name}.xml")

# mtd-util-tests
add_executable(mtd-util-tests "mtd-util-tests.cpp" "../debug.cpp" "../mtd.cpp" "../pfr.cpp")
target_link_libraries(mtd-util-tests Boost::iostreams)
target_link_libraries(mtd-util-tests ${GTEST_BOTH_LIBRARIES} gmock)
target_link_libraries(mtd-util-tests pthread)
add_test(mtd-util-tests mtd-util-tests "--gtest_output=xml:${test_name}.xml")

