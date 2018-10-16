cmake_minimum_required(VERSION 3.5)
project(kline_ccm)

set(CMAKE_CXX_STANDARD 11)

add_definitions(-D_CONSOLE)

if (WIN32)
    add_definitions(-DWIN32)
else ()
	add_definitions(-g)
endif ()
if (APPLE)
endif (APPLE)

file(GLOB LOCAL_SRC
  *.c
  *.cpp
)

file(GLOB MBEDTLS_SRC
  mbedtls/library/ccm.c
)

set(APP_SOURCE_FILES
  ${LOCAL_SRC}
  ${MBEDTLS_SRC}
)

include_directories(
  ./
  ${EXTERN_LIBS}/mbedtls/include
  ${EXTERN_LIBS}/mbedtls/include/mbedtls
)

add_executable(kline_ccm ${APP_SOURCE_FILES})

