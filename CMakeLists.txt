cmake_minimum_required(VERSION 3.5)
project(bus_auth)

set(CMAKE_CXX_STANDARD 11)

add_definitions(-D_CONSOLE)
# add_definitions(-DKLINE_CMAC)

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
  *.h
  *.hpp
)


# file(GLOB MBEDTLS_SRC
#   mbedtls/library/*.c
# )

file(GLOB MBEDTLS_SRC
  mbedtls/library/ccm.c
  mbedtls/library/cipher.c
  mbedtls/library/cipher_wrap.c
  mbedtls/library/aes.c
  mbedtls/library/platform_util.c
  mbedtls/library/cmac.c
)

set(APP_SOURCE_FILES
  ${LOCAL_SRC}
  ${MBEDTLS_SRC}
)

include_directories(
  ./
  config
  mbedtls/include
  mbedtls/include/mbedtls
)

add_executable(bus_auth ${APP_SOURCE_FILES})

