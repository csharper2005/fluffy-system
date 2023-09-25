cmake_minimum_required(VERSION 3.5)

set(CMAKE_PROJECT_NAME "mktplinkfw3")
project(${CMAKE_PROJECT_NAME} VERSION 1.0.0 LANGUAGES C)
set(TARGET ${CMAKE_PROJECT_NAME})

FIND_PACKAGE(OpenSSL REQUIRED)

MESSAGE("OpenSSL include dir: ${OPENSSL_INCLUDE_DIR}")
MESSAGE("OpenSSL libraries: ${OPENSSL_LIBRARIES}")

INCLUDE_DIRECTORIES(${OPENSSL_INCLUDE_DIR})
LIST(APPEND LIB_LIST ${OPENSSL_LIBRARIES})

ADD_DEFINITIONS(
	-Wall
	-O3
	-Wpedantic
	-Wno-unused-result
	-Wno-pointer-sign
	-lcrypto
	-lssl
)

SET(SOURCES
	mktplinkfw3.c
)

add_executable(${TARGET} ${SOURCES})
target_link_libraries(${TARGET} ssl crypto)

install(TARGETS ${TARGET})
