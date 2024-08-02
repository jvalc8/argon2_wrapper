cmake_minimum_required(VERSION 3.10)
set (SOURCES src/argon2.c)
set (TARGET "argon2")
set (CMAKE_C_STANDARD 11)
set (CMAKE_C_STANDARD_REQUIRED True)
project(${TARGET} VERSION 1.0)

find_package(PkgConfig)
include(ExternalProject)

set(argon2_PREFIX_DIR ${CMAKE_CURRENT_BINARY_DIR})
set(argon2_SOURCE_DIR ${argon2_PREFIX_DIR}/src/Argon2)
set(argon2_BINARY_DIR ${argon2_PREFIX_DIR}/src/Argon2-build)

find_library(Argon2 NAMES argon2 argon2.so argon2.so.1 libargon2 libargon2.so libargon2.so.1)

if (NOT Argon2)
	if ("${CMAKE_HOST_SYSTEM_NAME}-${CMAKE_HOST_SYSTEM_PROCESSOR}" STREQUAL "Linux-x86_64")
		set (CMAKE_LIBRARY_PATH "${argon2_BINARY_DIR}/usr/lib/${CMAKE_LIBRARY_ARCHITECTURE}")
	else()
		set (CMAKE_LIBRARY_PATH ${argon2_BINARY_DIR}/usr/lib)
	endif()

	ExternalProject_Add(
			Argon2
			GIT_REPOSITORY 	https://github.com/P-H-C/phc-winner-argon2.git
			GIT_TAG        	master
			PREFIX 		${argon2_PREFIX_DIR}
			SOURCE_DIR 	${argon2_SOURCE_DIR}
			CONFIGURE_COMMAND ""
			UPDATE_COMMAND 	""
            BUILD_COMMAND 	${CMAKE_MAKE_PROGRAM} -C ${argon2_SOURCE_DIR}
            INSTALL_COMMAND ${CMAKE_MAKE_PROGRAM} -C ${argon2_SOURCE_DIR} DESTDIR=${argon2_BINARY_DIR} install
	)
endif()
	

add_executable(${TARGET} ${SOURCES})
target_link_directories(${TARGET} PUBLIC ${CMAKE_LIBRARY_PATH})
target_include_directories(
    ${TARGET} 
    PRIVATE
    ${argon2_BINARY_DIR}/usr/include
    ${PROJECT_SOURCE_DIR}/include
)

if (NOT Argon2)
	target_link_libraries(${TARGET} -largon2)
else()
	target_link_libraries(${TARGET} ${Argon2})
endif()
