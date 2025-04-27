#=======================================
#SEAL SQ 2024
#Zero Touch Provisioning Demo with INeS
#IoT / Tools / Provisioning / Firmware Team
#=======================================

#SPDX-License-Identifier: Apache-2.0*/

# Nous voulons un cmake "récent" pour utiliser les dernières fonctionnalités
cmake_minimum_required(VERSION 3.6)

#Project name
project(softwareSigning_demo VERSION 1.0.0)
add_subdirectory(lib/Seal_SQ_Ines_SDK)

#VAULTIC LIB

if(${COMPILATION_MODE} STREQUAL "DEBUG")
    add_compile_definitions(INES_SDK_DEBUG)
else()
    remove_definitions(INES_SDK_DEBUG)
endif()



include_directories(include)

#source files directory
set(SRCS 
    "src/main.c"
    )

add_executable(softwareSigning_demo ${SRCS} ${HEADERS})
target_link_libraries(softwareSigning_demo ines_SDK_lib wolfssl)
target_include_directories(softwareSigning_demo PUBLIC lib/Seal_SQ_Ines_SDK/include)
target_link_directories(softwareSigning_demo PUBLIC lib/Seal_SQ_Ines_SDK/include)
