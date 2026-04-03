cmake_minimum_required(VERSION 3.21.0)
project(detour VERSION 0.1.0 LANGUAGES C CXX)

set(CMAKE_EXPORT_COMPILE_COMMANDS ON)
add_library(${PROJECT_NAME} STATIC deps/Zydis/Zydis.c)
target_compile_definitions(${PROJECT_NAME} PUBLIC ZYDIS_STATIC_DEFINE)
target_compile_features(${PROJECT_NAME} PUBLIC cxx_std_23)

target_include_directories(${PROJECT_NAME}
    PUBLIC
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/deps/Zydis>
        $<INSTALL_INTERFACE:include>
)

if (CMAKE_CXX_COMPILER_ID MATCHES "GNU|Clang")
    target_compile_options(${PROJECT_NAME} PUBLIC -mavx2)
    target_compile_options(${PROJECT_NAME} PUBLIC -fno-exceptions)
    target_compile_options(${PROJECT_NAME} PUBLIC -fno-unwind-tables)
    target_compile_options(${PROJECT_NAME} PUBLIC -fno-rtti)
elseif (CMAKE_CXX_COMPILER_ID STREQUAL "MSVC")
    target_compile_options(${PROJECT_NAME} PUBLIC /arch:AVX2)
    target_compile_options(${PROJECT_NAME} PUBLIC /D_HAS_EXCEPTIONS=0)
    target_compile_options(${PROJECT_NAME} PUBLIC /utf-8)
endif()

add_library(rezero::detour ALIAS ${PROJECT_NAME})


if (PROJECT_IS_TOP_LEVEL)
    include(CTest)
endif()

enable_testing()
if(BUILD_TESTING)
    add_subdirectory(tests)
endif()


include(GNUInstallDirs)
include(CMakePackageConfigHelpers)

install(
    TARGETS detour
    EXPORT detourTargets
    ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
    LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
    RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
)
install(
    EXPORT detourTargets
    FILE detourTargets.cmake
    NAMESPACE rezero::
    DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/detour
)

install(
    DIRECTORY deps/Zydis/ include/
    DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}
    FILES_MATCHING PATTERN "*.h"
)

configure_package_config_file(
    "cmake/detourConfig.cmake.in"
    "${CMAKE_CURRENT_BINARY_DIR}/detourConfig.cmake"
    INSTALL_DESTINATION "${CMAKE_INSTALL_LIBDIR}/cmake/detour"
)
write_basic_package_version_file(
    "${CMAKE_CURRENT_BINARY_DIR}/detourConfigVersion.cmake"
    VERSION ${PROJECT_VERSION}
    COMPATIBILITY SameMajorVersion
)

install(
    FILES
        "${CMAKE_CURRENT_BINARY_DIR}/detourConfig.cmake"
        "${CMAKE_CURRENT_BINARY_DIR}/detourConfigVersion.cmake"
    DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/detour
)
