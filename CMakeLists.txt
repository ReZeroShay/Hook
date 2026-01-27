cmake_minimum_required(VERSION 3.21.0)
project(hook VERSION 0.1.0 LANGUAGES C CXX)

add_subdirectory(deps/Zydis)

add_library(${PROJECT_NAME} INTERFACE)
target_compile_features(${PROJECT_NAME} INTERFACE cxx_std_23)

target_include_directories(${PROJECT_NAME}
    INTERFACE
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
        $<INSTALL_INTERFACE:include>
)
target_link_libraries(${PROJECT_NAME}
    INTERFACE
        Zydis
)
# 检查编译器类型
if (CMAKE_CXX_COMPILER_ID MATCHES "GNU|Clang")
    target_compile_options(${PROJECT_NAME} INTERFACE -mavx2)
    target_compile_options(${PROJECT_NAME} INTERFACE -fno-exceptions)
    target_compile_options(${PROJECT_NAME} INTERFACE -fno-unwind-tables)
    target_compile_options(${PROJECT_NAME} INTERFACE -fno-rtti)
elseif (CMAKE_CXX_COMPILER_ID STREQUAL "MSVC")
    target_compile_options(${PROJECT_NAME} INTERFACE /arch:AVX2)
    target_compile_options(${PROJECT_NAME} INTERFACE /EHsc)
    target_compile_options(${PROJECT_NAME} INTERFACE /D_HAS_EXCEPTIONS=0)
    target_compile_options(${PROJECT_NAME} INTERFACE /utf-8)
endif()

add_library(hook::hook ALIAS ${PROJECT_NAME})


if (PROJECT_IS_TOP_LEVEL)
    include(CTest)
endif()

enable_testing()
if(BUILD_TESTING)
    add_subdirectory(tests)
endif()
