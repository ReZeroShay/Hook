cmake_minimum_required(VERSION 3.28)

project(Zydis LANGUAGES C)


add_library(Zydis STATIC Zydis.c)

target_include_directories(Zydis PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})
target_compile_definitions(Zydis
    PUBLIC ZYDIS_STATIC_DEFINE
)
