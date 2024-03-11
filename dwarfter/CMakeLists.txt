cmake_minimum_required (VERSION 3.8)

project("dwarfter")

add_library(dwarfter
    "dwarfter.cpp"
 "dwarf.h")
target_include_directories(dwarfter PUBLIC "${CMAKE_CURRENT_SOURCE_DIR}")