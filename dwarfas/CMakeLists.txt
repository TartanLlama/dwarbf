cmake_minimum_required (VERSION 3.8)

project("dwarfas")

add_library(dwarfas
    "dwarfas.cpp"
)
target_include_directories(dwarfas PUBLIC "${CMAKE_CURRENT_SOURCE_DIR}")