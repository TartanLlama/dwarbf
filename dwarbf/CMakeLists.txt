add_executable (dwarbf "dwarbf.cpp")
target_link_libraries(dwarbf PRIVATE dwarfas dwarfter)

file(READ ${CMAKE_CURRENT_SOURCE_DIR}/dwarbf.dw INTERPRETER_TEXT)
file(TOUCH ${CMAKE_CURRENT_SOURCE_DIR}/dwarbf_interpreter.hpp.in)
configure_file(
    ${CMAKE_CURRENT_SOURCE_DIR}/dwarbf_interpreter.hpp.in
    ${CMAKE_CURRENT_BINARY_DIR}/dwarbf_interpreter.gen.hpp
    @ONLY
)

target_include_directories(dwarbf PRIVATE ${CMAKE_CURRENT_BINARY_DIR})