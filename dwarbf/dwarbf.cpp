#include <string>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <dwarfas.hpp>
#include <dwarfter.hpp>
#include "dwarbf_interpreter.gen.hpp"

void print_usage() {
    std::cerr << "Usage: dwarbf <input_file> [--run/--debug]\n";
}
int main(int argc, const char** argv) {
    if (argc < 2 or !std::filesystem::exists(argv[1])) {
        print_usage();
        return -1;
    }
    std::filesystem::path program_path = argv[1];
    std::ifstream program_file(program_path);
    std::ostringstream program_text;
    program_text << program_file.rdbuf();

    auto dwarf_program = dwas::assemble_dwarf_program(dwarbf::interpreter_text);
    auto load_segment = dwas::create_elf(
        dwarf_program, "dwarbf", 
        program_text.str(), "dwarbf_program", 
        program_path.filename().replace_extension());

    if (argc > 3) {
        print_usage();
        return -1;
    }
    if (argc == 3) {
        if (std::string(argv[2]) == "--run" or std::string(argv[2]) == "--debug") {
            auto debug = std::string(argv[2]) == "--debug";
            auto result = dwter::eval(load_segment, 0x08048000, 0x08048038, dwarf_program, debug);
            std::cout << "Result: " << result << std::endl;
            return result;
        }
        else {
            print_usage();
            return -1;
        }
    }
}