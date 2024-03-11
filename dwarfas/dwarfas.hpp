#ifndef DWARFAS_DWARFAS_HPP
#define DWARFAS_DWARFAS_HPP

#include <vector>
#include <bit>
#include <string>

namespace dwas {
    std::vector<std::byte> assemble_dwarf_program(const std::string& dwarf_program);
    std::vector<std::byte> create_elf(
        const std::vector<std::byte>& dwarf_program,
        std::string_view compile_unit_name,
        std::string_view string_text,
        std::string_view program_symbol_name,
        std::filesystem::path output_path);
}

#endif