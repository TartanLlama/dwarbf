#include <iostream>
#include <string>
#include <filesystem>
#include <sstream>
#include <fstream>
#include <fcntl.h>
#include "dwarf.h"
#include "elf.h"
#include <sys/stat.h>
#include <algorithm>
#include "dwarfas.hpp"

std::vector<std::string> split(std::string_view text) {
    size_t pos = text.find(' ');
    size_t initial_pos = 0;

    std::vector<std::string> result;

    while (pos != std::string::npos) {
        result.push_back(std::string(text.substr(initial_pos, pos - initial_pos)));
        initial_pos = pos + 1;

        pos = text.find(' ', initial_pos);
    }

    result.push_back(std::string(text.substr(initial_pos, std::min(pos, text.size()) - initial_pos + 1)));

    return result;
}

struct fixup {
    std::string label;
    std::size_t index;
};
void encode_dwarf_expression_instruction(std::string_view instruction, std::vector<std::byte>& buffer, std::vector<fixup>& fixups) {
    auto data = split(instruction);
    auto opcode = data[0];
    bool handled = false;

    auto output = [&](auto obj) {
        handled = true;
        std::copy(reinterpret_cast<std::byte*>(&obj), reinterpret_cast<std::byte*>(&obj) + sizeof(obj),
            std::back_inserter(buffer));
        };
    auto output_opcode = [&](std::uint8_t opcode) {
        output(opcode);
        };

    if (opcode == "addr") {
        auto address = std::stoull(data[1], nullptr, 16);
        output_opcode(DW_OP_addr);
        output(address);
    }
    else if (opcode == "deref") output_opcode(DW_OP_deref);
    else if (opcode == "deref_size") {
        output_opcode(DW_OP_deref_size);
        std::uint8_t size = std::stoi(data[1]);
        output(size);
    }

    else if (opcode == "dup") output_opcode(DW_OP_dup);
    else if (opcode == "drop") output_opcode(DW_OP_drop);
    else if (opcode == "over") output_opcode(DW_OP_over);
    else if (opcode == "pick") {
        output_opcode(DW_OP_pick);
        std::uint8_t idx = std::stoi(data[1]);
        output(idx);
    }
    else if (opcode == "swap") output_opcode(DW_OP_swap);
    else if (opcode == "rot") output_opcode(DW_OP_rot);
    else if (opcode == "xderef") output_opcode(DW_OP_xderef);
    else if (opcode == "abs") output_opcode(DW_OP_abs);
    else if (opcode == "and") output_opcode(DW_OP_and);
    else if (opcode == "div") output_opcode(DW_OP_div);
    else if (opcode == "minus") output_opcode(DW_OP_minus);
    else if (opcode == "mod") output_opcode(DW_OP_mod);
    else if (opcode == "mul") output_opcode(DW_OP_mul);
    else if (opcode == "neg") output_opcode(DW_OP_neg);
    else if (opcode == "not") output_opcode(DW_OP_not);
    else if (opcode == "or") output_opcode(DW_OP_or);
    else if (opcode == "plus") output_opcode(DW_OP_plus);
    else if (opcode == "shl") output_opcode(DW_OP_shl);
    else if (opcode == "shr") output_opcode(DW_OP_shr);
    else if (opcode == "shra") output_opcode(DW_OP_shra);
    else if (opcode == "xor") output_opcode(DW_OP_xor);
    else if (opcode == "bra") {
        output_opcode(DW_OP_bra);
        fixups.push_back({ data[1], buffer.size() });
        output(std::uint16_t{ 0 });
    }
    else if (opcode == "eq") output_opcode(DW_OP_eq);
    else if (opcode == "ge") output_opcode(DW_OP_ge);
    else if (opcode == "gt") output_opcode(DW_OP_gt);
    else if (opcode == "le") output_opcode(DW_OP_le);
    else if (opcode == "lt") output_opcode(DW_OP_lt);
    else if (opcode == "ne") output_opcode(DW_OP_ne);
    else if (opcode == "skip") {
        output_opcode(DW_OP_skip);
        fixups.push_back({ data[1], buffer.size() });
        output(std::uint16_t{ 0 });
    }

    else if (opcode == "nop") output_opcode(DW_OP_nop);
    else if (opcode.substr(0, 5) == "const") {
        auto size = std::stoi(opcode.substr(5, opcode.size() - 5));
        if (size == 1) {
            if (data[0][6] == 'u') {
                output_opcode(DW_OP_const1u);
                output(std::uint8_t{ std::stoi(data[1]) });
            }
            else {
                output_opcode(DW_OP_const1s);
                output(std::int8_t{ std::stoi(data[1]) });
            }
        }
        else if (size == 2) {
            if (data[0][6] == 'u') {
                output_opcode(DW_OP_const2u);
                output(std::uint16_t{ std::stoi(data[1]) });
            }
            else {
                output_opcode(DW_OP_const2s);
                output(std::int16_t{ std::stoi(data[1]) });
            }
        }
        else if (size == 4) {
            if (data[0][6] == 'u') {
                output_opcode(DW_OP_const4u);
                output(std::uint32_t{ std::stoul(data[1]) });
            }
            else {
                output_opcode(DW_OP_const4s);
                output(std::int32_t{ std::stoi(data[1]) });
            }
        }
        else if (size == 8) {
            if (data[0][6] == 'u') {
                output_opcode(DW_OP_const8u);
                output(std::uint64_t{ std::stoull(data[1]) });
            }
            else {
                output_opcode(DW_OP_const8s);
                output(std::int64_t{ std::stoll(data[1]) });
            }
        }
    }
    else if (opcode.substr(0, 3) == "lit") {
        output_opcode(DW_OP_lit0 + std::stoi(data[0].substr(3)));
    }

    if (!handled)
        throw std::runtime_error(std::string("Unsuported opcode ") + std::string(instruction));
}

std::uintptr_t align(std::uintptr_t pointer, uintptr_t size) {
    intptr_t value = static_cast<intptr_t>(pointer);
    value += (-value) & (size - 1);
    return value;
}

void ltrim(std::string& s) {
    s.erase(s.begin(), std::find_if(s.begin(), s.end(), [](unsigned char ch) {
        return !std::isspace(ch);
        }));
}

void rtrim(std::string& s) {
    s.erase(std::find_if(s.rbegin(), s.rend(), [](unsigned char ch) {
        return !std::isspace(ch);
        }).base(), s.end());
}

void trim(std::string& s) {
    rtrim(s);
    ltrim(s);
}

template <class From>
std::byte* as_bytes(From& from) {
    return reinterpret_cast<std::byte*>(&from);
}

std::vector<std::byte> dwas::assemble_dwarf_program(const std::string& dwarf_program) {
    std::vector<std::byte> data;
    std::unordered_map<std::string, std::size_t> labels;

    std::vector<fixup> fixups;

    std::istringstream in(dwarf_program);
    std::string line;
    while (std::getline(in, line)) {
        trim(line);
        if (line.front() == '.' and line.back() == ':') {
            labels[line.substr(0, line.size() - 1)] = data.size();
        }
        else if (!line.empty() and line[0] != '#') {
            encode_dwarf_expression_instruction(line, data, fixups);
        }
    }

    for (auto fixup : fixups) {
        if (labels.find(fixup.label) == labels.end())
            throw std::runtime_error("Undefined label " + fixup.label);

        auto label = labels[fixup.label];
        std::int64_t offset = label - (fixup.index + 2);
        if (offset > std::numeric_limits<std::int16_t>::max() or offset < std::numeric_limits<std::int16_t>::min())
            throw std::runtime_error("Branch target out of range");
        auto offset16 = static_cast<std::int16_t>(offset);
        std::copy(as_bytes(offset16), as_bytes(offset16) + sizeof(offset16), &data[fixup.index]);
    }

    return data;
}

auto create_debug_abbrev() {
    std::vector<std::uint8_t> data{
        1, //abbrev code
        DW_TAG_compile_unit, //tag
        1, //has children
        DW_AT_name, DW_FORM_string, //name
        DW_AT_low_pc, DW_FORM_addr, //low_pc
        DW_AT_high_pc, DW_FORM_addr, //high_pc
        0, 0, //end of children

        2, //abbrev code
        DW_TAG_subprogram, //tag
        0, //has children
        DW_AT_name, DW_FORM_string, //name
        DW_AT_low_pc, DW_FORM_addr, //low_pc
        DW_AT_high_pc, DW_FORM_addr, //high_pc
        0, 0, //end of children

        3, //abbrev code
        DW_TAG_variable, //tag
        0, //has children
        DW_AT_name, DW_FORM_string, //name
        DW_AT_location, DW_FORM_sec_offset, //location
        0, 0, //end of children

        0 //end of abbrevs
    };
    return data;
}

auto create_dies(std::string_view compile_unit_name, std::string_view embed_symbol_name) {
    std::vector<std::uint8_t> data1{
        //compile unit header
        0xff, 0xff, 0xff, 0xff, //length
        0x04, 0x00, //version
        0x00, 0x00, 0x00, 0x00, //abbrev offset
        0x08, //address size

        //compile unit die
        1, //abbrev code
    };

    data1.insert(data1.end(), compile_unit_name.begin(), compile_unit_name.end());
    data1.push_back(0);

    std::vector<std::uint8_t> data2{
        0x00, 0x80, 0x04, 0x08, 0x00, 0x00, 0x00, 0x00, //low_pc
        0x0c, 0x80, 0x04, 0x08, 0x00, 0x00, 0x00, 0x00, //high_pc

        //subprogram die
        2, //abbrev code
        '_', 's', 't', 'a', 'r', 't', '\0',//name
        0x00, 0x80, 0x04, 0x08, 0x00, 0x00, 0x00, 0x00, //low_pc
        0x0c, 0x80, 0x04, 0x08, 0x00, 0x00, 0x00, 0x00, //high_pc

        //variable die
        3, //abbrev code
    };
    data2.insert(data2.end(), embed_symbol_name.begin(), embed_symbol_name.end());
    data2.push_back(0);

    std::vector<std::uint8_t> data3{
        0x00, 0x00, 0x00, 0x00, //location

        0x00 //end of children
    };

    data1.insert(data1.end(), data2.begin(), data2.end());
    data1.insert(data1.end(), data3.begin(), data3.end());
    std::uint32_t length = data1.size() - 4;
    std::copy(reinterpret_cast<char*>(&length), reinterpret_cast<char*>(&length) + sizeof(length), data1.begin());
    return data1;
}

std::vector<std::byte> dwas::create_elf(
    const std::vector<std::byte>& dwarf_program,
    std::string_view compile_unit_name,
    std::string_view embed_string_text, 
    std::string_view embed_symbol_name, 
    std::filesystem::path output_path) {
    auto entry_point = 0x08048000;
    Elf64_Ehdr header{
        {
         0x7f, 'E', 'L', 'F', 2, 1, 1	/* Magic number and other info */
        },
        ET_EXEC,			            /* Object file type */
        EM_X86_64,		                /* Architecture */
        1,		                        /* Object file version */
        entry_point,		            /* Entry point virtual address */
        0x40,		                    /* Program header table file offset */
        0xffff,		                    /* Section header table file offset */
        0,		                        /* Processor-specific flags */
        64,		                        /* ELF header size in bytes */
        56,		                        /* Program header table entry size */
        1,		                        /* Program header table entry count */
        64,		                        /* Section header table entry size */
        8,		                        /* Section header table entry count */
        4		                        /* Section header string table index */
    };

    using namespace std::string_literals;
    auto section_string_table = "\0.text\0.shstrtab\0.debug_loc\0.strtab\0.symtab\0.debug_info\0.debug_abbrev\0"s;

    Elf64_Shdr null_section_header{};

    Elf64_Shdr debug_loc_section_header{
      section_string_table.find(".debug_loc"),	/* Section name (string tbl index) */
      SHT_PROGBITS,                             /* Section type */
        0,		                                /* Section flags */
        0,		                                /* Section virtual addr at execution */
        0xffff,		                            /* Section file offset */
        0xffff,		                            /* Section size in bytes */
        0,		                                /* Link to another section */
        0,		                                /* Additional section information */
        1,		                                /* Section alignment */
        0                                        /* Entry size if section holds table */
    };

    auto text_section_header = debug_loc_section_header;
    text_section_header.sh_name = section_string_table.find(".text");
    text_section_header.sh_addralign = 16;

    std::vector<std::uint8_t> text{
        0xbb, 0x00, 0x00, 0x00, 0x00, // movl $0, %ebx
        0xb8, 0x01, 0x00, 0x00, 0x00, // movl $1, %eax
        0xcd, 0x80                    // int $0x80
    };

    Elf64_Shdr shstrtab_section_header = debug_loc_section_header;
    shstrtab_section_header.sh_name = section_string_table.find(".shstrtab");
    shstrtab_section_header.sh_type = SHT_STRTAB;

    auto strtab = "\0_start\0"s;
    strtab.append(embed_symbol_name);
    strtab.append("\0"s);
    auto strtab_section_header = shstrtab_section_header;
    strtab_section_header.sh_name = section_string_table.find(".strtab");

    auto symbol_table_section_header = debug_loc_section_header;
    symbol_table_section_header.sh_name = section_string_table.find(".symtab");
    symbol_table_section_header.sh_type = SHT_SYMTAB;
    symbol_table_section_header.sh_entsize = sizeof(Elf64_Sym);
    symbol_table_section_header.sh_link = 2;

    Elf64_Sym start_symbol{
          strtab.find("_start"),		    /* Symbol name (string tbl index) */
          (STB_GLOBAL << 4) | STT_FUNC, 	/* Symbol type and binding */
          0,		                        /* Symbol visibility */
          1,		                        /* Section index */
          entry_point,		                /* Symbol value */
          text.size()		                /* Symbol size */
    };

    Elf64_Sym embed_symbol{
        strtab.find(embed_symbol_name),	        /* Symbol name (string tbl index) */
        (STB_GLOBAL << 4) | STT_OBJECT, 	        /* Symbol type and binding */
        0,		                                    /* Symbol visibility */
        2,		                                    /* Section index */
        entry_point + text.size() + strtab.size(),	/* Symbol value */
        embed_string_text.size()		                    /* Symbol size */
    };

    auto debug_abbrev_section_header = strtab_section_header;
    debug_abbrev_section_header.sh_name = section_string_table.find(".debug_abbrev");
    debug_abbrev_section_header.sh_type = SHT_PROGBITS;


    auto debug_info_section_header = debug_abbrev_section_header;
    debug_info_section_header.sh_name = section_string_table.find(".debug_info");

    Elf64_Phdr program_header{
        PT_LOAD,		/* Segment type */
        PF_X | PF_R,	/* Segment flags */
        0xffff,		    /* Segment file offset */
        entry_point,	/* Segment virtual address */
        entry_point,	/* Segment physical address */
        0xffff,		    /* Segment size in file */
        0xffff,		    /* Segment size in memory */
        0x1000		    /* Segment alignment */
    };

    std::vector<std::byte> elf_data;
    auto insert = [&](const auto& data) {
        elf_data.insert(elf_data.end(),
            reinterpret_cast<const std::byte*>(&data),
            reinterpret_cast<const std::byte*>(&data) + sizeof(data));
        };
    auto insert_range = [&](const auto& range) {
        auto begin = range.data();
        auto end = begin + range.size();
        elf_data.insert(elf_data.end(),
            reinterpret_cast<const std::byte*>(begin),
            reinterpret_cast<const std::byte*>(end));
        };

    //----start of ELF file creation----
    insert(header);

    auto program_header_offset = elf_data.size();
    insert(program_header);

    auto program_header_end = elf_data.size();
    auto text_section_offset = align(program_header_end, program_header.p_align);
    elf_data.insert(elf_data.end(), text_section_offset - program_header_end, std::byte{ 0 });
    insert_range(text);
    text_section_header.sh_addr = entry_point;
    text_section_header.sh_offset = text_section_offset;
    text_section_header.sh_size = text.size();
    text_section_header.sh_flags = SHF_EXECINSTR | SHF_ALLOC;

    auto strtab_section_offset = elf_data.size();
    insert_range(strtab);
    insert_range(embed_string_text);
    strtab_section_header.sh_addr = entry_point + text_section_header.sh_size;
    strtab_section_header.sh_offset = strtab_section_offset;
    strtab_section_header.sh_size = elf_data.size() - strtab_section_offset;
    strtab_section_header.sh_flags = SHF_ALLOC;

    auto debug_loc_section_offset = elf_data.size();
    insert(std::uint64_t{ 0 });
    insert(std::uint64_t{ text_section_header.sh_size });
    insert(std::uint16_t{ dwarf_program.size() + 9 });
    insert(std::uint8_t{ DW_OP_addr });
    insert(std::uint64_t{ strtab_section_header.sh_addr + strtab.size() });
    insert_range(dwarf_program);
    insert(std::uint64_t{ 0 }); insert(std::uint64_t{ 0 }); //end of list
    debug_loc_section_header.sh_offset = debug_loc_section_offset;
    debug_loc_section_header.sh_size = elf_data.size() - debug_loc_section_offset;

    auto shstrtab_section_offset = elf_data.size();
    insert_range(section_string_table);
    shstrtab_section_header.sh_offset = shstrtab_section_offset;
    shstrtab_section_header.sh_size = section_string_table.size();

    auto symbol_table_section_offset = elf_data.size();
    insert(start_symbol);
    insert(embed_symbol);
    symbol_table_section_header.sh_offset = symbol_table_section_offset;
    symbol_table_section_header.sh_size = elf_data.size() - symbol_table_section_offset;

    auto debug_abbrev_section_offset = elf_data.size();
    auto debug_abbrev = create_debug_abbrev();
    insert_range(debug_abbrev);
    debug_abbrev_section_header.sh_offset = debug_abbrev_section_offset;
    debug_abbrev_section_header.sh_size = elf_data.size() - debug_abbrev_section_offset;

    auto debug_info_section_offset = elf_data.size();
    auto debug_info = create_dies(compile_unit_name, embed_symbol_name);
    insert_range(debug_info);
    debug_info_section_header.sh_offset = debug_info_section_offset;
    debug_info_section_header.sh_size = elf_data.size() - debug_info_section_offset;

    auto section_header_start = elf_data.size();
    insert(null_section_header);
    insert(text_section_header);
    insert(strtab_section_header);
    insert(debug_loc_section_header);
    insert(shstrtab_section_header);
    insert(symbol_table_section_header);
    insert(debug_abbrev_section_header);
    insert(debug_info_section_header);


    //Fixup program headers
    program_header.p_offset = text_section_offset;
    program_header.p_filesz = text_section_header.sh_size + strtab_section_header.sh_size;
    program_header.p_memsz = program_header.p_filesz;
    std::copy(as_bytes(program_header), as_bytes(program_header) + sizeof(program_header),
        elf_data.begin() + program_header_offset);

    //Fixup ELF header
    auto field_offset = offsetof(Elf64_Ehdr, e_shoff);
    std::copy(as_bytes(section_header_start), as_bytes(section_header_start) + sizeof(section_header_start),
        elf_data.begin() + field_offset);

    std::ofstream elf_file(output_path, std::ios_base::binary | std::ios_base::out);
    elf_file.write((char*)elf_data.data(), elf_data.size());
    elf_file.close();

    chmod(output_path.c_str(), 0777);

    // Return the load segment contents for testing
    elf_data.clear();
    insert(text);
    insert(strtab);
    insert_range(embed_string_text);
    return elf_data;
}
