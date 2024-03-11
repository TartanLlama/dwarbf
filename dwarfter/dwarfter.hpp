#ifndef DWARFTER_DWARFTER_HPP
#define DWARFTER_DWARFTER_HPP

#include <cstdint>
#include <vector>

namespace dwter {
    std::uint64_t eval(
        const std::vector<std::byte>& memory,
        std::uint64_t base_address,
        std::uint64_t initial_value,
        const std::vector<std::byte>& expr,
        bool debug = false);
}

#endif