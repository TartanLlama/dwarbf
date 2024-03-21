#include <vector>
#include <bit>
#include <exception>
#include <stdexcept>
#include <string_view>
#include <algorithm>
#include "dwarf.h"
#include "dwarfter.hpp"

class cursor {
public:
    explicit cursor(const std::vector<std::byte>& data)
        : begin_(data.data()), end_(data.data() + data.size()), pos_(data.data()) {}

    cursor& operator++() { ++pos_; return *this; }
    cursor& operator+=(std::size_t size) { pos_ += size; return *this; }

    const std::byte* position() const { return pos_; }

    bool finished() const {
        return pos_ >= end_;
    }

    template <class T>
    T fixed() {
        T t = T{};
        std::copy(pos_, pos_ + sizeof(T), reinterpret_cast<std::byte*>(&t));
        pos_ += sizeof(T);
        return t;
    }

    std::string_view string() {
        auto null_terminator = std::find(pos_, end_, std::byte{ 0 });
        std::string_view ret(reinterpret_cast<const char*>(pos_),
            null_terminator - pos_);
        pos_ = null_terminator + 1;
        return ret;
    }

    std::uint64_t uleb128() {
        std::uint64_t res = 0;
        int shift = 0;
        std::uint8_t byte = 0;
        do {
            byte = fixed<std::uint8_t>();
            auto masked = static_cast<uint64_t>(byte & 0x7f);
            res |= masked << shift;
            shift += 7;
        } while ((byte & 0x80) != 0);
        return res;
    }

    std::int64_t sleb128() {
        std::uint64_t res = 0;
        int shift = 0;
        std::uint8_t byte = 0;
        do {
            byte = fixed<std::uint8_t>();
            auto masked = static_cast<uint64_t>(byte & 0x7f);
            res |= masked << shift;
            shift += 7;
        } while ((byte & 0x80) != 0);

        if ((shift < sizeof(res) * 8) && (byte & 0x40)) {
            res |= (~static_cast<std::uint64_t>(0) << shift);
        }

        return res;
    }

    void skip_form(std::uint64_t form) {
        switch (form) {
        case DW_FORM_flag_present:
            break;

        case DW_FORM_data1:
        case DW_FORM_ref1:
        case DW_FORM_flag:
            pos_ += 1; break;

        case DW_FORM_data2:
        case DW_FORM_ref2:
            pos_ += 2; break;

        case DW_FORM_data4:
        case DW_FORM_ref4:
        case DW_FORM_ref_addr:
        case DW_FORM_sec_offset:
        case DW_FORM_strp:
            pos_ += 4; break;

        case DW_FORM_data8:
        case DW_FORM_addr:
            pos_ += 8; break;


        case DW_FORM_sdata:
            sleb128(); break;
        case DW_FORM_udata:
        case DW_FORM_ref_udata:
            uleb128(); break;


        case DW_FORM_block1:
            pos_ += fixed<std::uint8_t>();
            break;
        case DW_FORM_block2:
            pos_ += fixed<std::uint16_t>();
            break;
        case DW_FORM_block4:
            pos_ += fixed<std::uint32_t>();
            break;
        case DW_FORM_block:
        case DW_FORM_exprloc:
            pos_ += uleb128();
            break;

        case DW_FORM_string:
            while (!finished() && *pos_ != std::byte(0)) {
                ++pos_;
            }
            ++pos_;
            break;
        default: throw std::runtime_error("Unrecognized DWARF form");
        }
    }

private:
    const std::byte* begin_;
    const std::byte* end_;
    const std::byte* pos_;
};
#include <iostream>



std::string opcode_to_string(std::uint8_t opcode) {
    switch (opcode) {
    case DW_OP_addr: return "addr";
    case DW_OP_deref: return "deref";
    case DW_OP_deref_size: return "deref_size";
    case DW_OP_dup: return "dup";
    case DW_OP_drop: return "drop";
    case DW_OP_over: return "over";
    case DW_OP_pick: return "pick";
    case DW_OP_swap: return "swap";
    case DW_OP_rot: return "rot";
    case DW_OP_xderef: return "xderef";
    case DW_OP_abs: return "abs";
    case DW_OP_and: return "and";
    case DW_OP_div: return "div";
    case DW_OP_minus: return "minus";
    case DW_OP_mod: return "mod";
    case DW_OP_mul: return "mul";
    case DW_OP_neg: return "neg";
    case DW_OP_not: return "not";
    case DW_OP_or: return "or";
    case DW_OP_plus: return "plus";
    case DW_OP_shl: return "shl";
    case DW_OP_shr: return "shr";
    case DW_OP_shra: return "shra";
    case DW_OP_xor: return "xor";
    case DW_OP_bra: return "bra";
    case DW_OP_eq: return "eq";
    case DW_OP_ge: return "ge";
    case DW_OP_gt: return "gt";
    case DW_OP_le: return "le";
    case DW_OP_lt: return "lt";
    case DW_OP_ne: return "ne";
    case DW_OP_skip: return "skip";
    case DW_OP_nop: return "nop";
    case DW_OP_lit0: return "lit0";
    case DW_OP_lit1: return "lit1";
    case DW_OP_lit2: return "lit2";
    case DW_OP_lit3: return "lit3";
    case DW_OP_lit4: return "lit4";
    case DW_OP_lit5: return "lit5";
    case DW_OP_lit6: return "lit6";
    case DW_OP_lit7: return "lit7";
    case DW_OP_lit8: return "lit8";
    case DW_OP_lit9: return "lit9";
    case DW_OP_lit10: return "lit10";
    case DW_OP_lit11: return "lit11";
    case DW_OP_lit12: return "lit12";
    case DW_OP_lit13: return "lit13";
    case DW_OP_lit14: return "lit14";
    case DW_OP_lit15: return "lit15";
    case DW_OP_lit16: return "lit16";
    case DW_OP_lit17: return "lit17";
    case DW_OP_lit18: return "lit18";
    case DW_OP_lit19: return "lit19";
    case DW_OP_lit20: return "lit20";
    case DW_OP_lit21: return "lit21";
    case DW_OP_lit22: return "lit22";
    case DW_OP_lit23: return "lit23";
    case DW_OP_lit24: return "lit24";
    case DW_OP_lit25: return "lit25";
    case DW_OP_lit26: return "lit26";
    case DW_OP_lit27: return "lit27";
    case DW_OP_lit28: return "lit28";
    case DW_OP_lit29: return "lit29";
    case DW_OP_lit30: return "lit30";
    case DW_OP_lit31: return "lit31";
    case DW_OP_reg0: return "reg0";
    case DW_OP_reg1: return "reg1";
    case DW_OP_reg2: return "reg2";
    case DW_OP_reg3: return "reg3";
    case DW_OP_reg4: return "reg4";
    case DW_OP_reg5: return "reg5";
    case DW_OP_reg6: return "reg6";
    case DW_OP_reg7: return "reg7";
    case DW_OP_reg8: return "reg8";
    case DW_OP_reg9: return "reg9";
    case DW_OP_reg10: return "reg10";
    case DW_OP_reg11: return "reg11";
    case DW_OP_reg12: return "reg12";
    case DW_OP_reg13: return "reg13";
    case DW_OP_reg14: return "reg14";
    case DW_OP_reg15: return "reg15";
    case DW_OP_reg16: return "reg16";
    case DW_OP_reg17: return "reg17";
    case DW_OP_reg18: return "reg18";
    case DW_OP_reg19: return "reg19";
    case DW_OP_reg20: return "reg20";
    case DW_OP_reg21: return "reg21";
    case DW_OP_reg22: return "reg22";
    case DW_OP_reg23: return "reg23";
    case DW_OP_reg24: return "reg24";
    case DW_OP_reg25: return "reg25";
    case DW_OP_reg26: return "reg26";
    case DW_OP_reg27: return "reg27";
    case DW_OP_reg28: return "reg28";
    case DW_OP_reg29: return "reg29";
    case DW_OP_reg30: return "reg30";
    case DW_OP_reg31: return "reg31";
    case DW_OP_breg0: return "breg0";
    case DW_OP_breg1: return "breg1";
    case DW_OP_breg2: return "breg2";
    case DW_OP_breg3: return "breg3";
    case DW_OP_breg4: return "breg4";
    case DW_OP_breg5: return "breg5";
    case DW_OP_breg6: return "breg6";
    case DW_OP_breg7: return "breg7";
    case DW_OP_breg8: return "breg8";
    case DW_OP_breg9: return "breg9";
    case DW_OP_breg10: return "breg10";
    case DW_OP_breg11: return "breg11";
    case DW_OP_breg12: return "breg12";
    case DW_OP_breg13: return "breg13";
    case DW_OP_breg14: return "breg14";
    case DW_OP_breg15: return "breg15";
    case DW_OP_breg16: return "breg16";
    case DW_OP_breg17: return "breg17";
    case DW_OP_breg18: return "breg18";
    case DW_OP_breg19: return "breg19";
    case DW_OP_breg20: return "breg20";
    case DW_OP_breg21: return "breg21";
    case DW_OP_breg22: return "breg22";
    case DW_OP_breg23: return "breg23";
    case DW_OP_breg24: return "breg24";
    case DW_OP_breg25: return "breg25";
    case DW_OP_breg26: return "breg26";
    case DW_OP_breg27: return "breg27";
    case DW_OP_breg28: return "berg28";
    case DW_OP_breg29: return "breg29";
    case DW_OP_breg30: return "breg30";
    case DW_OP_breg31: return "breg31";
    case DW_OP_regx: return "regx";
    case DW_OP_fbreg: return "fbreg";
    case DW_OP_bregx: return "bregx";
    case DW_OP_piece: return "piece";
    case DW_OP_xderef_size: return "xderef_size";
    case DW_OP_push_object_address: return "push_object_address";
    case DW_OP_call2: return "call2";
    case DW_OP_call4: return "call4";
    case DW_OP_call_ref: return "call_ref";
    case DW_OP_form_tls_address: return "form_tls_address";
    case DW_OP_call_frame_cfa: return "call_frame_cfa";
    case DW_OP_bit_piece: return "bit_piece";
    case DW_OP_implicit_value: return "implicit_value";
    case DW_OP_stack_value: return "stack_value";
    case DW_OP_lo_user: return "lo_user";
    case DW_OP_hi_user: return "hi_user";
    case DW_OP_const1s: return "const1s";
    case DW_OP_const1u: return "const1u";
    case DW_OP_const2s: return "const2s";
    case DW_OP_const2u: return "const2u";
    case DW_OP_const4s: return "const4s";
    case DW_OP_const4u: return "const4u";
    case DW_OP_const8s: return "const8s";
    case DW_OP_const8u: return "const8u";
    case DW_OP_constu: return "constu";
    case DW_OP_consts: return "consts";
    }
}


std::uint64_t dwter::eval(const std::vector<std::byte>& memory, std::uint64_t base_address, std::uint64_t initial_value, const std::vector<std::byte>& expr, bool debug) {
    std::vector<std::uint64_t> stack;
    stack.push_back(initial_value);

    cursor cur(expr);

    auto binop = [&](auto op) {
        auto rhs = stack.back();
        stack.pop_back();
        auto lhs = stack.back();
        stack.pop_back();
        stack.push_back(op(lhs, rhs));
        };

    auto relop = [&](auto op) {
        auto rhs = static_cast<std::int64_t>(stack.back());
        stack.pop_back();
        auto lhs = static_cast<std::int64_t>(stack.back());
        stack.pop_back();
        stack.push_back(op(lhs, rhs) ? 1 : 0);
        };

    while (!cur.finished()) {
        auto opcode = cur.fixed<std::uint8_t>();

        if (debug) {
            std::cout << "opcode: " << opcode_to_string(opcode) << std::endl;
            std::cout << "stack: " << std::endl;
            for (auto it = stack.rbegin(); it != stack.rend(); ++it) {
                std::cout << std::hex << *it << std::dec << std::endl;
            }
            std::cout << std::endl;
        }

        if (opcode >= DW_OP_lit0 and opcode <= DW_OP_lit31) {
            stack.push_back(opcode - DW_OP_lit0);
        }
        else if (opcode >= DW_OP_breg0 and opcode <= DW_OP_breg31) {
            throw std::runtime_error("Unsupported opcode DW_OP_breg");
        }
        else if (opcode >= DW_OP_reg0 and opcode <= DW_OP_reg31) {
            throw std::runtime_error("Unsupported opcode DW_OP_reg");
        }
        switch (opcode) {
        case DW_OP_addr:
            stack.push_back(cur.fixed<std::uint64_t>());
            break;
        case DW_OP_const1u:
            stack.push_back(cur.fixed<std::uint8_t>());
            break;
        case DW_OP_const1s:
            stack.push_back(cur.fixed<std::int8_t>());
            break;
        case DW_OP_const2u:
            stack.push_back(cur.fixed<std::uint16_t>());
            break;
        case DW_OP_const2s:
            stack.push_back(cur.fixed<std::int16_t>());
            break;
        case DW_OP_const4u:
            stack.push_back(cur.fixed<std::uint32_t>());
            break;
        case DW_OP_const4s:
            stack.push_back(cur.fixed<std::int32_t>());
            break;
        case DW_OP_const8u:
            stack.push_back(cur.fixed<std::uint64_t>());
            break;
        case DW_OP_const8s:
            stack.push_back(cur.fixed<std::int64_t>());
            break;
        case DW_OP_constu:
            stack.push_back(cur.uleb128());
            break;
        case DW_OP_consts:
            stack.push_back(cur.sleb128());
            break;


        case DW_OP_fbreg: throw std::runtime_error("Unsupported opcode DW_OP_fbreg");
        case DW_OP_bregx: throw std::runtime_error("Unsupported opcode DW_OP_bregx");
        case DW_OP_dup:
            stack.push_back(stack.back());
            break;
        case DW_OP_drop:
            stack.pop_back();
            break;
        case DW_OP_pick:
            stack.push_back(stack[stack.size() - 1 - cur.fixed<std::uint8_t>()]);
            break;
        case DW_OP_over:
            stack.push_back(stack[stack.size() - 2]);
            break;
        case DW_OP_swap:
            std::swap(stack[stack.size() - 1], stack[stack.size() - 2]);
            break;
        case DW_OP_rot: {
            auto tmp = stack.end()[-3];
            stack.end()[-3] = stack.end()[-1];
            stack.end()[-1] = stack.end()[-2];
            stack.end()[-2] = tmp;
            break;
        }
        case DW_OP_deref: {
            std::uint64_t mem = 0;
            auto start = reinterpret_cast<const std::byte*>(&memory[stack.back() - base_address]);
            stack.pop_back();
            std::copy(start, start + sizeof(mem), reinterpret_cast<std::byte*>(&mem));
            stack.push_back(mem);
            break;
        }
        case DW_OP_deref_size: {
            auto size = cur.fixed<std::uint8_t>();
            std::uint64_t mem = 0;
            auto start = reinterpret_cast<const std::byte*>(&memory[stack.back() - base_address]);
            stack.pop_back();
            std::copy(start, start + size, reinterpret_cast<std::byte*>(&mem));
            stack.push_back(mem);
            break;
        }
        case DW_OP_xderef: throw std::runtime_error("Unsupported opcode DW_OP_xderef");
        case DW_OP_xderef_size: throw std::runtime_error("Unsupported opcode DW_OP_xderef_size");
        case DW_OP_push_object_address: throw std::runtime_error("Unsupported opcode DW_OP_push_object_address");
        case DW_OP_form_tls_address: throw std::runtime_error("Unsupported opcode DW_OP_form_tls_address");
        case DW_OP_call_frame_cfa: throw std::runtime_error("Unsupported opcode DW_OP_call_frame_cfa");

        case DW_OP_abs: {
            auto sval = static_cast<std::int64_t>(stack.back());
            sval = std::abs(sval);
            stack.back() = static_cast<std::uint64_t>(sval);
            break;
        }
        case DW_OP_and:
            binop(std::bit_and{});
            break;
        case DW_OP_div: {
            auto rhs = static_cast<std::int64_t>(stack.back());
            stack.pop_back();
            auto lhs = static_cast<std::int64_t>(stack.back());
            stack.pop_back();
            stack.push_back(static_cast<std::uint64_t>(lhs / rhs));
            break;
        }
        case DW_OP_minus:
            binop(std::minus{});
            break;
        case DW_OP_mod: {
            binop(std::modulus{});
            break;
        }
        case DW_OP_mul:
            binop(std::multiplies{});
            break;
        case DW_OP_neg: {
            auto neg = -static_cast<std::int64_t>(stack.back());
            stack.back() = static_cast<std::uint64_t>(neg);
            break;
        }
        case DW_OP_not:
            stack.back() = ~stack.back();
            break;
        case DW_OP_or:
            binop(std::bit_or{});
            break;
        case DW_OP_plus:
            binop(std::plus{});
            break;
        case DW_OP_plus_uconst:
            stack.back() += cur.uleb128();
            break;
        case DW_OP_shl:
            binop([](auto lhs, auto rhs) { return lhs << rhs; });
            break;
        case DW_OP_shr:
            binop([](auto lhs, auto rhs) { return lhs >> rhs; });
            break;
        case DW_OP_shra:
            binop([](auto lhs, auto rhs) { return static_cast<std::int64_t>(lhs) >> rhs; });
            break;
        case DW_OP_xor:
            binop(std::bit_xor{});
            break;

        case DW_OP_le:
            relop(std::less_equal{});
            break;
        case DW_OP_ge:
            relop(std::greater_equal{});
            break;
        case DW_OP_eq:
            relop(std::equal_to{});
            break;
        case DW_OP_lt:
            relop(std::less{});
            break;
        case DW_OP_gt:
            relop(std::greater{});
            break;
        case DW_OP_ne:
            relop(std::not_equal_to{});
            break;
        case DW_OP_skip:
            cur += cur.fixed<std::int16_t>();
            break;
        case DW_OP_bra: {
            auto offset = cur.fixed<std::int16_t>();
            if (stack.back() != 0) {
                cur += offset;
            }
            stack.pop_back();
            break;
        }
        case DW_OP_call2: throw std::runtime_error("Unsupported opcode DW_OP_call2");
        case DW_OP_call4: throw std::runtime_error("Unsupported opcode DW_OP_call4");
        case DW_OP_call_ref: throw std::runtime_error("Unsupported opcode DW_OP_call_ref");

        case DW_OP_nop:
            break;

        case DW_OP_regx: throw std::runtime_error("Unsupported opcode DW_OP_regx");

        case DW_OP_implicit_value: throw std::runtime_error("Unsupported opcode DW_OP_implicit_value");
        case DW_OP_stack_value: throw std::runtime_error("Unsupported opcode DW_OP_stack_value");
        case DW_OP_piece: throw std::runtime_error("Unsupported opcode DW_OP_piece");
        case DW_OP_bit_piece: throw std::runtime_error("Unsupported opcode DW_OP_bit_piece");
        }
    }
    return stack.back();
}