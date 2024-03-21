# dwarbf 

A Brainfuck interpreter written in DWARF debug information

## Background

[Brainfuck](https://en.wikipedia.org/wiki/Brainfuck) is an esoteric programming language that runs on a tape of memory and has only eight instructions.

[DWARF](https://en.wikipedia.org/wiki/DWARF) is a format for encoding debug information that links binary machine code back to its source code representation.

DWARF expressions are a part of DWARF information that are used for calculating the addresses of variables. They run on a simple stack machine.

`dwarbf` is a set of tools that embeds a Brainfuck interpreter inside the DWARF information for a Linux executable. The interpreter is implemented as a DWARF expression.

## Building

There are no dependencies. The project uses CMake for building:

```shell
$ mkdir build && cd build
$ cmake ..
$ cmake --build .
```

## Running

Build an executable that has an embedded Brainfuck interpreter that will interpret the given program with:

```shell
$ dwarbf path/to/brainfuck/program.bf
```

This will create a `program` executable in the current working directory. The executable will have a variable called `dwarbf_program`. Evaluating the address of this variable will execute the Brainfuck program using the embedded interpreter.

Execute the Brainfuck program with `gdb`:

```shell
$ gdb --eval-command=starti --eval-command="p (int)&dwarbf_program" program --batch
```

Alternatively, `dwarbf` comes with a built-in DWARF interpreter than can be used for debugging:


```shell
$ dwarbf path/to/brainfuck/program.bf --run   #Builds and runs the program
$ dwarbf path/to/brainfuck/program.bf --debug #Also prints each opcode and stack contents after every instruction
```

## Limitations

There is no way to read or write from a stream in DWARF expressions, so the `,` and `.` Brainfuck operations are not supported.

## Components

### `dwarfas`
The `dwarfas` folder contains a DWARF expression assembler. It contains functions for assembling a string that holds a DWARF expression into a byte sequence that represents its binary encoding. It also has a function for creating an ELF executable that has the resulting DWARF expression embedded in the location information for a string variable.

The assembler supports comments on their own lines, prefixed with a `#`. It also supports labels for `skip` and `bra` instructions. Labels are of the form `.label_name:` and label references are of the form `.label_name`
.

Not all instructions are supported by the assembler because I'm lazy and I just wrote what I needed to support `dwarbf`.

The ELF file produced by `dwarfas` looks like this:

```
ELF Header:
  Magic:   7f 45 4c 46 02 01 01 00 00 00 00 00 00 00 00 00
  Class:                             ELF64
  Data:                              2's complement, little endian
  Version:                           1 (current)
  OS/ABI:                            UNIX - System V
  ABI Version:                       0
  Type:                              EXEC (Executable file)
  Machine:                           Advanced Micro Devices X86-64
  Version:                           0x1
  Entry point address:               0x8048000
  Start of program headers:          64 (bytes into file)
  Start of section headers:          9808 (bytes into file)
  Flags:                             0x0
  Size of this header:               64 (bytes)
  Size of program headers:           56 (bytes)
  Number of program headers:         1
  Size of section headers:           64 (bytes)
  Number of section headers:         8
  Section header string table index: 4

Section Headers:
  [Nr] Name              Type             Address           Offset
       Size              EntSize          Flags  Link  Info  Align
  [ 0]                   NULL             0000000000000000  00000000
       0000000000000000  0000000000000000           0     0     0
  [ 1] .text             PROGBITS         0000000008048000  00001000
       000000000000000c  0000000000000000  AX       0     0     16
  [ 2] .strtab           STRTAB           000000000804800c  0000100c
       0000000000000051  0000000000000000   A       0     0     1
  [ 3] .debug_loc        PROGBITS         0000000000000000  0000105d
       000000000000150d  0000000000000000           0     0     1
  [ 4] .shstrtab         STRTAB           0000000000000000  0000256a
       0000000000000046  0000000000000000           0     0     1
  [ 5] .symtab           SYMTAB           0000000000000000  000025b0
       0000000000000030  0000000000000018           2     0     1
  [ 6] .debug_abbrev     PROGBITS         0000000000000000  000025e0
       0000000000000020  0000000000000000           0     0     1
  [ 7] .debug_info       PROGBITS         0000000000000000  00002600
       0000000000000050  0000000000000000           0     0     1
Key to Flags:
  W (write), A (alloc), X (execute), M (merge), S (strings), I (info),
  L (link order), O (extra OS processing required), G (group), T (TLS),
  C (compressed), x (unknown), o (OS specific), E (exclude),
  D (mbind), l (large), p (processor specific)

There are no section groups in this file.

Program Headers:
  Type           Offset             VirtAddr           PhysAddr
                 FileSiz            MemSiz              Flags  Align
  LOAD           0x0000000000001000 0x0000000008048000 0x0000000008048000
                 0x000000000000005d 0x000000000000005d  R E    0x1000

 Section to Segment mapping:
  Segment Sections...
   00     .text .strtab

There is no dynamic section in this file.

There are no relocations in this file.
No processor specific unwind information to decode

Symbol table '.symtab' contains 2 entries:
   Num:    Value          Size Type    Bind   Vis      Ndx Name
     0: 0000000008048000    12 FUNC    GLOBAL DEFAULT    1 _start
     1: 0000000008048023    58 OBJECT  GLOBAL DEFAULT    2 dwarbf_program

No version information found in this file.
```

The `.debug_loc` section contains the DWARF expression that will be executed by the interpreter. The `_start` symbol is the entry point for the program, which just returns immediately. The `dwarbf_program` symbol will have the name given to the assembler. The symbol value points to the `string_text` argument given to the assembler (`dwarbf` uses this to hold the text of the Brainfuck program).

The DWARF information looks like this:

```
.debug_info

COMPILE_UNIT<header overall offset = 0x00000000>:
< 0><0x0000000b>  DW_TAG_compile_unit
                    DW_AT_name                  dwarbf
                    DW_AT_low_pc                0x08048000
                    DW_AT_high_pc               0x0804800c

LOCAL_SYMBOLS:
< 1><0x00000023>    DW_TAG_subprogram
                      DW_AT_name                  _start
                      DW_AT_low_pc                0x08048000
                      DW_AT_high_pc               0x0804800c
< 1><0x0000003b>    DW_TAG_variable
                      DW_AT_name                  dwarbf_program
                      DW_AT_location              0x00000000
      .debug_loc      offset  : 0x00000000
      <loclist at offset 0x00000000 with 1 entries follows>
   [ 0]<low,hi addrs       0x08048000 , 0x0804800c>
   <DWARF expression given to assembler>
```

The DWARF expression that was given to the assembler is stored in the `.debug_loc` section and the `DW_AT_location` attribute of the `dwarbf_program` variable points to it.

### `dwarbf`

The `dwarbf` folder contains a Brainfuck interpreter written as a DWARF expression and a C++ command-line driver for assembling it into an executable and potentially executing the interpreter.

The general algorithm is this:

- The top of the DWARF stack holds a pointer to the current character of the Brainfuck program, the index of the current Brainfuck memory cell, and a list of memory update records.
- The memory update records are stored as a list of 8-byte values, where the first 7 bytes are the index of the memory cell to update, and the last byte is the new value to store in the cell.
- The memory update list is terminated with an 8-byte value of 0xffffffffffffff00.
- The interpreter reads the current character of the BF program, and then uses a series of conditional branches to execute the appropriate BF command.
- The < and > commands are implemented by incrementing or decrementing the cell pointer.
- The + and - commands search the list of memory updates for the most recent update to the current cell, and then create a new update record with the new value. If no existing record is found, they act as if they found a record with a value of 0.
- The [ and ] commands search the list of memory updates for the most recent update to the current cell, and then skip to matching brace depending on the cell value. If no existing record is found, they act as if they found a record with a value of 0.
- The , and . commands are not implemented.
- These is no way to access memory cells past the first three without a `pick N` command, which requires a constant N to be known at compile time. As such, I implement a "pick table" that uses a series of conditional branches to implement the `pick N` command for all possible values of N (up to 255)
- A lot of code is duplicated, since deduplication would require more state, and adding more state would prevent the interpreter from being able to add entries to the memory update list.

### `dwarfter`

The `dwarfter` folder contains a DWARF expression interpreter. It contains functions for interpreting a byte sequence that represents a DWARF expression.

Not all DWARF instructions are supported by the interpreter because some require call frame information, register reading, or just a lot more work to implement.

## "This is absurd and useless"

Yes.