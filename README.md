# R6DumpCleaner

## Purpose

In the latest Update, Rainbow Six Siege includes lot of junk code that looks like this:

```cpp
v483 = (char *)&v688 - (char *)&v689;
if ( (char *)&v688 - (char *)&v689 < 0 )
    v483 = (char *)&v689 - (char *)&v688;
```

This code essentially computes:

```cpp
v483 = 8; // Because v689 and v688 are just 8 Bytes apart on the stack
```

This tool will scan for such patterns and remove the nonsense

## Usage

Run the tool from the command line using:

```
R6DumpCleaner.exe <DumpFile> [OutputFile]
```

- `<DumpFile>`: **Required.** The input file to be cleaned.
- `[OutputFile]`: **Optional.** The output file name. If not provided, the tool will create a file named `<DumpFile>_patched` in the same directory.

## Building

This project depends on Zydis. You can either include Zydis in the project directory or install it via vcpkg:

```
vcpkg install zydis
```

Then, build the project using your preferred build system.

## How it works

The tool searches for the following instruction sequence in the .text section:

```asm
mov A, [rsp+var1]
sub A, [rsp+var2]
mov B, A
neg B
cmovs B, A
```

It then converts this sequence to a single instruction:

```asm
mov B, abs(var1 - var2)
```

The rest of the old bytes are filled with NOPs (`0x90`)
