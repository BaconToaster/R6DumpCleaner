#include <cstdio>
#include <cstdint>
#include <cstring>
#include <vector>
#include <fstream>
#include <Windows.h>
#include <Zydis/Zydis.h>

#define REGISTER_A (ZYDIS_REGISTER_MAX_VALUE + 1)
#define REGISTER_B (ZYDIS_REGISTER_MAX_VALUE + 2)

struct PatternOperand {
    ZydisOperandType type;
    int reg;
    union
    {
        ZydisDecodedOperandMem mem;
        ZydisDecodedOperandPtr ptr;
        ZydisDecodedOperandImm imm;
    };
};
struct PatternInstruction {
    ZydisMnemonic mnemonic;
    uint8_t operandCount;
    PatternOperand operands[2];
};

constexpr PatternInstruction junkPattern[] = {
    {
        .mnemonic = ZYDIS_MNEMONIC_MOV,
        .operandCount = 2,
        .operands = {
            {
                .type = ZYDIS_OPERAND_TYPE_REGISTER,
                .reg = REGISTER_A
            },
            {
                .type = ZYDIS_OPERAND_TYPE_MEMORY,
                .mem = { .base = ZYDIS_REGISTER_RSP }
            }
        }
    },
    {
        .mnemonic = ZYDIS_MNEMONIC_SUB,
        .operandCount = 2,
        .operands = {
            {
                .type = ZYDIS_OPERAND_TYPE_REGISTER,
                .reg = REGISTER_A
            },
            {
                .type = ZYDIS_OPERAND_TYPE_MEMORY,
                .mem = { .base = ZYDIS_REGISTER_RSP }
            }
        }
    },
    {
        .mnemonic = ZYDIS_MNEMONIC_MOV,
        .operandCount = 2,
        .operands = {
            {
                .type = ZYDIS_OPERAND_TYPE_REGISTER,
                .reg = REGISTER_B
            },
            {
                .type = ZYDIS_OPERAND_TYPE_REGISTER,
                .reg = REGISTER_A
            }
        }
    },
    {
        .mnemonic = ZYDIS_MNEMONIC_NEG,
        .operandCount = 1,
        .operands = {
            {
                .type = ZYDIS_OPERAND_TYPE_REGISTER,
                .reg = REGISTER_B
            }
        }
    },
    {
        .mnemonic = ZYDIS_MNEMONIC_CMOVS,
        .operandCount = 2,
        .operands = {
            {
                .type = ZYDIS_OPERAND_TYPE_REGISTER,
                .reg = REGISTER_B
            },
            {
                .type = ZYDIS_OPERAND_TYPE_REGISTER,
                .reg = REGISTER_A
            }
        }
    }
};

ZydisDecoder decoder{};
int regA = ZYDIS_REGISTER_NONE;
int regB = ZYDIS_REGISTER_NONE;
uint64_t numBytesPatched = 0;

bool LoadFile(const std::string& filename, std::vector<uint8_t>& buffer) {
    std::ifstream file(filename, std::ios::binary | std::ios::ate);
    if (!file) {
        return false;
    }

    size_t size = file.tellg();
    buffer.resize(size);
    file.seekg(0, std::ios::beg);
    file.read((char*)buffer.data(), size);
    return true;
}
bool SaveFile(const std::string& filename, const std::vector<uint8_t>& buffer) {
    std::ofstream file(filename, std::ios::binary);
    if (!file) {
        return false;
    }
    file.write((const char*)buffer.data(), buffer.size());
    return true;
}

uint8_t* FindSection(uint8_t* image, const char* section, size_t& size) {
    auto dos = (PIMAGE_DOS_HEADER)image;
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) {
        return 0;
    }
    auto nt = (PIMAGE_NT_HEADERS)(image + dos->e_lfanew);
    const auto imageSectionHeaders = IMAGE_FIRST_SECTION(nt);

    for (uint16_t i = 0; i < nt->FileHeader.NumberOfSections; i++) {
        PIMAGE_SECTION_HEADER header = &imageSectionHeaders[i];
        uint32_t address = header->VirtualAddress;
        uint32_t sectionSize = header->Misc.VirtualSize;
        if (!address || !sectionSize) {
            continue;
        }
        char name[IMAGE_SIZEOF_SHORT_NAME + 1]{};
        memcpy(name, header->Name, sizeof(header->Name));
        if (strcmp(section, name) != 0) {
            continue;
        }

        size = sectionSize;
        return image + header->PointerToRawData;
    }
    return 0;
}

bool CompareOperands(const PatternOperand* pattern, const ZydisDecodedOperand* code, uint8_t count) {
    for (uint8_t i = 0; i < count; i++) {
        const PatternOperand& patOp = pattern[i];
        const ZydisDecodedOperand& codeOp = code[i];
        if (patOp.type != codeOp.type) {
            return false;
        }
        if (patOp.type == ZYDIS_OPERAND_TYPE_REGISTER && patOp.reg != ZYDIS_REGISTER_NONE) {
            if (patOp.reg == REGISTER_A) {
                if (regA == ZYDIS_REGISTER_NONE) {
                    regA = codeOp.reg.value;
                }
                else if (codeOp.reg.value != regA) {
                    return false;
                }
            }
            if (patOp.reg == REGISTER_B) {
                if (regB == ZYDIS_REGISTER_NONE) {
                    regB = codeOp.reg.value;
                }
                else if (codeOp.reg.value != regB) {
                    return false;
                }
            }
        }
        if (patOp.type == ZYDIS_OPERAND_TYPE_MEMORY && patOp.mem.base != codeOp.mem.base) {
            return false;
        }
    }
    return true;
}
bool FindZydisPattern(uint8_t* bytes, size_t size, const PatternInstruction* instructions, size_t patternLen, size_t& hitOffset, size_t& patternBytesLen) {
    ZyanUSize offset = 0;
    ZydisDisassembledInstruction inst{};

    uint32_t patternIndex = 0;
    regA = ZYDIS_REGISTER_NONE;
    regB = ZYDIS_REGISTER_NONE;

    while (offset < size) {
        if (ZYAN_FAILED(ZydisDecoderDecodeFull(&decoder, bytes + offset, size - offset, &inst.info, inst.operands))) {
            offset++;
            continue;
        }

        if (instructions[patternIndex].mnemonic == inst.info.mnemonic &&
            instructions[patternIndex].operandCount <= inst.info.operand_count &&
            CompareOperands(instructions[patternIndex].operands, inst.operands, instructions[patternIndex].operandCount)) {
            if (patternIndex == 0) {
                hitOffset = offset;
            }
            patternIndex++;
            if (patternIndex == patternLen) {
                patternBytesLen = (offset - hitOffset) + inst.info.length;
                return true;
            }
        }
        else {
            patternIndex = 0;
            regA = ZYDIS_REGISTER_NONE;
            regB = ZYDIS_REGISTER_NONE;
        }
        offset += inst.info.length;
    }
    return false;
}

bool CleanDump(std::vector<uint8_t>& bytes) {
    size_t textSize = 0;
    uint8_t* text = FindSection(bytes.data(), ".text", textSize);
    if (!text) {
        return false;
    }

    if (ZYAN_FAILED(ZydisDecoderInit(&decoder, ZYDIS_MACHINE_MODE_LONG_64, ZYDIS_STACK_WIDTH_64))) {
        return false;
    }

    size_t offset = 0;
    ZydisDisassembledInstruction inst{};

    while (offset < textSize) {
        size_t hitOffset = 0;
        size_t lenBytes = 0;
        if (!FindZydisPattern(text + offset, textSize - offset, junkPattern, sizeof(junkPattern) / sizeof(*junkPattern), hitOffset, lenBytes)) {
            break;
        }
        offset += hitOffset;

        int64_t stackOffA = 0;
        int64_t stackOffB = 0;
        ZydisRegister targetRegister = ZYDIS_REGISTER_NONE;
        {
            ZyanUSize off = offset;
            ZydisDecoderDecodeFull(&decoder, text + off, textSize - off, &inst.info, inst.operands);
            stackOffA = inst.operands[1].mem.disp.value;
            off += inst.info.length;
            ZydisDecoderDecodeFull(&decoder, text + off, textSize - off, &inst.info, inst.operands);
            stackOffB = inst.operands[1].mem.disp.value;
            off += inst.info.length;
            ZydisDecoderDecodeFull(&decoder, text + off, textSize - off, &inst.info, inst.operands);
            targetRegister = inst.operands[0].reg.value;
        }

        ZydisEncoderRequest req{};
        req.mnemonic = ZYDIS_MNEMONIC_MOV;
        req.machine_mode = ZYDIS_MACHINE_MODE_LONG_64;
        req.operand_count = 2;
        req.operands[0].type = ZYDIS_OPERAND_TYPE_REGISTER;
        req.operands[0].reg.value = targetRegister;
        req.operands[1].type = ZYDIS_OPERAND_TYPE_IMMEDIATE;
        req.operands[1].imm.s = abs(stackOffA - stackOffB);

        ZyanU8 encodedInstruction[ZYDIS_MAX_INSTRUCTION_LENGTH];
        ZyanUSize encodedLength = sizeof(encodedInstruction);
        if (ZYAN_FAILED(ZydisEncoderEncodeInstruction(&req, encodedInstruction, &encodedLength))) {
            return false;
        }

        memset(text + offset, 0x90, lenBytes);
        memcpy(text + offset, encodedInstruction, encodedLength);

        numBytesPatched += lenBytes;

        offset += lenBytes;
    }

    return true;
}

int main(int argc, char* argv[]) {
    if (argc < 2) {
        char* filename = strrchr(argv[0], '\\') + 1;
        printf("Usage: %s <DumpFile> [OutputFile]\n<> = required, [] = optional\n", filename);
        return -1;
    }
    std::vector<uint8_t> fileBytes;
    if (!LoadFile(argv[1], fileBytes)) {
        printf("Failed to load %s\n", argv[1]);
        return -2;
    }
    printf("Loaded %s, patching..\n", argv[1]);

    if (!CleanDump(fileBytes)) {
        printf("Failed to clean dump\n");
        return -3;
    }
    printf("Patched %llu bytes, saving..\n", numBytesPatched);

    char* fileExtension = strrchr(argv[1], '.');
    std::string outFile = argc > 2 ?
        argv[2] :
        std::string(argv[1], fileExtension - argv[1]) + "_patched" + fileExtension;
    if (!SaveFile(outFile, fileBytes)) {
        printf("Failed to save %s\n", outFile.c_str());
        return -4;
    }
    printf("Fixed dump written to %s\n", outFile.c_str());
    return 0;
}