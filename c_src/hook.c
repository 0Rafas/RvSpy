#include <stdint.h>
#include <windows.h>
#include <string.h>

// RvSpy Hooking Engine (x64)
// This file provides low-level trampoline support for inline hooking.

#pragma pack(push, 1)
typedef struct _JMP_ABS64 {
    uint8_t  opcode[2]; /* 0xFF 0x25 */
    uint32_t offset;    /* 0x00000000 */
    uint64_t address;   /* target address */
} JMP_ABS64;
#pragma pack(pop)


/**
 * Installs an absolute 64-bit jump hook.
 */
BOOL InstallNativeHook(LPVOID target, LPVOID detour, LPVOID *original) {
    DWORD oldProtect;
    if (!VirtualProtect(target, sizeof(JMP_ABS64), PAGE_EXECUTE_READWRITE, &oldProtect)) {
        return FALSE;
    }

    *original = target;

    JMP_ABS64 jmp;
    jmp.opcode[0] = 0xFF;
    jmp.opcode[1] = 0x25;
    jmp.offset = 0;
    jmp.address = (uint64_t)detour;

    memcpy(target, &jmp, sizeof(JMP_ABS64));

    VirtualProtect(target, sizeof(JMP_ABS64), oldProtect, &oldProtect);
    return TRUE;
}
