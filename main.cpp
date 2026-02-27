#include "CorDrv.hpp"
#include <cstdio>

typedef struct _PROCESS_BASIC_INFORMATION {
    PVOID Reserved1;
    PVOID PebBaseAddress;
    PVOID Reserved2[2];
    ULONG_PTR UniqueProcessId;
    PVOID Reserved3;
} PROCESS_BASIC_INFORMATION;

static void HexDump(const uint8_t* Data, size_t Size, uint64_t BaseAddr = 0) {
    for (size_t i = 0; i < Size; i++) {
        if (i % 16 == 0) printf("  %llX: ", (unsigned long long)(BaseAddr + i));
        printf("%02X ", Data[i]);
        if (i % 16 == 15) printf("\n");
    }
    if (Size % 16 != 0) printf("\n");
}

int main() {
    CorDrv drv;

    printf("[*] Initializing CorDrv...\n");
    if (!drv.Initialize()) { printf("[-] Failed. Is CORMEM.SYS loaded?\n"); return 1; }
    printf("[+] Driver initialized.\n\n");

    uint64_t sysDTB = drv.FindSystemDTB();
    if (!sysDTB) { printf("[-] Failed to find system DTB.\n"); return 1; }
    printf("\n");

    printf("[*] Spawning Notepad...\n");
    STARTUPINFOA si = {};
    PROCESS_INFORMATION pi = {};
    si.cb = sizeof(si);
    if (!CreateProcessA(nullptr, (LPSTR)"notepad.exe", nullptr, nullptr, FALSE, 0, nullptr, nullptr, &si, &pi)) {
        printf("[-] CreateProcess failed.\n"); return 1;
    }
    WaitForInputIdle(pi.hProcess, 3000);

    PROCESS_BASIC_INFORMATION pbi = {};
    auto NtQueryInformationProcess = reinterpret_cast<NTSTATUS(NTAPI*)(HANDLE, ULONG, PVOID, ULONG, PULONG)>(
        GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtQueryInformationProcess"));

    NtQueryInformationProcess(pi.hProcess, 0, &pbi, sizeof(pbi), nullptr);
    uint64_t pebAddr = reinterpret_cast<uint64_t>(pbi.PebBaseAddress);

    uint64_t base = 0;
    ReadProcessMemory(pi.hProcess, (LPCVOID)(pebAddr + 0x10), &base, sizeof(base), nullptr);

    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);

    printf("[+] PID: %u\n", pi.dwProcessId);
    printf("[+] Base: 0x%llX\n\n", (unsigned long long)base);

    uint64_t npDTB = drv.FindProcessDTB(pi.dwProcessId);
    if (!npDTB) { printf("[-] Failed to find DTB.\n"); return 1; }
    printf("\n");

    uint64_t phys = drv.TranslateVirtualAddress(npDTB, base);
    if (!phys) { printf("[-] Page table walk failed.\n"); return 1; }
    printf("[+] VA 0x%llX -> PA 0x%llX\n\n", (unsigned long long)base, (unsigned long long)phys);

    uint8_t header[0x100] = {};
    if (!drv.ReadProcessMemory(npDTB, base, header, sizeof(header))) {
        printf("[-] ReadProcessMemory failed.\n"); return 1;
    }

    if (header[0] == 'M' && header[1] == 'Z')
        printf("[+] MZ verified! Cross-process read success!\n\n");
    else
        printf("[?] No MZ (0x%02X 0x%02X)\n\n", header[0], header[1]);

    printf("Notepad PE header:\n");
    HexDump(header, 0x80, base);

    printf("\n[+] Done.\n");
    return 0;
}