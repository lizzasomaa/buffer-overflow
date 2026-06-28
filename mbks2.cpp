#undef UNICODE
#undef _UNICODE
#include <Windows.h>
#include <tlhelp32.h>

#define TO_LOWERCASE(out, c1) (out = (c1 <= 'Z' && c1 >= 'A') ? c1 = (c1 - 'A') + 'a' : c1)

typedef struct _UNICODE_STRING {
    USHORT Length;
    USHORT MaximumLength;
    PWSTR Buffer;
} UNICODE_STRING, * PUNICODE_STRING;

typedef struct _PEB_LDR_DATA {
    ULONG Length;
    BOOLEAN Initialized;
    HANDLE SsHandle;
    LIST_ENTRY InLoadOrderModuleList;
    LIST_ENTRY InMemoryOrderModuleList;
    LIST_ENTRY InInitializationOrderModuleList;
    PVOID EntryInProgress;
} PEB_LDR_DATA, * PPEB_LDR_DATA;

typedef struct _LDR_DATA_TABLE_ENTRY {
    LIST_ENTRY InLoadOrderModuleList;
    LIST_ENTRY InMemoryOrderModuleList;
    LIST_ENTRY InInitializationOrderModuleList;
    void* BaseAddress;
    void* EntryPoint;
    ULONG SizeOfImage;
    UNICODE_STRING FullDllName;
    UNICODE_STRING BaseDllName;
    ULONG Flags;
    SHORT LoadCount;
    SHORT TlsIndex;
    HANDLE SectionHandle;
    ULONG CheckSum;
    ULONG TimeDateStamp;
} LDR_DATA_TABLE_ENTRY, * PLDR_DATA_TABLE_ENTRY;

typedef struct _PEB {
    BOOLEAN InheritedAddressSpace;
    BOOLEAN ReadImageFileExecOptions;
    BOOLEAN BeingDebugged;
    BOOLEAN SpareBool;
    HANDLE Mutant;
    PVOID ImageBaseAddress;
    PPEB_LDR_DATA Ldr;
} PEB, * PPEB;

inline LPVOID get_module_by_name(WCHAR* module_name) {
    PPEB peb = (PPEB)__readfsdword(0x30);
    PPEB_LDR_DATA ldr = peb->Ldr;
    LIST_ENTRY list = ldr->InLoadOrderModuleList;
    PLDR_DATA_TABLE_ENTRY curr = *((PLDR_DATA_TABLE_ENTRY*)(&list));
    while (curr != NULL && curr->BaseAddress != NULL) {
        if (curr->BaseDllName.Buffer == NULL) {
            curr = (PLDR_DATA_TABLE_ENTRY)curr->InLoadOrderModuleList.Flink;
            continue;
        }
        WCHAR* curr_name = curr->BaseDllName.Buffer;
        size_t i = 0;
        for (i = 0; module_name[i] != 0 && curr_name[i] != 0; i++) {
            WCHAR c1, c2;
            TO_LOWERCASE(c1, module_name[i]);
            TO_LOWERCASE(c2, curr_name[i]);
            if (c1 != c2) break;
        }
        if (module_name[i] == 0 && curr_name[i] == 0)
            return curr->BaseAddress;
        curr = (PLDR_DATA_TABLE_ENTRY)curr->InLoadOrderModuleList.Flink;
    }
    return NULL;
}

inline LPVOID get_func_by_name(LPVOID module, char* func_name) {
    IMAGE_DOS_HEADER* idh = (IMAGE_DOS_HEADER*)module;
    if (idh->e_magic != IMAGE_DOS_SIGNATURE) return NULL;
    IMAGE_NT_HEADERS* nt = (IMAGE_NT_HEADERS*)((BYTE*)module + idh->e_lfanew);
    IMAGE_DATA_DIRECTORY* expDir =
        &(nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT]);
    if (expDir->VirtualAddress == NULL) return NULL;
    IMAGE_EXPORT_DIRECTORY* exp =
        (IMAGE_EXPORT_DIRECTORY*)((BYTE*)module + expDir->VirtualAddress);
    DWORD* names = (DWORD*)((BYTE*)module + exp->AddressOfNames);
    WORD* ords = (WORD*)((BYTE*)module + exp->AddressOfNameOrdinals);
    DWORD* funcs = (DWORD*)((BYTE*)module + exp->AddressOfFunctions);
    for (SIZE_T i = 0; i < exp->NumberOfNames; i++) {
        char* curr_name = (char*)((BYTE*)module + names[i]);
        size_t k = 0;
        for (k = 0; func_name[k] != 0 && curr_name[k] != 0; k++)
            if (func_name[k] != curr_name[k]) break;
        if (func_name[k] == 0 && curr_name[k] == 0)
            return (BYTE*)module + funcs[ords[i]];
    }
    return NULL;
}

int main() {
    wchar_t k32name[] = { 'k','e','r','n','e','l','3','2','.','d','l','l',0 };
    LPVOID k32 = get_module_by_name(k32name);

    char gpaName[] = { 'G','e','t','P','r','o','c','A','d','d','r','e','s','s',0 };
    FARPROC(WINAPI * GetProcAddress_)(HMODULE, LPCSTR) =
        (FARPROC(WINAPI*)(HMODULE, LPCSTR))get_func_by_name(k32, gpaName);

    char snapName[] = { 'C','r','e','a','t','e','T','o','o','l','h','e','l','p',
                       '3','2','S','n','a','p','s','h','o','t',0 };
    HANDLE(WINAPI * CreateSnapshot_)(DWORD, DWORD) =
        (HANDLE(WINAPI*)(DWORD, DWORD))GetProcAddress_((HMODULE)k32, snapName);

    char p32fName[] = { 'P','r','o','c','e','s','s','3','2','F','i','r','s','t',0 };
    BOOL(WINAPI * Process32First_)(HANDLE, LPPROCESSENTRY32) =
        (BOOL(WINAPI*)(HANDLE, LPPROCESSENTRY32))GetProcAddress_((HMODULE)k32, p32fName);

    char p32nName[] = { 'P','r','o','c','e','s','s','3','2','N','e','x','t',0 };
    BOOL(WINAPI * Process32Next_)(HANDLE, LPPROCESSENTRY32) =
        (BOOL(WINAPI*)(HANDLE, LPPROCESSENTRY32))GetProcAddress_((HMODULE)k32, p32nName);

    char opName[] = { 'O','p','e','n','P','r','o','c','e','s','s',0 };
    HANDLE(WINAPI * OpenProcess_)(DWORD, BOOL, DWORD) =
        (HANDLE(WINAPI*)(DWORD, BOOL, DWORD))GetProcAddress_((HMODULE)k32, opName);

    char iwName[] = { 'I','s','W','o','w','6','4','P','r','o','c','e','s','s',0 };
    BOOL(WINAPI * IsWow64Process_)(HANDLE, PBOOL) =
        (BOOL(WINAPI*)(HANDLE, PBOOL))GetProcAddress_((HMODULE)k32, iwName);

    char chName[] = { 'C','l','o','s','e','H','a','n','d','l','e',0 };
    BOOL(WINAPI * CloseHandle_)(HANDLE) =
        (BOOL(WINAPI*)(HANDLE))GetProcAddress_((HMODULE)k32, chName);

    char gshName[] = { 'G','e','t','S','t','d','H','a','n','d','l','e',0 };
    HANDLE(WINAPI * GetStdHandle_)(DWORD) =
        (HANDLE(WINAPI*)(DWORD))GetProcAddress_((HMODULE)k32, gshName);

    char wcName[] = { 'W','r','i','t','e','C','o','n','s','o','l','e','A',0 };
    BOOL(WINAPI * WriteConsole_)(HANDLE, LPCVOID, DWORD, LPDWORD, LPVOID) =
        (BOOL(WINAPI*)(HANDLE, LPCVOID, DWORD, LPDWORD, LPVOID))GetProcAddress_((HMODULE)k32, wcName);

    char lstrlenName[] = { 'l','s','t','r','l','e','n','A',0 };
    int(WINAPI * lstrlenA_)(LPCSTR) =
        (int(WINAPI*)(LPCSTR))GetProcAddress_((HMODULE)k32, lstrlenName);

    HANDLE hOut = GetStdHandle_(STD_OUTPUT_HANDLE);
    HANDLE snap = CreateSnapshot_(TH32CS_SNAPPROCESS, 0);

    PROCESSENTRY32 pe;
    pe.dwSize = sizeof(pe);
    DWORD written;

    if (Process32First_(snap, &pe)) {
        do {
            HANDLE hProc = OpenProcess_(PROCESS_QUERY_INFORMATION,
                FALSE, pe.th32ProcessID);
            BOOL isWow64 = FALSE;
            if (hProc) {
                IsWow64Process_(hProc, &isWow64);
                CloseHandle_(hProc);
            }
            WriteConsole_(hOut, pe.szExeFile,
                lstrlenA_(pe.szExeFile), &written, NULL);
            char sep[] = { ' ','=',' ',0 };
            WriteConsole_(hOut, sep, 3, &written, NULL);
            char bits32[] = { '3','2','-','b','i','t',0 };
            char bits64[] = { '6','4','-','b','i','t',0 };
            char* bits = isWow64 ? bits32 : bits64;
            WriteConsole_(hOut, bits, 6, &written, NULL);
            char nl[] = { '\r','\n',0 };
            WriteConsole_(hOut, nl, 2, &written, NULL);
        } while (Process32Next_(snap, &pe));
    }

    CloseHandle_(snap);

    char exitName[] = { 'E','x','i','t','P','r','o','c','e','s','s',0 };
    VOID(WINAPI * ExitProcess_)(int) =
        (VOID(WINAPI*)(int))GetProcAddress_((HMODULE)k32, exitName);
    ExitProcess_(0);
}