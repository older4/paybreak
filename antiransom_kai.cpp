/***************************************************************************************************
* PayBreak
* Eugene Kolo | eugene@eugenekolo.com | 2017
*
* Hook and trampoline into the MS Crypto API - Replaces Real_Crypt* with Fake_Crypt*
* Record calls, and trampoline back to the real functions.
* Recorded calls are logged in `C:\Users\Public\CryptoHookLog.dl"`
*
***************************************************************************************************/

#include <stdio.h>
#include <windows.h>
#include <string>
#include <wincrypt.h>
#include <bcrypt.h>
#include "detours/detours.h"
#include <tchar.h>
#include "antiransom.h"

#include "spdlog/spdlog.h"
#include "spdlog/async.h"
#include "spdlog/sinks/basic_file_sink.h"

#include <atlconv.h>
#include <atlstr.h>

#pragma comment (lib, "advapi32")
#pragma comment (lib, "user32")
#pragma comment (lib, "detours/detours")
#pragma comment (lib, "bcrypt.lib")
#pragma comment (lib, "ntdll")

static DWORD g_dwKeyBlobLen_Exfil = 0;
static PBYTE g_pbKeyBlob_Exfil = NULL;
static BOOL recursive = FALSE;
static BOOL recursive2 = FALSE;

// Works for Crypto++563-Debug
const DWORD NEEDLE_SIZE = 32;
char NEEDLE[NEEDLE_SIZE] = {0x55, 0x89, 0xE5, 0x53, 0x83, 0xEC, 0x24, 0x89, 0x4D, 0xF4, 0x8B, 0x45, 0xF4, 0x8B, 0x55, 0x0C,
                            0x89, 0x14, 0x24, 0x89, 0xC1, 0xE8, 0x8A, 0x02, 0x00, 0x00, 0x83, 0xEC, 0x04, 0x8B, 0x45, 0x00};

/* This is a hack to not find the needle in this DLL's memory */
int dudd1 = 0x123123;
int dudd2 = 0x123123;
int dudd3 = 0x123123;
int dudd4 = 0x123123;
char NEEDLE_END = 0xF4;

/***********************************************************************************************/
/* Our trampoline functions */
/***********************************************************************************************/
/* Crypto API functions */
BOOL WINAPI Fake_CryptDecrypt(HCRYPTKEY hKey, HCRYPTHASH hHash, BOOL Final, DWORD dwFlags, BYTE* pbData,
  DWORD* pdwDataLen) {
    OutputDebugString("Fake_CryptDecrypt loaded");
    // spdlog::debug("Fake_CryptDecrypt loaded");
    // spdlog::debug("\t HCRYPTKEY hKey = %x", hKey);
    // spdlog::debug("\t HCRYPTHASH hHash = %x", hHash);
    // spdlog::debug("\t BOOL Final = %x", Final);
    // spdlog::debug("\t DWORD dwFlags = %x", dwFlags);
    // spdlog::debug("\t BYTE* pbData = %x, *pbdata = %s", pbData, "BROKEN");
    // spdlog::debug("\t DWORD* pdwDataLen = %x, *pdwDataLen = ", pdwDataLen);

    if (pdwDataLen != NULL) {
        // spdlog::debug("%x", *pdwDataLen);
    } else {
        // spdlog::debug("NUL");
    }
    // spdlog::debug("");
    return Real_CryptDecrypt(hKey, hHash, Final, dwFlags, pbData, pdwDataLen);
}

BOOL WINAPI Fake_CryptSetKeyParam(HCRYPTKEY hKey, DWORD dwParam, BYTE* pbData, DWORD dwFlags) {
    OutputDebugString("Fake_CryptSetKeyParam loaded");
    std::string mytime = CurrentTime();

    // spdlog::debug("[CryptSetKeyParam] %s", mytime.c_str());
    // spdlog::debug("\t HCRYPTKEY hKey = %x", hKey);
    // spdlog::debug("\t DWORD dwParam = %x", dwParam);
    // spdlog::debug("\t BYTE* pbData = %x, *pbData = ", pbData);
    if (pbData != NULL) {
        // spdlog::debug("%x", "This requires extra work, as pbData depends on the value of dwParam");
    } else {
        // spdlog::debug("NUL");
    }
    // spdlog::debug("\t DWORD dwFlags = %x", dwFlags);

    // Print out some key params
    DWORD dwCount;
    BYTE pbData2[16];
    CryptGetKeyParam(hKey, KP_IV, NULL, &dwCount, 0); // Get size of KP_IV
    CryptGetKeyParam(hKey, KP_IV, pbData2, &dwCount, 0); // Get KP_IV data
    // spdlog::debug("KP_IV =  ");
    for (int i = 0 ; i < dwCount ; i++) {
        // spdlog::debug("%02x ",pbData2[i]);
    }

    return Real_CryptSetKeyParam(hKey, dwParam, pbData, dwFlags);

}


BOOL WINAPI Fake_CryptEncrypt(HCRYPTKEY hKey, HCRYPTHASH hHash, BOOL Final, DWORD dwFlags, BYTE* pbData,
  DWORD* pdwDataLen, DWORD dwBufLen) {
    OutputDebugString("Fake_CryptEncrypt loaded");

    // spdlog::debug("[CryptEncrypt] %s", mytime.c_str());
    // spdlog::debug("\t HCRYPTKEY hKey = %x", hKey);
    // spdlog::debug("\t HCRYPTHASH hHash = %x", hHash);
    // spdlog::debug("\t BOOL Final = %x", Final);
    // spdlog::debug("\t DWORD dwFlags = %x", dwFlags);
    // spdlog::debug("\t BYTE* pbData = %x, *pbdata = %s", pbData, "BROKEN");
    // spdlog::debug("\t DWORD* pdwDataLen = %x, *pdwDataLen = %s", pdwDataLen, "BROKEN");
    // spdlog::debug("\t DWORD dwBufLen = %x", dwBufLen);

    DWORD dwCount;
    BYTE pbData2[16];
    CryptGetKeyParam(hKey, KP_IV, NULL, &dwCount, 0); // Get size of KP_IV
    CryptGetKeyParam(hKey, KP_IV, pbData2, &dwCount, 0); // Get KP_IV data
    // spdlog::debug("KP_IV =  ");
    for (int i = 0 ; i < dwCount ; i++) {
        // spdlog::debug("%02x ",pbData2[i]);
    }

    if (recursive == FALSE) {
        recursive = TRUE;
        if (pbData == NULL) {
            // CryptEncrypt being used to get allocation size for cipher data
            if(!Real_CryptExportKey(hKey, NULL, PLAINTEXTKEYBLOB, 0, NULL, &g_dwKeyBlobLen_Exfil)){
                MyHandleError(TEXT("[FAIL] Exfil key length failed "), GetLastError());
                // spdlog::debug("[FAIL] Exfil key length failed ");
            }
            // spdlog::debug("\t ExfilKeyLen = %d", g_dwKeyBlobLen_Exfil);
        }
        else if (g_dwKeyBlobLen_Exfil != NULL) {
            // CryptEncrypt is encrypting data, and was used to get the allocation size
            g_pbKeyBlob_Exfil = (BYTE*)malloc(g_dwKeyBlobLen_Exfil);
            if (!Real_CryptExportKey(hKey, NULL, PLAINTEXTKEYBLOB, 0, g_pbKeyBlob_Exfil, &g_dwKeyBlobLen_Exfil)){
                MyHandleError(TEXT("[FAIL] Exfil key length failed "), GetLastError());
                // spdlog::debug("[FAIL] Exfil key data failed ");
            }
            // spdlog::debug("\t ExfilKeyData = ");
            for (int i = 0 ; i < g_dwKeyBlobLen_Exfil ; i++) {
                // spdlog::debug("%02x",g_pbKeyBlob_Exfil[i]);
            }
            // spdlog::debug("");
        }
        else {
            // CryptEncrypt is encrypting data, and was NOT called to get the alloca size
            // Do the export in one step.

            // Get the size to allocate for the export blob
            if(!Real_CryptExportKey(hKey, NULL, PLAINTEXTKEYBLOB, 0, NULL, &g_dwKeyBlobLen_Exfil)){
                MyHandleError(TEXT("[FAIL] no-alloca Exfil key length failed "), GetLastError());
                // spdlog::debug("[FAIL] no-alloca Exfil key length failed ");
            }

            g_pbKeyBlob_Exfil = (BYTE*)malloc(g_dwKeyBlobLen_Exfil);

            // Get the export blob
            if (!Real_CryptExportKey(hKey, NULL, PLAINTEXTKEYBLOB, 0, g_pbKeyBlob_Exfil, &g_dwKeyBlobLen_Exfil)){
                MyHandleError(TEXT("[FAIL] Exfil key data failed "), GetLastError());
                // spdlog::debug("[FAIL] no-alloca Exfil key data failed ");
            }

            // Print the export blob
            // spdlog::debug("\t no-alloca ExfilKeyData = ");
            for (int i = 0 ; i < g_dwKeyBlobLen_Exfil ; i++) {
                // spdlog::debug("%02x", g_pbKeyBlob_Exfil[i]);
            }
            // spdlog::debug("");

            //free(pbKeyBlob);
        }
            recursive = FALSE;
    }

    return Real_CryptEncrypt(hKey, hHash, Final, dwFlags, pbData, pdwDataLen, dwBufLen);
}

BOOL WINAPI Fake_CryptAcquireContext(HCRYPTPROV* phProv, LPCTSTR pszContainer, LPCTSTR pszProvider, DWORD dwProvType,
  DWORD dwFlags) {
    OutputDebugString("Fake_CryptAcquireContext loaded");
    std::string mytime = CurrentTime();
    char buf[512];
    sprintf_s(buf, "HCRYPTPROV* phProv %x, LPCTSTR pszContainer %s, LPCTSTR pszProvider %s, DWORD dwProvType %x,",
        phProv, pszContainer, pszProvider, dwProvType);
    OutputDebugString(buf);
    // spdlog::debug("[CryptAcquireContext] %s", mytime.c_str());
    // spdlog::debug("\t HCRYPTPROV* phProv = %x, *phProv = %s", phProv, "OUTPUT, so probably can't deref NUL");
    // spdlog::debug("\t LPCTSTR pszContainer = %s", pszContainer);
    // spdlog::debug("\t LPCTSTR pszProvider = %s", pszProvider);
    // spdlog::debug("\t DWORD dwProvType = %x", dwProvType);
    // spdlog::debug("\t DWORD dwFlags = %x", dwFlags);

    return Real_CryptAcquireContext(phProv, pszContainer, pszProvider, dwProvType, dwFlags);
}

BOOL WINAPI Fake_CryptCreateHash(HCRYPTPROV hProv, ALG_ID Algid, HCRYPTKEY hKey, DWORD dwFlags,
  HCRYPTHASH* phHash) {
    OutputDebugString("Fake_CryptCreateHash loaded");

    // spdlog::debug("[CryptCreateHash] %s", mytime.c_str());
    // spdlog::debug("\t HCRYPTPROV hProv = %x", hProv);
    // spdlog::debug("\t ALG_ID Algid = %x", Algid);
    // spdlog::debug("\t HCRYPTKEY hKey = %x", hKey);
    // spdlog::debug("\t DWORD dwFlags = %x", dwFlags);
    // spdlog::debug("\t HCRYPTHASH* phHash = %x, *phHash = %s", phHash, "OUTPUT, so probably can't deref NUL");

    return Real_CryptCreateHash(hProv, Algid, hKey,dwFlags, phHash);
}

BOOL WINAPI Fake_CryptHashData(HCRYPTHASH hHash, BYTE* pbData, DWORD dwDataLen, DWORD dwFlags) {
    OutputDebugString("Fake_CryptHashData loaded");

    // spdlog::debug("[CryptHashData] %s", mytime.c_str());
    // spdlog::debug("\t HCRYPTHASH hHash = %x", hHash);
    // spdlog::debug("\t BYTE* pbData = %x, *pbData = ", pbData);
    if (pbData != NULL) {
        for (int i = 0; i < dwDataLen; i++) {
            // spdlog::debug("%x", pbData[i]);
        }
    } else {
        // spdlog::debug("NUL");
    }
    // spdlog::debug("");
    // spdlog::debug("\t DWORD dwDataLen = %x", dwDataLen);
    // spdlog::debug("\t DWORD dwFlags = %x", dwFlags);

    return Real_CryptHashData(hHash, pbData, dwDataLen, dwFlags);
}

BOOL WINAPI Fake_CryptDeriveKey(HCRYPTPROV hProv, ALG_ID Algid, HCRYPTHASH hBaseData, DWORD dwFlags,
  HCRYPTKEY* phKey) {
    OutputDebugString("Fake_CryptDeriveKey loaded");

    // spdlog::debug("[CryptDeriveKey] %s", mytime.c_str());
    // spdlog::debug("\t HCRYPTPROV hProv = %x", hProv);
    // spdlog::debug("\t ALG_ID Algid = %x", Algid);
    // spdlog::debug("\t HCRYPTHASH hBaseData = %x", hBaseData);
    // spdlog::debug("\t DWORD dwFlags = %x", dwFlags);
    // spdlog::debug("\t HCRYPTKEY* phKey = %x, *phKey = %s", phKey, "Cannot deref the key directly");

    return Real_CryptDeriveKey(hProv, Algid, hBaseData, dwFlags | CRYPT_EXPORTABLE, phKey);
}

BOOL WINAPI Fake_CryptGenKey(HCRYPTPROV hProv, ALG_ID Algid, DWORD dwFlags, HCRYPTKEY* phKey) {
    OutputDebugString("Fake_CryptGenKey loaded");

    // spdlog::debug("[CryptGenKey] %s", mytime.c_str());
    // spdlog::debug("\t HCRYPTPROV hProv = %x", hProv);
    // spdlog::debug("\t ALG_ID Algid = %x", Algid);
    // spdlog::debug("\t DWORD dwFlags = %x", dwFlags);
    // spdlog::debug("\t HCRYPTKEY* phKey = %x, *phKey = %s", phKey, "Cannot deref the key directly");

    return Real_CryptGenKey(hProv, Algid, dwFlags | CRYPT_EXPORTABLE, phKey);
}

BOOL WINAPI Fake_CryptGenRandom(HCRYPTPROV hProv, DWORD dwLen, BYTE* pbBuffer) {
    OutputDebugString("Fake_CryptGenRandom loaded");
    std::string mytime = CurrentTime();

    // spdlog::debug("[CryptGenRandom] %s", mytime.c_str());
    // spdlog::debug("\t HCRYPTPROV hProv = %x", hProv);
    // spdlog::debug("\t DWORD dwLen = %x", dwLen);

    // spdlog::debug("\t BYTE* pbBuffer = %x, *pbBuffer = OUTPUT, cannot deref", pbBuffer);

    BOOL ret = Real_CryptGenRandom(hProv, dwLen, pbBuffer);

    // spdlog::debug("\t RandomData = ");
    for (int i = 0 ; i < dwLen ; i++) {
        // spdlog::debug("%02x",pbBuffer[i]);
    }
    // spdlog::debug("");

    return ret;
}

BOOL WINAPI Fake_CryptImportKey(HCRYPTPROV hProv, BYTE* pbData, DWORD dwDataLen, HCRYPTKEY hPubKey,
  DWORD dwFlags, HCRYPTKEY* phKey) {
    OutputDebugString("Fake_CryptImportKey loaded");

    // spdlog::debug("[CryptImportKey] %s", mytime.c_str());
    // spdlog::debug("\t HCRYPTPROV hProv = %x", hProv);
    // spdlog::debug("\t BYTE* pbData = %x, *pbData = %s", pbData, "BROKEN");
    // spdlog::debug("\t DWORD dwDataLen = %x", dwDataLen);
    // spdlog::debug("\t HCRYPTKEY hPubKey = %x", hPubKey);
    // spdlog::debug("\t DWORD dwFlags = %x", dwFlags);
    // spdlog::debug("\t HCRYPTKEY* phKey = %x, *phKey = %s", phKey, "BROKEN");

    return Real_CryptImportKey(hProv, pbData, dwDataLen, hPubKey, dwFlags|CRYPT_EXPORTABLE, phKey);
}

BOOL WINAPI Fake_CryptExportKey(HCRYPTKEY hKey, HCRYPTKEY hExpKey, DWORD dwBlobType, DWORD dwFlags,
  BYTE* pbData, DWORD* pdwDataLen) {
    OutputDebugString("Fake_CryptExportKey loaded");
    std::string mytime = CurrentTime();

    // spdlog::debug("[CryptExportKey] %s", mytime.c_str());
    // spdlog::debug("\t HCRYPTKEY hKey = %x", hKey);
    // spdlog::debug("\t HCRYPTKEY hExpKey = %x", hExpKey);
    // spdlog::debug("\t DWORD dwBlobType = %x", dwBlobType);
    // spdlog::debug("\t DWORD dwFlags = %x", dwFlags);
    // spdlog::debug("\t BYTE* pbData = %x, *pbData = %s", pbData, "BROKEN");
    // spdlog::debug("\t DWORD* pdwDataLen = %x, *pdwDataLen = %d", pdwDataLen, *pdwDataLen);

    if (recursive == FALSE) {
        recursive = TRUE;
        if (pbData == NULL) {
            // CryptEncrypt being used to get allocation size for cipher data
            if(!Real_CryptExportKey(hKey, NULL, PLAINTEXTKEYBLOB, 0, NULL, &g_dwKeyBlobLen_Exfil)){
                MyHandleError(TEXT("[FAIL] Exfil key length failed "), GetLastError());
                // spdlog::debug("[FAIL] Exfil key length failed ");
            }
            // spdlog::debug("\t ExfilKeyLen = %d", g_dwKeyBlobLen_Exfil);
        }
        else if (g_dwKeyBlobLen_Exfil != NULL) {
            // CryptEncrypt is encrypting data, and was used to get the allocation size
            g_pbKeyBlob_Exfil = (BYTE*)malloc(g_dwKeyBlobLen_Exfil);
            if (!Real_CryptExportKey(hKey, NULL, PLAINTEXTKEYBLOB, 0, g_pbKeyBlob_Exfil, &g_dwKeyBlobLen_Exfil)){
                MyHandleError(TEXT("[FAIL] Exfil key data failed "), GetLastError());
                // spdlog::debug("[FAIL] Exfil key data failed ");
            }
            // spdlog::debug("\t ExfilKeyData = ");
            for (int i = 0 ; i < g_dwKeyBlobLen_Exfil ; i++) {
                // spdlog::debug("%02x",g_pbKeyBlob_Exfil[i]);
            }
            // spdlog::debug("");
        }
        else {
            // CryptEncrypt is encrypting data, and was NOT called to get the alloca size
            // Do the export in one step.

            // Get the size to allocate for the export blob
            if(!Real_CryptExportKey(hKey, NULL, PLAINTEXTKEYBLOB, 0, NULL, &g_dwKeyBlobLen_Exfil)){
                MyHandleError(TEXT("[FAIL] Exfil key length failed "), GetLastError());
                // spdlog::debug("[FAIL] Exfil key length failed ");
            }

            g_pbKeyBlob_Exfil = (BYTE*)malloc(g_dwKeyBlobLen_Exfil);

            // Get the export blob
            if (!Real_CryptExportKey(hKey, NULL, PLAINTEXTKEYBLOB, 0, g_pbKeyBlob_Exfil, &g_dwKeyBlobLen_Exfil)){
                MyHandleError(TEXT("[FAIL] Exfil key data failed "), GetLastError());
                // spdlog::debug("[FAIL] Exfil key data failed ");
            }

            // Print the export blob
            // spdlog::debug("\t ExfilKeyData = ");
            for (int i = 0 ; i < g_dwKeyBlobLen_Exfil ; i++) {
                // spdlog::debug("%02x", g_pbKeyBlob_Exfil[i]);
            }
            // spdlog::debug("");

            //free(pbKeyBlob);
        }
            recursive = FALSE;
    }

    return Real_CryptExportKey(hKey, hExpKey, dwBlobType, dwFlags, pbData, pdwDataLen);
}

///////////////////////////////////////////////////////////////////////////////////////////////////
/* CryptoNG API functions */
NTSTATUS WINAPI Fake_BCryptEncrypt(BCRYPT_KEY_HANDLE hKey, PUCHAR pbInput, ULONG cbInput, VOID *pPaddingInfo,
  PUCHAR pbIV, ULONG cbIV, PUCHAR pbOutput, ULONG cbOutput, ULONG *pcbResult, ULONG dwFlags) {
    OutputDebugString("Fake_BCryptEncrypt loaded");
    // spdlog::debug("[BCryptEncrypt] %s", mytime.c_str());

    return Real_BCryptEncrypt(hKey, pbInput, cbInput, pPaddingInfo, pbIV, cbIV, pbOutput, cbOutput,
        pcbResult, dwFlags);
}


///////////////////////////////////////////////////////////////////////////////////////////////////
/* File functions */
HFILE WINAPI Fake_OpenFile(LPCSTR lpFileName, LPOFSTRUCT lpReOpenBuff, UINT uStyle) {
    OutputDebugString("Fake_OpenFile loaded");
    USES_CONVERSION;
    spdlog::debug("\t LPCSTR lpFileName = %s", lpFileName);
    return Real_OpenFile(lpFileName, lpReOpenBuff, uStyle);
    spdlog::drop_all();
}

NTSTATUS WINAPI Fake_NtOpenFile(PHANDLE FileHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes,
  PIO_STATUS_BLOCK IoStatusBlock, ULONG ShareAccess, ULONG OpenOptions) {
    OutputDebugString("Fake_NtOpenFile loaded");
    //std::string mytime = CurrentTime();

    PUNICODE_STRING FileName = ObjectAttributes->ObjectName;
    //spdlog::debug("\t PUNICODE_STRING lpFileName = %s", filename_s +4);

    

  return Real_NtOpenFile(FileHandle, DesiredAccess, ObjectAttributes, IoStatusBlock, ShareAccess, OpenOptions);
}

HANDLE WINAPI Fake_CreateFile(LPCTSTR lpFileName, DWORD dwDesiredAccess, DWORD dwShareMode,
  LPSECURITY_ATTRIBUTES lpSecurityAttributes, DWORD dwCreationDisposition,DWORD dwFlagsAndAttributes, HANDLE hTemplateFile) {
    OutputDebugString("Fake_CreateFile loaded");
    spdlog::debug("\t LPCSTR lpFileName = %s", lpFileName);
    spdlog::drop_all();
    return Real_CreateFile(lpFileName, dwDesiredAccess, dwShareMode, lpSecurityAttributes, dwCreationDisposition, dwFlagsAndAttributes, hTemplateFile);
}



NTSTATUS WINAPI Fake_NtCreateFile(PHANDLE FileHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, PIO_STATUS_BLOCK IoStatusBlock,
  PLARGE_INTEGER AllocationSize, ULONG FileAttributes, ULONG ShareAccess, ULONG CreateDisposition, ULONG CreateOptions, PVOID EaBuffer,
  ULONG EaLength) {
    OutputDebugString("Fake_NtCreateFile loaded");
    return Real_NtCreateFile(FileHandle, DesiredAccess, ObjectAttributes, IoStatusBlock, AllocationSize, FileAttributes,
        ShareAccess, CreateDisposition, CreateOptions, EaBuffer, EaLength);
}

/*
BOOL WINAPI Fake_ReadFile(HANDLE hFile, LPVOID lpBuffer, DWORD nNumberOfBytesToRead, LPDWORD lpNumberOfBytesRead, LPOVERLAPPED lpOverlapped) {
    FILE* *fd = fopen("C:\\CryptoHookLog.dl", "a");
    std::string mytime = CurrentTime();
    // spdlog::debug("[ReadFile] %s", mytime.c_str());

    if (Real_HookedSig == NULL) {
        unsigned char* sig_address = search_memory(NEEDLE, NEEDLE_END, NEEDLE_SIZE);
        //printf("[fake_readfile] Setting real_hookedsig");
        if (sig_address != NULL) {
            Real_HookedSig = (void (__thiscall*)(void*, const BYTE*, size_t, DWORD*))sig_address;
            //printf("[fake_readfile] sig_address = [%08x]", sig_address);
            //printf("[fake_readfile] Real_HookedSig = [%08x]", Real_HookedSig);
            DetourTransactionBegin();
            DetourUpdateThread(GetCurrentThread());
            DetourAttach(&(PVOID&)Real_HookedSig, Fake_HookedSig);
            //printf("[fake_readfile2] Real_HookedSig = [%08x]", Real_HookedSig);
            DetourTransactionCommit();
        }
    }

    if (Real_HookedSig != NULL) {
        // ReadFile's job is done...
        DetourTransactionBegin();
        DetourUpdateThread(GetCurrentThread());
        DetourDetach(&(PVOID&)Real_ReadFile, Fake_ReadFile);
        DetourTransactionCommit();
    }

    return Real_ReadFile(hFile, lpBuffer, nNumberOfBytesToRead, lpNumberOfBytesRead, lpOverlapped);
}
*/
/*
NTSTATUS WINAPI Fake_NtReadFile(HANDLE FileHandle, HANDLE Event, PIO_APC_ROUTINE ApcRoutine, PVOID ApcContext,
  PIO_STATUS_BLOCK IoStatusBlock, PVOID Buffer, ULONG Length, PLARGE_INTEGER ByteOffset, PULONG Key) {
    FILE* *fd = fopen("C:\\CryptoHookLog.dl", "a");
    std::string mytime = CurrentTime();
    // spdlog::debug("[NtReadFile] %s", mytime.c_str());

    if (Real_HookedSig == NULL) {
        unsigned char* sig_address = search_memory(NEEDLE, NEEDLE_END, NEEDLE_SIZE);
        //printf("[fake_readfile] Setting real_hookedsig");
        if (sig_address != NULL) {
            Real_HookedSig = (void (__thiscall*)(void*, const BYTE*, size_t, DWORD*))sig_address;
            //printf("[fake_readfile] sig_address = [%08x]", sig_address);
            //printf("[fake_readfile] Real_HookedSig = [%08x]", Real_HookedSig);
            DetourTransactionBegin();
            DetourUpdateThread(GetCurrentThread());
            DetourAttach(&(PVOID&)Real_HookedSig, Fake_HookedSig);
            //printf("[fake_readfile2] Real_HookedSig = [%08x]", Real_HookedSig);
            DetourTransactionCommit();
        }
    }

    if (Real_HookedSig != NULL) {
        // ReadFile's job is done...
        DetourTransactionBegin();
        DetourUpdateThread(GetCurrentThread());
        DetourDetach(&(PVOID&)Real_NtReadFile, Fake_NtReadFile);
        DetourTransactionCommit();
    }

    return Real_NtReadFile(FileHandle, Event, ApcRoutine, ApcContext, IoStatusBlock, Buffer, Length, ByteOffset, Key);
}
*/
VOID __fastcall Fake_HookedSig(void * This, void * throwaway, const BYTE* key, size_t length, DWORD* whatever) {
    spdlog::debug("\t CryptoPPKey = ");
    for (int i = 0 ; i < length ; i++) {
        //spdlog::debug("%02x",key[i]);
    }

    return Real_HookedSig(This, key, length, whatever);
}

INT APIENTRY DllMain(HMODULE hModule, DWORD Reason, LPVOID lpReserved) {
    auto key_logger = spdlog::basic_logger_mt<spdlog::async_factory>("key_logger", "C:\\basic.txt");
    spdlog::set_default_logger(key_logger);
    spdlog::set_level(spdlog::level::debug);

    switch(Reason){
    case DLL_PROCESS_ATTACH:
        OutputDebugString("start dll load");
        spdlog::debug("start dll load");

        DetourRestoreAfterWith(); // eugenek: not sure if this is necessary
        DetourTransactionBegin();
        DetourUpdateThread(GetCurrentThread());


        DetourAttach(&(PVOID&)Real_CryptEncrypt, Fake_CryptEncrypt);
        DetourAttach(&(PVOID&)Real_CryptDecrypt, Fake_CryptDecrypt);

        DetourAttach(&(PVOID&)Real_CryptAcquireContext, Fake_CryptAcquireContext);
        DetourAttach(&(PVOID&)Real_CryptSetKeyParam, Fake_CryptSetKeyParam);
        // TODO(eugenek): Disabled because the function needs logic to check the key wasn't already
        // exported, else it keeps crashing. Somebody should add this logic.
        // DetourAttach(&(PVOID&)Real_CryptDestroyKey, Fake_CryptDestroyKey);

        DetourAttach(&(PVOID&)Real_CryptCreateHash, Fake_CryptCreateHash);
        DetourAttach(&(PVOID&)Real_CryptHashData, Fake_CryptHashData);

        DetourAttach(&(PVOID&)Real_CryptDeriveKey, Fake_CryptDeriveKey);
        DetourAttach(&(PVOID&)Real_CryptGenKey, Fake_CryptGenKey);

        DetourAttach(&(PVOID&)Real_CryptImportKey, Fake_CryptImportKey);
        DetourAttach(&(PVOID&)Real_CryptExportKey, Fake_CryptExportKey);

        DetourAttach(&(PVOID&)Real_CryptGenRandom, Fake_CryptGenRandom);

        //DetourAttach(&(PVOID&)Real_ReadFile, Fake_ReadFile);
        //DetourAttach(&(PVOID&)Real_NtReadFile, Fake_NtReadFile);
        DetourAttach(&(PVOID&)Real_OpenFile, Fake_OpenFile);
        DetourAttach(&(PVOID&)Real_NtOpenFile, Fake_NtOpenFile);
        DetourAttach(&(PVOID&)Real_CreateFile, Fake_CreateFile);
        DetourAttach(&(PVOID&)Real_NtCreateFile, Fake_NtCreateFile);

        DetourAttach(&(PVOID&)Real_BCryptEncrypt, Fake_BCryptEncrypt);

        DetourTransactionCommit();
        OutputDebugString("commit done");
        spdlog::debug("commit done");
        break;

    case DLL_PROCESS_DETACH:
        DetourTransactionBegin();
        DetourUpdateThread(GetCurrentThread());

        DetourDetach(&(PVOID&)Real_CryptEncrypt, Fake_CryptEncrypt);
        DetourDetach(&(PVOID&)Real_CryptDecrypt, Fake_CryptDecrypt);

        DetourDetach(&(PVOID&)Real_CryptAcquireContext, Fake_CryptAcquireContext);
        DetourDetach(&(PVOID&)Real_CryptSetKeyParam, Fake_CryptSetKeyParam);
        // TODO(eugenek): Disabled because the function needs logic to check the key wasn't already
        // exported, else it keeps crashing. Somebody should add this logic.
        // DetourDetach(&(PVOID&)Real_CryptDestroyKey, Fake_CryptDestroyKey);

        DetourDetach(&(PVOID&)Real_CryptCreateHash, Fake_CryptCreateHash);
        DetourDetach(&(PVOID&)Real_CryptHashData, Fake_CryptHashData);

        DetourDetach(&(PVOID&)Real_CryptDeriveKey, Fake_CryptDeriveKey);
        DetourDetach(&(PVOID&)Real_CryptGenKey, Fake_CryptGenKey);

        DetourDetach(&(PVOID&)Real_CryptImportKey, Fake_CryptImportKey);
        DetourDetach(&(PVOID&)Real_CryptExportKey, Fake_CryptExportKey);

        DetourDetach(&(PVOID&)Real_CryptGenRandom, Fake_CryptGenRandom);

        //DetourDetach(&(PVOID&)Real_ReadFile, Fake_ReadFile);
        //DetourDetach(&(PVOID&)Real_NtReadFile, Fake_NtReadFile);
        DetourDetach(&(PVOID&)Real_OpenFile, Fake_OpenFile);
        DetourDetach(&(PVOID&)Real_NtOpenFile, Fake_NtOpenFile);
        DetourDetach(&(PVOID&)Real_CreateFile, Fake_CreateFile);
        DetourDetach(&(PVOID&)Real_NtCreateFile, Fake_NtCreateFile);

        DetourDetach(&(PVOID&)Real_BCryptEncrypt, Fake_BCryptEncrypt);

        DetourTransactionCommit();
        break;

    case DLL_THREAD_ATTACH:
        break;

    case DLL_THREAD_DETACH:
        break;
    }

    //spdlog::shutdown();
    spdlog::drop_all();
    return TRUE;
}


/*
* Searches the virtual memory of the process for a byte signature.
* Input:
*   sig - the signature to search for
*   sigend - the end of the signature to search for
*   sigsize - the size of the signature to search for
* Output:
*   virtual memory address of the byte signature if found. NULL if not found */
unsigned char* search_memory(char* sig, char sigend, size_t sigsize) {
    unsigned char* sig_address = NULL;
    /* Get our PID and a handle to the process */
    DWORD pid = GetCurrentProcessId();
    HANDLE process = OpenProcess(PROCESS_VM_READ| PROCESS_QUERY_INFORMATION, FALSE, pid);

    /* Intelligently iterate over only mapped executable pages and dump them */
    /* Search for the signature in the pages */
    MEMORY_BASIC_INFORMATION info;
    DWORD bytesRead = 0;
    char* pbuf = NULL;
    unsigned char* current = NULL;
    for (current = NULL; VirtualQueryEx(process, current, &info, sizeof(info)) == sizeof(info); current += info.RegionSize) {
        // Only iterate over mapped executable memory
        if (info.State == MEM_COMMIT && (info.Type == MEM_MAPPED || info.Type == MEM_PRIVATE || info.Type == MEM_IMAGE) &&
            (info.AllocationProtect == PAGE_EXECUTE || info.AllocationProtect == PAGE_EXECUTE_READ
                || info.AllocationProtect == PAGE_EXECUTE_READWRITE || info.AllocationProtect == PAGE_EXECUTE_WRITECOPY)) {

            pbuf = (char*)malloc(info.RegionSize);
            ReadProcessMemory(process, current, pbuf, info.RegionSize, &bytesRead);
            size_t match_offset = search_array(sig, sigend, sigsize, pbuf, bytesRead, 31); // 80% match
            if (match_offset != NULL) {
                sig_address = current+match_offset;
                break;

            }

        }
    }

    return sig_address;
}

/*
* Searches an array for a fuzzy subarray.
* Input:
*   needle - subarray to search for
*   needle_end - last part of the subarray to search for
*   needleSize - size of aubarray to search for
*   haystack - array to search in
*   haystackSize - size of array to search in
*   threshold - integer amount of bytes that much match to return a match
* Output:
*   offset to the first match (only aim for one!). If none, then NULL. */
size_t search_array(char *needle, char needle_end, size_t needleSize, char *haystack, size_t haystackSize, size_t threshold) {
    size_t match_offset = NULL;
    for (int i = 0; i + needleSize <= haystackSize; i++) {
        size_t match_count = 0;
        for (int j = 0; j < needleSize; j++) {
            char needle_compare = needle[j];
            /* This is a hack to not find the needle in this DLL's memory */
            if (j == needleSize - 1) {
                needle_compare = needle_end;
            }
            if (haystack[i+j] == needle_compare) {
                match_count++;
            }
        }

        if(match_count >= threshold) {
            match_offset = i;
            break;
        }
    }

    return match_offset;
}

const std::string CurrentTime() {
    SYSTEMTIME st;
    GetSystemTime(&st);
    char currentTime[100] = "";
    sprintf(currentTime,"%d:%d:%d %d",st.wHour, st.wMinute, st.wSecond , st.wMilliseconds);
    return std::string(currentTime);
}

void MyHandleError(LPTSTR psz, int nErrorNumber) {
    _ftprintf(stderr, TEXT("An error occurred in the program. "));
    _ftprintf(stderr, TEXT("%s"), psz);
    _ftprintf(stderr, TEXT("Error number %x."), nErrorNumber);
}

