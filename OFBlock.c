// OFBlock.dll - blocks any attempt to open URLs/paths containing "online-fix.me",
// and suppresses message boxes whose text or caption mentions it (the "Credits" popup).
// Hooks: ShellExecuteA/W, ShellExecuteExA/W (shell32), CreateProcessA/W (kernelbase),
//        MessageBoxA/W, MessageBoxExA/W, MessageBoxIndirectA/W, MessageBoxTimeoutA/W (user32)
// Blocked calls are logged to OFBlock.log next to this DLL, but only if that file
// already exists (create an empty OFBlock.log to turn logging on).

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <shellapi.h>
#include <stdio.h>
#include <wchar.h>
#include "MinHook.h"

static const wchar_t *BLOCK_W = L"online-fix.me";
static const char *BLOCK_A = "online-fix.me";

static wchar_t g_logPath[MAX_PATH];
static CRITICAL_SECTION g_logLock;

typedef HINSTANCE (WINAPI *ShellExecuteA_t)(HWND, LPCSTR, LPCSTR, LPCSTR, LPCSTR, INT);
typedef HINSTANCE (WINAPI *ShellExecuteW_t)(HWND, LPCWSTR, LPCWSTR, LPCWSTR, LPCWSTR, INT);
typedef BOOL (WINAPI *ShellExecuteExA_t)(SHELLEXECUTEINFOA *);
typedef BOOL (WINAPI *ShellExecuteExW_t)(SHELLEXECUTEINFOW *);
typedef BOOL (WINAPI *CreateProcessA_t)(LPCSTR, LPSTR, LPSECURITY_ATTRIBUTES, LPSECURITY_ATTRIBUTES, BOOL, DWORD, LPVOID, LPCSTR, LPSTARTUPINFOA, LPPROCESS_INFORMATION);
typedef BOOL (WINAPI *CreateProcessW_t)(LPCWSTR, LPWSTR, LPSECURITY_ATTRIBUTES, LPSECURITY_ATTRIBUTES, BOOL, DWORD, LPVOID, LPCWSTR, LPSTARTUPINFOW, LPPROCESS_INFORMATION);

typedef int (WINAPI *MessageBoxA_t)(HWND, LPCSTR, LPCSTR, UINT);
typedef int (WINAPI *MessageBoxW_t)(HWND, LPCWSTR, LPCWSTR, UINT);
typedef int (WINAPI *MessageBoxExA_t)(HWND, LPCSTR, LPCSTR, UINT, WORD);
typedef int (WINAPI *MessageBoxExW_t)(HWND, LPCWSTR, LPCWSTR, UINT, WORD);
typedef int (WINAPI *MessageBoxIndirectA_t)(const MSGBOXPARAMSA *);
typedef int (WINAPI *MessageBoxIndirectW_t)(const MSGBOXPARAMSW *);
typedef int (WINAPI *MessageBoxTimeoutA_t)(HWND, LPCSTR, LPCSTR, UINT, WORD, DWORD);
typedef int (WINAPI *MessageBoxTimeoutW_t)(HWND, LPCWSTR, LPCWSTR, UINT, WORD, DWORD);

static ShellExecuteA_t oShellExecuteA;
static ShellExecuteW_t oShellExecuteW;
static ShellExecuteExA_t oShellExecuteExA;
static ShellExecuteExW_t oShellExecuteExW;
static CreateProcessA_t oCreateProcessA;
static CreateProcessW_t oCreateProcessW;
static MessageBoxA_t oMessageBoxA;
static MessageBoxW_t oMessageBoxW;
static MessageBoxExA_t oMessageBoxExA;
static MessageBoxExW_t oMessageBoxExW;
static MessageBoxIndirectA_t oMessageBoxIndirectA;
static MessageBoxIndirectW_t oMessageBoxIndirectW;
static MessageBoxTimeoutA_t oMessageBoxTimeoutA;
static MessageBoxTimeoutW_t oMessageBoxTimeoutW;

// Case-insensitive substring search, no CRT locale dependence
static BOOL ContainsW(const wchar_t *hay)
{
	if (!hay)
		return FALSE;
	size_t n = wcslen(BLOCK_W);
	for (const wchar_t *p = hay; *p; p++) {
		size_t i = 0;
		while (i < n && p[i] && towlower(p[i]) == BLOCK_W[i])
			i++;
		if (i == n)
			return TRUE;
	}
	return FALSE;
}

static BOOL ContainsA(const char *hay)
{
	if (!hay)
		return FALSE;
	size_t n = strlen(BLOCK_A);
	for (const char *p = hay; *p; p++) {
		size_t i = 0;
		while (i < n && p[i] && (char)tolower((unsigned char)p[i]) == BLOCK_A[i])
			i++;
		if (i == n)
			return TRUE;
	}
	return FALSE;
}

static void LogBlockedW(const wchar_t *api, const wchar_t *what)
{
	if (!g_logPath[0])
		return;
	EnterCriticalSection(&g_logLock);
	FILE *f = _wfopen(g_logPath, L"a, ccs=UTF-8");
	if (f) {
		SYSTEMTIME st;
		GetLocalTime(&st);
		fwprintf(f, L"%04u-%02u-%02u %02u:%02u:%02u blocked %ls: %ls\n",
			st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond,
			api, what ? what : L"(null)");
		fclose(f);
	}
	LeaveCriticalSection(&g_logLock);
}

static void LogBlockedA(const wchar_t *api, const char *what)
{
	wchar_t buf[2048];
	buf[0] = 0;
	if (what)
		MultiByteToWideChar(CP_ACP, 0, what, -1, buf, (int)(sizeof(buf) / sizeof(buf[0])));
	buf[2047] = 0;
	LogBlockedW(api, buf);
}

// ---- hooks ----

static HINSTANCE WINAPI hkShellExecuteA(HWND h, LPCSTR op, LPCSTR file, LPCSTR params, LPCSTR dir, INT show)
{
	if (ContainsA(file) || ContainsA(params)) {
		LogBlockedA(L"ShellExecuteA", ContainsA(file) ? file : params);
		return (HINSTANCE)(ULONG_PTR)42; // >32 = success
	}
	return oShellExecuteA(h, op, file, params, dir, show);
}

static HINSTANCE WINAPI hkShellExecuteW(HWND h, LPCWSTR op, LPCWSTR file, LPCWSTR params, LPCWSTR dir, INT show)
{
	if (ContainsW(file) || ContainsW(params)) {
		LogBlockedW(L"ShellExecuteW", ContainsW(file) ? file : params);
		return (HINSTANCE)(ULONG_PTR)42;
	}
	return oShellExecuteW(h, op, file, params, dir, show);
}

static BOOL WINAPI hkShellExecuteExA(SHELLEXECUTEINFOA *sei)
{
	if (sei && (ContainsA(sei->lpFile) || ContainsA(sei->lpParameters))) {
		LogBlockedA(L"ShellExecuteExA", ContainsA(sei->lpFile) ? sei->lpFile : sei->lpParameters);
		sei->hInstApp = (HINSTANCE)(ULONG_PTR)42;
		if (sei->fMask & SEE_MASK_NOCLOSEPROCESS)
			sei->hProcess = NULL;
		return TRUE;
	}
	return oShellExecuteExA(sei);
}

static BOOL WINAPI hkShellExecuteExW(SHELLEXECUTEINFOW *sei)
{
	if (sei && (ContainsW(sei->lpFile) || ContainsW(sei->lpParameters))) {
		LogBlockedW(L"ShellExecuteExW", ContainsW(sei->lpFile) ? sei->lpFile : sei->lpParameters);
		sei->hInstApp = (HINSTANCE)(ULONG_PTR)42;
		if (sei->fMask & SEE_MASK_NOCLOSEPROCESS)
			sei->hProcess = NULL;
		return TRUE;
	}
	return oShellExecuteExW(sei);
}

static BOOL WINAPI hkCreateProcessA(LPCSTR app, LPSTR cmd, LPSECURITY_ATTRIBUTES pa, LPSECURITY_ATTRIBUTES ta,
	BOOL inherit, DWORD flags, LPVOID env, LPCSTR dir, LPSTARTUPINFOA si, LPPROCESS_INFORMATION pi)
{
	if (ContainsA(app) || ContainsA(cmd)) {
		LogBlockedA(L"CreateProcessA", cmd ? cmd : app);
		SetLastError(ERROR_ACCESS_DENIED);
		return FALSE;
	}
	return oCreateProcessA(app, cmd, pa, ta, inherit, flags, env, dir, si, pi);
}

static BOOL WINAPI hkCreateProcessW(LPCWSTR app, LPWSTR cmd, LPSECURITY_ATTRIBUTES pa, LPSECURITY_ATTRIBUTES ta,
	BOOL inherit, DWORD flags, LPVOID env, LPCWSTR dir, LPSTARTUPINFOW si, LPPROCESS_INFORMATION pi)
{
	if (ContainsW(app) || ContainsW(cmd)) {
		LogBlockedW(L"CreateProcessW", cmd ? cmd : app);
		SetLastError(ERROR_ACCESS_DENIED);
		return FALSE;
	}
	return oCreateProcessW(app, cmd, pa, ta, inherit, flags, env, dir, si, pi);
}

// Message boxes: pretend the user clicked OK (the Credits box only has OK)
static BOOL MsgMatchW(LPCWSTR text, LPCWSTR caption)
{
	return (!IS_INTRESOURCE(text) && ContainsW(text)) || (!IS_INTRESOURCE(caption) && ContainsW(caption));
}

static BOOL MsgMatchA(LPCSTR text, LPCSTR caption)
{
	return (!IS_INTRESOURCE(text) && ContainsA(text)) || (!IS_INTRESOURCE(caption) && ContainsA(caption));
}

static int WINAPI hkMessageBoxA(HWND h, LPCSTR text, LPCSTR caption, UINT type)
{
	if (MsgMatchA(text, caption)) {
		LogBlockedA(L"MessageBoxA", text);
		return IDOK;
	}
	return oMessageBoxA(h, text, caption, type);
}

static int WINAPI hkMessageBoxW(HWND h, LPCWSTR text, LPCWSTR caption, UINT type)
{
	if (MsgMatchW(text, caption)) {
		LogBlockedW(L"MessageBoxW", text);
		return IDOK;
	}
	return oMessageBoxW(h, text, caption, type);
}

static int WINAPI hkMessageBoxExA(HWND h, LPCSTR text, LPCSTR caption, UINT type, WORD lang)
{
	if (MsgMatchA(text, caption)) {
		LogBlockedA(L"MessageBoxExA", text);
		return IDOK;
	}
	return oMessageBoxExA(h, text, caption, type, lang);
}

static int WINAPI hkMessageBoxExW(HWND h, LPCWSTR text, LPCWSTR caption, UINT type, WORD lang)
{
	if (MsgMatchW(text, caption)) {
		LogBlockedW(L"MessageBoxExW", text);
		return IDOK;
	}
	return oMessageBoxExW(h, text, caption, type, lang);
}

static int WINAPI hkMessageBoxIndirectA(const MSGBOXPARAMSA *p)
{
	if (p && MsgMatchA(p->lpszText, p->lpszCaption)) {
		LogBlockedA(L"MessageBoxIndirectA", p->lpszText);
		return IDOK;
	}
	return oMessageBoxIndirectA(p);
}

static int WINAPI hkMessageBoxIndirectW(const MSGBOXPARAMSW *p)
{
	if (p && MsgMatchW(p->lpszText, p->lpszCaption)) {
		LogBlockedW(L"MessageBoxIndirectW", p->lpszText);
		return IDOK;
	}
	return oMessageBoxIndirectW(p);
}

static int WINAPI hkMessageBoxTimeoutA(HWND h, LPCSTR text, LPCSTR caption, UINT type, WORD lang, DWORD ms)
{
	if (MsgMatchA(text, caption)) {
		LogBlockedA(L"MessageBoxTimeoutA", text);
		return IDOK;
	}
	return oMessageBoxTimeoutA(h, text, caption, type, lang, ms);
}

static int WINAPI hkMessageBoxTimeoutW(HWND h, LPCWSTR text, LPCWSTR caption, UINT type, WORD lang, DWORD ms)
{
	if (MsgMatchW(text, caption)) {
		LogBlockedW(L"MessageBoxTimeoutW", text);
		return IDOK;
	}
	return oMessageBoxTimeoutW(h, text, caption, type, lang, ms);
}

// ---- setup ----

static void Hook(HMODULE mod, const char *name, LPVOID detour, LPVOID *orig)
{
	if (!mod)
		return;
	LPVOID target = (LPVOID)GetProcAddress(mod, name);
	if (target && MH_CreateHook(target, detour, orig) == MH_OK)
		MH_EnableHook(target);
}

static void InstallHooks(HMODULE self)
{
	InitializeCriticalSection(&g_logLock);

	// Log path: same folder as this DLL
	if (GetModuleFileNameW(self, g_logPath, MAX_PATH)) {
		wchar_t *slash = wcsrchr(g_logPath, L'\\');
		if (slash && (size_t)(slash - g_logPath) + 12 < MAX_PATH)
			wcscpy(slash + 1, L"OFBlock.log");
		else
			g_logPath[0] = 0;
	}
	// Logging is opt-in: only log if OFBlock.log already exists next to the DLL
	if (g_logPath[0] && GetFileAttributesW(g_logPath) == INVALID_FILE_ATTRIBUTES)
		g_logPath[0] = 0;

	if (MH_Initialize() != MH_OK)
		return;

	// shell32 may not be loaded yet; load it so hooks are in place before OnlineFix runs
	HMODULE shell32 = LoadLibraryW(L"shell32.dll");
	HMODULE user32 = LoadLibraryW(L"user32.dll");
	HMODULE kbase = GetModuleHandleW(L"kernelbase.dll");
	if (!kbase)
		kbase = GetModuleHandleW(L"kernel32.dll");

	Hook(shell32, "ShellExecuteA", (LPVOID)hkShellExecuteA, (LPVOID *)&oShellExecuteA);
	Hook(shell32, "ShellExecuteW", (LPVOID)hkShellExecuteW, (LPVOID *)&oShellExecuteW);
	Hook(shell32, "ShellExecuteExA", (LPVOID)hkShellExecuteExA, (LPVOID *)&oShellExecuteExA);
	Hook(shell32, "ShellExecuteExW", (LPVOID)hkShellExecuteExW, (LPVOID *)&oShellExecuteExW);
	Hook(kbase, "CreateProcessA", (LPVOID)hkCreateProcessA, (LPVOID *)&oCreateProcessA);
	Hook(kbase, "CreateProcessW", (LPVOID)hkCreateProcessW, (LPVOID *)&oCreateProcessW);
	Hook(user32, "MessageBoxA", (LPVOID)hkMessageBoxA, (LPVOID *)&oMessageBoxA);
	Hook(user32, "MessageBoxW", (LPVOID)hkMessageBoxW, (LPVOID *)&oMessageBoxW);
	Hook(user32, "MessageBoxExA", (LPVOID)hkMessageBoxExA, (LPVOID *)&oMessageBoxExA);
	Hook(user32, "MessageBoxExW", (LPVOID)hkMessageBoxExW, (LPVOID *)&oMessageBoxExW);
	Hook(user32, "MessageBoxIndirectA", (LPVOID)hkMessageBoxIndirectA, (LPVOID *)&oMessageBoxIndirectA);
	Hook(user32, "MessageBoxIndirectW", (LPVOID)hkMessageBoxIndirectW, (LPVOID *)&oMessageBoxIndirectW);
	// Undocumented, but every MessageBox* variant funnels into these
	Hook(user32, "MessageBoxTimeoutA", (LPVOID)hkMessageBoxTimeoutA, (LPVOID *)&oMessageBoxTimeoutA);
	Hook(user32, "MessageBoxTimeoutW", (LPVOID)hkMessageBoxTimeoutW, (LPVOID *)&oMessageBoxTimeoutW);
}

// Dummy export so loaders that require at least one export are happy
__declspec(dllexport) void OFBlock_Loaded(void)
{
}

BOOL WINAPI DllMain(HINSTANCE inst, DWORD reason, LPVOID reserved)
{
	(void)reserved;
	if (reason == DLL_PROCESS_ATTACH) {
		DisableThreadLibraryCalls(inst);
		InstallHooks(inst);
	}
	// Intentionally never unhook: the process is going away on detach anyway
	return TRUE;
}
