#define NOMINMAX
#include <Windows.h>
#include <cstdint>
#include <exception>
#include <vector>

std::uint8_t* PatternScan(void* module, const char* signature)
{
	static auto pattern_to_byte = [](const char* pattern) {
		auto bytes = std::vector<int>{};
		auto start = const_cast<char*>(pattern);
		auto end = const_cast<char*>(pattern) + strlen(pattern);

		for (auto current = start; current < end; ++current) {
			if (*current == '?') {
				++current;
				if (*current == '?')
					++current;
				bytes.push_back(-1);
			}
			else {
				bytes.push_back(strtoul(current, &current, 16));
			}
		}
		return bytes;
	};

	auto dosHeader = (PIMAGE_DOS_HEADER)module;
	auto ntHeaders = (PIMAGE_NT_HEADERS)((std::uint8_t*)module + dosHeader->e_lfanew);

	auto sizeOfImage = ntHeaders->OptionalHeader.SizeOfImage;
	auto patternBytes = pattern_to_byte(signature);
	auto scanBytes = reinterpret_cast<std::uint8_t*>(module);

	auto s = patternBytes.size();
	auto d = patternBytes.data();

	for (auto i = 0ul; i < sizeOfImage - s; ++i) {
		bool found = true;
		for (auto j = 0ul; j < s; ++j) {
			if (scanBytes[i + j] != d[j] && d[j] != -1) {
				found = false;
				break;
			}
		}
		if (found) {
			return &scanBytes[i];
		}
	}
	return nullptr;
}

DWORD WINAPI OnDllAttach(LPVOID base)
{
	while (!GetModuleHandleA("serverbrowser.dll"))
		Sleep(1000);

	try {
		static uint8_t* fakePrimeStatus = PatternScan(GetModuleHandleW(L"client_panorama.dll"), "83 F8 05 5E 0F 94 C0 C3");
		DWORD old_protect;

		VirtualProtect(fakePrimeStatus, 3, PAGE_EXECUTE_READWRITE, &old_protect);
		char patch[] = { 0x83, 0xF8, 0x00 }; // bytes for cmp instuction, 0x00 is so the instruction becomes cmp eax,0
		memcpy(fakePrimeStatus, patch, 3);
		VirtualProtect(fakePrimeStatus, 3, old_protect, nullptr);

		FreeLibraryAndExitThread(static_cast<HMODULE>(base), 1);
	}
	catch (const std::exception & ex) {
		FreeLibraryAndExitThread(static_cast<HMODULE>(base), 1);
	}
}

BOOL WINAPI DllMain(
	_In_      HINSTANCE hinstDll,
	_In_      DWORD     fdwReason,
	_In_opt_  LPVOID    lpvReserved
)
{
	switch (fdwReason) {
	case DLL_PROCESS_ATTACH:
		DisableThreadLibraryCalls(hinstDll);
		CreateThread(nullptr, 0, OnDllAttach, hinstDll, 0, nullptr);
		return TRUE;
	case DLL_PROCESS_DETACH:
		return TRUE;
	default:
		return TRUE;
	}
}