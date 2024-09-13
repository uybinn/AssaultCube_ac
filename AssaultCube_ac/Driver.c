#include <ntddk.h>
#include <ntstrsafe.h>

// 프로세스 정보를 가져올 때 사용하는 정보 클래스의 값 5를 정의
#define SystemProcessInformation 5
// 프로세스 정보 조회에 필요한 권한을 정의 (프로세스 정보 쿼리)
#define PROCESS_QUERY_INFORMATION (0x0400)
// 프로세스 메모리 읽기에 필요한 권한을 정의
#define PROCESS_VM_READ (0x0010)
// 모니터링할 프로세스 리스트의 크기 정의 (5개)
#define ProcessListLength 5
// 프로세스 종료 권한을 정의
#define PROCESS_TERMINATE (0x0001)

// 메모리 정보 클래스를 정의
typedef enum _MEMORY_INFORMATION_CLASS {
    MemoryBasicInformation,   // 기본 메모리 정보
    MemoryWorkingSetInformation,   // 워킹 셋 정보
    MemorySectionName,   // 섹션 이름
    MemoryBasicVlmInformation   // 가상 메모리 정보
} MEMORY_INFORMATION_CLASS;

// 메모리 기본 정보 구조체 정의 (각 필드는 메모리 영역에 대한 정보를 담음)
typedef struct _MEMORY_BASIC_INFORMATION {
    PVOID BaseAddress;      // 기본 주소
    PVOID AllocationBase;   // 할당된 기본 주소
    ULONG AllocationProtect; // 할당된 보호 속성
    SIZE_T RegionSize;      // 메모리 영역 크기
    ULONG State;            // 메모리 상태 (커밋된 상태인지 등)
    ULONG Protect;          // 보호 속성
    ULONG Type;             // 메모리 타입 (이미지, 페이지 등)
} MEMORY_BASIC_INFORMATION, * PMEMORY_BASIC_INFORMATION;

// MEM_IMAGE 플래그 정의 (메모리 타입이 이미지인 경우를 나타냄)
#define MEM_IMAGE 0x1000000

// 시스템 프로세스 정보 구조체 정의 (프로세스 관련 정보를 저장하는 구조체)
typedef struct _SYSTEM_PROCESS_INFORMATION {
    ULONG NextEntryOffset;         // 다음 프로세스 정보로의 오프셋
    ULONG NumberOfThreads;         // 프로세스에 있는 스레드 수
    LARGE_INTEGER WorkingSetPrivateSize; // 워킹 셋 프라이빗 크기
    ULONG HardFaultCount;          // 하드 페이지 폴트 수
    ULONG NumberOfThreadsHighWatermark;  // 최대 스레드 수
    ULONGLONG CycleTime;           // 프로세스의 CPU 사이클 시간
    LARGE_INTEGER CreateTime;      // 프로세스 생성 시간
    LARGE_INTEGER UserTime;        // 사용자 모드에서의 실행 시간
    LARGE_INTEGER KernelTime;      // 커널 모드에서의 실행 시간
    UNICODE_STRING ImageName;      // 프로세스 이미지 이름
    ULONG BasePriority;            // 프로세스 우선 순위
    HANDLE UniqueProcessId;        // 고유한 프로세스 ID
    HANDLE InheritedFromUniqueProcessId; // 상속된 프로세스 ID
    ULONG HandleCount;             // 핸들 개수
    ULONG SessionId;               // 세션 ID
    ULONG_PTR UniqueProcessKey;    // 고유한 프로세스 키
    SIZE_T PeakVirtualSize;        // 최대 가상 메모리 크기
    SIZE_T VirtualSize;            // 현재 가상 메모리 크기
    ULONG PageFaultCount;          // 페이지 폴트 횟수
    SIZE_T PeakWorkingSetSize;     // 최대 워킹 셋 크기
    SIZE_T WorkingSetSize;         // 현재 워킹 셋 크기
    SIZE_T QuotaPeakPagedPoolUsage; // 페이지드 풀 최대 사용량
    SIZE_T QuotaPagedPoolUsage;    // 페이지드 풀 사용량
    SIZE_T QuotaPeakNonPagedPoolUsage;  // 비페이지드 풀 최대 사용량
    SIZE_T QuotaNonPagedPoolUsage; // 비페이지드 풀 사용량
    SIZE_T PagefileUsage;          // 페이지 파일 사용량
    SIZE_T PeakPagefileUsage;      // 페이지 파일 최대 사용량
    SIZE_T PrivatePageCount;       // 프라이빗 페이지 수
    LARGE_INTEGER ReadOperationCount;  // 읽기 작업 횟수
    LARGE_INTEGER WriteOperationCount; // 쓰기 작업 횟수
    LARGE_INTEGER OtherOperationCount; // 기타 작업 횟수
    LARGE_INTEGER ReadTransferCount;   // 읽기 전송 횟수
    LARGE_INTEGER WriteTransferCount;  // 쓰기 전송 횟수
    LARGE_INTEGER OtherTransferCount;  // 기타 전송 횟수
} SYSTEM_PROCESS_INFORMATION, * PSYSTEM_PROCESS_INFORMATION;

// ZwQuerySystemInformation: 시스템 정보를 쿼리하는 함수 (NTSTATUS 반환)
NTSYSCALLAPI
NTSTATUS
ZwQuerySystemInformation(
    ULONG SystemInformationClass,    // 시스템 정보 클래스
    PVOID SystemInformation,         // 시스템 정보 버퍼
    ULONG SystemInformationLength,   // 시스템 정보 버퍼 크기
    PULONG ReturnLength              // 반환되는 정보 길이
);

// ZwQueryInformationProcess: 프로세스 정보를 쿼리하는 함수
NTSYSCALLAPI
NTSTATUS
ZwQueryInformationProcess(
    HANDLE ProcessHandle,            // 프로세스 핸들
    PROCESSINFOCLASS ProcessInformationClass, // 프로세스 정보 클래스
    PVOID ProcessInformation,        // 프로세스 정보 버퍼
    ULONG ProcessInformationLength,  // 버퍼 크기
    PULONG ReturnLength              // 반환되는 정보 길이
);

// ZwQueryVirtualMemory: 프로세스 가상 메모리 정보를 쿼리하는 함수
NTSYSCALLAPI
NTSTATUS
ZwQueryVirtualMemory(
    HANDLE ProcessHandle,            // 프로세스 핸들
    PVOID BaseAddress,               // 시작 주소
    MEMORY_INFORMATION_CLASS MemoryInformationClass, // 메모리 정보 클래스
    PVOID MemoryInformation,         // 메모리 정보 버퍼
    SIZE_T MemoryInformationLength,  // 버퍼 크기
    PSIZE_T ReturnLength             // 반환되는 정보 길이
);


VOID DriverUnload(PDRIVER_OBJECT pDriverObject);
DWORD GetProcessIDByName(PCWSTR szProcessName);
BOOLEAN IsDllInWhitelist(UNICODE_STRING* dllName);
INT ListDllsInProcess(HANDLE hProcess);
VOID ProcessListKill(DWORD AC_PID);
NTSTATUS TerminateProcessByPID(DWORD dwPID);
VOID PrintDllListByPID(DWORD dwPID);
VOID PeriodicTask(PVOID context);
NTSTATUS DriverEntry(PDRIVER_OBJECT pDriverObject, PUNICODE_STRING pRegistryPath);

VOID DriverUnload(PDRIVER_OBJECT pDriverObject)
{
    UNREFERENCED_PARAMETER(pDriverObject); // pDriverObject가 사용되지 않음을 명시하여 경고를 방지합니다.
    DbgPrint("Driver Unload\n"); // 디버그 출력으로 드라이버가 언로드된다는 메시지를 출력합니다.
}

DWORD GetProcessIDByName(PCWSTR szProcessName)
{
    NTSTATUS status; // NTSTATUS 변수를 선언하여 ZwQuerySystemInformation의 결과 상태를 저장할 것입니다.
    ULONG bufferSize = 0x10000; // 버퍼 크기를 64KB로 설정합니다. 이는 프로세스 정보를 저장하기 위함입니다.
    PVOID buffer = ExAllocatePool2(POOL_FLAG_NON_PAGED, bufferSize, 'proc'); // 비페이징 메모리 풀에서 64KB 크기의 메모리를 할당합니다.
    DWORD dwPID = 0; // 찾은 프로세스의 PID를 저장할 변수입니다. 초기값은 0입니다.

    if (!buffer) {
        DbgPrint("Failed to allocate buffer\n"); // 메모리 할당에 실패하면, 디버그 출력으로 에러 메시지를 출력하고 함수 종료
        return 0;
    }

    status = ZwQuerySystemInformation(SystemProcessInformation, buffer, bufferSize, &bufferSize);
    // 시스템의 모든 프로세스 정보를 가져옵니다.

    if (status == STATUS_INFO_LENGTH_MISMATCH) {
        // 만약 버퍼가 충분하지 않다면, 새로운 버퍼 크기를 할당해 다시 시도합니다.
        ExFreePool(buffer); // 기존 버퍼를 해제합니다.
        buffer = ExAllocatePool2(POOL_FLAG_NON_PAGED, bufferSize, 'proc'); // 새로운 크기의 버퍼를 할당합니다.
        if (!buffer) {
            DbgPrint("Failed to allocate new buffer\n"); // 버퍼 할당 실패 시 에러 메시지를 출력하고 함수 종료
            return 0;
        }
        status = ZwQuerySystemInformation(SystemProcessInformation, buffer, bufferSize, &bufferSize);
        // 새 버퍼 크기로 다시 프로세스 정보를 요청합니다.
    }

    if (NT_SUCCESS(status)) { // ZwQuerySystemInformation 호출이 성공하면
        PSYSTEM_PROCESS_INFORMATION processInfo = (PSYSTEM_PROCESS_INFORMATION)buffer; // 반환된 버퍼를 프로세스 정보 구조체로 캐스팅

        while (TRUE) { // 모든 프로세스를 순회하면서 탐색
            if (processInfo->ImageName.Buffer != NULL &&
                _wcsicmp(processInfo->ImageName.Buffer, szProcessName) == 0) {
                // 프로세스 이름이 일치하는지 확인 (대소문자 무시)
                dwPID = (DWORD)(ULONG_PTR)processInfo->UniqueProcessId; // 일치하면 해당 프로세스의 PID를 저장
                DbgPrint("Found process: %ws with PID: %d\n", processInfo->ImageName.Buffer, dwPID);
                // 프로세스 이름과 PID를 출력
                break; // 프로세스를 찾았으므로 루프 종료
            }

            if (processInfo->NextEntryOffset == 0) {
                // 더 이상 프로세스 정보가 없으면 루프를 종료합니다.
                break;
            }

            processInfo = (PSYSTEM_PROCESS_INFORMATION)((PUCHAR)processInfo + processInfo->NextEntryOffset);
            // 다음 프로세스 정보로 이동합니다.
        }
    }

    ExFreePool(buffer); // 버퍼를 해제합니다.
    return dwPID; // 찾은 프로세스의 PID를 반환합니다. 찾지 못했을 경우 0을 반환합니다.
}

BOOLEAN IsDllInWhitelist(UNICODE_STRING* dllName)
{
    static const wchar_t* whitelistedDlls[] = {
        // 허용된 DLL 파일들의 경로 목록을 정의합니다. 
        L"\\Device\\HarddiskVolume3\\Program Files (x86)\\AssaultCube 1.3.0.2\\bin_win32\\ac_client.exe",
        L"\\Device\\HarddiskVolume3\\Windows\\SYSTEM32\\ntdll.dll",
        L"\\Device\\HarddiskVolume3\\Windows\\System32\\wow64.dll",
        L"\\Device\\HarddiskVolume3\\Windows\\System32\\wow64win.dll",
        L"\\Device\\HarddiskVolume3\\Windows\\System32\\wow64cpu.dll",
        L"\\Device\\HarddiskVolume3\\Windows\\SysWOW64\\ntdll.dll",
        L"\\Device\\HarddiskVolume3\\Windows\\SysWOW64\\KERNEL32.DLL",
        L"\\Device\\HarddiskVolume3\\Windows\\SysWOW64\\KERNELBASE.dll",
        L"\\Device\\HarddiskVolume3\\Windows\\SysWOW64\\WS2_32.dll",
        L"\\Device\\HarddiskVolume3\\Windows\\SysWOW64\\RPCRT4.dll",
        L"\\Device\\HarddiskVolume3\\Windows\\SysWOW64\\USER32.dll",
        L"\\Device\\HarddiskVolume3\\Windows\\SysWOW64\\win32u.dll",
        L"\\Device\\HarddiskVolume3\\Windows\\SysWOW64\\GDI32.dll",
        L"\\Device\\HarddiskVolume3\\Windows\\SysWOW64\\gdi32full.dll",
        L"\\Device\\HarddiskVolume3\\Windows\\SysWOW64\\msvcp_win.dll",
        L"\\Device\\HarddiskVolume3\\Windows\\SysWOW64\\ucrtbase.dll",
        L"\\Device\\HarddiskVolume3\\Windows\\SysWOW64\\ADVAPI32.dll",
        L"\\Device\\HarddiskVolume3\\Windows\\SysWOW64\\msvcrt.dll",
        L"\\Device\\HarddiskVolume3\\Windows\\SysWOW64\\sechost.dll",
        L"\\Device\\HarddiskVolume3\\Windows\\SysWOW64\\bcrypt.dll",
        L"\\Device\\HarddiskVolume3\\Windows\\SysWOW64\\SHELL32.dll",
        L"\\Device\\HarddiskVolume3\\Windows\\SysWOW64\\OpenAL32.dll",
        L"\\Device\\HarddiskVolume3\\Program Files (x86)\\AssaultCube 1.3.0.2\\bin_win32\\zlib1.dll",
        L"\\Device\\HarddiskVolume3\\Windows\\SysWOW64\\OPENGL32.dll",
        L"\\Device\\HarddiskVolume3\\Windows\\SysWOW64\\combase.dll",
        L"\\Device\\HarddiskVolume3\\Program Files (x86)\\AssaultCube 1.3.0.2\\bin_win32\\SDL2.dll",
        L"\\Device\\HarddiskVolume3\\Windows\\SysWOW64\\IMM32.DLL",
        L"\\Device\\HarddiskVolume3\\Windows\\SysWOW64\\ole32.dll",
        L"\\Device\\HarddiskVolume3\\Windows\\SysWOW64\\OLEAUT32.dll",
        L"\\Device\\HarddiskVolume3\\Windows\\SysWOW64\\SETUPAPI.dll",
        L"\\Device\\HarddiskVolume3\\Windows\\SysWOW64\\cfgmgr32.dll",
        L"\\Device\\HarddiskVolume3\\Program Files (x86)\\AssaultCube 1.3.0.2\\bin_win32\\SDL2_image.dll",
        L"\\Device\\HarddiskVolume3\\Windows\\SysWOW64\\WINMM.dll",
        L"\\Device\\HarddiskVolume3\\Windows\\SysWOW64\\dbghelp.dll",
        L"\\Device\\HarddiskVolume3\\Windows\\SysWOW64\\GLU32.dll",
        L"\\Device\\HarddiskVolume3\\Windows\\SysWOW64\\VERSION.dll",
        L"\\Device\\HarddiskVolume3\\Program Files (x86)\\AssaultCube 1.3.0.2\\bin_win32\\libvorbisfile.dll",
        L"\\Device\\HarddiskVolume3\\Program Files (x86)\\AssaultCube 1.3.0.2\\bin_win32\\ogg.dll",
        L"\\Device\\HarddiskVolume3\\Program Files (x86)\\AssaultCube 1.3.0.2\\bin_win32\\libvorbis.dll",
        L"\\Device\\HarddiskVolume3\\Windows\\SysWOW64\\shcore.dll",
        L"\\Device\\HarddiskVolume3\\Windows\\SysWOW64\\uxtheme.dll",
        L"\\Device\\HarddiskVolume3\\Windows\\SysWOW64\\MSCTF.dll",
        L"\\Device\\HarddiskVolume3\\Windows\\SysWOW64\\kernel.appcore.dll",
        L"\\Device\\HarddiskVolume3\\Windows\\SysWOW64\\bcryptPrimitives.dll",
        L"\\Device\\HarddiskVolume3\\Windows\\SysWOW64\\clbcatq.dll",
        L"\\Device\\HarddiskVolume3\\Windows\\SysWOW64\\vm3dgl.dll",
        L"\\Device\\HarddiskVolume3\\Windows\\SysWOW64\\vm3dglhelper.dll",
        L"\\Device\\HarddiskVolume3\\Windows\\SysWOW64\\IME\\IMEKR\\imkrtip.dll",
        L"\\Device\\HarddiskVolume3\\Windows\\SysWOW64\\PROPSYS.dll",
        L"\\Device\\HarddiskVolume3\\Windows\\SysWOW64\\IME\\shared\\imetip.dll",
        L"\\Device\\HarddiskVolume3\\Windows\\SysWOW64\\OLEACC.dll",
        L"\\Device\\HarddiskVolume3\\Windows\\SysWOW64\\DUI70.dll",
        L"\\Device\\HarddiskVolume3\\Windows\\SysWOW64\\textinputframework.dll",
        L"\\Device\\HarddiskVolume3\\Windows\\SysWOW64\\CoreMessaging.dll",
        L"\\Device\\HarddiskVolume3\\Windows\\SysWOW64\\CoreUIComponents.dll",
        L"\\Device\\HarddiskVolume3\\Windows\\SysWOW64\\ntmarta.dll",
        L"\\Device\\HarddiskVolume3\\Windows\\SysWOW64\\wintypes.dll",
        L"\\Device\\HarddiskVolume3\\Windows\\SysWOW64\\SHLWAPI.dll",
        L"\\Device\\HarddiskVolume3\\Windows\\SysWOW64\\IME\\IMEKR\\imkrapi.dll",
        L"\\Device\\HarddiskVolume3\\Windows\\SysWOW64\\policymanager.dll",
        L"\\Device\\HarddiskVolume3\\Windows\\SysWOW64\\msvcp110_win.dll",
        L"\\Device\\HarddiskVolume3\\Windows\\SysWOW64\\IME\\shared\\imjkapi.dll",
        L"\\Device\\HarddiskVolume3\\Program Files (x86)\\AssaultCube 1.3.0.2\\bin_win32\\libpng16-16.dll",
        L"\\Device\\HarddiskVolume3\\Program Files (x86)\\AssaultCube 1.3.0.2\\bin_win32\\libjpeg-9.dll",
        L"\\Device\\HarddiskVolume3\\Windows\\SysWOW64\\dwmapi.dll",
        L"\\Device\\HarddiskVolume3\\Windows\\SysWOW64\\dxgi.dll",
        L"\\Device\\HarddiskVolume3\\Windows\\SysWOW64\\d3d11.dll",
        L"\\Device\\HarddiskVolume3\\Windows\\SysWOW64\\vm3dum_loader.dll",
        L"\\Device\\HarddiskVolume3\\Windows\\SysWOW64\\vm3dum_10.dll",
        L"\\Device\\HarddiskVolume3\\Windows\\SysWOW64\\dxcore.dll",
        L"\\Device\\HarddiskVolume3\\Windows\\SysWOW64\\winmmbase.dll",
        L"\\Device\\HarddiskVolume3\\Windows\\SysWOW64\\MMDevAPI.DLL",
        L"\\Device\\HarddiskVolume3\\Windows\\SysWOW64\\DEVOBJ.dll",
        L"\\Device\\HarddiskVolume3\\Windows\\SysWOW64\\wdmaud.drv",
        L"\\Device\\HarddiskVolume3\\Windows\\SysWOW64\\ksuser.dll",
        L"\\Device\\HarddiskVolume3\\Windows\\SysWOW64\\AVRT.dll",
        L"\\Device\\HarddiskVolume3\\Windows\\SysWOW64\\AUDIOSES.DLL",
        L"\\Device\\HarddiskVolume3\\Windows\\SysWOW64\\powrprof.dll",
        L"\\Device\\HarddiskVolume3\\Windows\\SysWOW64\\UMPDC.dll",
        L"\\Device\\HarddiskVolume3\\Windows\\SysWOW64\\msacm32.drv",
        L"\\Device\\HarddiskVolume3\\Windows\\SysWOW64\\MSACM32.dll",
        L"\\Device\\HarddiskVolume3\\Windows\\SysWOW64\\midimap.dll",
        L"\\Device\\HarddiskVolume3\\Windows\\SysWOW64\\dsound.dll",
        L"\\Device\\HarddiskVolume3\\Windows\\SysWOW64\\resourcepolicyclient.dll",
        L"\\Device\\HarddiskVolume3\\Windows\\SysWOW64\\wrap_oal.dll",
        L"\\Device\\HarddiskVolume3\\Windows\\SysWOW64\\Windows.UI.dll",
        L"\\Device\\HarddiskVolume3\\Windows\\SysWOW64\\WindowManagementAPI.dll",
        L"\\Device\\HarddiskVolume3\\Windows\\SysWOW64\\InputHost.dll",
        L"\\Device\\HarddiskVolume3\\Windows\\SysWOW64\\twinapi.appcore.dll"
    };

    for (INT i = 0; i < sizeof(whitelistedDlls) / sizeof(whitelistedDlls[0]); i++) {
        // 허용된 DLL 목록을 순회하면서
        if (_wcsicmp(dllName->Buffer, whitelistedDlls[i]) == 0) {
            // 전달된 DLL 경로와 일치하는 허용된 DLL이 있으면 TRUE를 반환합니다.
            return TRUE;
        }
    }
    return FALSE; // 허용된 DLL 목록에 없으면 FALSE를 반환합니다.
}

INT ListDllsInProcess(HANDLE hProcess)
{
    NTSTATUS status; // NTSTATUS 변수를 선언하여 ZwQueryVirtualMemory의 상태를 저장할 것입니다.
    PVOID baseAddress = 0; // 프로세스 내의 가상 메모리 베이스 주소를 0으로 초기화합니다.
    MEMORY_BASIC_INFORMATION memInfo; // 메모리의 기본 정보를 저장할 구조체를 선언합니다.
    ULONG resultLength; // ZwQueryVirtualMemory 호출의 결과 길이를 저장할 변수
    INT Alert_CNT = 0; // 허용되지 않은 DLL의 개수를 저장할 변수

    while (NT_SUCCESS(ZwQueryVirtualMemory(hProcess, baseAddress, MemoryBasicInformation, &memInfo, sizeof(memInfo), &resultLength))) {
        // 프로세스의 메모리 정보를 조회합니다. 성공하면 반복
        if (memInfo.Type == MEM_IMAGE) {
            // 해당 메모리 영역이 이미지(즉, DLL)인지 확인합니다.
            PVOID buffer = ExAllocatePool2(POOL_FLAG_NON_PAGED, 512, 'dlls');
            // DLL 경로 정보를 저장할 512바이트 크기의 메모리 버퍼를 할당합니다.
            if (!buffer) {
                DbgPrint("Failed to allocate buffer\n"); // 버퍼 할당 실패 시 에러 메시지를 출력하고 함수 종료
                return;
            }

            status = ZwQueryVirtualMemory(hProcess, memInfo.AllocationBase, MemorySectionName, buffer, 512, &resultLength);
            // 해당 메모리 영역의 섹션 이름(즉, DLL 경로)를 조회합니다.
            if (NT_SUCCESS(status)) {
                UNICODE_STRING* dllName = (UNICODE_STRING*)buffer;
                // 버퍼를 UNICODE_STRING 타입으로 캐스팅하여 DLL 이름을 확인합니다.
                if (dllName->Buffer != NULL) {
                    if (!IsDllInWhitelist(dllName)) {
                        DbgPrint("Alert! Unrecognized DLL loaded: %wZ\n", dllName);
                        // 허용되지 않은 DLL이 로드되었으면 경고 메시지를 출력하고 카운트 증가
                        Alert_CNT += 1;
                    }
                    else {
                        DbgPrint("Loaded DLL: %wZ\n", dllName); // 허용된 DLL은 로드 메시지만 출력
                    }
                }
            }
            ExFreePool(buffer); // 사용한 버퍼를 해제합니다.
        }
        baseAddress = (PVOID)((ULONG_PTR)memInfo.BaseAddress + memInfo.RegionSize);
        // 다음 메모리 영역으로 이동하여 계속 검사합니다.
    }
    return Alert_CNT; // 허용되지 않은 DLL의 개수를 반환합니다.
}

VOID ProcessListKill(DWORD AC_PID)
{
    PCWSTR szProcessNameList[ProcessListLength] = {
        L"cheatengine-x86_64-SSE4-AVX2.exe",
        L"x32dbg.exe",
        L"x64dbg.exe",
        L"x32dbg-unsigned.exe",
        L"x64dbg-unsigned.exe"
    };
    // 종료할 대상 프로세스 이름들의 목록을 정의합니다.
    int KillProcessCnt = 0; // 종료한 프로세스의 수를 카운트할 변수입니다.
    for (int i = 0; i < ProcessListLength; i++) {
        DWORD dwPID = 0; // 프로세스 ID를 저장할 변수입니다.
        dwPID = GetProcessIDByName(szProcessNameList[i]);
        // 정의된 각 프로세스 이름을 기반으로 PID를 찾습니다.
        if (dwPID != 0) {
            TerminateProcessByPID(dwPID);
            // PID가 유효하면 해당 프로세스를 종료합니다.
            DbgPrint("Debugging Process Name:%ws\nKill Process ID : %d\n", szProcessNameList[i], dwPID);
            // 디버그 출력으로 종료한 프로세스 이름과 PID를 출력합니다.
            KillProcessCnt++;
        }
    }
    if (KillProcessCnt != 0) {
        // 만약 종료된 프로세스가 있으면 메인 프로세스도 종료합니다.
        TerminateProcessByPID(AC_PID);
        DbgPrint("Main Process Name:ac_client.exe\nKill Process ID : %d\n", AC_PID);
    }
    return;
}

NTSTATUS TerminateProcessByPID(DWORD dwPID)
{
    NTSTATUS status;  // 함수의 반환 상태 코드 저장
    HANDLE hProcess;  // 프로세스 핸들 변수
    OBJECT_ATTRIBUTES objAttrs;  // 오브젝트 속성 구조체
    CLIENT_ID clientId;  // 클라이언트 ID 구조체로 프로세스 및 스레드 ID 저장

    // 오브젝트 속성 초기화
    InitializeObjectAttributes(&objAttrs, NULL, 0, NULL, NULL);
    clientId.UniqueProcess = (HANDLE)(ULONG_PTR)dwPID;  // PID를 클라이언트 ID에 설정
    clientId.UniqueThread = NULL;  // 스레드 ID는 사용하지 않음

    // PROCESS_TERMINATE 권한으로 프로세스 핸들을 열기
    status = ZwOpenProcess(&hProcess, PROCESS_TERMINATE, &objAttrs, &clientId);

    // 프로세스를 성공적으로 열었는지 확인
    if (NT_SUCCESS(status)) {
        // 프로세스를 종료
        status = ZwTerminateProcess(hProcess, STATUS_SUCCESS);

        // 종료에 성공했는지 확인
        if (NT_SUCCESS(status)) {
            DbgPrint("Successfully terminated process with PID: %d\n", dwPID);  // 성공 메시지 출력
        }
        else {
            DbgPrint("Failed to terminate process with PID: %d\n", dwPID);  // 실패 메시지 출력
        }

        // 프로세스 핸들 닫기
        ZwClose(hProcess);
    }
    else {
        DbgPrint("Failed to open process with PID: %d\n", dwPID);  // 프로세스를 열지 못했을 때 메시지 출력
    }

    // 함수의 최종 상태를 반환
    return status;
}

VOID PrintDllListByPID(DWORD dwPID)
{
    HANDLE hProcess;  // 프로세스 핸들 변수
    OBJECT_ATTRIBUTES objAttrs;  // 오브젝트 속성 구조체
    CLIENT_ID clientId;  // 클라이언트 ID 구조체
    NTSTATUS status;  // 함수의 반환 상태 코드 저장
    INT Alert_CNT = 0;  // 경고 카운터 변수 초기화

    // 오브젝트 속성 초기화
    InitializeObjectAttributes(&objAttrs, NULL, 0, NULL, NULL);
    clientId.UniqueProcess = (HANDLE)(ULONG_PTR)dwPID;  // PID를 클라이언트 ID에 설정
    clientId.UniqueThread = NULL;  // 스레드 ID는 사용하지 않음

    // PROCESS_QUERY_INFORMATION 및 PROCESS_VM_READ 권한으로 프로세스 핸들을 열기
    status = ZwOpenProcess(&hProcess, PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, &objAttrs, &clientId);

    // 프로세스를 성공적으로 열었는지 확인
    if (NT_SUCCESS(status)) {
        // 해당 프로세스에서 로드된 DLL 목록을 출력하고 경고 수를 받아옴
        Alert_CNT = ListDllsInProcess(hProcess);

        // 경고가 발생한 경우 프로세스 종료
        if (Alert_CNT != 0) {
            TerminateProcessByPID(dwPID);
        }

        // 프로세스 핸들 닫기
        ZwClose(hProcess);
    }
    else {
        DbgPrint("Failed to open process with PID: %d\n", dwPID);  // 프로세스를 열지 못했을 때 메시지 출력
    }
}

VOID PeriodicTask(PVOID context)
{
    UNREFERENCED_PARAMETER(context);  // 매개변수를 사용하지 않으므로 무시

    while (TRUE) {  // 무한 루프
        // 특정 프로세스 이름을 가진 프로세스의 PID를 얻기
        DWORD dwPID = GetProcessIDByName(L"ac_client.exe");
        DbgPrint("Process ID: %d\n", dwPID);  // PID 출력

        // PID가 0이 아니면 (즉, 해당 프로세스가 존재하면) 처리 수행
        if (dwPID != 0) {
            ProcessListKill(dwPID);  // 해당 PID의 프로세스를 종료
            PrintDllListByPID(dwPID);  // 해당 PID의 프로세스에서 DLL 목록을 출력하고 필요한 경우 종료
        }

        // 30초 대기 (100ns 단위로 30초)
        LARGE_INTEGER interval;
        interval.QuadPart = -300000000LL;  // 음수 값은 상대적인 대기를 의미
        KeDelayExecutionThread(KernelMode, FALSE, &interval);  // 30초 대기
    }
}

NTSTATUS DriverEntry(PDRIVER_OBJECT pDriverObject, PUNICODE_STRING pRegistryPath)
{
    UNREFERENCED_PARAMETER(pRegistryPath);  // 매개변수를 사용하지 않으므로 무시

    DbgPrint("DriverEntry\n");  // 드라이버가 로드되었음을 출력

    pDriverObject->DriverUnload = DriverUnload;  // 드라이버 언로드 함수 설정

    HANDLE threadHandle;  // 시스템 스레드 핸들 변수
    // 시스템 스레드를 생성하고 PeriodicTask 함수로 실행되도록 설정
    NTSTATUS status = PsCreateSystemThread(&threadHandle, THREAD_ALL_ACCESS, NULL, NULL, NULL, PeriodicTask, NULL);

    // 스레드 생성에 실패했는지 확인
    if (!NT_SUCCESS(status)) {
        DbgPrint("Failed to create system thread\n");  // 실패 메시지 출력
        return status;  // 실패 상태 반환
    }

    // 스레드 핸들 닫기
    ZwClose(threadHandle);

    // 드라이버 초기화 성공 반환
    return STATUS_SUCCESS;
}