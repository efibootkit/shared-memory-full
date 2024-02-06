#include <ntifs.h>
#include <cstdint>    

#define cidOffset 0x478
#define processOffset 0x220
#define _DbgPrint DbgPrint
inline std::uint64_t _SharedMemAddr;
inline std::uint32_t _ClientPID;
inline PEPROCESS _Client;
inline PEPROCESS _Game;

extern "C"
{
	NTSTATUS NTAPI MmCopyVirtualMemory( PEPROCESS SourceProcess, PVOID SourceAddress, PEPROCESS TargetProcess, PVOID TargetAddress, SIZE_T BufferSize, KPROCESSOR_MODE PreviousMode, PSIZE_T ReturnSize );
	NTKERNELAPI PVOID PsGetProcessSectionBaseAddress( PEPROCESS Process );
	NTKERNELAPI PVOID NTAPI PsGetProcessWow64Process( IN PEPROCESS Process );
	NTKERNELAPI PPEB NTAPI PsGetProcessPeb( IN PEPROCESS Process );
	NTSTATUS NTAPI ZwQuerySystemInformation( ULONG SystemInformationClass, PVOID SystemInformation, ULONG SystemInformationLength, PULONG ReturnLength );
	NTKERNELAPI PVOID NTAPI RtlFindExportedRoutineByName( PVOID ImageBase, PCCH RoutineNam );
	NTSYSAPI NTSTATUS NTAPI ObReferenceObjectByName( PUNICODE_STRING ObjectName, ULONG Attributes, PACCESS_STATE AccessState, ACCESS_MASK DesiredAccess, POBJECT_TYPE ObjectType, KPROCESSOR_MODE AccessMode, PVOID ParseContext, PVOID* Object );
	NTKERNELAPI PVOID __fastcall PsGetProcessImageFileName( PEPROCESS process );
	NTKERNELAPI PVOID PsGetThreadWin32Thread( PKTHREAD thread );
	NTKERNELAPI PVOID PsSetThreadWin32Thread( PKTHREAD thread, PVOID wantedValue, PVOID compareValue );
}

namespace EtwEventRW
{
	NTSTATUS PhysWrite( int pid, uint64_t Address, uint64_t AllocatedBuffer, SIZE_T size, SIZE_T* written );
	NTSTATUS PhysRead( int pid, uint64_t Address, uint64_t AllocatedBuffer, SIZE_T size, SIZE_T* read );
}

namespace pCore
{

	bool
		SendPing
		(

		);


	bool
		SendSharedMemTick
		(
		);
}

enum EOperation
{
	Complete,
	Read,
	Write,
	ImageBase,
	Ping
};

struct c_PhysMem
{
	std::uint32_t source_pid;
	std::uint64_t source_address;
	std::uint32_t target_pid;
	std::uint64_t target_address;
	std::uint64_t base_address;
	size_t size;
};
 
struct c_SharedMem
{
	std::uint32_t Operation; 
	c_PhysMem PhysMem;
}; 
 
inline c_SharedMem* SharedMem;