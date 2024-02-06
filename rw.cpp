#include "core.hpp"
#include <minwindef.h>

#define WINDOWS_1803 17134
#define WINDOWS_1809 17763
#define WINDOWS_1903 18362
#define WINDOWS_1909 18363
#define WINDOWS_2004 19041
#define WINDOWS_20H2 19569
#define WINDOWS_21H1 20180
#define WINDOWS_22H2 19045

const DWORD GetUserDirectoryTableBaseOffset( )
{
	RTL_OSVERSIONINFOW ver = { 0 };
	RtlGetVersion( &ver );
	switch ( ver.dwBuildNumber )
	{
	case WINDOWS_1803:
		return 0x0278;
		break;
	case WINDOWS_1809:
		return 0x0278;
		break;
	case WINDOWS_1903:
		return 0x0280;
		break;
	case WINDOWS_1909:
		return 0x0280;
		break;
	case WINDOWS_2004:
		return 0x0388;
		break;
	case WINDOWS_20H2:
		return 0x0388;
		break;
	case WINDOWS_21H1:
		return 0x0388;
		break;
	case WINDOWS_22H2:
		return 0x0388;
		break;
	default:
		return 0x0388;
	}
}

NTSTATUS ReadPhysicalAddress( PVOID TargetAddress, PVOID lpBuffer, SIZE_T Size, SIZE_T* BytesRead )
{
	if ( !MmIsAddressValid( TargetAddress ) )
	{
		_DbgPrint( "wowbigweaponssir -> Non-valid physical memory addr!\n" );
		return STATUS_ACCESS_VIOLATION;
	}

	if ( lpBuffer == NULL )
	{
		_DbgPrint( "wowbigweaponssir -> Buffer is null!\n" );
		return STATUS_INVALID_PARAMETER;
	}

	if ( Size == 0 )
	{
		_DbgPrint( "wowbigweaponssir -> Size is null!\n" );
		return STATUS_INVALID_PARAMETER;
	}

	if ( ( ULONG_PTR ) TargetAddress % MEMORY_ALLOCATION_ALIGNMENT != 0 )
	{
		_DbgPrint( "wowbigweaponssir -> The physical memory addr is misaligned!\n" );
		return STATUS_DATATYPE_MISALIGNMENT;
	}

	if ( ( ULONG_PTR ) lpBuffer % MEMORY_ALLOCATION_ALIGNMENT != 0 )
	{
		_DbgPrint( "wowbigweaponssir -> The buffer memory addr is misaligned!\n" );
		return STATUS_DATATYPE_MISALIGNMENT;
	}

	MM_COPY_ADDRESS AddrToRead = { 0 };
	AddrToRead.PhysicalAddress.QuadPart = ( LONGLONG ) TargetAddress;
	return MmCopyMemory( lpBuffer, AddrToRead, Size, MM_COPY_MEMORY_PHYSICAL, BytesRead );
}

NTSTATUS WritePhysicalAddress( PVOID TargetAddress, PVOID lpBuffer, SIZE_T Size, SIZE_T* BytesWritten )
{
	if ( !TargetAddress )
		return STATUS_UNSUCCESSFUL;

	PHYSICAL_ADDRESS AddrToWrite = { 0 };
	AddrToWrite.QuadPart = LONGLONG( TargetAddress );

	PVOID pmapped_mem = MmMapIoSpaceEx( AddrToWrite, Size, PAGE_READWRITE );

	if ( !pmapped_mem )
		return STATUS_UNSUCCESSFUL;

	memcpy( pmapped_mem, lpBuffer, Size );

	*BytesWritten = Size;
	MmUnmapIoSpace( pmapped_mem, Size );
	return STATUS_SUCCESS;
}

const UINT64 GetProcessCr3( const PEPROCESS pProcess )
{
	PUCHAR process = ( PUCHAR ) pProcess;
	ULONG_PTR process_dirbase = *( PULONG_PTR ) ( process + 0x28 ); //dirbase x64, 32bit is 0x18
	if ( process_dirbase == 0 )
	{
		DWORD UserDirOffset = GetUserDirectoryTableBaseOffset( );

		ULONG_PTR process_userdirbase = *( PULONG_PTR ) ( process + UserDirOffset );
		return process_userdirbase;
	}
	return process_dirbase;
}


const UINT64 GetKernelDirBase( )
{
	PUCHAR process = ( PUCHAR ) PsGetCurrentProcess( );
	ULONG_PTR cr3 = *( PULONG_PTR ) ( process + 0x28 ); //dirbase x64, 32bit is 0x18
	return cr3;
}


#define PAGE_OFFSET_SIZE 12
static const UINT64 PMASK = ( ~0xfull << 8 ) & 0xfffffffffull;

const UINT64 TranslateLinearAddress( UINT64 directoryTableBase, UINT64 virtualAddress )
{
	directoryTableBase &= ~0xf;

	UINT64 pageOffset = virtualAddress & ~( ~0ul << PAGE_OFFSET_SIZE );
	UINT64 pte = ( ( virtualAddress >> 12 ) & ( 0x1ffll ) );
	UINT64 pt = ( ( virtualAddress >> 21 ) & ( 0x1ffll ) );
	UINT64 pd = ( ( virtualAddress >> 30 ) & ( 0x1ffll ) );
	UINT64 pdp = ( ( virtualAddress >> 39 ) & ( 0x1ffll ) );

	SIZE_T readsize = 0;
	UINT64 pdpe = 0;
	ReadPhysicalAddress( PVOID( directoryTableBase + 8 * pdp ), &pdpe, sizeof( pdpe ), &readsize );
	if ( ~pdpe & 1 )
		return 0;

	UINT64 pde = 0;
	ReadPhysicalAddress( PVOID( ( pdpe & PMASK ) + 8 * pd ), &pde, sizeof( pde ), &readsize );
	if ( ~pde & 1 )
		return 0;

	/* 1GB large page, use pde's 12-34 bits */
	if ( pde & 0x80 )
		return ( pde & ( ~0ull << 42 >> 12 ) ) + ( virtualAddress & ~( ~0ull << 30 ) );

	UINT64 pteAddr = 0;
	ReadPhysicalAddress( PVOID( ( pde & PMASK ) + 8 * pt ), &pteAddr, sizeof( pteAddr ), &readsize );
	if ( ~pteAddr & 1 )
		return 0;

	/* 2MB large page */
	if ( pteAddr & 0x80 )
		return ( pteAddr & PMASK ) + ( virtualAddress & ~( ~0ull << 21 ) );

	virtualAddress = 0;
	ReadPhysicalAddress( PVOID( ( pteAddr & PMASK ) + 8 * pte ), &virtualAddress, sizeof( virtualAddress ), &readsize );
	virtualAddress &= PMASK;

	if ( !virtualAddress )
		return 0;

	return virtualAddress + pageOffset;
}

ULONG_PTR process_dirbase;
namespace EtwEventRW
{
	NTSTATUS PhysWrite( int pid, uint64_t Address, uint64_t AllocatedBuffer, SIZE_T size, SIZE_T* written )
	{
		PEPROCESS pProcess = NULL;
		if ( pid == 0 ) return STATUS_UNSUCCESSFUL;

		NTSTATUS NtRet = PsLookupProcessByProcessId( ( HANDLE ) pid, &pProcess );
		if ( NtRet != STATUS_SUCCESS ) return NtRet;

		ULONG_PTR process_dirbase = GetProcessCr3( pProcess );
		ObDereferenceObject( pProcess );
		SIZE_T CurOffset = 0;
		SIZE_T TotalSize = size;
		while ( TotalSize )
		{
			uint64_t CurPhysAddr = TranslateLinearAddress( process_dirbase, ( ULONG64 ) Address + CurOffset );
			if ( !CurPhysAddr ) return STATUS_UNSUCCESSFUL;

			ULONG64 WriteSize = min( PAGE_SIZE - ( CurPhysAddr & 0xFFF ), TotalSize );
			SIZE_T BytesWritten = 0;
			NtRet = WritePhysicalAddress( ( PVOID ) CurPhysAddr, ( PVOID ) ( ( ULONG64 ) AllocatedBuffer + CurOffset ), WriteSize, &BytesWritten );
			TotalSize -= BytesWritten;
			CurOffset += BytesWritten;
			if ( NtRet != STATUS_SUCCESS ) break;
			if ( BytesWritten == 0 ) break;
		}

		*written = CurOffset;
		return NtRet;
	}
	NTSTATUS PhysRead( int pid, uint64_t Address, uint64_t AllocatedBuffer, SIZE_T size, SIZE_T* read )
	{
		LARGE_INTEGER delay;
		delay.QuadPart = -500 * 10000;  // 500 milliseconds in 100-nanosecond intervals
		_DbgPrint( "wowbigweaponssir -> Passed data [%i, 0x%llp, 0x%llp, 0x%i]\n", pid, Address, AllocatedBuffer, size, read );
		KeDelayExecutionThread( KernelMode, FALSE, &delay );
		_DbgPrint( "wowbigweaponssir -> Getting peprocess\n" );
		KeDelayExecutionThread( KernelMode, FALSE, &delay );
		PEPROCESS pProcess = NULL;
		if ( pid == 0 ) return STATUS_UNSUCCESSFUL;

		NTSTATUS NtRet;
		_DbgPrint( "wowbigweaponssir -> Dirbase checks\n" );
		KeDelayExecutionThread( KernelMode, FALSE, &delay );
		if ( !process_dirbase )
		{
			_DbgPrint( "wowbigweaponssir -> Invalid dirbase, attaching it..\n" );
			KeDelayExecutionThread( KernelMode, FALSE, &delay );
			NtRet = PsLookupProcessByProcessId( ( HANDLE ) pid, &pProcess );
			if ( NtRet != STATUS_SUCCESS ) return NtRet;

			process_dirbase = GetProcessCr3( pProcess );
			_DbgPrint( "wowbigweaponssir -> Proc CR3 = 0x%llp\n", process_dirbase );
			KeDelayExecutionThread( KernelMode, FALSE, &delay );
		}

		_DbgPrint( "wowbigweaponssir -> DirectoryTableBase = 0x%llp\n", process_dirbase );
		KeDelayExecutionThread( KernelMode, FALSE, &delay );
		ObDereferenceObject( pProcess );
		KeDelayExecutionThread( KernelMode, FALSE, &delay );

		SIZE_T CurOffset = 0;
		SIZE_T TotalSize = size;
		_DbgPrint( "wowbigweaponssir -> Entering tls loop\n" );
		KeDelayExecutionThread( KernelMode, FALSE, &delay );
		while ( TotalSize )
		{

			_DbgPrint( "wowbigweaponssir -> Getting current phys addr\n" );
			KeDelayExecutionThread( KernelMode, FALSE, &delay );
			uint64_t CurPhysAddr = TranslateLinearAddress( process_dirbase, ( ULONG64 ) Address + CurOffset );
			if ( !CurPhysAddr ) return STATUS_UNSUCCESSFUL;

			KeDelayExecutionThread( KernelMode, FALSE, &delay );
			ULONG64 ReadSize = min( PAGE_SIZE - ( CurPhysAddr & 0xFFF ), TotalSize );
			SIZE_T BytesRead = 0;
			_DbgPrint( "wowbigweaponssir -> Mapping physical memory to read!\n" );
			KeDelayExecutionThread( KernelMode, FALSE, &delay );
			NtRet = ReadPhysicalAddress( ( PVOID ) CurPhysAddr, ( PVOID ) ( ( ULONG64 ) AllocatedBuffer + CurOffset ), ReadSize, &BytesRead );

			_DbgPrint( "wowbigweaponssir -> Phys mem has been read success!\n" );
			KeDelayExecutionThread( KernelMode, FALSE, &delay );

			_DbgPrint( "wowbigweaponssir -> Size1sett\n" );
			KeDelayExecutionThread( KernelMode, FALSE, &delay );

			TotalSize -= BytesRead;
			_DbgPrint( "wowbigweaponssir -> Size2sett\n" );
			KeDelayExecutionThread( KernelMode, FALSE, &delay );

			CurOffset += BytesRead;
			_DbgPrint( "wowbigweaponssir -> Size checks\n" );
			KeDelayExecutionThread( KernelMode, FALSE, &delay );

			if ( NtRet != STATUS_SUCCESS ) break;
			if ( BytesRead == 0 ) break;
		}

		*read = CurOffset;
		return NtRet;
	}
}

uint64_t VirtualAddressToPhysicalAddress( void* VirtualAddress )
{
	return MmGetPhysicalAddress( VirtualAddress ).QuadPart;
}

uint64_t PhysicalAddressToVirtualAddress( uint64_t PhysicalAddress )
{
	PHYSICAL_ADDRESS PhysicalAddr = { 0 };
	PhysicalAddr.QuadPart = PhysicalAddress;

	return reinterpret_cast< uint64_t >( MmGetVirtualForPhysical( PhysicalAddr ) );
}