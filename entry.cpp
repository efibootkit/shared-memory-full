#include "core.hpp"

KAPC_STATE Apc;
KAPC_STATE Apc2;
PVOID currentWin32Thread = 0;
PEPROCESS currentProcess = 0;
PETHREAD currentThread = 0;
CLIENT_ID currentCid = { 0 }; 
bool isWin32Thread = false;

PETHREAD GetValidWin32Thread( PVOID* win32Thread )
{
	int currentThreadId = 1;
	NTSTATUS status = STATUS_SUCCESS;
	do
	{
		PETHREAD currentEthread = 0;
		status = PsLookupThreadByThreadId( ( HANDLE ) currentThreadId, &currentEthread );

		if ( !NT_SUCCESS( status ) || !currentEthread )
		{
			currentThreadId++;
			continue;
		}

		if ( PsIsThreadTerminating( currentEthread ) )
		{
			currentThreadId++;
			continue;
		}

		PVOID Win32Thread = PsGetThreadWin32Thread( currentEthread );
		//memcpy(&Win32Thread, (PVOID)((UINT64)currentEthread + win32ThreadOffset), sizeof(PVOID));

		if ( Win32Thread )
		{
			PEPROCESS threadOwner = PsGetThreadProcess( currentEthread );
			char procName[ 15 ];
			memcpy( &procName, PsGetProcessImageFileName( threadOwner ), sizeof( procName ) );
			if ( !strcmp( procName, "explorer.exe" ) )
			{
				*win32Thread = Win32Thread;
				return currentEthread;
			}
		}
		currentThreadId++;
	} while ( 0x3000 > currentThreadId );

	return 0;
}

inline void SpoofWin32Thread( PVOID newWin32Value, PEPROCESS newProcess, CLIENT_ID newClientId )
{
	PKTHREAD currentThread = KeGetCurrentThread( );

	PsSetThreadWin32Thread( currentThread, newWin32Value, PsGetThreadWin32Thread( currentThread ) );

	PVOID processPtr = ( PVOID ) ( ( char* ) currentThread + processOffset );
	memcpy( processPtr, &newProcess, sizeof( PEPROCESS ) );

	PVOID clientIdPtr = ( PVOID ) ( ( char* ) currentThread + cidOffset );
	memcpy( clientIdPtr, &newClientId, sizeof( CLIENT_ID ) );
}


bool SpoofWin32Thread( )
{ 
	if ( isWin32Thread )
	{
		_DbgPrint( "already win32\n" );
		return true;
	}

	PVOID targetWin32Thread = 0;
	PETHREAD targetThread = GetValidWin32Thread( &targetWin32Thread );
	if ( !targetWin32Thread || !targetThread )
	{
		_DbgPrint( "failed to find win32thread" );
		return false;
	}
	PEPROCESS targetProcess = PsGetThreadProcess( targetThread );

	CLIENT_ID targetCid = { 0 };
	memcpy( &targetCid, ( PVOID ) ( ( char* ) targetThread + cidOffset ), sizeof( CLIENT_ID ) );

	KeStackAttachProcess( targetProcess, &Apc );
	SpoofWin32Thread( targetWin32Thread, targetProcess, targetCid );

	isWin32Thread = true;
}

void UnspoofWin32Thread( )
{
	if ( !isWin32Thread )
		return;

	SpoofWin32Thread( currentWin32Thread, currentProcess, currentCid );
	KeUnstackDetachProcess( &Apc );
	isWin32Thread = false;
}

VOID
ThreadEntry
(
	PVOID Ctx
)
{
	currentProcess = IoGetCurrentProcess( );
	currentThread = KeGetCurrentThread( ); // __readgsqword(0x188u)
	//_ETHREAD->_CLIENT_ID Cid;  
	memcpy( &currentCid, ( PVOID ) ( ( char* ) currentThread + cidOffset ), sizeof( CLIENT_ID ) );
	 
	KeStackAttachProcess(
		(PRKPROCESS)_Client,
		&Apc2
	);

	PHYSICAL_ADDRESS PhysShared = MmGetPhysicalAddress(
			reinterpret_cast< PVOID >( _SharedMemAddr )
		);

	if ( PhysShared.QuadPart )
	{
		SharedMem = reinterpret_cast< c_SharedMem* >(
				MmMapIoSpace(
					PhysShared,
					sizeof( SharedMem ),
					MmNonCached
			)
		);
	}

	KeUnstackDetachProcess(
		&Apc2
	);

	if ( SharedMem )
	{
		while ( TRUE )
		{
			if ( !SpoofWin32Thread( ) && !isWin32Thread )
			{
				_DbgPrint( "Spoof thread failed\n" );
				continue;
			}

			if ( !pCore::SendSharedMemTick( ) )
			{
				_DbgPrint( "Sent tick failed\n" );
				continue;
			}

			UnspoofWin32Thread( );
			YieldProcessor( );
		}
	}

	ObDereferenceObject( _Client );
}

NTSTATUS
ReroutedEntry( 
	std::uint64_t SharedMemAddr,
	std::uint32_t ClientPID
)
{ 
	_SharedMemAddr = SharedMemAddr;
	_ClientPID = ClientPID;

	_DbgPrint( "wowbigweaponssir -> Shared mem ptr -> 0x%llp\n", _SharedMemAddr ); 
	_DbgPrint( "wowbigweaponssir -> Client proc ID-> 0x%llp\n", _ClientPID );

	if ( !NT_SUCCESS(			     // [amap] driver entry returned [0xC0000001L]			
		PsLookupProcessByProcessId(
			HANDLE( ClientPID ),
			&_Client 
			)
		)
	)
	{
		return STATUS_UNSUCCESSFUL;  // [amap] driver entry returned [0xC0000001L]
	}

	HANDLE SystemThreadHdl;
	PsCreateSystemThread(
		&SystemThreadHdl,
		THREAD_ALL_ACCESS,
		NULL,
		NULL,
		NULL,
		ThreadEntry,
		NULL
	);

	return ZwClose(
		SystemThreadHdl				// [amap] driver entry returned [0x00000000L]
	); 
}