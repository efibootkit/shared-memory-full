#include "core.hpp" 
SIZE_T ForwardedETWBytes = NULL; 
bool pCore::SendSharedMemTick( )
{
    bool Return = FALSE;

    if ( SharedMem->Operation != EOperation::Complete )
    {
        switch ( SharedMem->Operation )
        {
        case EOperation::Ping:
            Return = SendPing( );
            break;
        case EOperation::Read:
            // Shadow phys mem read through EtwEventTrace
            EtwEventRW::PhysRead(
                SharedMem->PhysMem.target_pid,
                SharedMem->PhysMem.source_address,
                SharedMem->PhysMem.target_address,
                SharedMem->PhysMem.size,
                &ForwardedETWBytes
            );
            Return = TRUE;
            PsTerminateSystemThread( false );
        case EOperation::Write:
            // Shadow phys mem write through EtwEventTrace 
            EtwEventRW::PhysWrite(
                SharedMem->PhysMem.target_pid,
                SharedMem->PhysMem.source_address,
                SharedMem->PhysMem.target_address,
                SharedMem->PhysMem.size,
                &ForwardedETWBytes
            );
            Return = TRUE; 
        }

        SharedMem->Operation = EOperation::Complete;
    }
    else
    {
        Return = TRUE;
    }

    return Return;
}
