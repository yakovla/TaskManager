// ListProcesses.cpp : Defines the entry point for the console application.
//

#include "stdafx.h"
#include <windows.h>
#include <tlhelp32.h>
#include <tchar.h>
#include <psapi.h>


//  Forward declarations:

BOOL GetProcessList( );
BOOL ListProcessModules( DWORD dwPID );
BOOL ListProcessThreads( DWORD dwOwnerPID );

void printError( TCHAR* msg );

DWORD dWorkingSetPages[ 1024 * 128 ]; // hold the working set 
// information get from QueryWorkingSet()
DWORD dPageSize = 0x1000;
int main( void )
{
  GetProcessList( );
  return 0;
}
int Compare( const void * Val1, const void * Val2 )
{
    if ( *(PDWORD)Val1 == *(PDWORD)Val2 )
    return 0;

    return *(PDWORD)Val1 > *(PDWORD)Val2 ? 1 : -1;
}
void EnableDebugPriv()
{
    HANDLE hToken;
    LUID luid;
    TOKEN_PRIVILEGES tkp;

    OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken);

    LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &luid);

    tkp.PrivilegeCount = 1;
    tkp.Privileges[0].Luid = luid;
    tkp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

    AdjustTokenPrivileges(hToken, false, &tkp, sizeof(tkp), NULL, NULL);

    CloseHandle(hToken); 
}

float GetProcessCpuUsage(HANDLE proc){
	float cpuUsage=0;
	FILETIME ftSysIdle, ftSysKernel, ftSysUser;
	FILETIME ftProcCreation, ftProcExit, ftProcKernel, ftProcUser;

	GetSystemTimes(&ftSysIdle, &ftSysKernel, &ftSysUser);
	GetProcessTimes(proc, &ftProcCreation,&ftProcExit, &ftProcKernel, &ftProcUser);

	LARGE_INTEGER a;
	LARGE_INTEGER b;
	a.LowPart = ftSysKernel.dwLowDateTime;
	a.HighPart = ftSysKernel.dwHighDateTime;
	b.LowPart = ftSysUser.dwLowDateTime;
	b.HighPart = ftSysUser.dwHighDateTime;

	ULONGLONG nTotalSys =  a.QuadPart + b.QuadPart;

	a.LowPart = ftProcKernel.dwLowDateTime;
	a.HighPart = ftProcKernel.dwHighDateTime;
	b.LowPart = ftProcKernel.dwLowDateTime;
	b.HighPart = ftProcKernel.dwHighDateTime;

	ULONGLONG nTotalProc = a.QuadPart + b.QuadPart;

	cpuUsage = (float)((100.0 * nTotalProc) / nTotalSys);
	

	return cpuUsage;
}

 DWORD CalculateWSPrivate(DWORD processID)
{
    DWORD dSharedPages = 0;
    DWORD dPrivatePages = 0; 
    DWORD dPageTablePages = 0;
 
    HANDLE hProcess = OpenProcess( PROCESS_QUERY_INFORMATION | 
		PROCESS_VM_READ, FALSE, processID );

    if ( !hProcess )
    return 0;

    __try
    { 
        char szBuffer[MAX_PATH * 4];

        if ( !QueryWorkingSet(hProcess, dWorkingSetPages, sizeof(dWorkingSetPages)) )
        __leave;

        DWORD dPages = dWorkingSetPages[0];

        qsort( &dWorkingSetPages[1], dPages, sizeof(DWORD), Compare );

        for ( DWORD i = 1; i <= dPages; i++ )
        {
            DWORD dCurrentPageStatus = 0; 
            DWORD dCurrentPageAddress;
            DWORD dNextPageAddress;
            DWORD dNextPageFlags;
            DWORD dPageAddress = dWorkingSetPages[i] & 0xFFFFF000;
            DWORD dPageFlags = dWorkingSetPages[i] & 0x00000FFF;

            while ( i <= dPages ) // iterate all pages
            {
                dCurrentPageStatus++;

                if ( i == dPages ) //if last page
                break;
 
                dCurrentPageAddress = dWorkingSetPages[i] & 0xFFFFF000;
                dNextPageAddress = dWorkingSetPages[i+1] & 0xFFFFF000;
                dNextPageFlags = dWorkingSetPages[i+1] & 0x00000FFF;
 
                //decide whether iterate further or exit
                //(this is non-contiguous page or have different flags) 
                if ( (dNextPageAddress == (dCurrentPageAddress + dPageSize)) 
			&& (dNextPageFlags == dPageFlags) )
                {
                    i++;
                }
                else
                break;
            }
 
            if ( (dPageAddress < 0xC0000000) || (dPageAddress > 0xE0000000) )
            {
                if ( dPageFlags & 0x100 ) // this is shared one
                dSharedPages += dCurrentPageStatus;

                else // private one
                dPrivatePages += dCurrentPageStatus;
            }
            else
            dPageTablePages += dCurrentPageStatus; //page table region 
        } 

        DWORD dTotal = dPages * 4;
        DWORD dShared = dSharedPages * 4;
        DWORD WSPrivate = dTotal - dShared;

        return WSPrivate;
    }
    __finally
    {
        CloseHandle( hProcess );
    }
}

 

 
 BOOL GetProcessList( )
{
  HANDLE hProcessSnap;
  HANDLE hProcess;
  PROCESSENTRY32 pe32;
  DWORD dwPriorityClass;
  EnableDebugPriv();
  // Take a snapshot of all processes in the system.
  hProcessSnap = CreateToolhelp32Snapshot( TH32CS_SNAPPROCESS, 0 );
  if( hProcessSnap == INVALID_HANDLE_VALUE )
  {
    printError( TEXT("CreateToolhelp32Snapshot (of processes)") );
    return( FALSE );
  }

  // Set the size of the structure before using it.
  pe32.dwSize = sizeof( PROCESSENTRY32 );

  // Retrieve information about the first process,
  // and exit if unsuccessful
  if( !Process32First( hProcessSnap, &pe32 ) )
  {
    printError( TEXT("Process32First") ); // show cause of failure
    CloseHandle( hProcessSnap );          // clean the snapshot object
    return( FALSE );
  }


  // Now walk the snapshot of processes, and
  // display information about each process in turn
  _PROCESS_MEMORY_COUNTERS_EX info;
  do
  {
    _tprintf( TEXT("\n\n=====================================================" ));
    _tprintf( TEXT("\nPROCESS NAME:  %s"), pe32.szExeFile );
    _tprintf( TEXT("\n-------------------------------------------------------" ));

    
    hProcess = OpenProcess( PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pe32.th32ProcessID );
    if( hProcess == NULL )
      printError( TEXT("OpenProcess") );
    
	DWORD memory = CalculateWSPrivate(pe32.th32ProcessID);
	
	float cpuUsage = GetProcessCpuUsage(hProcess);
	_tprintf( TEXT("\nProcess ID: %d  \n"), pe32.th32ProcessID );
	_tprintf( TEXT("Memory(Private working set): %lu  \n"),memory);
	_tprintf( TEXT("CPU: %f%%  \n"), cpuUsage);



  } while( Process32Next( hProcessSnap, &pe32 ) );

  CloseHandle( hProcessSnap );
  return( TRUE );
}


BOOL ListProcessModules( DWORD dwPID )
{
  HANDLE hModuleSnap = INVALID_HANDLE_VALUE;
  MODULEENTRY32 me32;

  // Take a snapshot of all modules in the specified process.
  hModuleSnap = CreateToolhelp32Snapshot( TH32CS_SNAPMODULE, dwPID );
  if( hModuleSnap == INVALID_HANDLE_VALUE )
  {
    printError( TEXT("CreateToolhelp32Snapshot (of modules)") );
    return( FALSE );
  }

  // Set the size of the structure before using it.
  me32.dwSize = sizeof( MODULEENTRY32 );

  // Retrieve information about the first module,
  // and exit if unsuccessful
  if( !Module32First( hModuleSnap, &me32 ) )
  {
    printError( TEXT("Module32First") );  // show cause of failure
    CloseHandle( hModuleSnap );           // clean the snapshot object
    return( FALSE );
  }

  // Now walk the module list of the process,
  // and display information about each module
  do
  {
	
    _tprintf( TEXT("\n\n     MODULE NAME:     %s"),   me32.szModule );
    _tprintf( TEXT("\n     Executable     = %s"),     me32.szExePath );
    _tprintf( TEXT("\n     Process ID     = 0x%08X"),         me32.th32ProcessID );
    _tprintf( TEXT("\n     Ref count (g)  = 0x%04X"),     me32.GlblcntUsage );
    _tprintf( TEXT("\n     Ref count (p)  = 0x%04X"),     me32.ProccntUsage );
    _tprintf( TEXT("\n     Base address   = 0x%08X"), (DWORD) me32.modBaseAddr );
    _tprintf( TEXT("\n     Base size      = %d"),             me32.modBaseSize );

  } while( Module32Next( hModuleSnap, &me32 ) );

  CloseHandle( hModuleSnap );
  return( TRUE );
}

BOOL ListProcessThreads( DWORD dwOwnerPID ) 
{ 
  HANDLE hThreadSnap = INVALID_HANDLE_VALUE; 
  THREADENTRY32 te32; 
 
  // Take a snapshot of all running threads  
  hThreadSnap = CreateToolhelp32Snapshot( TH32CS_SNAPTHREAD, 0 ); 
  if( hThreadSnap == INVALID_HANDLE_VALUE ) 
    return( FALSE ); 
 
  // Fill in the size of the structure before using it. 
  te32.dwSize = sizeof(THREADENTRY32); 
 
  // Retrieve information about the first thread,
  // and exit if unsuccessful
  if( !Thread32First( hThreadSnap, &te32 ) ) 
  {
    printError( TEXT("Thread32First") ); // show cause of failure
    CloseHandle( hThreadSnap );          // clean the snapshot object
    return( FALSE );
  }

  // Now walk the thread list of the system,
  // and display information about each thread
  // associated with the specified process
  do 
  { 
    if( te32.th32OwnerProcessID == dwOwnerPID )
    {
      _tprintf( TEXT("\n\n     THREAD ID      = 0x%08X"), te32.th32ThreadID ); 
      _tprintf( TEXT("\n     Base priority  = %d"), te32.tpBasePri ); 
      _tprintf( TEXT("\n     Delta priority = %d"), te32.tpDeltaPri ); 
      _tprintf( TEXT("\n"));
    }
  } while( Thread32Next(hThreadSnap, &te32 ) ); 

  CloseHandle( hThreadSnap );
  return( TRUE );
}

void printError( TCHAR* msg )
{
  DWORD eNum;
  TCHAR sysMsg[256];
  TCHAR* p;

  eNum = GetLastError( );
  FormatMessage( FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
         NULL, eNum,
         MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), // Default language
         sysMsg, 256, NULL );

  // Trim the end of the line and terminate it with a null
  p = sysMsg;
  while( ( *p > 31 ) || ( *p == 9 ) )
    ++p;
  do { *p-- = 0; } while( ( p >= sysMsg ) &&
                          ( ( *p == '.' ) || ( *p < 33 ) ) );

  // Display the message
  _tprintf( TEXT("\n  WARNING: %s failed with error %d (%s)"), msg, eNum, sysMsg );
}
