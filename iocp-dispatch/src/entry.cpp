#include "dispatcher/dispatcher.hpp"

static uint32_t get_pid_from_name( const wchar_t* process_name )
{
	const HANDLE snapshot = CreateToolhelp32Snapshot( TH32CS_SNAPPROCESS, 0 );
	if ( snapshot == INVALID_HANDLE_VALUE )
		return 0;

	PROCESSENTRY32W process_entry{ sizeof( PROCESSENTRY32W ) };

	if ( !Process32FirstW( snapshot, &process_entry ) )
	{
		CloseHandle( snapshot );
		return 0;
	}

	do
	{
		if ( !_wcsicmp( process_entry.szExeFile, process_name ) )
		{
			CloseHandle( snapshot );
			return process_entry.th32ProcessID;
		}

	} while ( Process32NextW( snapshot, &process_entry ) );

	CloseHandle( snapshot );
	return 0;
}

int main( )
{
	const uint32_t target_pid = get_pid_from_name( L"notepad.exe" );
	LOG( "[main]: target_pid: %u\n", target_pid );
	if ( !target_pid )
		return EXIT_FAILURE;

	uint8_t shellcode[ ] =
	{
		0x48, 0x83, 0xec, 0x28,											//sub rsp, 0x28
		0x48, 0x31, 0xc9,												//xor rcx, rcx
		0x48, 0x8d, 0x15, 0x1b, 0x00, 0x00, 0x00,						//lea rdx, [rip+0x1b]
		0x4c, 0x8d, 0x05, 0x17, 0x00, 0x00, 0x00,						//lea r8, [rip+0x17]
		0x4d, 0x31, 0xc9,												//xor r9, r9
		0x48, 0xb8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,		//mov rax, 0x0000000000000000
		0xff, 0xd0,														//call rax
		0x48, 0x83, 0xc4, 0x28,											//add rsp, 0x28
		0xc3,															//ret
		0x68, 0x69, 0x00,												//"hi"
		0x68, 0x65, 0x6c, 0x6c, 0x6f, 0x00,								//"hello"
	};

	*reinterpret_cast< uint64_t* >( &shellcode[ 26 ] ) = reinterpret_cast< uint64_t >( &MessageBoxA );

	const dispatcher::e_status stauts = dispatcher::send( target_pid, shellcode, sizeof( shellcode ) );
	LOG( "[main]: status: %d\n", stauts );

	system( "pause" );
	return EXIT_SUCCESS;
}