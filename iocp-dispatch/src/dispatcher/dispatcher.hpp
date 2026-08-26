#pragma once

#include <windows.h>
#include <tlhelp32.h>
#include <iostream>
#include <cstdint>
#include <vector>

#pragma comment( lib, "mincore.lib" )

#ifdef _DEBUG
#define LOG( ... ) printf( __VA_ARGS__ )
#else
#define LOG( ... )
#endif

#define STATUS_SUCCESS ( ( NTSTATUS )0 )

namespace dispatcher
{
	enum e_status : uint8_t
	{
		success = 0,
		open_process_failed,
		get_module_handle_failed,
		get_proc_addr_failed,
		tpp_global_pool_invalid,
		iocp_handle_invalid,
		iocp_duplicate_invalid,
		allocation_failed,
		write_failed,
		call_target_failed,
		set_completion_failed
	};

	const e_status send( const uint32_t pid, uint8_t* code, const size_t size );
}