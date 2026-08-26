# iocp-dispatch

code execution via hijacking the windows thread pool i/o completion port to dispatch code inside a target process.
every windows process that uses the default thread pool (CreateThreadpoolWork etc.) has an internal pool object managed by ntdll.
this pool object contains a handle to the i/o completion port at +0x40.

# background

worker threads in the pool sit in a loop calling ZwWaitForWorkViaWorkerFactory, which waits for the iocp, when it arrives 1 of 2 things happen:
- if completion key is null, the worker scans the pools internal priority queues for pending tasks.
- if completion key is not null, the worker treats it as a pointer to an object and calls a callback at +0x38 (what we use)

# advantages
- no new threads are created, execution happens on an existing pool worker thread
- no apc, no thread hijacking
- single api call triggers execution
- worker dispatches through its normal code path

# offsets
tested on windows 11 25h2 (23200.9168)
- TppPoolpGlobalPool+0x40 -> iocp handle
- dispatch_object+0x38 -> execute callback
- dispatch_object+0x40 -> NUMA node
- dispatch_object+0x44 -> ideal processor
