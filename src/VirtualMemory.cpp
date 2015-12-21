#include "Log.h"
#include "VirtualMemory.h"
#include "GNU.h"
#include "StrFmt.h"

#ifdef _WIN32
#include <Windows.h>
#else
#include <sys/mman.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/types.h>
#endif

namespace memory_helper
{
	void* reserve_memory(size_t size)
	{
#ifdef _WIN32
		void* ret = VirtualAlloc(NULL, size, MEM_RESERVE, PAGE_NOACCESS);
		CHECK_ASSERTION(ret != NULL);
#else
		void* ret = mmap(nullptr, size, PROT_NONE, MAP_ANON | MAP_PRIVATE, -1, 0);
		CHECK_ASSERTION(ret != 0);
#endif
		return ret;
	}

	void commit_page_memory(void* pointer, size_t page_size)
	{
#ifdef _WIN32
		CHECK_ASSERTION(VirtualAlloc((u8*)pointer, page_size, MEM_COMMIT, PAGE_READWRITE) != NULL);
#else
		CHECK_ASSERTION(mprotect((u8*)pointer, page_size, PROT_READ | PROT_WRITE) != -1);
#endif
	}

	void free_reserved_memory(void* pointer, size_t size)
	{
#ifdef _WIN32
		CHECK_ASSERTION(VirtualFree(pointer, 0, MEM_RELEASE) != 0);
#else
		CHECK_ASSERTION(munmap(pointer, size) == 0);
#endif
	}
}
