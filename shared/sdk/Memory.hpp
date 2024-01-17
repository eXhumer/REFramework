#include <Windows.h>

#pragma once

namespace sdk {
namespace memory {
void* allocate(size_t size);
void deallocate(void* ptr);
BOOL IsBadMemPtr(BOOL write, void* ptr, size_t size);
}
}