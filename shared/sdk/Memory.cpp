#include <utility/Scan.hpp>
#include <utility/Module.hpp>
#include <spdlog/spdlog.h>

#include "Memory.hpp"

namespace sdk {
namespace memory {
void* allocate(size_t size) {
    static decltype(sdk::memory::allocate)* allocate_fn = []() -> decltype(sdk::memory::allocate)* {
        spdlog::info("[via::memory::allocate] Finding allocate function...");

        // this pattern literally works back to the very first version of the RE Engine!
        // it is within the startup function that creates the window/application
        // Relevant string references:
        // "RE ENGINE [%ls] %ls port:%3d"
        auto ref = utility::scan(utility::get_executable(), "B9 ? ? ? ? E8 ? ? ? ? 45 33 F6 48 85 C0");

        if (!ref) {
            spdlog::error("[via::memory::allocate] Failed to find allocate function!");
            return nullptr;
        }

        spdlog::info("[via::memory::allocate] Ref {:x}", (uintptr_t)*ref);

        auto fn = (decltype(sdk::memory::allocate)*)utility::calculate_absolute(*ref + 6);

        if (!fn) {
            spdlog::error("[via::memory::allocate] Failed to calculate allocate function!");
            return nullptr;
        }

        spdlog::info("[via::memory::allocate] Found allocate function at {:x}", (uintptr_t)fn);

        return fn;
    }();

    return allocate_fn(size);
}

void deallocate(void* ptr) {
    // In every RE Engine game, the deallocate function is the next function in the disassembly for some reason.
    static decltype(sdk::memory::deallocate)* deallocate_fn = []() -> decltype(sdk::memory::deallocate)* {
        spdlog::info("[via::memory::deallocate] Finding deallocate function...");

        // this pattern literally works back to the very first version of the RE Engine!
        // it is within the startup function that creates the window/application
        // Relevant string references:
        // "RE ENGINE [%ls] %ls port:%3d"
        auto ref = utility::scan(utility::get_executable(), "B9 ? ? ? ? E8 ? ? ? ? 45 33 F6 48 85 C0");

        if (!ref) {
            spdlog::error("[via::memory::deallocate] Failed to find allocate function!");
            return nullptr;
        }

        auto allocate_fn = utility::calculate_absolute(*ref + 6);

        if (!allocate_fn) {
            spdlog::error("[via::memory::deallocate] Failed to calculate allocate function!");
            return nullptr;
        }

        spdlog::info("[via::memory::deallocate] Found allocate function at {:x}", (uintptr_t)allocate_fn);

        // Scan until we hit a jmp.
        ref = utility::scan_opcode((uintptr_t)allocate_fn + 1, 50, 0xE9);

        if (!ref) {
            spdlog::error("[via::memory::deallocate] Failed to find deallocate function!");
            return nullptr;
        }

        auto fn = (decltype(sdk::memory::deallocate)*)*ref;

        spdlog::info("[via::memory::deallocate] Found deallocate function at {:x}", (uintptr_t)fn);

        return fn;
    }();

    deallocate_fn(ptr);
}

BOOL IsBadMemPtr(BOOL write, void* ptr, size_t size) {
    MEMORY_BASIC_INFORMATION mbi;
    BOOL ok;
    DWORD mask;
    BYTE* p = (BYTE*)ptr;
    BYTE* maxp = p + size;
    BYTE* regend = NULL;

    if (size == 0) {
        return FALSE;
    }

    if (p == NULL) {
        return TRUE;
    }

    if (write == FALSE) {
        mask = PAGE_READONLY | PAGE_READWRITE | PAGE_WRITECOPY | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY;
    } else {
        mask = PAGE_READWRITE | PAGE_WRITECOPY | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY;
    }

    do {
        if (p == ptr || p == regend) {
            if (VirtualQuery((LPCVOID)p, &mbi, sizeof(mbi)) == 0) {
                return TRUE;
            } else {
                regend = ((BYTE*)mbi.BaseAddress + mbi.RegionSize);
            }
        }

        ok = (mbi.Protect & mask) != 0;

        if (mbi.Protect & (PAGE_GUARD | PAGE_NOACCESS)) {
            ok = FALSE;
        }

        if (!ok) {
            return TRUE;
        }

        if (maxp <= regend) {
            return FALSE;
        } else if (maxp > regend) {
            p = regend;
        }
    } while (p < maxp);

    return FALSE;
}
}
}