#include <Zydis.h>
#include <atomic>
#include <cstdint>
#include <array>
#include <type_traits>
#ifdef _WIN32
#    define WIN32_LEAN_AND_MEAN
#    include <windows.h>
#else
#    include <sys/mman.h>
#endif

#ifndef LOG_INFO
#    define LOG_INFO(fmt, ...)
#endif
#ifndef LOG_WARN
#    define LOG_WARN(fmt, ...)
#endif
#ifndef LOG_ERROR
#    define LOG_ERROR(fmt, ...)
#endif

#if defined(_MSC_VER)
#    pragma warning(push)
#    pragma warning(disable : 4141)
#endif

#ifndef NOINLINE
#    if defined(_MSC_VER)
#        define NOINLINE __declspec(noinline)
#    elif defined(__GNUC__) || defined(__clang__)
#        define NOINLINE __attribute__((noinline))
#    else
#        define NOINLINE
#    endif
#endif
#ifndef INLINE
#    if defined(_MSC_VER)
#        define INLINE __forceinline
#    elif defined(__GNUC__) || defined(__clang__)
#        define INLINE inline __attribute__((always_inline))
#    else
#        define INLINE inline
#    endif
#endif
inline std::uint8_t *TryAllocateNear(std::uint8_t *nearest) {
    const size_t alloc_size = 0x1000;
    const intptr_t search_size = 0x80000000; // 2GB
    uintptr_t addr = reinterpret_cast<uintptr_t>(nearest);
    if (nearest == nullptr) {
        return nullptr;
    }
#ifdef _WIN32
    const uint64_t radius = 0x80000000ULL; // 2GB
    const uintptr_t align = 0x10000;       // 64KB 对齐（Windows 分配粒度）

    if (nearest == nullptr) {
        return nullptr;
    }

    const uintptr_t center = reinterpret_cast<uintptr_t>(nearest);
    const uintptr_t maxPtr = (uintptr_t)UINTPTR_MAX;

    // 用 64 位中间值计算，避免溢出，然后 clamp 到 uintptr_t 范围
    uint64_t lower64 = (center > radius) ? (uint64_t)center - radius : 0;
    uint64_t upper64 = (uint64_t)center + radius;
    if (upper64 > (uint64_t)maxPtr)
        upper64 = maxPtr;

    const uintptr_t lower = static_cast<uintptr_t>(lower64);
    const uintptr_t upper = static_cast<uintptr_t>(upper64);

    // 将起点向下对齐到 64KB
    const uintptr_t start = center & ~(align - 1);

    MEMORY_BASIC_INFORMATION mbi;

    // Helper lambda：尝试在 mbi 表示的 free region 中分配
    auto try_alloc_in_region = [&](uintptr_t regionBase, SIZE_T regionSize) -> std::uint8_t * {
        if (regionSize < alloc_size)
            return nullptr;
        uintptr_t rb = (uintptr_t)regionBase;
        uintptr_t rs = (uintptr_t)regionSize;

        // 首选：区域尾部向下对齐后分配（更靠近 center）
        uintptr_t candidate = rb + rs - alloc_size;
        candidate &= ~(align - 1); // 向下对齐
        if (candidate < rb)
            candidate = rb;

        LPVOID buf = VirtualAlloc((LPVOID)candidate, alloc_size, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);
        if (buf)
            return (std::uint8_t *)buf;

        // 备选：区域头部，向上对齐
        uintptr_t alt = (rb + (align - 1)) & ~(align - 1); // 向上对齐
        if (alt + alloc_size <= rb + rs) {
            buf = VirtualAlloc((LPVOID)alt, alloc_size, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);
            if (buf)
                return (std::uint8_t *)buf;
        }
        return nullptr;
    };

    // 向下搜索（包括 start）
    if (start >= lower) {
        uint64_t steps_down = (start - lower) / align;
        for (uint64_t i = 0; i <= steps_down; ++i) {
            uintptr_t addr = start - static_cast<uintptr_t>(i * align);
            if (!VirtualQuery((LPCVOID)addr, &mbi, sizeof(mbi)))
                continue;
            if (mbi.State == MEM_FREE) {
                std::uint8_t *r = try_alloc_in_region((uintptr_t)mbi.BaseAddress, mbi.RegionSize);
                if (r)
                    return r;
            }
        }
    }

    // 向上搜索（注意：从 start+align 开始，避免重复检查 start）
    if (upper >= start + align) {
        uint64_t steps_up = (upper - start) / align;
        for (uint64_t i = 1; i <= steps_up; ++i) {
            uintptr_t addr = start + static_cast<uintptr_t>(i * align);
            if (!VirtualQuery((LPCVOID)addr, &mbi, sizeof(mbi)))
                continue;
            if (mbi.State == MEM_FREE) {
                std::uint8_t *r = try_alloc_in_region((uintptr_t)mbi.BaseAddress, mbi.RegionSize);
                if (r)
                    return r;
            }
        }
    }

    return nullptr;
#else
    void *buf{nullptr};
    const size_t page_size = sysconf(_SC_PAGESIZE);
    // 系统内存页大小必须是 2 的幂
    if (page_size == 0 || (page_size & (page_size - 1)) != 0) {
        LOG_ERROR("Invalid system page size: %zu (must be power of two)", page_size);
        return nullptr;
    }

    for (intptr_t offset = 0; offset < search_size; offset += 1) {
        // 向下搜索2GB范围的内存
        uintptr_t try_addr = addr - offset;
        void *ptr = mmap(std::bit_cast<void *>(try_addr), alloc_size, PROT_READ | PROT_WRITE | PROT_EXEC,
                         MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED_NOREPLACE, -1, 0);
        // 找到
        if (ptr != MAP_FAILED && std::bit_cast<uintptr_t>(ptr) == try_addr) {
            buf = ptr;
            break;
        }
        // 向上搜索2GB范围的内存
        try_addr = addr + offset;
        ptr = mmap(std::bit_cast<void *>(try_addr), alloc_size, PROT_READ | PROT_WRITE | PROT_EXEC,
                   MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED_NOREPLACE, -1, 0);
        // 找到
        if (ptr != MAP_FAILED && std::bit_cast<uintptr_t>(ptr) == try_addr) {
            buf = ptr;
            break;
        }
    }
    if (buf == nullptr) {
        // 如果附近都找不到 → 讓 kernel 自己決定位置
        buf = mmap(nullptr, alloc_size, PROT_READ | PROT_WRITE | PROT_EXEC, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    }
    if (buf == MAP_FAILED) {
        return nullptr;
    }
    return std::bit_cast<std::uint8_t *>(buf);
#endif
}
inline auto WriteProtectedMemory(void *address, const void *data, size_t size) -> bool {
#if defined(_WIN32)
    DWORD oldProtect = 0;
    DWORD temp;
    if (!VirtualProtect(address, size, PAGE_EXECUTE_READWRITE, &oldProtect)) {
        LOG_ERROR("VirtualProtect failed\n");
        return false;
    }
    memcpy(address, data, size);
    if (!VirtualProtect(address, size, oldProtect, &temp)) {
        LOG_ERROR("VirtualProtect failed\n");
    }

    return true;
#else
    uintptr_t page = std::bit_cast<uintptr_t>(address) & ~(getpagesize() - 1UL);
    if (size > getpagesize()) {
        LOG_ERROR("patchMemory size too large");
        return false;
    }
    if (mprotect(std::bit_cast<void *>(page), getpagesize(), PROT_READ | PROT_WRITE | PROT_EXEC) == -1) {
        LOG_ERROR("mprotect RWX failed");
        return false;
    }
    memcpy(std::bit_cast<void *>(address), data, size);
    if (mprotect(std::bit_cast<void *>(page), getpagesize(), PROT_READ | PROT_EXEC) == -1) {
        LOG_ERROR("mprotect RX failed");
        return false;
    }
    return true;
#endif
}

INLINE inline bool TryEnterReentrantSection(std::uint32_t *reentrant) {
    return 0 == _InterlockedCompareExchange(reentrant, 1, 0);
}

INLINE inline void LeaveReentrantSection(std::uint32_t *reentrant) {
    auto old_val = _InterlockedExchange(reentrant, 0);
    _Analysis_assume_(old_val == 1);
}
struct ReentrantGuard {
    bool entered;
    std::uint32_t *reentrant;

    INLINE ReentrantGuard(std::uint32_t *reentrant)
        : reentrant(reentrant), entered(TryEnterReentrantSection(reentrant)) {}

    INLINE ~ReentrantGuard() {
        if (entered)
            LeaveReentrantSection(reentrant);
    }

    explicit operator bool() const { return entered; }
};
enum HookType {
    EnterHook,
    ExitHook,
    ReplaceHook,
};
struct HookContext {
    alignas(4) std::uint32_t reentrant;
    std::uint8_t *target_fn{nullptr}; // 原函数地址
    std::uint8_t *detour_fn{nullptr}; // 用户传入的 hook 回调函数
    std::uint8_t *trampoline{nullptr};
    HookType hook_type;
    bool use_original_result{false};
};

template <typename T> struct HookInvocation : HookContext {};

template <typename R, typename... Args> struct HookInvocation<R (*)(Args...)> : HookContext {
    using ReturnType = std::conditional_t<std::is_same_v<R, void>, int, R>;
    using FnType = R (*)(Args...);

    INLINE static auto Self() {
#ifdef _WIN32
        HookInvocation *self =
            reinterpret_cast<HookInvocation *>(reinterpret_cast<_NT_TIB *>(NtCurrentTeb())->ArbitraryUserPointer);
        return self;
#else
        uint64_t value{0};
        __asm__ __volatile__("movq %%fs:-0x20, %0" : "=r"(value) : : "memory");
        HookInvocation *self = std::bit_cast<HookInvocation *>(value);
        return self;
#endif
    }
    NOINLINE static ReturnType InvocationEntry(Args... args) { return Self()->Dispatch(std::forward<Args>(args)...); }
    inline ReturnType Dispatch(Args... args) {
        ReturnType original_result, new_result;
        bool was_free = false;

        ReentrantGuard guard(&this->reentrant);
        if (!guard) {
            original_result = new_result = InvokeTarget(std::forward<Args>(args)...);
            return original_result;
        }

        if (hook_type == EnterHook) {
            new_result = InvokeDetour(std::forward<Args>(args)...);
            original_result = InvokeTarget(std::forward<Args>(args)...);
        } else if (hook_type == ExitHook) {
            original_result = InvokeTarget(std::forward<Args>(args)...);
            new_result = InvokeDetour(std::forward<Args>(args)...);
        } else if (hook_type == ReplaceHook) {
            original_result = new_result = InvokeDetour(std::forward<Args>(args)...);
        }

        ReturnType result = use_original_result ? original_result : new_result;
        return result;
    }
    inline ReturnType InvokeTarget(Args... args) {
        auto fn = reinterpret_cast<FnType>(trampoline);
        if constexpr (std::is_same_v<R, void>) {
            fn(std::forward<Args>(args)...);
            return 0;
        } else {
            return fn(std::forward<Args>(args)...);
        }
    }
    inline ReturnType InvokeDetour(Args... args) {
        auto fn = reinterpret_cast<FnType>(detour_fn);
        if constexpr (std::is_same_v<R, void>) {
            fn(std::forward<Args>(args)...);
            return 0;
        } else {
            return fn(std::forward<Args>(args)...);
        }
    }
};
template <typename Fn> struct InlineHook : HookInvocation<Fn> {
    using FnType = typename HookInvocation<Fn>::FnType;
    using typename HookInvocation<Fn>::Self;

    constexpr InlineHook() {}

    auto BuildJumpToInvocationPrologue() {
#if 0
        std::array<ZydisEncoderRequest, 2> req;
        std::array<ZyanU8, ZYDIS_MAX_INSTRUCTION_LENGTH * 2> encoded;
        ZyanUSize encoded_length = ZYDIS_MAX_INSTRUCTION_LENGTH;
        size_t length{0};

        memset(&req, 0, sizeof(req));

        req[0].mnemonic = ZYDIS_MNEMONIC_MOV;
        req[0].machine_mode = ZYDIS_MACHINE_MODE_LONG_64;
        req[0].operand_count = 2;
        req[0].operands[0].type = ZYDIS_OPERAND_TYPE_REGISTER;
        req[0].operands[0].reg.value = ZYDIS_REGISTER_RAX;
        req[0].operands[1].type = ZYDIS_OPERAND_TYPE_IMMEDIATE;
        req[0].operands[1].imm.s = reinterpret_cast<intptr_t>(invocation_prologue);
        req[1].mnemonic = ZYDIS_MNEMONIC_JMP;
        req[1].machine_mode = ZYDIS_MACHINE_MODE_LONG_64;
        req[1].operand_count = 1;
        req[1].operands[0].type = ZYDIS_OPERAND_TYPE_REGISTER;
        req[1].operands[0].reg.value = ZYDIS_REGISTER_RAX;
        size_t total_length = 0;
        for (auto &item : req) {
            encoded_length = ZYDIS_MAX_INSTRUCTION_LENGTH;
            if (auto result = ZydisEncoderEncodeInstruction(&item, &encoded[length], &encoded_length);
                ZYAN_FAILED(result)) {
                LOG_ERROR("Instruction encoding failed: mnemonic=%d statuss=0x%08X", item.mnemonic, result);
                return false;
            }
            length += encoded_length;
        }
#else
        ZyanUSize length = ZYDIS_MAX_INSTRUCTION_LENGTH;
        std::array<ZyanU8, ZYDIS_MAX_INSTRUCTION_LENGTH> encoded;
        ZydisEncoderRequest req{};
        memset(&req, 0, sizeof(req));

        req.mnemonic = ZYDIS_MNEMONIC_JMP;
        req.machine_mode = ZYDIS_MACHINE_MODE_LONG_64;
        req.operand_count = 1;

        // 假设当前指令的 RIP = 0x00007FF612341000
        // 目标地址           = 0x00007FF612341500
        // 则 disp = 目标 - (当前RIP + 指令长度) = 0x500 - 5 = 0x4FB
        // 你自己提前算好的相对偏移
        ZyanI64 cur_rip = reinterpret_cast<ZyanI64>(this->target_fn);
        ZyanI64 jmp_addr = reinterpret_cast<ZyanI64>(this->invocation_prologue);
        ZyanI64 inst_length = 5;
        ZyanI64 disp = jmp_addr - (cur_rip + inst_length);

        req.operands[0].type = ZYDIS_OPERAND_TYPE_IMMEDIATE;
        req.operands[0].imm.s = disp;

        if (auto result = ZydisEncoderEncodeInstruction(&req, &encoded[0], &length); ZYAN_FAILED(result)) {
            LOG_ERROR("Instruction encoding failed: mnemonic=%d statuss=0x%08X", req.mnemonic, result);
            return false;
        }
#endif
        BuildTrampolineFromPrologue(this->target_fn, length);
        WriteProtectedMemory((void *)this->target_fn, encoded.data(), length);
#if defined(_MSC_VER)
        FlushInstructionCache(GetCurrentProcess(), NULL, 0);
#elif defined(__GNUC__) || defined(__clang__)
        __builtin___clear_cache(this->target_fn, this->target_fn + length);
#else
#endif
        return true;
    }
    auto BuildJumpToInvocation() {
        std::array<ZydisEncoderRequest, 4> req;
        std::array<ZyanU8, ZYDIS_MAX_INSTRUCTION_LENGTH * 4> encoded;
        size_t length{0};
        memset(&req, 0, sizeof(req));
        // 1. mov rax, imm64
        req[0].mnemonic = ZYDIS_MNEMONIC_MOV;
        req[0].machine_mode = ZYDIS_MACHINE_MODE_LONG_64;
        req[0].operand_count = 2;
        req[0].operands[0].type = ZYDIS_OPERAND_TYPE_REGISTER;
        req[0].operands[0].reg.value = ZYDIS_REGISTER_RAX;
        req[0].operands[1].type = ZYDIS_OPERAND_TYPE_IMMEDIATE;
        req[0].operands[1].imm.u = reinterpret_cast<ZyanU64>(this);

        // 2. mov qword ptr fs:[fs_offset], rax
        req[1].mnemonic = ZYDIS_MNEMONIC_MOV;
        req[1].machine_mode = ZYDIS_MACHINE_MODE_LONG_64;
        req[1].operand_count = 2;
        req[1].prefixes = ZYDIS_ATTRIB_HAS_SEGMENT_GS;
        req[1].operands[0].type = ZYDIS_OPERAND_TYPE_MEMORY;
        req[1].operands[0].mem.base = ZYDIS_REGISTER_NONE;
        req[1].operands[0].mem.index = ZYDIS_REGISTER_NONE;
        req[1].operands[0].mem.scale = 0;
#ifdef _WIN32
        req[1].operands[0].mem.displacement = 0x28;

#else
        req[1].operands[0].mem.displacement = -0x20;
#endif
        req[1].operands[0].mem.size = 8;

        req[1].operands[1].type = ZYDIS_OPERAND_TYPE_REGISTER;
        req[1].operands[1].reg.value = ZYDIS_REGISTER_RAX;
        req[2].mnemonic = ZYDIS_MNEMONIC_MOV;
        req[2].machine_mode = ZYDIS_MACHINE_MODE_LONG_64;
        req[2].operand_count = 2;
        req[2].operands[0].type = ZYDIS_OPERAND_TYPE_REGISTER;
        req[2].operands[0].reg.value = ZYDIS_REGISTER_RAX;
        req[2].operands[1].type = ZYDIS_OPERAND_TYPE_IMMEDIATE;
        req[2].operands[1].imm.s = reinterpret_cast<intptr_t>(&HookInvocation<Fn>::InvocationEntry);
        req[3].mnemonic = ZYDIS_MNEMONIC_JMP;
        req[3].machine_mode = ZYDIS_MACHINE_MODE_LONG_64;
        req[3].operand_count = 1;
        req[3].operands[0].type = ZYDIS_OPERAND_TYPE_REGISTER;
        req[3].operands[0].reg.value = ZYDIS_REGISTER_RAX;
        for (auto &item : req) {
            ZyanUSize encoded_length = ZYDIS_MAX_INSTRUCTION_LENGTH;
            if (auto result = ZydisEncoderEncodeInstruction(&item, &encoded[length], &encoded_length);
                ZYAN_FAILED(result)) {
                LOG_ERROR("Instruction encoding failed: mnemonic=%d statuss=0x%08X", item.mnemonic, result);
                return false;
            }
            length += encoded_length;
        }
        memcpy(invocation_prologue, encoded.data(), length);
#if defined(_MSC_VER)
        FlushInstructionCache(GetCurrentProcess(), NULL, 0);
#elif defined(__GNUC__) || defined(__clang__)
        __builtin___clear_cache(invocation_prologue, invocation_prologue + length);
#else
#endif
        return true;
    }
    bool uninstall() {
        if (!hooked) {
            LOG_WARN("Hook not installed, skipping uninstall");
            return false;
        }
        WriteProtectedMemory((void *)this->target_fn, backup_prologue.data(), prologue_size);
        hooked = false;
        return true;
    }
    bool Install(FnType targetAddr, FnType hookAddr, HookType hook_type, bool use_original_result) {
        if (hooked) {
            LOG_WARN("Hook already installed, skipping");
            return false;
        }
        invocation_prologue = TryAllocateNear(reinterpret_cast<std::uint8_t *>(targetAddr));
        this->trampoline = invocation_prologue + 200;
        this->hook_type = hook_type;
        this->use_original_result = use_original_result;
        this->target_fn = reinterpret_cast<std::uint8_t *>(targetAddr);
        this->detour_fn = reinterpret_cast<std::uint8_t *>(hookAddr);
        BuildJumpToInvocation();
        BuildJumpToInvocationPrologue();
        hooked = true;
        return true;
    }
    bool BuildTrampolineFromPrologue(std::uint8_t *src, size_t size) {
        size_t offset{0};
        ZydisDecoder decoder;
        ZydisDecodedInstruction instruction;
        ZydisDecodedOperand operands[ZYDIS_MAX_OPERAND_COUNT];
        ZyanStatus status = ZydisDecoderInit(&decoder, ZYDIS_MACHINE_MODE_LONG_64, ZYDIS_STACK_WIDTH_64);
        if (ZYAN_FAILED(status)) {
            LOG_ERROR("ZydisDecoderInit failed (machine=LONG_64, stack=64)");
            return false;
        }

        do {
            status = ZydisDecoderDecodeFull(&decoder, &src[offset], 0x1000, &instruction, operands);
            if (ZYAN_FAILED(status)) {
                LOG_ERROR("Instruction decode failed at offset 0x%zx (address=%p)", offset, src + offset);
                return false;
            }
            // ret，说明函数逻辑结束
            // int3 不是正常控制流,复制后执行会直接异常,说明代码已被 patch / 对齐填充 / 不可执行
            if (instruction.opcode == ZYDIS_MNEMONIC_INT3 || instruction.opcode == ZYDIS_MNEMONIC_RET) {
                LOG_WARN("Unsupported instruction for relocation: %s at offset 0x%zx",
                         instruction.mnemonic == ZYDIS_MNEMONIC_RET ? "RET" : "INT3", offset);

                return false;
            }
            // 复制原始指令到 trampoline
            std::memcpy(&this->trampoline[offset], &src[offset], instruction.length);
            std::memcpy(&backup_prologue[offset], &src[offset], instruction.length);
            // 处理指令中的相对位移,处理重定位 (Relative Addressing)
            if (instruction.attributes & ZYDIS_ATTRIB_IS_RELATIVE) {
                for (ZyanU8 i = 0; i < instruction.operand_count_visible; ++i) {
                    const ZydisDecodedOperand *op = &operands[i];

                    // 情况1:相对立即数（jmp rel32, call rel32, jcc rel8/rel32 等）
                    if (op->type == ZYDIS_OPERAND_TYPE_IMMEDIATE && op->imm.is_relative) {

                        // 位移的原始大小（8/32 bit）
                        ZyanU8 size_in_bytes = op->size / 8; // bits -> bytes

                        // 检查新位移是否超过指令对应的范围
                        intptr_t absolute_target =
                            reinterpret_cast<intptr_t>(src + offset + instruction.length) + op->imm.value.s;
                        intptr_t trampoline_rip_next =
                            reinterpret_cast<intptr_t>(this->trampoline + offset + instruction.length);
                        intptr_t new_disp = absolute_target - trampoline_rip_next;

                        // 检查能否用 size_in_bytes 表示
                        bool fits = false;
                        if (size_in_bytes == 1) {
                            fits = (std::abs(new_disp) < INT8_MAX);
                        } else if (size_in_bytes == 2) {
                            fits = (std::abs(new_disp) < INT16_MAX);
                        } else if (size_in_bytes == 4) {
                            fits = (std::abs(new_disp) < INT32_MAX);
                        } else {
                            fits = false;
                        }

                        if (!fits) {
                            LOG_ERROR("Relative jump relocation overflow: target=%p trampoline_next=%p size=%u bytes "
                                      "(out of range)",
                                      (void *)absolute_target, (void *)this->trampoline, (unsigned)size_in_bytes);
                            return false;
                        }
                        size_t imm_offset_in_instr = instruction.length - size_in_bytes;
                        uint8_t *patch_location = this->trampoline + offset + imm_offset_in_instr;
                        if (size_in_bytes == 1) {
                            int8_t v8 = static_cast<int8_t>(new_disp);
                            std::memcpy(patch_location, &v8, 1);
                        } else if (size_in_bytes == 2) {
                            int16_t v16 = static_cast<int16_t>(new_disp);
                            std::memcpy(patch_location, &v16, 2);
                        } else if (size_in_bytes == 4) {
                            int32_t v32 = static_cast<int32_t>(new_disp);
                            std::memcpy(patch_location, &v32, 4);
                        }
                        break;
                    }
                }
            }
            offset += instruction.length;
        } while (offset < size);
        prologue_size = offset;

        // 在 trampoline 尾部添加跳转回原函数剩余部分的跳转指令
        ZydisEncoderRequest req;
        ZyanU8 encoded[ZYDIS_MAX_INSTRUCTION_LENGTH];
        ZyanUSize encoded_length{ZYDIS_MAX_INSTRUCTION_LENGTH};

        memset(&req, 0, sizeof(req));
        req.mnemonic = ZYDIS_MNEMONIC_JMP;
        req.branch_type = ZYDIS_BRANCH_TYPE_NEAR;
        req.machine_mode = ZYDIS_MACHINE_MODE_LONG_64;
        req.operand_count = 1;

        req.operands[0].type = ZYDIS_OPERAND_TYPE_MEMORY;
        req.operands[0].mem.base = ZYDIS_REGISTER_RIP;
        req.operands[0].mem.index = ZYDIS_REGISTER_NONE;
        req.operands[0].mem.scale = 0;
        req.operands[0].mem.displacement = 0;
        req.operands[0].mem.size = 8;

        status = ZydisEncoderEncodeInstruction(&req, encoded, &encoded_length);
        if (ZYAN_FAILED(status)) {
            LOG_ERROR("Instruction encoding failed: mnemonic=%d statuss=0x%08X", req.mnemonic, status);
            return false;
        }
        memcpy(this->trampoline + offset, encoded, encoded_length);
        *reinterpret_cast<uint64_t *>(this->trampoline + offset + encoded_length) =
            reinterpret_cast<uint64_t>(src + offset);
        return true;
    }

    bool hooked{false};
    std::array<std::uint8_t, 200> backup_prologue;
    std::size_t prologue_size{0};
    std::uint8_t *invocation_prologue{nullptr};
};

/**
 * @brief Creates a persistent InlineHook instance.
 * @tparam Fn Target function signature.
 * @return Pointer to an InlineHook instance allocated on the heap.
 */
template <typename Fn> [[nodiscard]] INLINE inline InlineHook<Fn> *MakeInlineHook() {
    auto *instance = new (std::nothrow) InlineHook<Fn>();
    return instance;
}

#if defined(_MSC_VER)
#    pragma warning(pop)
#endif
