#pragma once
#include <Zydis.h>
#include <cstdint>
#include <array>
#include <type_traits>
#include <mutex>
#ifdef _WIN32
#    define WIN32_LEAN_AND_MEAN
#    define NOMINMAX
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

#ifndef RE_NOINLINE
#    if defined(_MSC_VER)
#        define RE_NOINLINE __declspec(noinline)
#    elif defined(__GNUC__) || defined(__clang__)
#        define RE_NOINLINE __attribute__((noinline))
#    else
#        define RE_NOINLINE
#    endif
#endif
#ifndef RE_INLINE
#    if defined(_MSC_VER)
#        define RE_INLINE __forceinline
#    elif defined(__GNUC__) || defined(__clang__)
#        define RE_INLINE inline __attribute__((always_inline))
#    else
#        define RE_INLINE inline
#    endif
#endif
namespace re {
    struct NearAllocator {
        RE_INLINE static auto alignDown(size_t addr, size_t align) -> size_t { return addr & ~(align - 1); }

        RE_INLINE static auto alignUp(size_t addr, size_t align) -> size_t { return (addr + align - 1) & ~(align - 1); }

        /**
         * @brief try to allocate executable memory near the given address (within ~2GB).
         *
         * @param nearest
         * @param size
         * @return PVOID
         */
        [[nodiscard]] static auto alloc(const std::uint8_t *nearest, size_t size = 0x1000) -> PVOID {
            if (nearest == nullptr)
                return nullptr;

            const uintptr_t range = 0x7FFFFFFF; // 2GB Limit
            const uintptr_t align = 0x10000;    // Windows allocation granularity is usually 64KB.

            auto base = reinterpret_cast<uintptr_t>(nearest);

            // Calculate the search bounds,taking care to prevent overflow
            uintptr_t minAddr = (base > range) ? (base - range) : size;
            uintptr_t maxAddr = (std::numeric_limits<size_t>::max() - base > range)
                                    ? (base + range)
                                    : std::numeric_limits<size_t>::max();

            MEMORY_BASIC_INFORMATION mbi{};
            auto tryAllocInRegion = [&](const MEMORY_BASIC_INFORMATION &mbi, bool searchUp) -> PVOID {
                if (mbi.State != MEM_FREE || mbi.RegionSize < size)
                    return nullptr;

                auto regionStart = reinterpret_cast<uintptr_t>(mbi.BaseAddress);
                size_t regionEnd = regionStart + mbi.RegionSize;
                size_t candidate{};

                if (searchUp) {
                    candidate = alignUp(regionStart, align);
                    if (candidate + size > regionEnd)
                        return nullptr;
                } else {
                    candidate = alignDown(regionEnd - size, align);
                    if (candidate < regionStart)
                        return nullptr;
                }

                return VirtualAlloc(reinterpret_cast<void *>(candidate), size, MEM_COMMIT | MEM_RESERVE,
                                    PAGE_EXECUTE_READWRITE);
            };

            // Search up
            for (auto addr = base; addr < maxAddr;) {
                if (!VirtualQuery(reinterpret_cast<LPCVOID>(addr), &mbi, sizeof(mbi)))
                    break;

                if (auto res = tryAllocInRegion(mbi, true); res)
                    return res;
                addr = reinterpret_cast<uintptr_t>(mbi.BaseAddress) + mbi.RegionSize;
            }
            // Search down
            for (uintptr_t addr = base; addr > minAddr;) {
                if (!VirtualQuery(reinterpret_cast<LPCVOID>(addr), &mbi, sizeof(mbi)))
                    break;

                if (auto res = tryAllocInRegion(mbi, false))
                    return res;

                uintptr_t prevAddr = reinterpret_cast<uintptr_t>(mbi.BaseAddress);
                if (prevAddr <= minAddr)
                    break;
                addr = prevAddr - 1;
            }
            return nullptr;
        }
    };

    inline auto writeProtectedMemory(void *address, const void *data, size_t size) -> bool {
#if defined(_WIN32)
        DWORD oldProtect{};
        DWORD temp{};
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

    RE_INLINE inline bool TryEnterReentrantSection(std::uint32_t *reentrant) {
        return 0 == _InterlockedCompareExchange(reentrant, 1, 0);
    }

    RE_INLINE inline void LeaveReentrantSection(std::uint32_t *reentrant) {
        auto oldValue = _InterlockedExchange(reentrant, 0);
        _Analysis_assume_(oldValue == 1);
    }
    struct ReentrantGuard {
        bool entered;
        std::uint32_t *reentrant;

        RE_INLINE ReentrantGuard(std::uint32_t *reentrant)
            : reentrant(reentrant), entered(TryEnterReentrantSection(reentrant)) {}

        RE_INLINE ~ReentrantGuard() {
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
        HookType type;
        PVOID userData{nullptr};
        PVOID targetFn{nullptr};
        PVOID detourFn{nullptr};
        PVOID trampoline{nullptr};
        bool useOriginalResult{false};
        alignas(4) std::uint32_t reentrant{0};
    };

    template <typename T> struct HookInvocation : HookContext {};

    template <typename R, typename... Args> struct HookInvocation<R (*)(Args...)> : HookContext {
        using ReturnType = std::conditional_t<std::is_same_v<R, void>, int, R>;
        using FnType = R (*)(Args...);

        /**
         * @brief Get the current instance.
         *
         * @return Pointer to the current instance
         */
        RE_INLINE static auto context() {
#ifdef _WIN32
            HookInvocation *instance =
                reinterpret_cast<HookInvocation *>(reinterpret_cast<_NT_TIB *>(NtCurrentTeb())->ArbitraryUserPointer);
            return instance;
#else
            uint64_t value{0};
            __asm__ __volatile__("movq %%fs:-0x20, %0" : "=r"(value) : : "memory");
            HookInvocation *instance = std::reinterpret_cast<HookInvocation *>(value);
            return instance;
#endif
        }
        RE_NOINLINE static auto invocationEntry(Args... args) -> ReturnType {
            return context()->dispatch(std::forward<Args>(args)...);
        }
        auto dispatch(Args... args) -> ReturnType {
            ReturnType originalResult{};
            ReturnType newResult{};

            ReentrantGuard guard(&this->reentrant);
            if (!guard) {
                originalResult = newResult = invokeOriginal(std::forward<Args>(args)...);
                return originalResult;
            }

            if (type == EnterHook) {
                newResult = invokeDetour(std::forward<Args>(args)...);
                originalResult = invokeOriginal(std::forward<Args>(args)...);
            } else if (type == ExitHook) {
                originalResult = invokeOriginal(std::forward<Args>(args)...);
                newResult = invokeDetour(std::forward<Args>(args)...);
            } else if (type == ReplaceHook) {
                originalResult = newResult = invokeDetour(std::forward<Args>(args)...);
            }

            ReturnType result = useOriginalResult ? originalResult : newResult;
            return result;
        }
        /**
         * @brief Call the original function.
         *
         * This calls the original function, not the hook.
         *
         * @param args Arguments to pass to the original function.
         * @return Result of the original function, or 0 if it returns void.
         */
        auto invokeOriginal(Args... args) -> ReturnType {
            auto fn = reinterpret_cast<FnType>(trampoline);
            if constexpr (std::is_same_v<R, void>) {
                fn(std::forward<Args>(args)...);
                return 0;
            } else {
                return fn(std::forward<Args>(args)...);
            }
        }
        auto invokeDetour(Args... args) -> ReturnType {
            auto fn = reinterpret_cast<FnType>(detourFn);
            if constexpr (std::is_same_v<R, void>) {
                fn(std::forward<Args>(args)...);
                return 0;
            } else {
                return fn(std::forward<Args>(args)...);
            }
        }
    };
    struct JumpBuilder {

        // push imm32
        // mov dword ptr [rsp+4], imm32
        // ret
        RE_INLINE auto absoluteJump(intptr_t dest) -> std::array<uint8_t, 14> {
            std::array<uint8_t, 14> code{};

            auto low = static_cast<uint32_t>(dest & 0xFFFFFFFF);
            auto high = static_cast<uint32_t>((uint64_t)dest >> 32);

            code[0] = 0x68;
            *reinterpret_cast<uint32_t *>(&code[1]) = low;
            code[5] = 0xC7;
            code[6] = 0x44;
            code[7] = 0x24;
            code[8] = 0x04;
            *reinterpret_cast<uint32_t *>(&code[9]) = high;
            code[13] = 0xC3;

            return code;
        }

        // JMP rel32 opcode
        RE_INLINE auto jmpRel32(PVOID src, PVOID dest) -> std::array<uint8_t, 5> {
            std::array<uint8_t, 5> code{};
            auto src2 = reinterpret_cast<intptr_t>(src);
            auto dest2 = reinterpret_cast<intptr_t>(dest);

            intptr_t disp = dest2 - (src2 + 5);

            code[0] = 0xE9;
            auto disp32 = static_cast<int32_t>(disp);
            std::memcpy(&code[1], &disp32, sizeof(disp32));
            return code;
        }
    };
    template <typename Fn> struct InlineHook : HookInvocation<Fn> {
        using FnType = typename HookInvocation<Fn>::FnType;
        using typename HookInvocation<Fn>::context;

        InlineHook() = default;

        auto buildJumpToInvocationPrologue() {
            auto ins = jumpBuilder.jmpRel32(this->targetFn, this->invocationPrologue);
            buildTrampolineFromPrologue(static_cast<uint8_t *>(this->targetFn), ins.size());
            writeProtectedMemory((void *)this->targetFn, ins.data(), ins.size());
#if defined(_MSC_VER)
            FlushInstructionCache(GetCurrentProcess(), NULL, 0);
#elif defined(__GNUC__) || defined(__clang__)
            __builtin___clear_cache(this->targetFn, this->targetFn + length);
#else
#endif
            return true;
        }
        // mov rax, this
        // mov gs:[0x28], rax
        // mov rax, invocationEntry
        // jmp rax
        // clang-format off
        uint8_t invocationAsm[31] = {0x48, 0xB8, 0, 0, 0, 0, 0, 0, 0, 0,
                           0x65, 0x48, 0x89, 0x04, 0x25, 0x28, 0x00, 0x00, 0x00,
                           0x48, 0xB8, 0, 0, 0, 0, 0, 0, 0, 0,
                           0xFF, 0xE0};

        // clang-format on
        auto buildJumpToInvocation() {
            uint64_t this2 = reinterpret_cast<uint64_t>(this);
            uint64_t invocationEntry2 = reinterpret_cast<uint64_t>(&HookInvocation<Fn>::invocationEntry);
            std::memcpy(&invocationAsm[2], &this2, 8);
            std::memcpy(&invocationAsm[21], &invocationEntry2, 8);
            memcpy(invocationPrologue, invocationAsm, sizeof(invocationAsm));
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
            writeProtectedMemory((void *)this->targetFn, backupPrologue.data(), prologueSize);
            hooked = false;
            return true;
        }

        bool install() {
            if (this->targetFn == nullptr || this->detourFn == nullptr) {
                LOG_ERROR("Invalid target or hook address provided");
                return false;
            }
            std::lock_guard<std::mutex> lock(hookMutex); // Ensure thread safety
            if (hooked) {
                LOG_WARN("Hook already installed, skipping");
                return false;
            }
            invocationPrologue = (std::uint8_t *)allocator.alloc(reinterpret_cast<std::uint8_t *>(this->targetFn));
            if (invocationPrologue == nullptr) {
                LOG_ERROR("Failed to allocate memory for invocation prologue");
                return false;
            }
            this->trampoline = invocationPrologue + 200;
            buildJumpToInvocation();
            buildJumpToInvocationPrologue();
            hooked = true;
            return true;
        }
        bool buildTrampolineFromPrologue(std::uint8_t *src, size_t size) {
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
                auto *trampoline2 = static_cast<uint8_t *>(this->trampoline);
                // 复制原始指令到 trampoline
                std::memcpy(&trampoline2[offset], &src[offset], instruction.length);
                std::memcpy(&backupPrologue[offset], &src[offset], instruction.length);
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
                            intptr_t trampoline_rip_next = reinterpret_cast<intptr_t>(
                                static_cast<uint8_t *>(this->trampoline) + offset + instruction.length);
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
                                LOG_ERROR(
                                    "Relative jump relocation overflow: target=%p trampoline_next=%p size=%u bytes "
                                    "(out of range)",
                                    (void *)absolute_target, (void *)this->trampoline, (unsigned)size_in_bytes);
                                return false;
                            }
                            size_t imm_offset_in_instr = instruction.length - size_in_bytes;
                            uint8_t *patch_location =
                                static_cast<uint8_t *>(this->trampoline) + offset + imm_offset_in_instr;
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
            prologueSize = offset;

            // 在 trampoline 尾部添加跳转回原函数剩余部分的跳转指令
            auto jmpAsm = jumpBuilder.absoluteJump(offset);
            memcpy(static_cast<uint8_t *>(this->trampoline) + offset, jmpAsm.data(), jmpAsm.size());
            return true;
        }

        bool hooked{false};
        std::array<std::uint8_t, 200> backupPrologue{};
        std::size_t prologueSize{0};
        std::uint8_t *invocationPrologue{nullptr};
        std::mutex hookMutex;
        NearAllocator allocator;
        JumpBuilder jumpBuilder;
    };

    struct InlineHookParams {
        HookType type{};
        PVOID detourFn{nullptr};
        PVOID targetFn{nullptr};
        //  userData Pointer to user-owned data.,The userData pointer must remain valid for the entire
        // lifetime of this instance.
        PVOID userData{nullptr};
        // use the original function's return valule instead of detour function'su
        bool useOriginalResult{false};
    };

    /**
     * @brief Creates a persistent InlineHook instance.
     *
     * @tparam Fn Target function signature.
     * @param params
     * @return Pointer to an InlineHook instance allocated on the heap.
     */
    template <typename Fn>
    [[nodiscard]] RE_INLINE inline InlineHook<Fn> *makeInlineHook(const InlineHookParams &params) {
        auto *self = new (std::nothrow) InlineHook<Fn>();
        self->targetFn = params.targetFn;
        self->detourFn = params.detourFn;
        self->type = params.type;
        self->userData = params.userData;
        self->useOriginalResult = params.useOriginalResult;
        return self;
    }

#if defined(_MSC_VER)
#    pragma warning(pop)
#endif
} // namespace re
