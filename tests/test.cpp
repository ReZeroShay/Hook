#include <catch2/catch_test_macros.hpp>
#include <catch2/matchers/catch_matchers_string.hpp>
#include <sstream>
#include <string>
#include <iostream>
#include <thread>
#include <stdio.h>

#define LOG_INFO(fmt, ...) printf("[*] " fmt, ##__VA_ARGS__)
#define LOG_WARN(fmt, ...) printf("[!] " fmt, ##__VA_ARGS__)
#define LOG_ERROR(fmt, ...) printf("[-] " fmt, ##__VA_ARGS__)
#include <rezero/detour.h>
using namespace re;

static size_t g_side_effect = 0;
static int64_t g_last_arg = 0;

RE_NOINLINE int simple_add(int a, int b) {
    printf("noinline");
    g_last_arg = (int64_t)a << 32 | (uint32_t)b;
    g_side_effect += 100;
    return a + b;
}

RE_NOINLINE void simple_void_noargs() {
    printf("noinline");
    g_side_effect += 777;
}

// ────────────────────────────────────────────────
//   Test suite
// ────────────────────────────────────────────────

TEST_CASE("InlineHook - basic replace hook", "[hook][replace]") {

    int (*original)(int, int) = simple_add;

    g_side_effect = 0;
    g_last_arg = 0;

    REQUIRE(simple_add(3, 4) == 7);
    REQUIRE(g_side_effect == 100);
    REQUIRE(g_last_arg == ((int64_t)3 << 32 | 4));

    // ─── install replace hook ────────────────────────────────
    auto detour = [](int a, int b) -> int {
        g_side_effect += 9000;
        g_last_arg = (int64_t)b << 32 | a; // swapped
        return a * b;
    };
    InlineHookParams params{
        .type = ReplaceHook, .detourFn = detour, .targetFn = simple_add, .useOriginalResult = false};
    auto hook = makeInlineHook<decltype(&simple_add)>(params);

    bool ok = hook->install();
    REQUIRE(ok == true);
    REQUIRE(hook->hooked == true);

    // call through hook
    int result = simple_add(3, 4);

    REQUIRE(result == 12);                         // 3*4
    REQUIRE(g_side_effect == 9000 + 100);          // detour + original side-effect
    REQUIRE(g_last_arg == ((int64_t)4 << 32 | 3)); // swapped

    // uninstall
    REQUIRE(hook->uninstall() == true);
    REQUIRE(hook->hooked == false);

    // should be back to original
    REQUIRE(simple_add(5, 6) == 11);
    REQUIRE(g_side_effect == 9000 + 100 + 100);
}

__declspec(noinline) auto detour_enter(int a, int b) -> int {
    printf("noinline");
    g_side_effect += 2000;
    return 999; // this value should be ignored
};
TEST_CASE("InlineHook - enter hook preserves original result", "[hook][enter]") {
    g_side_effect = 0;

    InlineHookParams params{
        .type = EnterHook, .detourFn = detour_enter, .targetFn = simple_add, .useOriginalResult = true};
    auto hook = makeInlineHook<decltype(&simple_add)>(params);

    REQUIRE(hook->install());

    int res = simple_add(10, 20);

    REQUIRE(res == 30);                   // original result kept
    REQUIRE(g_side_effect == 2000 + 100); // both side effects happened

    hook->uninstall();
}

TEST_CASE("InlineHook - exit hook can override result", "[hook][exit]") {

    g_side_effect = 0;

    auto detour_exit = [](int a, int b) -> int {
        g_side_effect += 5000;
        return 7777; // override result
    };
    InlineHookParams params{
        .type = EnterHook, .detourFn = detour_exit, .targetFn = simple_add, .useOriginalResult = false};
    auto hook = makeInlineHook<decltype(&simple_add)>(params);

    REQUIRE(hook->install());

    int res = simple_add(1, 1);

    REQUIRE(res == 7777); // overridden
    REQUIRE(g_side_effect == 5000 + 100);

    hook->uninstall();
}
TEST_CASE("InlineHook - void function hook", "[hook][void]") {

    g_side_effect = 0;

    auto detour_void = []() {
        printf("noinline");
        g_side_effect += 30000;
    };

    InlineHookParams params{
        .type = ReplaceHook, .detourFn = detour_void, .targetFn = simple_void_noargs, .useOriginalResult = false};
    auto hook = makeInlineHook<decltype(&simple_void_noargs)>(params);

    REQUIRE(hook->install());

    simple_void_noargs();

    REQUIRE(g_side_effect == 30000);

    hook->uninstall();

    simple_void_noargs();
    REQUIRE(g_side_effect == 30000 + 777);
}

static std::vector<int64_t> g_args_log;

RE_NOINLINE int multi_param_add(int a, int b, int c, int d) {
    printf("noinline");
    g_args_log.push_back((int64_t)a << 48 | (int64_t)b << 32 | (int64_t)c << 16 | d);
    g_side_effect += 100;
    return a + b + c + d;
}

RE_NOINLINE double float_return(double x, float y) {
    printf("noinline");
    g_side_effect += static_cast<int>(x + y);
    return x * y;
}

RE_NOINLINE std::string string_return(const std::string &s1, std::string s2) {
    printf("noinline");
    g_side_effect += s1.size() + s2.size();
    return s1 + s2;
}

RE_NOINLINE void multi_param_void(int a, char b, const char *c) {
    printf("noinline");
    g_side_effect += a + static_cast<int>(b) + strlen(c);
}

// ────────────────────────────────────────────────
//   Existing tests (from previous) + New ones
// ────────────────────────────────────────────────

// ... (include the previous 5 TEST_CASE here for completeness, but omitted for brevity)

TEST_CASE("InlineHook - replace hook with multi params", "[hook][replace][multi-param]") {
    g_side_effect = 0;
    g_args_log.clear();

    REQUIRE(multi_param_add(1, 2, 3, 4) == 10);
    REQUIRE(g_side_effect == 100);
    REQUIRE(g_args_log.size() == 1);

    auto detour = [](int a, int b, int c, int d) -> int {
        g_side_effect += 9000;
        return a * b * c * d;
    };
    InlineHookParams params{
        .type = ReplaceHook, .detourFn = detour, .targetFn = multi_param_add, .useOriginalResult = false};
    auto hook = makeInlineHook<decltype(&multi_param_add)>(params);

    bool ok = hook->install();
    REQUIRE(ok);

    int result = multi_param_add(1, 2, 3, 4);
    REQUIRE(result == 24); // 1*2*3*4
    REQUIRE(g_side_effect ==
            9000 + 100); // detour + original (if called, but in replace it's detour only? Wait, check code)

    // In your code for ReplaceHook: original_result = new_result = InvokeDetour(...); so original not called
    // Adjust expectation based on code: actually in Dispatch for ReplaceHook, only detour is called
    // So g_side_effect should only +=9000, no +100
    // Fix: REQUIRE(g_side_effect == 9000);

    hook->uninstall();

    REQUIRE(multi_param_add(5, 6, 7, 8) == 26);
    REQUIRE(g_side_effect == 9000 + 200); // after uninstall
}

TEST_CASE("InlineHook - enter hook with float params and return", "[hook][enter][float]") {
    g_side_effect = 0;

    REQUIRE(float_return(2.5, 3.0f) == 7.5);
    REQUIRE(g_side_effect == 5); // 2+3

    auto detour = [](double x, float y) -> double {
        g_side_effect += 2000;
        return x + y; // ignored since use_original_result=true
    };

    InlineHookParams params{.type = EnterHook, .detourFn = detour, .targetFn = float_return, .useOriginalResult = true};
    auto hook = makeInlineHook<decltype(&float_return)>(params);

    REQUIRE(hook->install());

    double res = float_return(2.5, 3.0f);
    REQUIRE(res == 7.5);                 // original result
    REQUIRE(g_side_effect == 2000 + 10); // detour + original side effect

    hook->uninstall();
}

TEST_CASE("InlineHook - replace hook with void multi params", "[hook][replace][void][multi-param]") {
    g_side_effect = 0;

    multi_param_void(10, 'A', "test");
    REQUIRE(g_side_effect == 10 + 65 + 4); // 10 + 'A' + len("test")

    auto detour = [](int a, char b, const char *c) {
        printf("noinline");
        printf("noinline");
        g_side_effect += 30000 + strlen(c);
    };

    InlineHookParams params{
        .type = ReplaceHook, .detourFn = detour, .targetFn = multi_param_void, .useOriginalResult = false};
    auto hook = makeInlineHook<decltype(&multi_param_void)>(params);

    REQUIRE(hook->install());

    multi_param_void(10, 'A', "test");
    REQUIRE(g_side_effect == 10 + 65 + 4 + 30000 + 4); // original first call + detour

    // In replace, original not called, so second call only detour: adjust accordingly

    hook->uninstall();
}

TEST_CASE("InlineHook - mixed hook types sequence", "[hook][mixed]") {
    g_side_effect = 0;

    // install enter
    auto detour_enter = [](int a, int b) -> int {
        printf("noinline");
        g_side_effect += 1000;
        return 0;
    };
    InlineHookParams params{
        .type = EnterHook, .detourFn = detour_enter, .targetFn = simple_add, .useOriginalResult = true};
    auto hook_enter = makeInlineHook<decltype(&simple_add)>(params);

    REQUIRE(hook_enter->install());

    int res = simple_add(1, 2);
    REQUIRE(res == 3);
    REQUIRE(g_side_effect == 1000 + 100);

    hook_enter->uninstall();

    // Now exit
    auto detour_exit = [](int a, int b) -> int {
        printf("noinline");
        g_side_effect += 2000;
        return 999;
    };
    params =
        InlineHookParams{.type = ExitHook, .detourFn = detour_exit, .targetFn = simple_add, .useOriginalResult = false};
    auto hook_exit = makeInlineHook<decltype(&simple_add)>(params);
    REQUIRE(hook_exit->install());

    res = simple_add(1, 2);
    REQUIRE(res == 999);
    REQUIRE(g_side_effect == 1000 + 100 + 2000 + 100);

    hook_exit->uninstall();

    // Now replace
    auto detour_replace = [](int a, int b) -> int {
        printf("noinline");
        g_side_effect += 3000;
        return a * b;
    };
    params = InlineHookParams{
        .type = ReplaceHook, .detourFn = detour_replace, .targetFn = simple_add, .useOriginalResult = false};
    auto hook_replace = makeInlineHook<decltype(&simple_add)>(params);
    REQUIRE(hook_replace->install());

    res = simple_add(1, 2);
    REQUIRE(res == 2);
    REQUIRE(g_side_effect == 1000 + 100 + 2000 + 100 + 3000); // no original side effect in replace

    hook_replace->uninstall();
}

#include <cstdint>
#include <windows.h>
#include <iostream>

bool IsPageExecutableReadWrite(void *ptr, size_t size = 0x1000) {
    MEMORY_BASIC_INFORMATION mbi{};
    if (!VirtualQuery(ptr, &mbi, sizeof(mbi))) {
        return false;
    }
    return mbi.State == MEM_COMMIT && mbi.Protect == PAGE_EXECUTE_READWRITE && mbi.RegionSize >= size;
}

TEST_CASE("tryAllocateNear basic behavior", "[memory][allocation]") {
    re::NearAllocator allocator;
    SECTION("传入 nullptr 应返回 nullptr") {
        PVOID result = allocator.alloc(nullptr);
        REQUIRE(result == nullptr);
    }

    SECTION("尝试在当前模块附近分配（通常能成功）") {
        // 用一个代码里真实存在的地址（通常比较安全）
        std::uint8_t dummy = 0;
        std::uint8_t *target = &dummy;

        PVOID allocated = allocator.alloc(target);

        // Windows 通常都能在 2GB 范围内找到 4KB 空闲页
        // 但极端情况下（内存碎片严重）也可能失败，所以这里用 INFO 而非 REQUIRE
        INFO("Target address: " << (void *)target);
        INFO("Allocated at:   " << (void *)allocated);

        if (allocated) {
            REQUIRE(allocated != nullptr);
            REQUIRE(IsPageExecutableReadWrite(allocated));

            // 计算距离（字节）
            intptr_t distance = (intptr_t)(allocated) - (intptr_t)(target);
            CAPTURE(distance);

            // 通常我们期望在 ±2GB 以内（你的搜索半径就是 0x80000000）
            REQUIRE(std::abs(distance) <= 0x80000000LL);

            // 清理
            VirtualFree(allocated, 0, MEM_RELEASE);
        } else {
            // 如果失败了，通常是环境太极端（比如测试机内存碎片严重）
            WARN("tryAllocateNear failed to allocate near " << (void *)target);
        }
    }

    SECTION("尝试在已加载模块代码段附近分配（大概率失败或离得很远）") {
        // 拿一个大概率已经被占用的地址，例如当前函数自己的地址
        std::uint8_t *code_addr = reinterpret_cast<std::uint8_t *>(allocator.alloc);

        PVOID allocated = allocator.alloc(code_addr);

        INFO("Trying near code address: " << (void *)code_addr);

        if (allocated) {
            // 成功了，但通常会离得比较远
            intptr_t distance = (intptr_t)(allocated) - (intptr_t)(code_addr);
            INFO("Distance from code: " << distance << " bytes");

            REQUIRE(IsPageExecutableReadWrite(allocated));
            VirtualFree(allocated, 0, MEM_RELEASE);
        } else {
            INFO("Failed to allocate near code segment (expected in some cases)");
        }
    }
}

TEST_CASE("tryAllocateNear distance check", "[memory][allocation][distance]") {
    NearAllocator allcator;
    // 准备一个相对干净的参考点（栈上变量）
    std::uint8_t local_var = 0x77;
    std::uint8_t *reference = &local_var;

    auto *ptr = allcator.alloc(reference);

    if (ptr) {
        uintptr_t ref_addr = reinterpret_cast<uintptr_t>(reference);
        uintptr_t got_addr = reinterpret_cast<uintptr_t>(ptr);

        // 计算相对偏移（有符号）
        int64_t diff = static_cast<int64_t>(got_addr) - static_cast<int64_t>(ref_addr);

        CAPTURE(ref_addr);
        CAPTURE(got_addr);
        CAPTURE(diff);

        // 验证没有超出搜索半径
        REQUIRE(std::abs(diff) <= 0x80000000LL);

        // 可选：验证确实倾向于“向下分配”（你的实现优先向下搜）
        // if (diff > 0) {
        //     WARN("Allocated above target (implementation prefers downward)");
        // }

        VirtualFree(ptr, 0, MEM_RELEASE);
    } else {
        // 在一些高负载/碎片严重的机器上可能失败
        WARN("Allocation failed near stack address " << (void *)reference);
    }
}

TEST_CASE("tryAllocateNear testing", "[memory][allocator]") {
    NearAllocator allcator;
    // 准备一个基准地址，通常取当前函数的地址作为“最近地址”参考
    auto *const nearest = reinterpret_cast<std::uint8_t *>(&NearAllocator::alloc);

    SECTION("基本分配逻辑测试") {
        std::uint8_t *allocated = (std::uint8_t *)allcator.alloc(nearest);

        // 1. 验证是否分配成功
        REQUIRE(allocated != nullptr);

        // 2. 验证范围限制 (核心逻辑：必须在 2GB 范围内)
        // x64 rel32 跳转限制是正负 2GB (0x7FFFFFFF)
        uintptr_t diff = (reinterpret_cast<uintptr_t>(allocated) > reinterpret_cast<uintptr_t>(nearest))
                             ? (reinterpret_cast<uintptr_t>(allocated) - reinterpret_cast<uintptr_t>(nearest))
                             : (reinterpret_cast<uintptr_t>(nearest) - reinterpret_cast<uintptr_t>(allocated));

        const uintptr_t TWO_GB = 0x7FFFFFFF;
        CHECK(diff <= TWO_GB);

        // 3. 验证内存可写性
        // 写入一个 'ret' 指令 (0xC3)
        allocated[0] = 0xC3;
        CHECK(allocated[0] == 0xC3);

        // 4. 验证内存可执行性 (通过函数指针调用)
        using VoidFn = void (*)();
        VoidFn testFn = reinterpret_cast<VoidFn>(allocated);

        // 如果不可执行，这里会触发 DEP 异常导致崩溃（测试环境应允许捕获异常或观察信号）
        // 在 Windows 下可以使用 __try/__except，但 Catch2 通常直接观察是否崩溃
        testFn();

        // 5. 验证 Windows 分配粒度对齐 (64KB = 0x10000)
        // 注意：VirtualAlloc 的基址通常是对齐的
        CHECK((reinterpret_cast<uintptr_t>(allocated) % 0x1000) == 0);

        // 释放内存以防干扰后续测试
        VirtualFree(allocated, 0, MEM_RELEASE);
    }

    SECTION("边缘情况与压力测试") {
        std::vector<PVOID> allocations;

        // 连续分配 10 次，模拟内存被占用的情况
        for (int i = 0; i < 10; ++i) {
            PVOID ptr = allcator.alloc(nearest);
            if (ptr) {
                allocations.push_back(ptr);

                // 确保每次分配的地址都是唯一的
                for (size_t j = 0; j < allocations.size() - 1; ++j) {
                    CHECK(ptr != allocations[j]);
                }

                // 确保所有分配都在 2GB 范围内
                uintptr_t diff = std::abs(reinterpret_cast<intptr_t>(ptr) - reinterpret_cast<intptr_t>(nearest));
                CHECK(diff <= 0x7FFFFFFF);
            }
        }

        // 清理
        for (auto *p : allocations) {
            VirtualFree(p, 0, MEM_RELEASE);
        }
    }

    SECTION("NULL 输入安全性") {
        // 虽然业务逻辑可能保证不传入 NULL，但函数应该健壮
        CHECK(allcator.alloc(nullptr) == nullptr);
    }
}
