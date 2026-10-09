#include "SceTypes.hpp"
#include "prx/libc/include/general/VabiMacros.hpp"
#include <array>
#include <chrono>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <future>
#include <initializer_list>
#include <latch>
#include <thread>

extern "C" {
int APS5_VABI sem_init_nid_postfix(void*, int, unsigned int);
int APS5_VABI sem_destroy_nid_postfix(void*);
int APS5_VABI sem_post_nid_postfix(void*);
int APS5_VABI sem_trywait_nid_postfix(void*);
int APS5_VABI sem_timedwait_nid_postfix(void*, const KernelTimespec*);
int APS5_VABI sem_getvalue_nid_postfix(void*, int*);
int APS5_VABI clock_gettime_nid_postfix(int, KernelTimespec*);
int* APS5_VABI __error_nid_postfix();
}

static void Require(bool condition, const char* message) {
    if (!condition) {
        std::fprintf(stderr, "%s\n", message);
        std::abort();
    }
}

static void TestTimedWait() {
    for (const KernelTimespec deadline : {KernelTimespec{0, -1}, KernelTimespec{0, 1000000000}, KernelTimespec{0, 0}}) {
        std::uintptr_t sem = 0;
        int value = -1;
        Require(sem_init_nid_postfix(&sem, 0, 2) == 0, "timed wait semaphore must initialize");
        for (int remaining = 1; remaining >= 0; --remaining) {
            Require(sem_timedwait_nid_postfix(&sem, &deadline) == 0, "available token must be acquired before validating the deadline");
            Require(sem_getvalue_nid_postfix(&sem, &value) == 0 && value == remaining, "timed wait must consume exactly one token");
        }
        const int expectedError = deadline.tv_nsec == 0 ? 60 : 22;
        *__error_nid_postfix() = 0;
        Require(sem_timedwait_nid_postfix(&sem, &deadline) == -1 && *__error_nid_postfix() == expectedError,
                "empty semaphore must validate or expire the deadline");
        Require(sem_getvalue_nid_postfix(&sem, &value) == 0 && value == 0, "failed timed wait must preserve the count");
        Require(sem_post_nid_postfix(&sem) == 0, "post after failed timed wait must succeed");
        Require(sem_timedwait_nid_postfix(&sem, &deadline) == 0, "failed timed wait must not prevent a later acquisition");
        Require(sem_getvalue_nid_postfix(&sem, &value) == 0 && value == 0, "recovered timed wait must consume the posted token");
        Require(sem_destroy_nid_postfix(&sem) == 0, "timed wait semaphore must destroy");
    }

    std::uintptr_t sem = 0;
    int value = -1;
    Require(sem_init_nid_postfix(&sem, 0, 1) == 0, "blocking wait semaphore must initialize");
    Require(sem_timedwait_nid_postfix(&sem, nullptr) == 0, "null deadline must acquire an available token");
    Require(sem_getvalue_nid_postfix(&sem, &value) == 0 && value == 0, "null deadline must consume exactly one token");
    for (const bool timed : {false, true}) {
        KernelTimespec deadline{};
        Require(clock_gettime_nid_postfix(0, &deadline) == 0, "realtime clock must be readable");
        deadline.tv_sec += 60;
        std::latch started(1);
        auto waiter = std::async(std::launch::async, [&] {
            started.count_down();
            return sem_timedwait_nid_postfix(&sem, timed ? &deadline : nullptr);
        });
        started.wait();
        Require(waiter.wait_for(std::chrono::milliseconds(10)) == std::future_status::timeout, "empty semaphore must wait for a post");
        Require(sem_post_nid_postfix(&sem) == 0, "post to waiting semaphore must succeed");
        Require(waiter.wait_for(std::chrono::seconds(5)) == std::future_status::ready, "post must wake the timed waiter");
        Require(waiter.get() == 0, "awakened timed waiter must succeed");
        Require(sem_getvalue_nid_postfix(&sem, &value) == 0 && value == 0, "awakened timed waiter must consume the posted token");
    }
    Require(sem_destroy_nid_postfix(&sem) == 0, "blocking wait semaphore must destroy");
}

static void TestTimedWaitContention() {
    for (const KernelTimespec deadline : {KernelTimespec{0, -1}, KernelTimespec{0, 1000000000}}) {
        std::uintptr_t sem = 0;
        Require(sem_init_nid_postfix(&sem, 0, 1) == 0, "contended semaphore must initialize");
        std::array<int, 4> results{};
        std::array<int, 4> errors{};
        std::array<std::thread, 4> waiters;
        std::latch started(waiters.size());
        std::latch start(1);
        for (std::size_t i = 0; i < waiters.size(); ++i) {
            waiters[i] = std::thread([&, i] {
                started.count_down();
                start.wait();
                *__error_nid_postfix() = 0;
                results[i] = sem_timedwait_nid_postfix(&sem, &deadline);
                errors[i] = *__error_nid_postfix();
            });
        }
        started.wait();
        start.count_down();
        for (auto& waiter : waiters) waiter.join();
        unsigned int acquired = 0;
        for (std::size_t i = 0; i < results.size(); ++i) {
            if (results[i] == 0) ++acquired;
            else Require(results[i] == -1 && errors[i] == 22, "contending waiters without a token must report EINVAL");
        }
        Require(acquired == 1, "exactly one contending waiter must acquire the token");
        int value = -1;
        Require(sem_getvalue_nid_postfix(&sem, &value) == 0 && value == 0, "contended timed wait must consume exactly one token");
        Require(sem_destroy_nid_postfix(&sem) == 0, "contended semaphore must destroy");
    }
}

int main(int argc, char** argv) {
    if (argc > 1 && std::strcmp(argv[1], "timedwait") == 0) {
        TestTimedWait();
        TestTimedWaitContention();
        return 0;
    }
    constexpr unsigned int maximum = 0x7fffffffu;
    std::uintptr_t sem = 0;
    int value = -1;
    if (argc > 1 && std::strcmp(argv[1], "init") == 0) {
        for (const unsigned int initial : {maximum + 1, 0xffffffffu}) {
            sem = 0x1234;
            *__error_nid_postfix() = 0;
            const int result = sem_init_nid_postfix(&sem, 0, initial);
            std::fprintf(stderr, "sem_init(%u): result=%d errno=%d\n", initial, result, *__error_nid_postfix());
            Require(result == -1 && *__error_nid_postfix() == 22, "initial count above maximum must fail with EINVAL");
            Require(sem == 0x1234, "failed initialization changed semaphore storage");
        }
        return 0;
    }
    Require(sem_init_nid_postfix(&sem, 0, maximum) == 0, "maximum count must initialize");
    Require(sem_getvalue_nid_postfix(&sem, &value) == 0 && value == static_cast<int>(maximum), "maximum count must be readable");
    *__error_nid_postfix() = 0;
    const int result = sem_post_nid_postfix(&sem);
    std::fprintf(stderr, "sem_post(maximum): result=%d errno=%d\n", result, *__error_nid_postfix());
    Require(result == -1 && *__error_nid_postfix() == 84, "post at maximum must fail with guest EOVERFLOW");
    Require(sem_getvalue_nid_postfix(&sem, &value) == 0 && value == static_cast<int>(maximum), "overflow changed count");
    Require(sem_trywait_nid_postfix(&sem) == 0, "wait at maximum must succeed");
    Require(sem_getvalue_nid_postfix(&sem, &value) == 0 && value == static_cast<int>(maximum - 1), "wait must decrement");
    Require(sem_post_nid_postfix(&sem) == 0, "post below maximum must succeed");
    Require(sem_getvalue_nid_postfix(&sem, &value) == 0 && value == static_cast<int>(maximum), "post must reach maximum");
    Require(sem_post_nid_postfix(&sem) == -1 && *__error_nid_postfix() == 84, "repeated overflow must fail");
    Require(sem_getvalue_nid_postfix(&sem, &value) == 0 && value == static_cast<int>(maximum), "repeated overflow changed count");
    Require(sem_destroy_nid_postfix(&sem) == 0, "destroy must succeed");
    Require(sem_init_nid_postfix(&sem, 0, 0) == 0, "zero count must initialize");
    Require(sem_trywait_nid_postfix(&sem) == -1 && *__error_nid_postfix() == 35, "empty semaphore must report EAGAIN");
    Require(sem_post_nid_postfix(&sem) == 0, "normal post must succeed");
    Require(sem_getvalue_nid_postfix(&sem, &value) == 0 && value == 1, "normal post must increment");
    Require(sem_trywait_nid_postfix(&sem) == 0, "normal wait must succeed");
    Require(sem_getvalue_nid_postfix(&sem, &value) == 0 && value == 0, "normal wait must decrement");
    Require(sem_destroy_nid_postfix(&sem) == 0, "normal destroy must succeed");
}
