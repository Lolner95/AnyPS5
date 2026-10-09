#include "prx/libc/include/general/VabiMacros.hpp"
#include <array>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#ifdef _WIN32
#include <barrier>
#include <thread>
#endif

struct PollDescriptor {
    int descriptor;
    short events;
    short revents;
};

extern "C" {
int APS5_VABI socket_nid_postfix(int, int, int);
int APS5_VABI bind_nid_postfix(int, const void*, std::uint32_t);
int APS5_VABI listen_nid_postfix(int, int);
int APS5_VABI getsockname_nid_postfix(int, void*, std::uint32_t*);
int APS5_VABI connect_nid_postfix(int, const void*, std::uint32_t);
int APS5_VABI accept_nid_postfix(int, void*, std::uint32_t*);
std::int64_t APS5_VABI send_nid_postfix(int, const void*, std::uint64_t, int);
std::int64_t APS5_VABI recv_nid_postfix(int, void*, std::uint64_t, int);
int APS5_VABI getpeername_nid_postfix(int, void*, std::uint32_t*);
int APS5_VABI close_nid_postfix(int);
int APS5_VABI ioctl_nid_postfix(int, std::uint64_t, void*);
int APS5_VABI getsockopt_nid_postfix(int, int, int, void*, std::uint32_t*);
int APS5_VABI setsockopt_nid_postfix(int, int, int, const void*, std::uint32_t);
int APS5_VABI poll_nid_postfix(PollDescriptor*, std::uint32_t, int);
int* APS5_VABI __error_nid_postfix();
}

static void Require(bool condition, const char* message = "TCP baseline check failed") {
    if (!condition) {
        std::fprintf(stderr, "%s (guest errno %d)\n", message, *__error_nid_postfix());
        std::abort();
    }
}

static std::array<std::uint8_t, 16> BindLoopback(int descriptor) {
    std::array<std::uint8_t, 16> address{16, 2, 0, 0, 127, 0, 0, 1};
    Require(bind_nid_postfix(descriptor, address.data(), address.size()) == 0, "bind loopback port");
    std::uint32_t size = address.size();
    Require(getsockname_nid_postfix(descriptor, address.data(), &size) == 0 && size == address.size(), "read loopback address");
    Require(address[2] != 0 || address[3] != 0, "bound port must be assigned");
    return address;
}

static void Nonblocking(int descriptor) {
    int enabled = 1;
    Require(ioctl_nid_postfix(descriptor, 0x8004667e, &enabled) == 0, "enable nonblocking socket");
}

static void WaitReady(int descriptor, short requested, short expected, const char* message) {
    PollDescriptor poll{descriptor, requested, 0};
    const int result = poll_nid_postfix(&poll, 1, 5000);
    if (result != 1 || !(poll.revents & expected) || (poll.revents & 0x20))
        std::fprintf(stderr, "poll: result=%d events=0x%x expected=0x%x\n", result, poll.revents, expected);
    Require(result == 1 && (poll.revents & expected) && !(poll.revents & 0x20), message);
}

static void CheckSocketError(int descriptor, int expected, bool allowCleared = false) {
    std::array<std::uint32_t, 3> output{0xa5a5a5a5u, 0xa5a5a5a5u, 0xa5a5a5a5u};
    std::uint32_t size = 2 * sizeof(output[1]);
    *__error_nid_postfix() = 71;
    const int result = getsockopt_nid_postfix(descriptor, 0xffff, 0x1007, &output[1], &size);
    const bool matches = output[1] == static_cast<std::uint32_t>(expected) || (allowCleared && output[1] == 0);
    if (result != 0 || !matches)
        std::fprintf(stderr, "SO_ERROR: result=%d value=%u expected=%d size=%u\n", result, output[1], expected, size);
    Require(result == 0 && matches, "SO_ERROR must return the socket's guest error");
    Require(size == sizeof(int), "SO_ERROR must report a four-byte value");
    Require(output[0] == 0xa5a5a5a5u && output[2] == 0xa5a5a5a5u, "SO_ERROR must preserve surrounding bytes");
    Require(*__error_nid_postfix() == 71, "successful SO_ERROR query must preserve guest errno");
}

static void CheckInvalidErrorQueries(int descriptor) {
    std::array<std::uint32_t, 2> output{0xa5a5a5a5u, 0x5a5a5a5au};
    const auto original = output;
    std::uint32_t size = 3;
    Require(getsockopt_nid_postfix(descriptor, 0xffff, 0x1007, output.data(), &size) == -1 && *__error_nid_postfix() == 22,
        "short SO_ERROR output must report EINVAL");
    Require(size == 3 && output == original, "short SO_ERROR query must preserve output");
    size = sizeof(int);
    Require(getsockopt_nid_postfix(descriptor, 0xffff, 0x1007, nullptr, &size) == -1 && *__error_nid_postfix() == 22,
        "null SO_ERROR output must report EINVAL");
    Require(size == sizeof(int), "null SO_ERROR output must preserve length");
    Require(getsockopt_nid_postfix(descriptor, 0xffff, 0x1007, output.data(), nullptr) == -1 && *__error_nid_postfix() == 22,
        "null SO_ERROR length must report EINVAL");
    Require(output == original, "null SO_ERROR length must preserve output");
    Require(setsockopt_nid_postfix(descriptor, 0xffff, 0x1007, output.data(), sizeof(int)) == -1 && *__error_nid_postfix() == 42,
        "SO_ERROR must remain read-only");
}

static void CheckFreshSocketError() {
    const int socket = socket_nid_postfix(2, 1, 6);
    Require(socket >= 0, "create fresh SO_ERROR socket");
    CheckSocketError(socket, 0);
    Require(close_nid_postfix(socket) == 0, "close fresh SO_ERROR socket");
    std::uint32_t error = 0xa5a5a5a5u;
    std::uint32_t size = sizeof(error);
    Require(getsockopt_nid_postfix(socket, 0xffff, 0x1007, &error, &size) == -1 && *__error_nid_postfix() == 9,
        "closed SO_ERROR socket must report EBADF");
    Require(error == 0xa5a5a5a5u && size == sizeof(error), "closed SO_ERROR query must preserve output");
}

static void CheckNonblockingConnect() {
    const int listener = socket_nid_postfix(2, 1, 6);
    const int client = socket_nid_postfix(2, 1, 6);
    Require(listener >= 0 && client >= 0, "create nonblocking-connect sockets");
    const auto address = BindLoopback(listener);
    Require(listen_nid_postfix(listener, 1) == 0, "listen for nonblocking connect");
    Nonblocking(client);
    const int result = connect_nid_postfix(client, address.data(), address.size());
    Require(result == 0 || (result == -1 && *__error_nid_postfix() == 36), "nonblocking connect must succeed or report EINPROGRESS");
    WaitReady(client, 0x4, 0x4, "connected socket must become writable");
    CheckSocketError(client, 0);
    WaitReady(listener, 0x1, 0x1, "connected peer must become acceptable");
    const int accepted = accept_nid_postfix(listener, nullptr, nullptr);
    Require(accepted >= 0, "accept nonblocking connection");
    Nonblocking(accepted);
    const char request = 'q';
    char response = 0;
    Require(send_nid_postfix(client, &request, sizeof(request), 0x20000) == sizeof(request), "send connected request");
    WaitReady(accepted, 0x1, 0x1, "request must become readable");
    Require(recv_nid_postfix(accepted, &response, sizeof(response), 0) == sizeof(response) && response == request, "receive connected request");
    Require(send_nid_postfix(accepted, &response, sizeof(response), 0x20000) == sizeof(response), "send connected reply");
    WaitReady(client, 0x1, 0x1, "reply must become readable");
    response = 0;
    Require(recv_nid_postfix(client, &response, sizeof(response), 0) == sizeof(response) && response == request, "receive connected reply");
    Require(close_nid_postfix(accepted) == 0 && close_nid_postfix(client) == 0 && close_nid_postfix(listener) == 0,
        "close nonblocking-connect sockets");
}

static void CheckRefusedConnect() {
    const int reserved = socket_nid_postfix(2, 1, 6);
    const int client = socket_nid_postfix(2, 1, 6);
    Require(reserved >= 0 && client >= 0, "create refused-connect sockets");
    const auto address = BindLoopback(reserved);
    Nonblocking(client);
    const int result = connect_nid_postfix(client, address.data(), address.size());
    const bool immediate = result == -1 && *__error_nid_postfix() == 61;
    Require(immediate || (result == -1 && *__error_nid_postfix() == 36),
        "nonblocking refused connect must report EINPROGRESS or ECONNREFUSED");
    if (!immediate) WaitReady(client, 0x4, 0x4 | 0x8, "refused connection must report completion");
    CheckInvalidErrorQueries(client);
    CheckSocketError(reserved, 0);
    CheckSocketError(client, 61, immediate);
    CheckSocketError(client, 0);
#ifdef _WIN32
    const int retry = connect_nid_postfix(client, address.data(), address.size());
    const bool retryImmediate = retry == -1 && *__error_nid_postfix() == 61;
    Require(retryImmediate || (retry == -1 && *__error_nid_postfix() == 36),
        "retry on the same socket must report EINPROGRESS or ECONNREFUSED");
    if (!retryImmediate) WaitReady(client, 0x4, 0x4 | 0x8, "retried refused connection must report completion");
    std::array<int, 4> errors{-1, -1, -1, -1};
    std::array<int, 4> results{};
    std::array<std::uint32_t, 4> sizes{};
    std::array<std::thread, 4> readers;
    std::barrier start(static_cast<std::ptrdiff_t>(readers.size() + 1));
    for (std::size_t index = 0; index < readers.size(); ++index) {
        readers[index] = std::thread([&, index] {
            sizes[index] = sizeof(errors[index]);
            start.arrive_and_wait();
            results[index] = getsockopt_nid_postfix(client, 0xffff, 0x1007, &errors[index], &sizes[index]);
        });
    }
    start.arrive_and_wait();
    for (auto& reader : readers) reader.join();
    int refused = 0;
    for (std::size_t index = 0; index < readers.size(); ++index) {
        Require(results[index] == 0 && sizes[index] == sizeof(int), "concurrent SO_ERROR query must succeed with four bytes");
        Require(errors[index] == 0 || errors[index] == 61, "concurrent SO_ERROR query must return zero or ECONNREFUSED");
        refused += errors[index] == 61;
    }
    const bool consumed = refused == 1 || (retryImmediate && refused == 0);
    if (!consumed) std::fprintf(stderr, "concurrent SO_ERROR: %d readers received ECONNREFUSED\n", refused);
    Require(consumed, "exactly one concurrent reader must consume a pending ECONNREFUSED");
    CheckSocketError(client, 0);
#endif
    Require(close_nid_postfix(client) == 0 && close_nid_postfix(reserved) == 0, "close refused-connect sockets");
}

int main(int argc, char** argv) {
    if (argc > 1) {
        if (std::strcmp(argv[1], "connect") == 0) CheckNonblockingConnect();
        else if (std::strcmp(argv[1], "error") == 0) CheckFreshSocketError();
        else if (std::strcmp(argv[1], "refused") == 0) CheckRefusedConnect();
        else Require(false, "unknown TCP test case");
        return 0;
    }
    CheckFreshSocketError();
    CheckNonblockingConnect();
    CheckRefusedConnect();
    const int listener = socket_nid_postfix(2, 1, 6);
    Require(listener >= 0);
    std::array<std::uint8_t, 16> address{16, 2, 0, 0, 127, 0, 0, 1};
    Require(bind_nid_postfix(listener, address.data(), address.size()) == 0);
    Require(bind_nid_postfix(listener, address.data(), address.size()) == -1 && *__error_nid_postfix() == 22);
    Require(listen_nid_postfix(listener, 4) == 0);
    std::uint32_t address_size = address.size();
    Require(getsockname_nid_postfix(listener, address.data(), &address_size) == 0);
    Require(address_size == 16 && (address[2] != 0 || address[3] != 0));

    const int client = socket_nid_postfix(2, 1, 0);
    Require(client >= 0);
    Require(accept_nid_postfix(client, nullptr, nullptr) == -1 && *__error_nid_postfix() == 22);
    Require(connect_nid_postfix(client, address.data(), address.size()) == 0);
    std::array<std::uint8_t, 16> peer{};
    address_size = peer.size();
    const int accepted = accept_nid_postfix(listener, peer.data(), &address_size);
    Require(accepted >= 0 && address_size == 16 && peer[1] == 2);

    std::array<std::uint8_t, 16> connected_peer{};
    address_size = connected_peer.size();
    Require(getpeername_nid_postfix(accepted, connected_peer.data(), &address_size) == 0);
    Require(address_size == 16 && connected_peer[1] == 2);

    const char request[] = "guest TCP loopback";
    char received[sizeof(request)]{};
    Require(send_nid_postfix(client, request, sizeof(request), 0x1) == -1 && *__error_nid_postfix() == 45);
    Require(send_nid_postfix(client, request, sizeof(request), 0x20000) == sizeof(request));
    Require(recv_nid_postfix(accepted, received, sizeof(received), 0) == sizeof(received));
    Require(std::strcmp(request, received) == 0);

    Require(close_nid_postfix(accepted) == 0);
#ifndef _WIN32
    std::int64_t sent = 0;
    for (int i = 0; i < 100 && sent >= 0; ++i) sent = send_nid_postfix(client, request, sizeof(request), 0x20000);
    Require(sent == -1 && *__error_nid_postfix() == 32);
#endif
    Require(close_nid_postfix(client) == 0);
    Require(close_nid_postfix(listener) == 0);
    Require(close_nid_postfix(listener) == -1 && *__error_nid_postfix() == 9);
}
