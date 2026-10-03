#include "NativeDecoder.h"
#include <cerrno>
#include <cstdio>
#include <cstring>
#include <memory>
#include <signal.h>
#include <unistd.h>

using namespace oneseg;
namespace {
struct End {};
void ReadExact(uint8_t* target, size_t size) {
    while (size) {
        ssize_t count = read(STDIN_FILENO, target, size);
        if (count < 0 && errno == EINTR) continue;
        if (count <= 0) throw End();
        target += count; size -= count;
    }
}
void WriteExact(const uint8_t* data, size_t size) {
    while (size) {
        ssize_t count = write(STDOUT_FILENO, data, size);
        if (count < 0 && errno == EINTR) continue;
        if (count <= 0) throw End();
        data += count; size -= count;
    }
}
void Send(uint8_t kind, const Bytes& data = Bytes()) {
    if (data.size() > 1024 * 1024) throw Error("decoder response too large");
    size_t n = data.size();
    uint8_t header[] = {kind, uint8_t(n), uint8_t(n >> 8), uint8_t(n >> 16), uint8_t(n >> 24)};
    WriteExact(header, 5);
    if (!data.empty()) WriteExact(data.data(), data.size());
}
void Note(const char* text) { Send('N', Bytes(text, text + std::strlen(text))); }
Bytes Receive(uint8_t& kind) {
    uint8_t h[5]; ReadExact(h, 5); kind = h[0];
    uint32_t n = uint32_t(h[1]) | (uint32_t(h[2]) << 8) | (uint32_t(h[3]) << 16) | (uint32_t(h[4]) << 24);
    if (n > 1024 * 1024) throw Error("decoder message too large");
    Bytes data(n);
    if (n) ReadExact(data.data(), n);
    return data;
}
class Wire : public Bridge {
public:
    Bytes Control(uint8_t type, uint8_t request, uint16_t value, uint16_t index,
        uint16_t length, const Bytes& payload) {
        if ((type != 0x40 && type != 0xc0) || length > 64
            || (type == 0x40 && payload.size() != length) || (type == 0xc0 && !payload.empty()))
            throw Error("invalid USB request");
        Bytes msg = {type, request, uint8_t(value), uint8_t(value >> 8),
            uint8_t(index), uint8_t(index >> 8), uint8_t(length), uint8_t(length >> 8)};
        msg.insert(msg.end(), payload.begin(), payload.end());
        Send('C', msg);
        uint8_t kind; Bytes reply = Receive(kind);
        if (kind != 'C' || reply.size() != 4u + (type == 0xc0 ? length : 0))
            throw Error("invalid USB reply length");
        uint32_t result = uint32_t(reply[0]) | (uint32_t(reply[1]) << 8)
            | (uint32_t(reply[2]) << 16) | (uint32_t(reply[3]) << 24);
        if (result != length) throw Error("USB control failed");
        return Bytes(reply.begin() + 4, reply.end());
    }
};
}
int main(int argc, char** argv) {
    signal(SIGPIPE, SIG_IGN);
    bool checking = argc == 3 && std::strcmp(argv[1], "--check-data") == 0;
    try {
        if (checking) {
            CheckData(argv[2]);
            std::fprintf(stderr, "Receiver data and native AES verified.\n");
            return 0;
        }
        std::string executable(argv[0]);
        size_t slash = executable.find_last_of('/');
        if (slash == std::string::npos) throw Error("decoder needs an explicit executable path");
        std::string profilePath = executable.substr(0, slash) + "/../link-auth.bin";
        std::string replay;
        for (int i = 1; i < argc; ++i) {
            if (std::strcmp(argv[i], "--replay") == 0 && i + 1 < argc) replay = argv[++i];
            else if (std::strcmp(argv[i], "--auth") == 0 && i + 1 < argc) profilePath = argv[++i];
            else throw Error("usage: decoder [--auth PROFILE] [--replay EXCHANGE.bin]");
        }
        Bytes profile = LoadProfile(profilePath);
        Note("Authenticating tuner on VAIO (C++)...");
        std::unique_ptr<Bridge> bridge(replay.empty() ? static_cast<Bridge*>(new Wire())
            : static_cast<Bridge*>(new ReplayBridge(replay)));
        Decoder decoder(EstablishSession(*bridge, profile));
        Note("Session keys ready on VAIO (C++)"); Send('R');
        for (;;) {
            uint8_t kind; Bytes data = Receive(kind);
            if (kind == 'Q' && data.empty()) return 0;
            if (kind == 'R' && data.empty()) { decoder.Reset(); Send('R'); }
            else if (kind == 'D') Send('T', decoder.Feed(data));
            else throw Error("unexpected decoder command");
        }
    } catch (const End&) {
        return 0;
    } catch (const std::exception& e) {
        std::fprintf(stderr, "roneseg decoder: %s\n", e.what());
        if (!checking) {
            try { Send('E', Bytes(e.what(), e.what() + std::strlen(e.what()))); } catch (...) {}
        }
        return 1;
    }
}
