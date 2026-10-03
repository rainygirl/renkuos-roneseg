#include "NativeDecoder.h"
#include <algorithm>
#include <cstdio>
#include <functional>

using namespace oneseg;
static void Check(bool ok, const char* text) { if (!ok) throw Error(text); }
static void Fails(const std::function<void()>& fn, const char* text) {
    try { fn(); } catch (const Error&) { return; }
    throw Error(text);
}
static Bytes Hex(const char* text) {
    Bytes b;
    while (*text) { unsigned int n; Check(std::sscanf(text, "%2x", &n) == 1, "bad hex"); b.push_back(n); text += 2; }
    return b;
}
static void Append(Bytes& to, const Bytes& from) { to.insert(to.end(), from.begin(), from.end()); }
static Bytes Payload(uint16_t pid, uint8_t cc = 0) {
    Bytes b(188, 0); b[0] = 0x47; b[1] = pid >> 8; b[2] = pid; b[3] = 0x10 | cc; return b;
}
static Bytes Pmt() { return FinishSection(Hex("02b0001234c10000e101f0001be101f0000fe102f0000de103f000")); }
static Bytes Frame(Aes& cipher, const Bytes& packet) {
    Bytes header = Hex("8cc40001020300000000000002000000");
    header[6] = packet[1]; header[7] = packet[2];
    Bytes plain(4, 0); Append(plain, packet); Append(header, cipher.Crypt(plain, true)); return header;
}
static bool ContainsPacket(const Bytes& stream, const Bytes& packet) {
    for (size_t i = 0; i + 188 <= stream.size(); i += 188)
        if (std::equal(packet.begin(), packet.end(), stream.begin() + i)) return true;
    return false;
}
struct CorruptReply : ReplayBridge {
    size_t position;
    explicit CorruptReply(const std::string& path) : ReplayBridge(path), position(0) {}
    Bytes Control(uint8_t t, uint8_t r, uint16_t v, uint16_t i, uint16_t n, const Bytes& p) {
        Bytes b = ReplayBridge::Control(t, r, v, i, n, p);
        if (position++ == 91) { Check(b.size() == 2, "wrong corrupt fixture index"); b[0] ^= 0xff; }
        return b;
    }
};
struct Silent : Bridge {
    int reads = 0;
    Bytes Control(uint8_t t, uint8_t, uint16_t, uint16_t, uint16_t n, const Bytes&) {
        if (t == 0xc0) { ++reads; return Bytes(n, 0); } return Bytes();
    }
    void Delay() {}
};
int main(int argc, char** argv) {
    try {
        Check(argc == 2, "usage: native_decoder_test FIXTURE_DIRECTORY");
        std::string root(argv[1]);
        Bytes profile = LoadProfile(root + "/auth.bin");
        ReplayBridge replay(root + "/native_exchange.bin");
        Bytes key = EstablishSession(replay, profile);
        Check(key == ReadFile(root + "/packet_key.bin", 16), "session key mismatch");
        CorruptReply badReply(root + "/native_exchange.bin");
        Fails([&] { EstablishSession(badReply, profile); }, "corrupt nonce accepted");
        ReplayBridge wrong(root + "/native_exchange.bin");
        Bytes wrongProfile(profile); wrongProfile.back() ^= 1;
        Fails([&] { EstablishSession(wrong, wrongProfile); }, "wrong profile accepted");
        Silent silent;
        Fails([&] { EstablishSession(silent, profile); }, "silent tuner accepted");
        Check(silent.reads == 1000, "initialization is not bounded");
        Bytes aesKey(16); for (int i = 0; i < 16; ++i) aesKey[i] = i;
        Aes aes(aesKey);
        Bytes encrypted = Hex("0a940bb5416ef045f1c39458c653ea5a3cf456b4ca488aa383c79c98b34797cb"
            "7e163e30ea49d32152a51a08a10ec02d677ff4ca5dd4696e75981c71283799c2"
            "b0f4065c0babdecc33b711f88f594e98d34dbf2b6da0584c37cfe113048069c1"
            "5f5466b0a1c864136fab0f6396277e4cad84c2adf7090cfc643a180dde410ee7"
            "b6123b1779f2d2b82919939671374f5ea6393f202ec81bde5fb478c6b5d7e6aa"
            "0b894273ff05f7148a552a6879090efc2517d8e6a4fd08563b45deae7f1efa82");
        Bytes expected(192); for (int i = 0; i < 192; ++i) expected[i] = i;
        Check(aes.Crypt(encrypted) == expected, "AES fixed vector failed");
        Check(aes.Crypt(encrypted) == expected, "AES IV is not reset");
        Fails([&] { aes.Crypt(Bytes(17)); }, "partial AES block accepted");
        Bytes section = Hex("42f0001234c100001234ff"); section.resize(311, 0);
        section = FinishSection(section);
        uint8_t cc = 0; Bytes split = Packetize(section, 17, cc);
        Sections assembler;
        Check(assembler.Feed(Bytes(split.begin(), split.begin() + 188)).empty(), "premature section");
        auto parts = assembler.Feed(Bytes(split.begin() + 188, split.end()));
        Check(parts.size() == 1 && parts[0] == section, "section reassembly failed");
        Sections gap; gap.Feed(Bytes(split.begin(), split.begin() + 188));
        Bytes tail(split.begin() + 188, split.end()); tail[3] = 0x13;
        Check(gap.Feed(tail).empty(), "continuity gap accepted");
        Sections corrupt; split[30] ^= 1;
        corrupt.Feed(Bytes(split.begin(), split.begin() + 188));
        Check(corrupt.Feed(Bytes(split.begin() + 188, split.end())).empty(), "bad CRC accepted");
        cc = 0; Bytes table = Packetize(Pmt(), 0x1fc8, cc);
        Bytes video = Payload(0x101), audio = Payload(0x102), data = Payload(0x103);
        Aes link(key); Bytes usb = Frame(link, table);
        Append(usb, Frame(link, video)); Append(usb, Frame(link, audio)); Append(usb, Frame(link, data));
        Append(usb, Frame(link, Payload(0x1fff)));
        Decoder decoder(key); Bytes output = decoder.Feed(usb);
        Check(output.size() == 4 * 188 && ContainsPacket(output, video) && ContainsPacket(output, audio)
            && !ContainsPacket(output, data), "A/V PID filtering failed");
        Check(output == ReadFile(root + "/normalized.ts", 4096), "Python reference output mismatch");
        for (size_t i = 0; i <= usb.size(); ++i) {
            Decoder chunked(key);
            Bytes actual = chunked.Feed(Bytes(usb.begin(), usb.begin() + i));
            Append(actual, chunked.Feed(Bytes(usb.begin() + i, usb.end())));
            Check(actual == output, "USB split changed output");
        }
        decoder.Reset(); Check(decoder.Feed(usb) == output, "reset did not reset packet/table state");
        Bytes bad = table; bad[20] ^= 1;
        Bytes badUsb = Frame(link, bad); Append(badUsb, Frame(link, video)); Append(badUsb, Frame(link, audio));
        Decoder invalid(key); Check(invalid.Feed(badUsb).empty(), "bad PMT authorized output");
        for (const Bytes& body : {Hex("02b0001234c10000"),
                Hex("02b0001234c10000e101ffff"),
                Hex("02b0001234c10000e101f0001be101ffff")}) {
            uint8_t count = 0;
            Bytes malformed = Packetize(FinishSection(body), 0x1fc8, count);
            Transport parser;
            Append(malformed, video);
            Check(parser.Feed(malformed).empty(), "malformed CRC-valid PMT accepted");
        }
        Bytes mismatch(usb); mismatch[208 + 7] ^= 3;
        Decoder mismatchDecoder(key);
        Fails([&] { mismatchDecoder.Feed(mismatch); }, "clear/encrypted PID mismatch accepted");
        Decoder resync(key); Bytes noisy = Frame(link, data); noisy.resize(90); Append(noisy, usb);
        Check(resync.Feed(noisy) == output, "corrupt USB frame did not resynchronize");
        Decoder oversized(key);
        Fails([&] { oversized.Feed(Bytes(4096 * 208 + 1)); }, "oversized USB batch accepted");
        // Malformed section and adaptation lengths: exercise all single-byte mutations.
        for (size_t pos = 0; pos < table.size(); ++pos) {
            for (unsigned int value = 0; value < 256; value += 17) {
                Transport parser; Bytes modified(table); modified[pos] = value;
                if (pos == 0) continue;
                parser.Feed(modified);
            }
        }
        std::puts("Native tests passed: exchange, nonce rejection, bounded timeout, AES, sections, PID filtering, framing, reset, malformed input.");
        return 0;
    } catch (const std::exception& e) { std::fprintf(stderr, "%s\n", e.what()); return 1; }
}
