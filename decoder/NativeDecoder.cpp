#include "NativeDecoder.h"
#include <algorithm>
#include <cstring>
#include <fstream>
#include <openssl/crypto.h>
#include <openssl/rand.h>
#include <unistd.h>

namespace oneseg {
static void Append(Bytes& to, const Bytes& from) { to.insert(to.end(), from.begin(), from.end()); }
static uint16_t Pid(const Bytes& p) { return ((p[1] & 31) << 8) | p[2]; }
static uint16_t FramePid(const Bytes& p) { return ((p[6] & 31) << 8) | p[7]; }
static uint32_t LE(const Bytes& b, size_t offset, size_t count) {
    if (offset > b.size() || count > b.size() - offset) throw Error("truncated exchange");
    uint32_t n = 0;
    for (size_t i = 0; i < count; ++i) n |= uint32_t(b[offset + i]) << (i * 8);
    return n;
}
Bytes ReadFile(const std::string& path, size_t limit) {
    std::ifstream file(path.c_str(), std::ios::binary | std::ios::ate);
    if (!file || file.tellg() < 0 || uint64_t(file.tellg()) > limit)
        throw Error("missing or oversized file: " + path);
    Bytes data(static_cast<size_t>(file.tellg()));
    file.seekg(0);
    if (!data.empty() && !file.read(reinterpret_cast<char*>(data.data()), data.size()))
        throw Error("could not read: " + path);
    return data;
}
Bytes LoadProfile(const std::string& path) {
    Bytes data = ReadFile(path, 28);
    if (data.size() != 28 || std::memcmp(data.data(), "R1AUTH01", 8) != 0)
        throw Error("invalid tuner authentication profile");
    return data;
}
Aes::Aes(const Bytes& key) : fKey(key), fContext(NULL) {
    if (key.size() != 16) throw Error("AES key must contain 16 bytes");
    fContext = EVP_CIPHER_CTX_new();
    if (!fContext) throw Error("could not allocate AES context");
}
Aes::~Aes() { EVP_CIPHER_CTX_free(fContext); OPENSSL_cleanse(fKey.data(), fKey.size()); }
Bytes Aes::Crypt(const Bytes& input, bool encrypt) {
    if (input.empty() || input.size() % 16 || input.size() > 4096 * 208)
        throw Error("invalid AES block count");
    const uint8_t iv[16] = {};
    Bytes output(input.size() + 16);
    int length = 0, tail = 0;
    if (EVP_CipherInit_ex(fContext, EVP_aes_128_cbc(), NULL, fKey.data(), iv, encrypt) != 1
        || EVP_CIPHER_CTX_set_padding(fContext, 0) != 1
        || EVP_CipherUpdate(fContext, output.data(), &length, input.data(), input.size()) != 1
        || EVP_CipherFinal_ex(fContext, output.data() + length, &tail) != 1
        || length != int(input.size()) || tail != 0)
        throw Error("native AES operation failed");
    output.resize(input.size());
    return output;
}
Bytes Bridge::Random(size_t size) {
    if (size != 16) throw Error("invalid random request");
    Bytes data(size);
    if (RAND_bytes(data.data(), data.size()) != 1) throw Error("secure random generation failed");
    return data;
}
void Bridge::Delay() { usleep(1000); }
ReplayBridge::ReplayBridge(const std::string& path)
    : fRecord(ReadFile(path, 1024 * 1024)), fOffset(44), fRandomOffset(8), fCount(0) {
    if (fRecord.size() < 44 || std::memcmp(fRecord.data(), "R1REPL01", 8) != 0)
        throw Error("invalid binary exchange recording");
    fCount = LE(fRecord, 40, 4);
    if (fCount > 10000) throw Error("oversized exchange recording");
}
Bytes ReplayBridge::Random(size_t size) {
    if (size != 16 || fRandomOffset >= 40) throw Error("unexpected recorded nonce request");
    Bytes value(fRecord.begin() + fRandomOffset, fRecord.begin() + fRandomOffset + size);
    fRandomOffset += size;
    return value;
}
Bytes ReplayBridge::Control(uint8_t type, uint8_t request, uint16_t value,
    uint16_t index, uint16_t length, const Bytes& payload) {
    size_t p = fOffset;
    if (!fCount || p > fRecord.size() || fRecord.size() - p < 12)
        throw Error("recorded exchange exhausted");
    if (fRecord[p] != type || fRecord[p + 1] != request || LE(fRecord, p + 2, 2) != value
        || LE(fRecord, p + 4, 2) != index || LE(fRecord, p + 6, 2) != length)
        throw Error("recorded USB request mismatch");
    if (LE(fRecord, p + 8, 4) != length || fRecord.size() - p - 12 < length)
        throw Error("recorded USB transfer failed");
    Bytes data(fRecord.begin() + p + 12, fRecord.begin() + p + 12 + length);
    if (!(type & 0x80) && data != payload) throw Error("recorded USB payload mismatch");
    fOffset += 12 + length;
    --fCount;
    return type & 0x80 ? data : Bytes();
}
void ReplayBridge::Complete() {
    if (fCount || fOffset != fRecord.size() || fRandomOffset != 40)
        throw Error("unconsumed recorded exchange");
}

class Link {
public:
    explicit Link(Bridge& bridge) : b(bridge), initialized(false) {}
    uint16_t Read(uint16_t reg) {
        Bytes data = b.Control(0xc0, 0x2b, 2, reg, 2);
        if (data.size() != 2) throw Error("short tuner register read");
        return data[0] | (data[1] << 8);
    }
    void Write(uint16_t reg, uint16_t value) {
        Bytes data = {uint8_t(value), uint8_t(value >> 8)};
        b.Control(0x40, 0x2c, 2, reg, 2, data);
    }
    void Set(uint16_t reg, uint16_t bits) { Write(reg, Read(reg) | bits); }
    void Pulse(uint16_t bits) { Write(0x2a, Read(0x2a) & ~bits); Set(0x2a, bits); }
    void Ready() { if (!(Read(0x2c) & 2)) throw Error("tuner link is not ready"); }
    void WriteBytes(uint16_t reg, const Bytes& data) {
        if (data.size() % 2) throw Error("incomplete FIFO word");
        for (size_t i = 0; i < data.size(); i += 2) Write(reg, (data[i] << 8) | data[i + 1]);
    }
    Bytes ReadBytes(uint16_t reg, size_t size) {
        Bytes data;
        for (size_t i = 0; i < size; i += 2) {
            uint16_t n = Read(reg); data.push_back(n >> 8); data.push_back(n);
        }
        return data;
    }
    void Select(const Bytes& client) {
        if (!initialized) {
            b.Control(0x40, 0x20, 1, 0x7f0b, 1, Bytes(1, 1));
            bool ready = false;
            for (int i = 0; i < 1000; ++i) {
                if (Read(0x2c) & 2) { ready = true; break; }
                b.Delay();
            }
            if (!ready) throw Error("tuner link initialization timed out");
            Write(0x1a, 0); Write(0x1a, 0x8000); Set(0x22, 0x100); Set(0x24, 1);
            initialized = true;
        }
        Ready(); Write(6, 2); Pulse(4); WriteBytes(0x34, client);
        if (Read(0x2c) & 1) throw Error("tuner rejected authentication client");
        if (!(Read(6) & 2)) throw Error("tuner did not acknowledge authentication client");
    }
    Bytes Challenge(const Bytes& client) {
        Select(client); Ready(); Pulse(0x10);
        Bytes data;
        for (int i = 0; i < 2; ++i) { Pulse(0x200); Append(data, ReadBytes(0x38, 4)); }
        return data;
    }
    void Authenticate(const Bytes& message) {
        Write(6, 0x10); Pulse(0x20); WriteBytes(0x2e, message);
        bool accepted = false;
        for (int i = 0; i < 10; ++i) {
            if (Read(6) & 0x20) { accepted = true; break; }
            if (Read(6) & 0x40) throw Error("tuner rejected authentication");
            b.Delay();
        }
        Write(6, 0x20);
        if (!accepted) throw Error("tuner authentication timed out");
    }
    Bytes Reply(const Bytes& client, const Bytes& request) {
        Select(client); Ready(); Pulse(0x40); WriteBytes(0x2e, request);
        bool received = false;
        for (int i = 0; i < 10; ++i) {
            if (Read(6) & 0x100) { received = true; break; }
            b.Delay();
        }
        Write(6, 0x100);
        if (!received) throw Error("tuner key reply timed out");
        return ReadBytes(0x30, 32);
    }
private:
    Bridge& b;
    bool initialized;
};
Bytes EstablishSession(Bridge& bridge, const Bytes& profile) {
    if (profile.size() != 28 || std::memcmp(profile.data(), "R1AUTH01", 8))
        throw Error("invalid authentication profile");
    Aes cipher(Bytes(profile.begin() + 12, profile.end()));
    Bytes client(profile.begin() + 8, profile.begin() + 12);
    Bytes secret = bridge.Random(16), nonce = bridge.Random(16);
    if (secret.size() != 16 || nonce.size() != 16) throw Error("invalid random source");
    Link link(bridge);
    Bytes phase2(8, 0);
    Append(phase2, link.Challenge(client)); Append(phase2, secret);
    link.Authenticate(cipher.Crypt(phase2, true));
    Bytes request(nonce); Append(request, secret);
    Bytes plain = cipher.Crypt(link.Reply(client, request));
    if (CRYPTO_memcmp(plain.data(), nonce.data(), 16)) throw Error("tuner key reply failed nonce verification");
    bridge.Complete();
    Bytes key(plain.begin() + 16, plain.end());
    OPENSSL_cleanse(plain.data(), plain.size());
    OPENSSL_cleanse(secret.data(), secret.size());
    OPENSSL_cleanse(phase2.data(), phase2.size());
    OPENSSL_cleanse(request.data(), request.size());
    return key;
}

uint32_t Crc32(const Bytes& data) {
    uint32_t crc = 0xffffffff;
    for (uint8_t byte : data) {
        crc ^= uint32_t(byte) << 24;
        for (int i = 0; i < 8; ++i) crc = (crc << 1) ^ (crc & 0x80000000 ? 0x04c11db7 : 0);
    }
    return crc;
}
Bytes FinishSection(Bytes s) {
    if (s.size() < 3 || s.size() > 4092) throw Error("invalid section length");
    size_t length = s.size() + 1;
    s[1] = (s[1] & 0xf0) | (length >> 8); s[2] = length;
    uint32_t crc = Crc32(s);
    for (int shift = 24; shift >= 0; shift -= 8) s.push_back(crc >> shift);
    return s;
}
Bytes Packetize(const Bytes& section, uint16_t pid, uint8_t& counter) {
    Bytes source(1, 0), output; Append(source, section);
    for (size_t offset = 0; offset < source.size(); offset += 184) {
        size_t p = output.size(); output.resize(p + 188, 0xff);
        output[p] = 0x47; output[p + 1] = (pid >> 8) | (offset == 0 ? 0x40 : 0);
        output[p + 2] = pid; output[p + 3] = 0x10 | counter;
        size_t count = std::min<size_t>(184, source.size() - offset);
        std::copy(source.begin() + offset, source.begin() + offset + count, output.begin() + p + 4);
        counter = (counter + 1) & 15;
    }
    return output;
}
std::vector<Bytes> Sections::Drain() {
    std::vector<Bytes> result;
    while (fPending.size() >= 3) {
        size_t length = 3 + ((fPending[1] & 15) << 8) + fPending[2];
        if (fPending[0] == 0xff || length < 12 || length > 4096) { fPending.clear(); break; }
        if (fPending.size() < length) break;
        Bytes section(fPending.begin(), fPending.begin() + length);
        fPending.erase(fPending.begin(), fPending.begin() + length);
        if (Crc32(section) == 0) result.push_back(section);
    }
    return result;
}
std::vector<Bytes> Sections::Feed(const Bytes& p) {
    std::vector<Bytes> result;
    if (p.size() != 188 || p[0] != 0x47 || (p[1] & 0x80)) {
        fPending.clear(); fPrevious = -1; return result;
    }
    if (!(p[3] & 0x10)) return result;
    size_t offset = 4;
    if (p[3] & 0x20) offset += 1 + p[4];
    if (offset >= 188) return result;
    int counter = p[3] & 15;
    if (fPrevious >= 0 && counter != ((fPrevious + 1) & 15)) fPending.clear();
    fPrevious = counter;
    if (p[1] & 0x40) {
        size_t pointer = p[offset++];
        if (pointer > 188 - offset) { fPending.clear(); return result; }
        if (!fPending.empty()) {
            fPending.insert(fPending.end(), p.begin() + offset, p.begin() + offset + pointer);
            result = Drain();
        }
        fPending.assign(p.begin() + offset + pointer, p.end());
        std::vector<Bytes> rest = Drain(); result.insert(result.end(), rest.begin(), rest.end());
    } else if (!fPending.empty()) {
        fPending.insert(fPending.end(), p.begin() + offset, p.end()); result = Drain();
    }
    return result;
}
Transport::Transport() : fPmtPid(0), fProgram(0), fTransportId(1), fUntilTables(0) {
    fCounters[0] = fCounters[1] = 0;
    for (uint16_t pid = 0x1fc8; pid < 0x1fd0; ++pid) fSections[pid] = Sections();
    fSections[0x11] = Sections();
}
void Transport::AcceptPmt(const Bytes& s, uint16_t pid) {
    if (s.size() < 16 || s[0] != 2 || !(s[5] & 1) || s[6] || s[7]) return;
    if (HasPmt() && fPmtPid != pid) return;
    size_t position = 12 + ((s[10] & 15) << 8) + s[11];
    if (position > s.size() - 4) return;
    Bytes filtered(s.begin(), s.begin() + position);
    std::set<uint16_t> kept = {uint16_t(((s[8] & 31) << 8) | s[9]), 0x11};
    int tracks = 0;
    while (position + 5 <= s.size() - 4) {
        size_t size = 5 + ((s[position + 3] & 15) << 8) + s[position + 4];
        if (size > s.size() - 4 - position) return;
        uint8_t type = s[position];
        if (type == 0x1b || type == 0x0f || type == 0x11 || type == 2 || type == 3 || type == 4) {
            filtered.insert(filtered.end(), s.begin() + position, s.begin() + position + size);
            kept.insert(((s[position + 1] & 31) << 8) | s[position + 2]); ++tracks;
        }
        position += size;
    }
    if (!tracks || position != s.size() - 4) return;
    fProgram = (s[3] << 8) | s[4]; fPmtPid = pid; fKept = kept;
    Bytes pmt = FinishSection(filtered);
    if (pmt != fPmt) fUntilTables = 0;
    fPmt = pmt;
}
Bytes Transport::Tables() {
    Bytes pat = {0, 0xb0, 0, uint8_t(fTransportId >> 8), uint8_t(fTransportId),
        0xc1, 0, 0, uint8_t(fProgram >> 8), uint8_t(fProgram), uint8_t(0xe0 | (fPmtPid >> 8)), uint8_t(fPmtPid)};
    Bytes out = Packetize(FinishSection(pat), 0, fCounters[0]);
    Append(out, Packetize(fPmt, fPmtPid, fCounters[1])); return out;
}
Bytes Transport::Feed(const Bytes& data) {
    Append(fPending, data);
    size_t offset = 0;
    Bytes packets;
    while (fPending.size() - offset >= 188) {
        Bytes p(fPending.begin() + offset, fPending.begin() + offset + 188); offset += 188;
        if (p[0] != 0x47) throw Error("decrypted TS lost packet alignment");
        uint16_t pid = Pid(p);
        if (IsSection(pid)) {
            for (const Bytes& s : fSections[pid].Feed(p)) {
                if (pid == 0x11 && s[0] == 0x42) {
                    uint16_t actual = (s[3] << 8) | s[4];
                    if (actual != fTransportId) { fTransportId = actual; fUntilTables = 0; }
                } else if (pid != 0x11) AcceptPmt(s, pid);
            }
        }
        Append(packets, p);
    }
    fPending.erase(fPending.begin(), fPending.begin() + offset);
    if (!HasPmt()) {
        Append(fPrelude, packets);
        if (fPrelude.size() > 4096 * 188) fPrelude.erase(fPrelude.begin(), fPrelude.end() - 4096 * 188);
        return Bytes();
    }
    Append(fPrelude, packets);
    Bytes output;
    for (size_t i = 0; i < fPrelude.size(); i += 188) {
        const uint8_t* p = fPrelude.data() + i;
        if (!fKept.count(((p[1] & 31) << 8) | p[2]) || (p[1] & 0x80)) continue;
        if (fUntilTables <= 0) { Append(output, Tables()); fUntilTables = 40; }
        output.insert(output.end(), p, p + 188); --fUntilTables;
    }
    fPrelude.clear(); return output;
}
static bool Header(const uint8_t* p) {
    return p[0] == 0x8c && p[1] == 0xc4 && p[8] == 0 && p[9] == 0 && p[10] == 0
        && p[11] == 0 && p[13] == 0 && p[14] == 0 && p[15] == 0;
}
void Decoder::Reset() { fPending.clear(); fTransport = Transport(); }
Bytes Decoder::Decode(const std::vector<Bytes>& frames) {
    if (frames.empty()) return Bytes();
    Bytes source;
    source.reserve(frames.size() * 208);
    for (const Bytes& f : frames) {
        source.insert(source.end(), f.begin() + 16, f.end());
        source.insert(source.end(), 16, 0); // next packet gets an independent zero IV
    }
    Bytes plain = fCipher.Crypt(source), ts;
    ts.reserve(frames.size() * 188);
    for (size_t i = 0; i < frames.size(); ++i) {
        const uint8_t* p = plain.data() + i * 208 + 4;
        if (p[0] != 0x47 || (((p[1] & 31) << 8) | p[2]) != FramePid(frames[i]))
            throw Error("USB and decrypted transport headers disagree");
        ts.insert(ts.end(), p, p + 188);
    }
    return fTransport.Feed(ts);
}
Bytes Decoder::Feed(const Bytes& data) {
    if (data.size() > 4096 * 208) throw Error("oversized USB batch");
    Append(fPending, data);
    std::vector<Bytes> frames;
    size_t cursor = 0;
    while (fPending.size() - cursor >= 224) {
        if (Header(fPending.data() + cursor) && Header(fPending.data() + cursor + 208)) {
            frames.push_back(Bytes(fPending.begin() + cursor, fPending.begin() + cursor + 208));
            cursor += 208;
        } else ++cursor;
    }
    fPending.erase(fPending.begin(), fPending.begin() + cursor);
    Bytes output;
    if (!fTransport.HasPmt()) {
        std::vector<Bytes> tables;
        for (const Bytes& f : frames) if (fTransport.IsSection(FramePid(f))) tables.push_back(f);
        output = Decode(tables);
        if (!fTransport.HasPmt()) return output;
        frames.erase(std::remove_if(frames.begin(), frames.end(), [this](const Bytes& f) {
            return fTransport.IsSection(FramePid(f)); }), frames.end());
    }
    std::vector<Bytes> kept;
    for (const Bytes& f : frames) if (fTransport.Keep(FramePid(f))) kept.push_back(f);
    Append(output, Decode(kept)); return output;
}
void CheckData(const std::string& directory) {
    struct Item { const char* name; const char* hash; } items[] = {
        {"oneseg_fw.rec", "866c14b9b4e81cd1a8083918bbb0a413c073381ab49678ebf15472f807d7c5d0"},
        {"oneseg_demod.bin", "cf48f54b5e2c582001172de085c16971d2a4b3c5214544b3ea4f57dbdf92b036"}
    };
    for (const Item& item : items) {
        Bytes data = ReadFile(directory + "/" + item.name, 65536);
        unsigned char hash[EVP_MAX_MD_SIZE]; unsigned int size = 0;
        if (EVP_Digest(data.data(), data.size(), hash, &size, EVP_sha256(), NULL) != 1 || size != 32)
            throw Error("firmware hash failed");
        std::string text;
        const char* digits = "0123456789abcdef";
        for (unsigned int i = 0; i < size; ++i) { text += digits[hash[i] >> 4]; text += digits[hash[i] & 15]; }
        if (text != item.hash) throw Error(std::string("invalid receiver data: ") + item.name);
    }
    LoadProfile(directory + "/link-auth.bin");
    Aes cipher(Bytes(16, 0));
    const uint8_t known[] = {0x66,0xe9,0x4b,0xd4,0xef,0x8a,0x2c,0x3b,0x88,0x4c,0xfa,0x59,0xca,0x34,0x2b,0x2e};
    if (cipher.Crypt(Bytes(16, 0), true) != Bytes(known, known + 16)) throw Error("native AES self-test failed");
}
}
