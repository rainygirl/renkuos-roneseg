#ifndef RONESEG_NATIVE_DECODER_H
#define RONESEG_NATIVE_DECODER_H

#include <stdint.h>
#include <map>
#include <set>
#include <stdexcept>
#include <string>
#include <vector>
#include <openssl/evp.h>

namespace oneseg {
typedef std::vector<uint8_t> Bytes;
struct Error : std::runtime_error { explicit Error(const std::string& text) : std::runtime_error(text) {} };
Bytes ReadFile(const std::string& path, size_t limit);
Bytes LoadProfile(const std::string& path);
void CheckData(const std::string& directory);

class Aes {
public:
    explicit Aes(const Bytes& key);
    ~Aes();
    Bytes Crypt(const Bytes& input, bool encrypt = false);
private:
    Aes(const Aes&) = delete;
    Aes& operator=(const Aes&) = delete;
    Bytes fKey;
    EVP_CIPHER_CTX* fContext;
};

class Bridge {
public:
    virtual ~Bridge() {}
    virtual Bytes Control(uint8_t type, uint8_t request, uint16_t value,
        uint16_t index, uint16_t length, const Bytes& data = Bytes()) = 0;
    virtual Bytes Random(size_t size);
    virtual void Delay();
    virtual void Complete() {}
};

// Bounded, strict binary transcript for offline tests; never used in live mode.
class ReplayBridge : public Bridge {
public:
    explicit ReplayBridge(const std::string& path);
    Bytes Control(uint8_t, uint8_t, uint16_t, uint16_t, uint16_t, const Bytes& = Bytes());
    Bytes Random(size_t);
    void Delay() {}
    void Complete();
private:
    Bytes fRecord;
    size_t fOffset;
    size_t fRandomOffset;
    uint32_t fCount;
};
Bytes EstablishSession(Bridge& bridge, const Bytes& profile);
uint32_t Crc32(const Bytes& data);
Bytes FinishSection(Bytes section);
Bytes Packetize(const Bytes& section, uint16_t pid, uint8_t& counter);

class Sections {
public:
    Sections() : fPrevious(-1) {}
    std::vector<Bytes> Feed(const Bytes& packet);
private:
    std::vector<Bytes> Drain();
    Bytes fPending;
    int fPrevious;
};

class Transport {
public:
    Transport();
    Bytes Feed(const Bytes& data);
    bool HasPmt() const { return !fPmt.empty(); }
    bool IsSection(uint16_t pid) const { return fSections.count(pid) != 0; }
    bool Keep(uint16_t pid) const { return fKept.count(pid) != 0 || IsSection(pid); }
private:
    void AcceptPmt(const Bytes& section, uint16_t pid);
    Bytes Tables();
    std::map<uint16_t, Sections> fSections;
    Bytes fPending, fPrelude, fPmt;
    uint16_t fPmtPid, fProgram, fTransportId;
    std::set<uint16_t> fKept;
    uint8_t fCounters[2];
    int fUntilTables;
};

class Decoder {
public:
    explicit Decoder(const Bytes& key) : fCipher(key) {}
    void Reset();
    Bytes Feed(const Bytes& data);
private:
    Bytes Decode(const std::vector<Bytes>& frames);
    Aes fCipher;
    Bytes fPending;
    Transport fTransport;
};
}
#endif
