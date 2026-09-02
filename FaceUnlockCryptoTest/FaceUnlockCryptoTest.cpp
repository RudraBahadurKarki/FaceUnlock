#include <windows.h>
#include <bcrypt.h>

#include <iostream>
#include <iomanip>
#include <vector>
#include <string>

#pragma comment(lib, "bcrypt.lib")

static void PrintHex(
    const char* name,
    const std::vector<BYTE>& data)
{
    std::cout << name << " (" << data.size() << " bytes):\n";

    for (BYTE b : data)
    {
        std::cout
            << std::hex
            << std::setw(2)
            << std::setfill('0')
            << static_cast<int>(b);
    }

    std::cout << std::dec << "\n\n";
}

static bool GenerateRandom(
    std::vector<BYTE>& data,
    size_t size)
{
    data.resize(size);

    NTSTATUS status = BCryptGenRandom(
        nullptr,
        data.data(),
        static_cast<ULONG>(data.size()),
        BCRYPT_USE_SYSTEM_PREFERRED_RNG);

    return BCRYPT_SUCCESS(status);
}

int main()
{
    std::cout
        << "============================================\n"
        << "       FaceUnlock Crypto Test\n"
        << "                 Stage 5A\n"
        << "============================================\n\n";

    BCRYPT_ALG_HANDLE algorithm = nullptr;
    BCRYPT_KEY_HANDLE key = nullptr;

    // ========================================================
    // 1. Open RSA provider
    // ========================================================

    std::cout
        << "[1] Opening RSA cryptographic provider...\n";

    NTSTATUS status = BCryptOpenAlgorithmProvider(
        &algorithm,
        BCRYPT_RSA_ALGORITHM,
        nullptr,
        0);

    if (!BCRYPT_SUCCESS(status))
    {
        std::cerr
            << "[ERROR] BCryptOpenAlgorithmProvider failed.\n";

        return 1;
    }

    std::cout
        << "[OK] RSA provider opened.\n\n";

    // ========================================================
    // 2. Generate RSA key pair
    // ========================================================

    std::cout
        << "[2] Generating RSA key pair...\n";

    status = BCryptGenerateKeyPair(
        algorithm,
        &key,
        2048,
        0);

    if (!BCRYPT_SUCCESS(status))
    {
        std::cerr
            << "[ERROR] BCryptGenerateKeyPair failed.\n";

        BCryptCloseAlgorithmProvider(
            algorithm,
            0);

        return 1;
    }

    status = BCryptFinalizeKeyPair(
        key,
        0);

    if (!BCRYPT_SUCCESS(status))
    {
        std::cerr
            << "[ERROR] BCryptFinalizeKeyPair failed.\n";

        BCryptDestroyKey(key);
        BCryptCloseAlgorithmProvider(algorithm, 0);

        return 1;
    }

    std::cout
        << "[OK] RSA-2048 key pair generated.\n\n";

    // ========================================================
    // 3. Generate authentication challenge
    // ========================================================

    std::cout
        << "[3] Generating authentication challenge...\n";

    std::vector<BYTE> challenge;

    if (!GenerateRandom(challenge, 32))
    {
        std::cerr
            << "[ERROR] Random challenge generation failed.\n";

        BCryptDestroyKey(key);
        BCryptCloseAlgorithmProvider(algorithm, 0);

        return 1;
    }

    PrintHex(
        "Challenge",
        challenge);

    // ========================================================
    // 4. Hash challenge using SHA-256
    // ========================================================

    std::cout
        << "[4] Creating SHA-256 hash...\n";

    BCRYPT_ALG_HANDLE sha256 = nullptr;

    status = BCryptOpenAlgorithmProvider(
        &sha256,
        BCRYPT_SHA256_ALGORITHM,
        nullptr,
        0);

    if (!BCRYPT_SUCCESS(status))
    {
        std::cerr
            << "[ERROR] SHA-256 provider failed.\n";

        BCryptDestroyKey(key);
        BCryptCloseAlgorithmProvider(algorithm, 0);

        return 1;
    }

    std::vector<BYTE> hash(32);

    status = BCryptHash(
        sha256,
        nullptr,
        0,
        challenge.data(),
        static_cast<ULONG>(challenge.size()),
        hash.data(),
        static_cast<ULONG>(hash.size()));

    if (!BCRYPT_SUCCESS(status))
    {
        std::cerr
            << "[ERROR] BCryptHash failed.\n";

        BCryptCloseAlgorithmProvider(sha256, 0);
        BCryptDestroyKey(key);
        BCryptCloseAlgorithmProvider(algorithm, 0);

        return 1;
    }

    PrintHex(
        "SHA-256 hash",
        hash);

    // ========================================================
    // 5. Create RSA signature
    // ========================================================

    std::cout
        << "[5] Signing challenge hash with private key...\n";

    BCRYPT_PKCS1_PADDING_INFO paddingInfo{};

    paddingInfo.pszAlgId = BCRYPT_SHA256_ALGORITHM;

    ULONG signatureSize = 0;

    status = BCryptSignHash(
        key,
        &paddingInfo,
        hash.data(),
        static_cast<ULONG>(hash.size()),
        nullptr,
        0,
        &signatureSize,
        BCRYPT_PAD_PKCS1);

    if (!BCRYPT_SUCCESS(status))
    {
        std::cerr
            << "[ERROR] Could not determine signature size.\n";

        BCryptCloseAlgorithmProvider(sha256, 0);
        BCryptDestroyKey(key);
        BCryptCloseAlgorithmProvider(algorithm, 0);

        return 1;
    }

    std::vector<BYTE> signature(signatureSize);

    status = BCryptSignHash(
        key,
        &paddingInfo,
        hash.data(),
        static_cast<ULONG>(hash.size()),
        signature.data(),
        static_cast<ULONG>(signature.size()),
        &signatureSize,
        BCRYPT_PAD_PKCS1);

    if (!BCRYPT_SUCCESS(status))
    {
        std::cerr
            << "[ERROR] BCryptSignHash failed.\n";

        BCryptCloseAlgorithmProvider(sha256, 0);
        BCryptDestroyKey(key);
        BCryptCloseAlgorithmProvider(algorithm, 0);

        return 1;
    }

    signature.resize(signatureSize);

    std::cout
        << "[OK] Signature generated.\n\n";

    PrintHex(
        "RSA signature",
        signature);

    // ========================================================
    // 6. Export public key
    // ========================================================

    std::cout
        << "[6] Exporting public key...\n";

    ULONG publicKeySize = 0;

    status = BCryptExportKey(
        key,
        nullptr,
        BCRYPT_RSAPUBLIC_BLOB,
        nullptr,
        0,
        &publicKeySize,
        0);

    if (!BCRYPT_SUCCESS(status))
    {
        std::cerr
            << "[ERROR] Could not determine public key size.\n";

        BCryptCloseAlgorithmProvider(sha256, 0);
        BCryptDestroyKey(key);
        BCryptCloseAlgorithmProvider(algorithm, 0);

        return 1;
    }

    std::vector<BYTE> publicKey(publicKeySize);

    status = BCryptExportKey(
        key,
        nullptr,
        BCRYPT_RSAPUBLIC_BLOB,
        publicKey.data(),
        static_cast<ULONG>(publicKey.size()),
        &publicKeySize,
        0);

    if (!BCRYPT_SUCCESS(status))
    {
        std::cerr
            << "[ERROR] Public key export failed.\n";

        BCryptCloseAlgorithmProvider(sha256, 0);
        BCryptDestroyKey(key);
        BCryptCloseAlgorithmProvider(algorithm, 0);

        return 1;
    }

    publicKey.resize(publicKeySize);

    std::cout
        << "[OK] Public key exported.\n\n";

    std::cout
        << "Public key size: "
        << publicKey.size()
        << " bytes\n\n";

    // ========================================================
    // 7. Import public key
    //
    // This simulates the Windows server having only the
    // public key while the client keeps the private key.
    // ========================================================

    std::cout
        << "[7] Importing public key...\n";

    BCRYPT_KEY_HANDLE verificationKey = nullptr;

    status = BCryptImportKeyPair(
        algorithm,
        nullptr,
        BCRYPT_RSAPUBLIC_BLOB,
        &verificationKey,
        publicKey.data(),
        static_cast<ULONG>(publicKey.size()),
        0);

    if (!BCRYPT_SUCCESS(status))
    {
        std::cerr
            << "[ERROR] Public key import failed.\n";

        BCryptCloseAlgorithmProvider(sha256, 0);
        BCryptDestroyKey(key);
        BCryptCloseAlgorithmProvider(algorithm, 0);

        return 1;
    }

    std::cout
        << "[OK] Public key imported.\n\n";

    // ========================================================
    // 8. Verify signature
    // ========================================================

    std::cout
        << "[8] Verifying signature...\n";

    status = BCryptVerifySignature(
        verificationKey,
        &paddingInfo,
        hash.data(),
        static_cast<ULONG>(hash.size()),
        signature.data(),
        static_cast<ULONG>(signature.size()),
        BCRYPT_PAD_PKCS1);

    if (!BCRYPT_SUCCESS(status))
    {
        std::cerr
            << "[ERROR] SIGNATURE VERIFICATION FAILED.\n";

        BCryptDestroyKey(verificationKey);
        BCryptCloseAlgorithmProvider(sha256, 0);
        BCryptDestroyKey(key);
        BCryptCloseAlgorithmProvider(algorithm, 0);

        return 1;
    }

    std::cout
        << "[OK] SIGNATURE VERIFIED.\n\n";

    // ========================================================
    // 9. Result
    // ========================================================

    std::cout
        << "============================================\n"
        << "             STAGE 5A RESULT\n"
        << "============================================\n\n";

    std::cout
        << "Random challenge       [OK]\n"
        << "SHA-256 hashing        [OK]\n"
        << "Private-key signing    [OK]\n"
        << "Public-key export      [OK]\n"
        << "Public-key import      [OK]\n"
        << "Signature verification [OK]\n\n";

    std::cout
        << "Cryptographic authentication test passed.\n";

    // ========================================================
    // Cleanup
    // ========================================================

    BCryptDestroyKey(verificationKey);
    BCryptCloseAlgorithmProvider(sha256, 0);
    BCryptDestroyKey(key);
    BCryptCloseAlgorithmProvider(algorithm, 0);

    std::cout
        << "\nPress ENTER to exit...";

    std::cin.get();

    return 0;
}