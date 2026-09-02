#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <bcrypt.h>

#include <iostream>
#include <iomanip>
#include <vector>

#pragma comment(lib, "ws2_32.lib")
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

static bool SendAll(
    SOCKET socket,
    const BYTE* data,
    int length)
{
    int sent = 0;

    while (sent < length)
    {
        int result = send(
            socket,
            reinterpret_cast<const char*>(data) + sent,
            length - sent,
            0);

        if (result == SOCKET_ERROR || result == 0)
            return false;

        sent += result;
    }

    return true;
}

static bool ReceiveAll(
    SOCKET socket,
    BYTE* data,
    int length)
{
    int received = 0;

    while (received < length)
    {
        int result = recv(
            socket,
            reinterpret_cast<char*>(data) + received,
            length - received,
            0);

        if (result == SOCKET_ERROR || result == 0)
            return false;

        received += result;

        std::cout
            << "[NETWORK] Received "
            << result
            << " byte(s). Total: "
            << received
            << "/"
            << length
            << "\n";
    }

    return true;
}

static bool GenerateRSAKeyPair(
    BCRYPT_KEY_HANDLE& privateKey,
    std::vector<BYTE>& publicKey)
{
    privateKey = nullptr;
    publicKey.clear();

    BCRYPT_ALG_HANDLE algorithm = nullptr;

    NTSTATUS status = BCryptOpenAlgorithmProvider(
        &algorithm,
        BCRYPT_RSA_ALGORITHM,
        nullptr,
        0);

    if (!BCRYPT_SUCCESS(status))
        return false;

    status = BCryptGenerateKeyPair(
        algorithm,
        &privateKey,
        2048,
        0);

    if (!BCRYPT_SUCCESS(status))
    {
        BCryptCloseAlgorithmProvider(algorithm, 0);
        return false;
    }

    status = BCryptFinalizeKeyPair(
        privateKey,
        0);

    if (!BCRYPT_SUCCESS(status))
    {
        BCryptDestroyKey(privateKey);
        privateKey = nullptr;

        BCryptCloseAlgorithmProvider(algorithm, 0);
        return false;
    }

    DWORD publicKeySize = 0;
    DWORD resultSize = 0;

    status = BCryptExportKey(
        privateKey,
        nullptr,
        BCRYPT_RSAPUBLIC_BLOB,
        nullptr,
        0,
        &publicKeySize,
        0);

    if (!BCRYPT_SUCCESS(status))
    {
        BCryptDestroyKey(privateKey);
        privateKey = nullptr;

        BCryptCloseAlgorithmProvider(algorithm, 0);
        return false;
    }

    publicKey.resize(publicKeySize);

    status = BCryptExportKey(
        privateKey,
        nullptr,
        BCRYPT_RSAPUBLIC_BLOB,
        publicKey.data(),
        publicKeySize,
        &resultSize,
        0);

    BCryptCloseAlgorithmProvider(algorithm, 0);

    if (!BCRYPT_SUCCESS(status))
    {
        BCryptDestroyKey(privateKey);
        privateKey = nullptr;

        publicKey.clear();

        return false;
    }

    publicKey.resize(resultSize);

    return true;
}

static bool HashSHA256(
    const std::vector<BYTE>& input,
    std::vector<BYTE>& hash)
{
    BCRYPT_ALG_HANDLE algorithm = nullptr;
    BCRYPT_HASH_HANDLE hashHandle = nullptr;

    NTSTATUS status = BCryptOpenAlgorithmProvider(
        &algorithm,
        BCRYPT_SHA256_ALGORITHM,
        nullptr,
        0);

    if (!BCRYPT_SUCCESS(status))
        return false;

    DWORD hashLength = 0;
    DWORD resultLength = 0;

    status = BCryptGetProperty(
        algorithm,
        BCRYPT_HASH_LENGTH,
        reinterpret_cast<PUCHAR>(&hashLength),
        sizeof(hashLength),
        &resultLength,
        0);

    if (!BCRYPT_SUCCESS(status))
    {
        BCryptCloseAlgorithmProvider(algorithm, 0);
        return false;
    }

    hash.resize(hashLength);

    status = BCryptCreateHash(
        algorithm,
        &hashHandle,
        nullptr,
        0,
        nullptr,
        0,
        0);

    if (!BCRYPT_SUCCESS(status))
    {
        BCryptCloseAlgorithmProvider(algorithm, 0);
        return false;
    }

    status = BCryptHashData(
        hashHandle,
        const_cast<PUCHAR>(input.data()),
        static_cast<ULONG>(input.size()),
        0);

    if (BCRYPT_SUCCESS(status))
    {
        status = BCryptFinishHash(
            hashHandle,
            hash.data(),
            static_cast<ULONG>(hash.size()),
            0);
    }

    BCryptDestroyHash(hashHandle);
    BCryptCloseAlgorithmProvider(algorithm, 0);

    return BCRYPT_SUCCESS(status);
}

static bool SignHash(
    BCRYPT_KEY_HANDLE privateKey,
    const std::vector<BYTE>& hash,
    std::vector<BYTE>& signature)
{
    BCRYPT_PKCS1_PADDING_INFO paddingInfo{};

    paddingInfo.pszAlgId = BCRYPT_SHA256_ALGORITHM;

    DWORD signatureSize = 0;

    NTSTATUS status = BCryptSignHash(
        privateKey,
        &paddingInfo,
        const_cast<PUCHAR>(hash.data()),
        static_cast<ULONG>(hash.size()),
        nullptr,
        0,
        &signatureSize,
        BCRYPT_PAD_PKCS1);

    if (!BCRYPT_SUCCESS(status))
        return false;

    signature.resize(signatureSize);

    status = BCryptSignHash(
        privateKey,
        &paddingInfo,
        const_cast<PUCHAR>(hash.data()),
        static_cast<ULONG>(hash.size()),
        signature.data(),
        signatureSize,
        &signatureSize,
        BCRYPT_PAD_PKCS1);

    if (!BCRYPT_SUCCESS(status))
    {
        signature.clear();
        return false;
    }

    signature.resize(signatureSize);

    return true;
}

int main()
{
    std::cout
        << "============================================\n"
        << "       FaceUnlock Crypto Client\n"
        << "                 Stage 5B\n"
        << "============================================\n\n";

    // ========================================================
    // 1. Initialize Winsock
    // ========================================================

    std::cout
        << "[1] Initializing networking...\n";

    WSADATA wsaData{};

    int result = WSAStartup(
        MAKEWORD(2, 2),
        &wsaData);

    if (result != 0)
    {
        std::cerr
            << "[ERROR] WSAStartup failed: "
            << result
            << "\n";

        return 1;
    }

    std::cout
        << "[OK] Winsock initialized.\n\n";

    // ========================================================
    // 2. Generate RSA key pair
    // ========================================================

    std::cout
        << "[2] Generating RSA-2048 key pair...\n";

    BCRYPT_KEY_HANDLE privateKey = nullptr;
    std::vector<BYTE> publicKey;

    if (!GenerateRSAKeyPair(
            privateKey,
            publicKey))
    {
        std::cerr
            << "[ERROR] RSA key generation failed.\n";

        WSACleanup();
        return 1;
    }

    std::cout
        << "[OK] RSA-2048 key pair generated.\n";

    std::cout
        << "Public key size: "
        << publicKey.size()
        << " bytes.\n\n";

    PrintHex(
        "Public key",
        publicKey);

    // ========================================================
    // 3. Create socket
    // ========================================================

    std::cout
        << "[3] Creating TCP socket...\n";

    SOCKET clientSocket = socket(
        AF_INET,
        SOCK_STREAM,
        IPPROTO_TCP);

    if (clientSocket == INVALID_SOCKET)
    {
        std::cerr
            << "[ERROR] socket() failed.\n";

        BCryptDestroyKey(privateKey);
        WSACleanup();

        return 1;
    }

    std::cout
        << "[OK] Socket created.\n\n";

    // ========================================================
    // 4. Connect to server
    // ========================================================

    sockaddr_in serverAddress{};

    serverAddress.sin_family = AF_INET;
    serverAddress.sin_port = htons(5050);

    inet_pton(
        AF_INET,
        "192.168.1.69",
        &serverAddress.sin_addr);

    std::cout
        << "[4] Connecting to 192.168.1.69:5050...\n";

    result = connect(
        clientSocket,
        reinterpret_cast<sockaddr*>(&serverAddress),
        sizeof(serverAddress));

    if (result == SOCKET_ERROR)
    {
        std::cerr
            << "[ERROR] Connection failed.\n";

        closesocket(clientSocket);
        BCryptDestroyKey(privateKey);
        WSACleanup();

        return 1;
    }

    std::cout
        << "[OK] Connected to FaceUnlock server.\n\n";

    // ========================================================
    // 5. Send public key
    //
    // First send a 4-byte length.
    // Then send the public key blob.
    // ========================================================

    std::cout
        << "[5] Sending public key to server...\n";

    DWORD publicKeyLength =
        static_cast<DWORD>(publicKey.size());

    if (!SendAll(
            clientSocket,
            reinterpret_cast<BYTE*>(&publicKeyLength),
            sizeof(publicKeyLength)))
    {
        std::cerr
            << "[ERROR] Failed to send public key length.\n";

        closesocket(clientSocket);
        BCryptDestroyKey(privateKey);
        WSACleanup();

        return 1;
    }

    if (!SendAll(
            clientSocket,
            publicKey.data(),
            static_cast<int>(publicKey.size())))
    {
        std::cerr
            << "[ERROR] Failed to send public key.\n";

        closesocket(clientSocket);
        BCryptDestroyKey(privateKey);
        WSACleanup();

        return 1;
    }

    std::cout
        << "[OK] Public key sent.\n\n";

    // ========================================================
    // 6. Receive challenge
    // ========================================================

    std::cout
        << "[6] Waiting for authentication challenge...\n";

    std::vector<BYTE> challenge(32);

    if (!ReceiveAll(
            clientSocket,
            challenge.data(),
            static_cast<int>(challenge.size())))
    {
        std::cerr
            << "[ERROR] Failed to receive challenge.\n";

        closesocket(clientSocket);
        BCryptDestroyKey(privateKey);
        WSACleanup();

        return 1;
    }

    std::cout
        << "[OK] Challenge received.\n\n";

    PrintHex(
        "Challenge",
        challenge);

    // ========================================================
    // 7. SHA-256
    // ========================================================

    std::cout
        << "[7] Creating SHA-256 challenge hash...\n";

    std::vector<BYTE> hash;

    if (!HashSHA256(
            challenge,
            hash))
    {
        std::cerr
            << "[ERROR] SHA-256 failed.\n";

        closesocket(clientSocket);
        BCryptDestroyKey(privateKey);
        WSACleanup();

        return 1;
    }

    std::cout
        << "[OK] SHA-256 hash created.\n\n";

    PrintHex(
        "SHA-256 hash",
        hash);

    // ========================================================
    // 8. Sign hash
    // ========================================================

    std::cout
        << "[8] Signing challenge hash with private key...\n";

    std::vector<BYTE> signature;

    if (!SignHash(
            privateKey,
            hash,
            signature))
    {
        std::cerr
            << "[ERROR] Signature generation failed.\n";

        closesocket(clientSocket);
        BCryptDestroyKey(privateKey);
        WSACleanup();

        return 1;
    }

    std::cout
        << "[OK] Signature generated.\n\n";

    PrintHex(
        "RSA signature",
        signature);

    // ========================================================
    // 9. Send signature
    // ========================================================

    std::cout
        << "[9] Sending signature to server...\n";

    if (!SendAll(
            clientSocket,
            signature.data(),
            static_cast<int>(signature.size())))
    {
        std::cerr
            << "[ERROR] Failed to send signature.\n";

        closesocket(clientSocket);
        BCryptDestroyKey(privateKey);
        WSACleanup();

        return 1;
    }

    std::cout
        << "[OK] Signature sent.\n\n";

    // ========================================================
    // Cleanup
    // ========================================================

    closesocket(clientSocket);

    BCryptDestroyKey(privateKey);

    WSACleanup();

    std::cout
        << "============================================\n"
        << "       STAGE 5B CLIENT RESULT\n"
        << "============================================\n\n";

    std::cout
        << "Network connection          [OK]\n"
        << "RSA key generation          [OK]\n"
        << "Public key sent             [OK]\n"
        << "Challenge received          [OK]\n"
        << "SHA-256 hashing              [OK]\n"
        << "Private-key signing          [OK]\n"
        << "Signature sent               [OK]\n\n";

    std::cout
        << "Client cryptographic operation completed.\n";

    std::cout
        << "\nPress ENTER to exit...";

    std::cin.get();

    return 0;
}