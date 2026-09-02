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

static bool GenerateChallenge(
    std::vector<BYTE>& challenge)
{
    challenge.resize(32);

    NTSTATUS status = BCryptGenRandom(
        nullptr,
        challenge.data(),
        static_cast<ULONG>(challenge.size()),
        BCRYPT_USE_SYSTEM_PREFERRED_RNG);

    return BCRYPT_SUCCESS(status);
}

static bool ImportPublicKey(
    const std::vector<BYTE>& publicKeyBlob,
    BCRYPT_KEY_HANDLE& publicKey)
{
    publicKey = nullptr;

    BCRYPT_ALG_HANDLE algorithm = nullptr;

    NTSTATUS status = BCryptOpenAlgorithmProvider(
        &algorithm,
        BCRYPT_RSA_ALGORITHM,
        nullptr,
        0);

    if (!BCRYPT_SUCCESS(status))
        return false;

    status = BCryptImportKeyPair(
        algorithm,
        nullptr,
        BCRYPT_RSAPUBLIC_BLOB,
        &publicKey,
        const_cast<PUCHAR>(publicKeyBlob.data()),
        static_cast<ULONG>(publicKeyBlob.size()),
        0);

    BCryptCloseAlgorithmProvider(
        algorithm,
        0);

    if (!BCRYPT_SUCCESS(status))
    {
        publicKey = nullptr;
        return false;
    }

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

static bool VerifySignature(
    BCRYPT_KEY_HANDLE publicKey,
    const std::vector<BYTE>& hash,
    const std::vector<BYTE>& signature)
{
    BCRYPT_PKCS1_PADDING_INFO paddingInfo{};

    paddingInfo.pszAlgId = BCRYPT_SHA256_ALGORITHM;

    NTSTATUS status = BCryptVerifySignature(
        publicKey,
        &paddingInfo,
        const_cast<PUCHAR>(hash.data()),
        static_cast<ULONG>(hash.size()),
        const_cast<PUCHAR>(signature.data()),
        static_cast<ULONG>(signature.size()),
        BCRYPT_PAD_PKCS1);

    return BCRYPT_SUCCESS(status);
}

int main()
{
    std::cout
        << "============================================\n"
        << "       FaceUnlock Crypto Server\n"
        << "                 Stage 5B\n"
        << "============================================\n\n";

    // ========================================================
    // 1. Initialize networking
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
    // 2. Create socket
    // ========================================================

    std::cout
        << "[2] Creating TCP socket...\n";

    SOCKET serverSocket = socket(
        AF_INET,
        SOCK_STREAM,
        IPPROTO_TCP);

    if (serverSocket == INVALID_SOCKET)
    {
        std::cerr
            << "[ERROR] socket() failed.\n";

        WSACleanup();
        return 1;
    }

    std::cout
        << "[OK] Socket created.\n\n";

    // ========================================================
    // 3. Bind
    // ========================================================

    sockaddr_in serverAddress{};

    serverAddress.sin_family = AF_INET;
    serverAddress.sin_port = htons(5050);

    inet_pton(
        AF_INET,
        "192.168.1.69",
        &serverAddress.sin_addr);

    std::cout
        << "[3] Binding to 192.168.1.69:5050...\n";

    result = bind(
        serverSocket,
        reinterpret_cast<sockaddr*>(&serverAddress),
        sizeof(serverAddress));

    if (result == SOCKET_ERROR)
    {
        std::cerr
            << "[ERROR] bind() failed.\n";

        closesocket(serverSocket);
        WSACleanup();

        return 1;
    }

    std::cout
        << "[OK] Server bound.\n\n";

    // ========================================================
    // 4. Listen
    // ========================================================

    std::cout
        << "[4] Starting listener...\n";

    result = listen(
        serverSocket,
        1);

    if (result == SOCKET_ERROR)
    {
        std::cerr
            << "[ERROR] listen() failed.\n";

        closesocket(serverSocket);
        WSACleanup();

        return 1;
    }

    std::cout
        << "[OK] Listening.\n\n";

    std::cout
        << "============================================\n"
        << " Server ready\n"
        << " Address: 192.168.1.69\n"
        << " Port:    5050\n"
        << "============================================\n\n";

    std::cout
        << "Waiting for Stage 5B client...\n\n";

    // ========================================================
    // 5. Accept client
    // ========================================================

    SOCKET clientSocket = accept(
        serverSocket,
        nullptr,
        nullptr);

    if (clientSocket == INVALID_SOCKET)
    {
        std::cerr
            << "[ERROR] accept() failed.\n";

        closesocket(serverSocket);
        WSACleanup();

        return 1;
    }

    std::cout
        << "[OK] Client connected.\n\n";

    // ========================================================
    // 6. Receive public-key length
    // ========================================================

    std::cout
        << "[5] Receiving client public key...\n";

    DWORD publicKeyLength = 0;

    if (!ReceiveAll(
            clientSocket,
            reinterpret_cast<BYTE*>(&publicKeyLength),
            sizeof(publicKeyLength)))
    {
        std::cerr
            << "[ERROR] Failed to receive public key length.\n";

        closesocket(clientSocket);
        closesocket(serverSocket);
        WSACleanup();

        return 1;
    }

    std::cout
        << "[INFO] Public key size: "
        << publicKeyLength
        << " bytes.\n";

    // Safety check.
    if (publicKeyLength == 0 ||
        publicKeyLength > 4096)
    {
        std::cerr
            << "[ERROR] Invalid public key size.\n";

        closesocket(clientSocket);
        closesocket(serverSocket);
        WSACleanup();

        return 1;
    }

    std::vector<BYTE> publicKeyBlob(
        publicKeyLength);

    if (!ReceiveAll(
            clientSocket,
            publicKeyBlob.data(),
            static_cast<int>(publicKeyBlob.size())))
    {
        std::cerr
            << "[ERROR] Failed to receive public key.\n";

        closesocket(clientSocket);
        closesocket(serverSocket);
        WSACleanup();

        return 1;
    }

    std::cout
        << "[OK] Public key received.\n\n";

    PrintHex(
        "Client public key",
        publicKeyBlob);

    // ========================================================
    // 7. Import public key
    // ========================================================

    std::cout
        << "[6] Importing client public key...\n";

    BCRYPT_KEY_HANDLE publicKey = nullptr;

    if (!ImportPublicKey(
            publicKeyBlob,
            publicKey))
    {
        std::cerr
            << "[ERROR] Public key import failed.\n";

        closesocket(clientSocket);
        closesocket(serverSocket);
        WSACleanup();

        return 1;
    }

    std::cout
        << "[OK] Public key imported.\n\n";

    // ========================================================
    // 8. Generate challenge
    // ========================================================

    std::cout
        << "[7] Generating random authentication challenge...\n";

    std::vector<BYTE> challenge;

    if (!GenerateChallenge(challenge))
    {
        std::cerr
            << "[ERROR] Challenge generation failed.\n";

        BCryptDestroyKey(publicKey);

        closesocket(clientSocket);
        closesocket(serverSocket);
        WSACleanup();

        return 1;
    }

    std::cout
        << "[OK] Challenge generated.\n\n";

    PrintHex(
        "Challenge",
        challenge);

    // ========================================================
    // 9. Send challenge
    // ========================================================

    std::cout
        << "[8] Sending challenge to client...\n";

    if (!SendAll(
            clientSocket,
            challenge.data(),
            static_cast<int>(challenge.size())))
    {
        std::cerr
            << "[ERROR] Failed to send challenge.\n";

        BCryptDestroyKey(publicKey);

        closesocket(clientSocket);
        closesocket(serverSocket);
        WSACleanup();

        return 1;
    }

    std::cout
        << "[OK] Challenge sent.\n\n";

    // ========================================================
    // 10. Receive signature
    // ========================================================

    std::cout
        << "[9] Waiting for client signature...\n";

    // RSA-2048 PKCS#1 signature = 256 bytes.
    std::vector<BYTE> signature(256);

    if (!ReceiveAll(
            clientSocket,
            signature.data(),
            static_cast<int>(signature.size())))
    {
        std::cerr
            << "[ERROR] Failed to receive signature.\n";

        BCryptDestroyKey(publicKey);

        closesocket(clientSocket);
        closesocket(serverSocket);
        WSACleanup();

        return 1;
    }

    std::cout
        << "[OK] Signature received.\n\n";

    PrintHex(
        "Client signature",
        signature);

    // ========================================================
    // 11. Hash challenge
    // ========================================================

    std::cout
        << "[10] Hashing challenge with SHA-256...\n";

    std::vector<BYTE> hash;

    if (!HashSHA256(
            challenge,
            hash))
    {
        std::cerr
            << "[ERROR] SHA-256 failed.\n";

        BCryptDestroyKey(publicKey);

        closesocket(clientSocket);
        closesocket(serverSocket);
        WSACleanup();

        return 1;
    }

    std::cout
        << "[OK] SHA-256 hash created.\n\n";

    PrintHex(
        "Challenge SHA-256 hash",
        hash);

    // ========================================================
    // 12. Verify signature
    // ========================================================

    std::cout
        << "[11] Verifying RSA signature...\n";

    bool verified = VerifySignature(
        publicKey,
        hash,
        signature);

    if (verified)
    {
        std::cout
            << "[OK] SIGNATURE VERIFIED.\n\n";
    }
    else
    {
        std::cout
            << "[ERROR] SIGNATURE VERIFICATION FAILED.\n\n";
    }

    // ========================================================
    // Cleanup
    // ========================================================

    BCryptDestroyKey(publicKey);

    closesocket(clientSocket);
    closesocket(serverSocket);

    WSACleanup();

    // ========================================================
    // Result
    // ========================================================

    std::cout
        << "============================================\n"
        << "             STAGE 5B RESULT\n"
        << "============================================\n\n";

    std::cout
        << "Network connection          [OK]\n"
        << "Public key received         [OK]\n"
        << "Public key imported         [OK]\n"
        << "Random challenge            [OK]\n"
        << "Challenge sent              [OK]\n"
        << "Signature received          [OK]\n"
        << "SHA-256 hashing             [OK]\n";

    if (verified)
    {
        std::cout
            << "RSA signature verification  [OK]\n\n";

        std::cout
            << "Cryptographic authentication "
               "passed successfully.\n";
    }
    else
    {
        std::cout
            << "RSA signature verification  [FAILED]\n\n";

        std::cout
            << "Cryptographic authentication "
               "failed.\n";
    }

    std::cout
        << "\nPress ENTER to exit...";

    std::cin.get();

    return verified ? 0 : 1;
}