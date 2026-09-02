#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <bcrypt.h>

#include <iostream>
#include <fstream>
#include <vector>
#include <iomanip>

#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "bcrypt.lib")

// ============================================================
// Configuration
// ============================================================

static const char* SERVER_IP = "192.168.1.69";
static const int SERVER_PORT = 5050;

static const char* PRIVATE_KEY_FILE =
    "C:\\Users\\user\\Desktop\\FaceUnlock\\FaceUnlockEnrollment\\FaceUnlockDevice.private";

// ============================================================
// Helpers
// ============================================================

static void PrintHex(
    const char* name,
    const std::vector<BYTE>& data)
{
    std::cout
        << name
        << " (" << data.size()
        << " bytes):\n";

    for (BYTE b : data)
    {
        std::cout
            << std::hex
            << std::setw(2)
            << std::setfill('0')
            << static_cast<int>(b);
    }

    std::cout
        << std::dec
        << "\n\n";
}

// ============================================================

static bool LoadBinaryFile(
    const char* filename,
    std::vector<BYTE>& data)
{
    std::ifstream file(
        filename,
        std::ios::binary);

    if (!file)
        return false;

    file.seekg(
        0,
        std::ios::end);

    std::streamsize size =
        file.tellg();

    if (size <= 0)
        return false;

    file.seekg(
        0,
        std::ios::beg);

    data.resize(
        static_cast<size_t>(size));

    file.read(
        reinterpret_cast<char*>(data.data()),
        size);

    return file.good();
}

// ============================================================

static bool SendAll(
    SOCKET socket,
    const BYTE* data,
    int length)
{
    int sent = 0;

    while (sent < length)
    {
        int result =
            send(
                socket,
                reinterpret_cast<const char*>(data) + sent,
                length - sent,
                0);

        if (result == SOCKET_ERROR ||
            result == 0)
        {
            return false;
        }

        sent += result;
    }

    return true;
}

// ============================================================

static bool ReceiveAll(
    SOCKET socket,
    BYTE* data,
    int length)
{
    int received = 0;

    while (received < length)
    {
        int result =
            recv(
                socket,
                reinterpret_cast<char*>(data) + received,
                length - received,
                0);

        if (result == SOCKET_ERROR ||
            result == 0)
        {
            return false;
        }

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

// ============================================================

static bool Sha256(
    const std::vector<BYTE>& input,
    std::vector<BYTE>& hash)
{
    BCRYPT_ALG_HANDLE algorithm = nullptr;
    BCRYPT_HASH_HANDLE hashHandle = nullptr;

    NTSTATUS status =
        BCryptOpenAlgorithmProvider(
            &algorithm,
            BCRYPT_SHA256_ALGORITHM,
            nullptr,
            0);

    if (!BCRYPT_SUCCESS(status))
        return false;

    DWORD objectSize = 0;
    DWORD dataSize = 0;

    status =
        BCryptGetProperty(
            algorithm,
            BCRYPT_OBJECT_LENGTH,
            reinterpret_cast<PUCHAR>(&objectSize),
            sizeof(objectSize),
            &dataSize,
            0);

    if (!BCRYPT_SUCCESS(status))
    {
        BCryptCloseAlgorithmProvider(
            algorithm,
            0);

        return false;
    }

    std::vector<BYTE> object(
        objectSize);

    status =
        BCryptCreateHash(
            algorithm,
            &hashHandle,
            object.data(),
            objectSize,
            nullptr,
            0,
            0);

    if (!BCRYPT_SUCCESS(status))
    {
        BCryptCloseAlgorithmProvider(
            algorithm,
            0);

        return false;
    }

    status =
        BCryptHashData(
            hashHandle,
            const_cast<PUCHAR>(
                input.data()),
            static_cast<ULONG>(
                input.size()),
            0);

    if (!BCRYPT_SUCCESS(status))
    {
        BCryptDestroyHash(hashHandle);
        BCryptCloseAlgorithmProvider(
            algorithm,
            0);

        return false;
    }

    hash.resize(32);

    status =
        BCryptFinishHash(
            hashHandle,
            hash.data(),
            static_cast<ULONG>(
                hash.size()),
            0);

    BCryptDestroyHash(hashHandle);

    BCryptCloseAlgorithmProvider(
        algorithm,
        0);

    return BCRYPT_SUCCESS(status);
}

// ============================================================

static bool SignHash(
    const std::vector<BYTE>& privateKeyBlob,
    const std::vector<BYTE>& hash,
    std::vector<BYTE>& signature)
{
    BCRYPT_ALG_HANDLE algorithm = nullptr;
    BCRYPT_KEY_HANDLE privateKey = nullptr;

    NTSTATUS status =
        BCryptOpenAlgorithmProvider(
            &algorithm,
            BCRYPT_RSA_ALGORITHM,
            nullptr,
            0);

    if (!BCRYPT_SUCCESS(status))
        return false;

    status =
        BCryptImportKeyPair(
            algorithm,
            nullptr,
            BCRYPT_RSAFULLPRIVATE_BLOB,
            &privateKey,
            const_cast<PUCHAR>(
                privateKeyBlob.data()),
            static_cast<ULONG>(
                privateKeyBlob.size()),
            0);

    if (!BCRYPT_SUCCESS(status))
    {
        BCryptCloseAlgorithmProvider(
            algorithm,
            0);

        return false;
    }

    BCRYPT_PKCS1_PADDING_INFO paddingInfo{};

    paddingInfo.pszAlgId =
        BCRYPT_SHA256_ALGORITHM;

    DWORD signatureSize = 0;

    status =
        BCryptSignHash(
            privateKey,
            &paddingInfo,
            const_cast<PUCHAR>(
                hash.data()),
            static_cast<ULONG>(
                hash.size()),
            nullptr,
            0,
            &signatureSize,
            BCRYPT_PAD_PKCS1);

    if (!BCRYPT_SUCCESS(status))
    {
        BCryptDestroyKey(privateKey);
        BCryptCloseAlgorithmProvider(
            algorithm,
            0);

        return false;
    }

    signature.resize(
        signatureSize);

    status =
        BCryptSignHash(
            privateKey,
            &paddingInfo,
            const_cast<PUCHAR>(
                hash.data()),
            static_cast<ULONG>(
                hash.size()),
            signature.data(),
            signatureSize,
            &signatureSize,
            BCRYPT_PAD_PKCS1);

    BCryptDestroyKey(privateKey);

    BCryptCloseAlgorithmProvider(
        algorithm,
        0);

    if (!BCRYPT_SUCCESS(status))
        return false;

    signature.resize(
        signatureSize);

    return true;
}

// ============================================================
// Main
// ============================================================

int main()
{
    std::cout
        << "============================================\n"
        << " FaceUnlock Persistent Auth Client\n"
        << "                 Stage 7\n"
        << "============================================\n\n";

    // ========================================================
    // 1. Load persistent private key
    // ========================================================

    std::cout
        << "[1] Loading enrolled private key...\n";

    std::vector<BYTE> privateKey;

    if (!LoadBinaryFile(
            PRIVATE_KEY_FILE,
            privateKey))
    {
        std::cerr
            << "[ERROR] Could not load:\n"
            << PRIVATE_KEY_FILE
            << "\n\n";

        std::cerr
            << "Make sure Stage 6 enrollment was completed.\n";

        return 1;
    }

    std::cout
        << "[OK] Enrolled private key loaded.\n";

    std::cout
        << "Private key size: "
        << privateKey.size()
        << " bytes.\n\n";

    // ========================================================
    // 2. Initialize networking
    // ========================================================

    std::cout
        << "[2] Initializing networking...\n";

    WSADATA wsaData{};

    int result =
        WSAStartup(
            MAKEWORD(2, 2),
            &wsaData);

    if (result != 0)
    {
        std::cerr
            << "[ERROR] WSAStartup failed.\n";

        return 1;
    }

    std::cout
        << "[OK] Winsock initialized.\n\n";

    // ========================================================
    // 3. Create socket
    // ========================================================

    std::cout
        << "[3] Creating TCP socket...\n";

    SOCKET clientSocket =
        socket(
            AF_INET,
            SOCK_STREAM,
            IPPROTO_TCP);

    if (clientSocket == INVALID_SOCKET)
    {
        std::cerr
            << "[ERROR] socket() failed.\n";

        WSACleanup();

        return 1;
    }

    std::cout
        << "[OK] Socket created.\n\n";

    // ========================================================
    // 4. Connect to server
    // ========================================================

    sockaddr_in serverAddress{};

    serverAddress.sin_family =
        AF_INET;

    serverAddress.sin_port =
        htons(SERVER_PORT);

    inet_pton(
        AF_INET,
        SERVER_IP,
        &serverAddress.sin_addr);

    std::cout
        << "[4] Connecting to "
        << SERVER_IP
        << ":"
        << SERVER_PORT
        << "...\n";

    result =
        connect(
            clientSocket,
            reinterpret_cast<sockaddr*>(
                &serverAddress),
            sizeof(serverAddress));

    if (result == SOCKET_ERROR)
    {
        std::cerr
            << "[ERROR] Could not connect to server.\n";

        closesocket(clientSocket);
        WSACleanup();

        return 1;
    }

    std::cout
        << "[OK] Connected to authentication server.\n\n";

    // ========================================================
    // 5. Receive challenge
    // ========================================================

    std::cout
        << "[5] Waiting for authentication challenge...\n";

    std::vector<BYTE> challenge(32);

    if (!ReceiveAll(
            clientSocket,
            challenge.data(),
            static_cast<int>(
                challenge.size())))
    {
        std::cerr
            << "[ERROR] Failed to receive challenge.\n";

        closesocket(clientSocket);
        WSACleanup();

        return 1;
    }

    std::cout
        << "[OK] Challenge received.\n\n";

    PrintHex(
        "Challenge",
        challenge);

    // ========================================================
    // 6. Hash challenge
    // ========================================================

    std::cout
        << "[6] Hashing challenge with SHA-256...\n";

    std::vector<BYTE> hash;

    if (!Sha256(
            challenge,
            hash))
    {
        std::cerr
            << "[ERROR] SHA-256 failed.\n";

        closesocket(clientSocket);
        WSACleanup();

        return 1;
    }

    std::cout
        << "[OK] SHA-256 hash created.\n\n";

    PrintHex(
        "Challenge SHA-256 hash",
        hash);

    // ========================================================
    // 7. Sign with persistent private key
    // ========================================================

    std::cout
        << "[7] Signing challenge with enrolled private key...\n";

    std::vector<BYTE> signature;

    if (!SignHash(
            privateKey,
            hash,
            signature))
    {
        std::cerr
            << "[ERROR] Signature generation failed.\n";

        closesocket(clientSocket);
        WSACleanup();

        return 1;
    }

    std::cout
        << "[OK] Signature generated.\n\n";

    PrintHex(
        "RSA signature",
        signature);

    // ========================================================
    // 8. Send signature
    // ========================================================

    std::cout
        << "[8] Sending signature to server...\n";

    if (!SendAll(
            clientSocket,
            signature.data(),
            static_cast<int>(
                signature.size())))
    {
        std::cerr
            << "[ERROR] Failed to send signature.\n";

        closesocket(clientSocket);
        WSACleanup();

        return 1;
    }

    std::cout
        << "[OK] Signature sent.\n\n";

    // ========================================================
    // 9. Result
    // ========================================================

    std::cout
        << "============================================\n"
        << "       STAGE 7 CLIENT RESULT\n"
        << "============================================\n\n";

    std::cout
        << "Private key loaded          [OK]\n"
        << "Network connection          [OK]\n"
        << "Challenge received          [OK]\n"
        << "SHA-256 hashing             [OK]\n"
        << "Private-key signing         [OK]\n"
        << "Signature sent              [OK]\n\n";

    std::cout
        << "Persistent authentication request completed.\n";

    closesocket(clientSocket);

    WSACleanup();

    std::cout
        << "\nPress ENTER to exit...";

    std::cin.get();

    return 0;
}