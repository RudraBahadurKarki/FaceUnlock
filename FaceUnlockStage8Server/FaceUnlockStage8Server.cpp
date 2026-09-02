#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <bcrypt.h>

#include <iostream>
#include <fstream>
#include <vector>
#include <iomanip>
#include <string>

#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "bcrypt.lib")

// ============================================================
// Configuration
// ============================================================

static const char* SERVER_IP = "192.168.1.69";
static const int SERVER_PORT = 5050;

static const char* PUBLIC_KEY_FILE =
    "C:\\Users\\user\\Desktop\\FaceUnlock\\FaceUnlockEnrollment\\FaceUnlockDevice.public";

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

static bool GenerateChallenge(
    std::vector<BYTE>& challenge)
{
    challenge.resize(32);

    NTSTATUS status =
        BCryptGenRandom(
            nullptr,
            challenge.data(),
            static_cast<ULONG>(
                challenge.size()),
            BCRYPT_USE_SYSTEM_PREFERRED_RNG);

    return BCRYPT_SUCCESS(status);
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
                reinterpret_cast<const char*>(
                    data) + sent,
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
                reinterpret_cast<char*>(
                    data) + received,
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
// SHA-256
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
            reinterpret_cast<PUCHAR>(
                &objectSize),
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
// Verify RSA signature
// ============================================================

static bool VerifySignature(
    const std::vector<BYTE>& publicKeyBlob,
    const std::vector<BYTE>& hash,
    const std::vector<BYTE>& signature)
{
    BCRYPT_ALG_HANDLE algorithm = nullptr;
    BCRYPT_KEY_HANDLE publicKey = nullptr;

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
            BCRYPT_RSAPUBLIC_BLOB,
            &publicKey,
            const_cast<PUCHAR>(
                publicKeyBlob.data()),
            static_cast<ULONG>(
                publicKeyBlob.size()),
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

    status =
        BCryptVerifySignature(
            publicKey,
            &paddingInfo,
            const_cast<PUCHAR>(
                hash.data()),
            static_cast<ULONG>(
                hash.size()),
            const_cast<PUCHAR>(
                signature.data()),
            static_cast<ULONG>(
                signature.size()),
            BCRYPT_PAD_PKCS1);

    BCryptDestroyKey(publicKey);

    BCryptCloseAlgorithmProvider(
        algorithm,
        0);

    return BCRYPT_SUCCESS(status);
}

// ============================================================
// Main
// ============================================================

int main()
{
    std::cout
        << "============================================\n"
        << "       FaceUnlock Stage 8 Server\n"
        << "============================================\n\n";

    // ========================================================
    // 1. Load enrolled public key
    // ========================================================

    std::cout
        << "[1] Loading enrolled public key...\n";

    std::vector<BYTE> publicKey;

    if (!LoadBinaryFile(
            PUBLIC_KEY_FILE,
            publicKey))
    {
        std::cerr
            << "[ERROR] Could not load enrolled public key.\n";

        return 1;
    }

    std::cout
        << "[OK] Enrolled public key loaded.\n";

    std::cout
        << "Public key size: "
        << publicKey.size()
        << " bytes.\n\n";

    // ========================================================
    // 2. Initialize Winsock
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
            << "[ERROR] WSAStartup failed: "
            << result
            << "\n";

        return 1;
    }

    std::cout
        << "[OK] Winsock initialized.\n\n";

    // ========================================================
    // 3. Create socket
    // ========================================================

    std::cout
        << "[3] Creating TCP socket...\n";

    SOCKET serverSocket =
        socket(
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
    // 4. Bind
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
        << "[4] Binding to "
        << SERVER_IP
        << ":"
        << SERVER_PORT
        << "...\n";

    result =
        bind(
            serverSocket,
            reinterpret_cast<sockaddr*>(
                &serverAddress),
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
    // 5. Listen
    // ========================================================

    std::cout
        << "[5] Starting listener...\n";

    result =
        listen(
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
        << " Stage 8 authentication server ready\n"
        << " Address: "
        << SERVER_IP
        << "\n"
        << " Port:    "
        << SERVER_PORT
        << "\n"
        << "============================================\n\n";

    std::cout
        << "Waiting for Stage 8 client...\n\n";

    // ========================================================
    // 6. Accept client
    // ========================================================

    SOCKET clientSocket =
        accept(
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
    // 7. Generate fresh challenge
    // ========================================================

    std::cout
        << "[6] Generating fresh authentication challenge...\n";

    std::vector<BYTE> challenge;

    if (!GenerateChallenge(challenge))
    {
        std::cerr
            << "[ERROR] Challenge generation failed.\n";

        closesocket(clientSocket);
        closesocket(serverSocket);
        WSACleanup();

        return 1;
    }

    std::cout
        << "[OK] Fresh challenge generated.\n\n";

    PrintHex(
        "Challenge",
        challenge);

    // ========================================================
    // 8. Send protocol header
    // ========================================================

    const char protocol[] =
        "FACEUNLOCK-AUTH-V1";

    const int protocolLength =
        sizeof(protocol) - 1;

    std::cout
        << "[7] Sending authentication protocol header...\n";

    if (!SendAll(
            clientSocket,
            reinterpret_cast<const BYTE*>(
                protocol),
            protocolLength))
    {
        std::cerr
            << "[ERROR] Failed to send protocol header.\n";

        closesocket(clientSocket);
        closesocket(serverSocket);
        WSACleanup();

        return 1;
    }

    std::cout
        << "[OK] Protocol header sent.\n\n";

    // ========================================================
    // 9. Send challenge
    // ========================================================

    std::cout
        << "[8] Sending authentication challenge...\n";

    if (!SendAll(
            clientSocket,
            challenge.data(),
            static_cast<int>(
                challenge.size())))
    {
        std::cerr
            << "[ERROR] Failed to send challenge.\n";

        closesocket(clientSocket);
        closesocket(serverSocket);
        WSACleanup();

        return 1;
    }

    std::cout
        << "[OK] Challenge sent.\n\n";

    // ========================================================
    // 10. Receive signature
    //
    // RSA-2048 PKCS#1 signature = 256 bytes
    // ========================================================

    std::cout
        << "[9] Waiting for authentication signature...\n";

    std::vector<BYTE> signature(256);

    if (!ReceiveAll(
            clientSocket,
            signature.data(),
            static_cast<int>(
                signature.size())))
    {
        std::cerr
            << "[ERROR] Failed to receive signature.\n";

        closesocket(clientSocket);
        closesocket(serverSocket);
        WSACleanup();

        return 1;
    }

    std::cout
        << "[OK] Signature received.\n\n";

    PrintHex(
        "Received signature",
        signature);

    // ========================================================
    // 11. Hash challenge
    // ========================================================

    std::cout
        << "[10] Hashing challenge with SHA-256...\n";

    std::vector<BYTE> hash;

    if (!Sha256(
            challenge,
            hash))
    {
        std::cerr
            << "[ERROR] SHA-256 failed.\n";

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

    bool verified =
        VerifySignature(
            publicKey,
            hash,
            signature);

    if (!verified)
    {
        std::cout
            << "[ERROR] SIGNATURE VERIFICATION FAILED.\n\n";

        std::cout
            << "Authentication denied.\n";

        closesocket(clientSocket);
        closesocket(serverSocket);
        WSACleanup();

        return 1;
    }

    std::cout
        << "[OK] SIGNATURE VERIFIED.\n\n";

    // ========================================================
    // Result
    // ========================================================

    std::cout
        << "============================================\n"
        << "       STAGE 8 SERVER RESULT\n"
        << "============================================\n\n";

    std::cout
        << "Enrolled public key loaded  [OK]\n"
        << "Network connection          [OK]\n"
        << "Fresh challenge             [OK]\n"
        << "Protocol header sent        [OK]\n"
        << "Challenge sent              [OK]\n"
        << "Signature received          [OK]\n"
        << "SHA-256 hashing             [OK]\n"
        << "RSA verification            [OK]\n\n";

    std::cout
        << "AUTHENTICATION SUCCESSFUL.\n\n";

    std::cout
        << "Stage 8 protocol test passed.\n";

    closesocket(clientSocket);
    closesocket(serverSocket);

    WSACleanup();

    std::cout
        << "\nPress ENTER to exit...";

    std::cin.get();

    return 0;
}