#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <bcrypt.h>

#include <iostream>
#include <iomanip>
#include <vector>
#include <string>

#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "bcrypt.lib")

static void PrintHex(
    const char *name,
    const std::vector<BYTE> &data)
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

static bool GenerateChallenge(
    std::vector<BYTE> &challenge)
{
    challenge.resize(32);

    NTSTATUS status = BCryptGenRandom(
        nullptr,
        challenge.data(),
        static_cast<ULONG>(challenge.size()),
        BCRYPT_USE_SYSTEM_PREFERRED_RNG);

    return BCRYPT_SUCCESS(status);
}

static bool SendAll(
    SOCKET socketHandle,
    const BYTE *data,
    int length)
{
    int sent = 0;

    while (sent < length)
    {
        int result = send(
            socketHandle,
            reinterpret_cast<const char *>(data) + sent,
            length - sent,
            0);

        if (result == SOCKET_ERROR || result == 0)
            return false;

        sent += result;
    }

    return true;
}

static bool ReceiveAll(
    SOCKET socketHandle,
    BYTE *data,
    int length)
{
    int received = 0;

    while (received < length)
    {
        int result = recv(
            socketHandle,
            reinterpret_cast<char *>(data) + received,
            length - received,
            0);

        if (result == SOCKET_ERROR)
        {
            std::cerr
                << "[ERROR] recv() failed. WSA error: "
                << WSAGetLastError()
                << "\n";

            return false;
        }

        if (result == 0)
        {
            std::cerr
                << "[ERROR] Client closed the connection.\n";

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

int main()
{
    std::cout
        << "============================================\n"
        << "       FaceUnlock Network Server\n"
        << "                 Stage 4B\n"
        << "============================================\n\n";

    // ========================================================
    // 1. Initialize Winsock
    // ========================================================

    std::cout
        << "[1] Initializing Windows networking...\n";

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
            << "[ERROR] socket() failed. WSA error: "
            << WSAGetLastError()
            << "\n";

        WSACleanup();
        return 1;
    }

    std::cout
        << "[OK] TCP socket created.\n\n";

    // ========================================================
    // 3. Bind
    // ========================================================

    sockaddr_in serverAddress{};

    serverAddress.sin_family = AF_INET;
    serverAddress.sin_port = htons(5050);

    if (inet_pton(
            AF_INET,
            "192.168.1.69",
            &serverAddress.sin_addr) != 1)
    {
        std::cerr
            << "[ERROR] Invalid server IP address.\n";

        closesocket(serverSocket);
        WSACleanup();
        return 1;
    }

    std::cout
        << "[3] Binding to 192.168.1.69:5050...\n";

    result = bind(
        serverSocket,
        reinterpret_cast<sockaddr *>(&serverAddress),
        sizeof(serverAddress));

    if (result == SOCKET_ERROR)
    {
        std::cerr
            << "[ERROR] bind() failed. WSA error: "
            << WSAGetLastError()
            << "\n";

        closesocket(serverSocket);
        WSACleanup();

        return 1;
    }

    std::cout
        << "[OK] Server bound successfully.\n\n";

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
            << "[ERROR] listen() failed. WSA error: "
            << WSAGetLastError()
            << "\n";

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
        << "Waiting for an iPhone/client connection...\n\n";

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
            << "[ERROR] accept() failed. WSA error: "
            << WSAGetLastError()
            << "\n";

        closesocket(serverSocket);
        WSACleanup();

        return 1;
    }

    std::cout
        << "[OK] Client connected.\n\n";

    // ========================================================
    // 6. Generate challenge
    // ========================================================

    std::cout
        << "[5] Generating authentication challenge...\n";

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
        << "[OK] Challenge generated.\n\n";

    PrintHex(
        "Challenge",
        challenge);

    // ========================================================
    // 7. Send challenge
    // ========================================================

    std::cout
        << "[6] Sending challenge to client...\n";

    if (!SendAll(
            clientSocket,
            challenge.data(),
            static_cast<int>(challenge.size())))
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
    // 8. Receive client response
    // ========================================================

    std::cout
        << "[7] Waiting for client response...\n"
        << "[INFO] Expected response size: 32 bytes.\n\n";

    std::vector<BYTE> response(32);

    if (!ReceiveAll(
            clientSocket,
            response.data(),
            static_cast<int>(response.size())))
    {
        std::cerr
            << "\n[ERROR] Client response was not received.\n"
            << "[INFO] This normally means the client connected "
               "but did not send the expected response.\n\n";

        closesocket(clientSocket);
        closesocket(serverSocket);
        WSACleanup();

        return 1;
    }

    std::cout
        << "\n[OK] Response received.\n\n";

    PrintHex(
        "Client response",
        response);

    // ========================================================
    // 9. Temporary test verification
    // ========================================================

    std::cout
        << "[8] Network-layer verification...\n";

    /*
        IMPORTANT:

        We are NOT treating this response as a real
        Face ID authentication yet.

        This stage only proves that the client can
        send 32 bytes back to Windows.
    */

    bool responseIsNonZero = false;

    for (BYTE b : response)
    {
        if (b != 0)
        {
            responseIsNonZero = true;
            break;
        }
    }

    if (responseIsNonZero)
    {
        std::cout
            << "[OK] Client returned non-zero test data.\n";
    }
    else
    {
        std::cout
            << "[WARNING] Client returned 32 zero bytes.\n";
    }

    // ========================================================
    // 10. Close connection
    // ========================================================

    closesocket(clientSocket);
    closesocket(serverSocket);
    WSACleanup();

    std::cout
        << "\n============================================\n"
        << "       STAGE 4B NETWORK TEST\n"
        << "============================================\n\n";

    std::cout
        << "TCP server                    [OK]\n"
        << "Client connection             [OK]\n"
        << "Challenge generation          [OK]\n"
        << "Challenge transmission        [OK]\n"
        << "Client response received      [OK]\n\n";

    std::cout
        << "PC <-> client communication works.\n";

    std::cout
        << "\nPress ENTER to exit...";

    std::cin.get();

    return 0;
}