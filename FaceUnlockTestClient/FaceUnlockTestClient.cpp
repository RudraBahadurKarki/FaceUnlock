#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>

#include <iostream>
#include <iomanip>
#include <vector>

#pragma comment(lib, "ws2_32.lib")

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

static bool ReceiveAll(
    SOCKET socketHandle,
    BYTE* data,
    int length)
{
    int received = 0;

    while (received < length)
    {
        int result = recv(
            socketHandle,
            reinterpret_cast<char*>(data) + received,
            length - received,
            0);

        if (result == SOCKET_ERROR)
        {
            std::cerr
                << "[ERROR] recv() failed: "
                << WSAGetLastError()
                << "\n";

            return false;
        }

        if (result == 0)
        {
            std::cerr
                << "[ERROR] Server closed connection.\n";

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

static bool SendAll(
    SOCKET socketHandle,
    const BYTE* data,
    int length)
{
    int sent = 0;

    while (sent < length)
    {
        int result = send(
            socketHandle,
            reinterpret_cast<const char*>(data) + sent,
            length - sent,
            0);

        if (result == SOCKET_ERROR || result == 0)
        {
            std::cerr
                << "[ERROR] send() failed: "
                << WSAGetLastError()
                << "\n";

            return false;
        }

        sent += result;
    }

    return true;
}

int main()
{
    std::cout
        << "============================================\n"
        << "       FaceUnlock Test Client\n"
        << "                 Stage 4B\n"
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
    // 2. Create socket
    // ========================================================

    std::cout
        << "[2] Creating TCP socket...\n";

    SOCKET clientSocket = socket(
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
    // 3. Connect
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
            << "[ERROR] Invalid server IP.\n";

        closesocket(clientSocket);
        WSACleanup();

        return 1;
    }

    std::cout
        << "[3] Connecting to 192.168.1.69:5050...\n";

    result = connect(
        clientSocket,
        reinterpret_cast<sockaddr*>(&serverAddress),
        sizeof(serverAddress));

    if (result == SOCKET_ERROR)
    {
        std::cerr
            << "[ERROR] Connection failed.\n"
            << "WSA error: "
            << WSAGetLastError()
            << "\n";

        closesocket(clientSocket);
        WSACleanup();

        return 1;
    }

    std::cout
        << "[OK] Connected to FaceUnlock server.\n\n";

    // ========================================================
    // 4. Receive challenge
    // ========================================================

    std::cout
        << "[4] Waiting for authentication challenge...\n";

    std::vector<BYTE> challenge(32);

    if (!ReceiveAll(
            clientSocket,
            challenge.data(),
            static_cast<int>(challenge.size())))
    {
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
    // 5. Create TEST response
    // ========================================================

    std::cout
        << "[5] Creating test response...\n";

    std::vector<BYTE> response(32);

    /*
        TEMPORARY TEST ONLY.

        We simply transform each challenge byte.
        This is NOT cryptographic authentication.
    */

    for (size_t i = 0; i < challenge.size(); ++i)
    {
        response[i] =
            static_cast<BYTE>(
                challenge[i] ^ 0xAA);
    }

    PrintHex(
        "Test response",
        response);

    // ========================================================
    // 6. Send response
    // ========================================================

    std::cout
        << "[6] Sending test response...\n";

    if (!SendAll(
            clientSocket,
            response.data(),
            static_cast<int>(response.size())))
    {
        closesocket(clientSocket);
        WSACleanup();

        return 1;
    }

    std::cout
        << "[OK] Test response sent.\n\n";

    // ========================================================
    // 7. Finished
    // ========================================================

    std::cout
        << "============================================\n"
        << "       STAGE 4B CLIENT TEST\n"
        << "============================================\n\n";

    std::cout
        << "Server connection       [OK]\n"
        << "Challenge received      [OK]\n"
        << "Response generated      [OK]\n"
        << "Response sent           [OK]\n\n";

    std::cout
        << "PC <-> PC network test completed.\n\n";

    closesocket(clientSocket);
    WSACleanup();

    std::cout
        << "Press ENTER to exit...";

    std::cin.get();

    return 0;
}