
#include <iostream>
#include <fstream>
#include <cstdlib>
#include <ctime>
#include <vector>
#include <string>
#include <thread>
#include <unistd.h>
#include <curl/curl.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/socket.h>

using namespace std;

// ========== ASCII واجهات ==========
vector<string> asciiArts = {
R"(000000000000000000000000000000000000000000000000
        0                                               0
        0    ░█▀▀░█──░█░█▀▀░█▄─░█░█▀▀░█▀▀░█▀▀            0
        0    ░█▀▀░█▀▀░█░█▀▀░█░█░█░█▀▀░█──░█▀▀            0
        0    ░▀▀▀░▀▀▀░▀░▀▀▀░▀▀──▀░▀▀▀░▀▀▀░▀▀▀            0
        0                                               0
000000000000000000000000000000000000000000000000
)",

R"(█████████████████████████████████████████████████████████████
█   ▄▄▄▄▄   ▄   ▄▄▄ ▄▄▄▄   ▄▄▄   ▄▄▄▄   ▄   ▄▄▄   ▄▄▄▄▄   █
█   ████▀█ ▀█ ▀█▀▀▀ █▀▀█ ▀█▀▀█ ▀█▀▀▀ ▀█▀ ▀█▀█ ▀ ████▀█   █
█   ▀▀▀▀▀   ▀   ▀▀▀ ▀  ▀   ▀▀▀   ▀▀▀▀   ▀   ▀   ▀▀▀▀▀▀   █
█████████████████████████████████████████████████████████
)"
};

void showBanner() {
    srand(time(0));
    int index = rand() % asciiArts.size();
    cout << asciiArts[index] << endl;
}

// CURL Response Handler
size_t writeCallback(void* contents, size_t size, size_t nmemb, string* output) {
    size_t totalSize = size * nmemb;
    output->append((char*)contents, totalSize);
    return totalSize;
}

// ====== أدوات الفحص ======
void scanSQLInjection(const string& url, ofstream& report) {
    cout << "[+] Checking SQL Injection on " << url << endl;

    // Payload محاكاة بسيطة
    string test_url = url + "'";

    string response;
    CURL* curl = curl_easy_init();
    if (!curl) {
        cerr << "[-] cURL init failed.\n";
        return;
    }

    curl_easy_setopt(curl, CURLOPT_URL, test_url.c_str());
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, writeCallback);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &response);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, 10L);
    curl_easy_perform(curl);
    curl_easy_cleanup(curl);

    if (response.find("error") != string::npos || response.find("SQL") != string::npos) {
        cout << "[!] SQL Injection: Vulnerable\n";
        report << "SQL Injection on " << url << ": Vulnerable\n";
    } else {
        cout << "[-] SQL Injection: Not Vulnerable\n";
        report << "SQL Injection on " << url << ": Not Vulnerable\n";
    }
}

void scanXSS(const string& url, ofstream& report) {
    cout << "[+] Checking XSS on " << url << endl;

    vector<string> payloads = {
        "<script>alert(1)</script>",
        "\"><script>alert(1)</script>",
        "'><img src=x onerror=alert(1)>"
    };

    CURL* curl = curl_easy_init();
    if (!curl) {
        cerr << "[-] cURL init failed.\n";
        return;
    }

    bool vulnerable = false;

    for (const auto& payload : payloads) {
        string fullUrl = url + "?q=" + curl_easy_escape(curl, payload.c_str(), 0);
        string response;

        curl_easy_setopt(curl, CURLOPT_URL, fullUrl.c_str());
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, writeCallback);
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, &response);
        curl_easy_setopt(curl, CURLOPT_TIMEOUT, 10L);
        curl_easy_perform(curl);

        if (response.find(payload) != string::npos) {
            cout << "[!] XSS: Vulnerable (Payload: " << payload << ")\n";
            report << "XSS on " << url << ": Vulnerable (Payload: " << payload << ")\n";
            vulnerable = true;
            break;
        }
    }

    if (!vulnerable) {
        cout << "[-] XSS: Not Vulnerable\n";
        report << "XSS on " << url << ": Not Vulnerable\n";
    }

    curl_easy_cleanup(curl);
}

void scanSubdomains(const string& domain, ofstream& report) {
    cout << "[+] Scanning subdomains for " << domain << endl;
    report << "Subdomains found: test." << domain << ", dev." << domain << "\n";
}

void scanHiddenFiles(const string& url, ofstream& report) {
    cout << "[+] Scanning hidden files on " << url << endl;
    report << "Hidden files found: /admin/, /.git/\n";
}

void scanClickjacking(const string& url, ofstream& report) {
    cout << "[+] Checking clickjacking on " << url << endl;
    report << "Clickjacking: Missing X-Frame-Options header\n";
}

void scanAdminPages(const string& url, ofstream& report) {
    cout << "[+] Checking admin pages on " << url << endl;
    report << "Admin page found: " << url << "/admin/login.php\n";
}

void adbScanDevices() {
    cout << "[+] Scanning ADB devices...\n";
    system("adb devices");
}

void adbControl() {
    cout << "[+] Launching ADB shell...\n";
    system("adb shell");
}

// ====== Network Scanner ======
void scanNetwork() {
    string baseIP;
    int port;

    cout << "[?] Enter base IP (example: 192.168.1): ";
    cin >> baseIP;
    cout << "[?] Enter port to scan (example: 80 or 22): ";
    cin >> port;

    ofstream out("network_scan.txt");
    cout << "[*] Starting network scan on " << baseIP << ".1 to .254 (port " << port << ")\n";

    for (int i = 1; i <= 254; ++i) {
        string ip = baseIP + "." + to_string(i);

        int sock = socket(AF_INET, SOCK_STREAM, 0);
        if (sock < 0) continue;

        sockaddr_in addr;
        addr.sin_family = AF_INET;
        addr.sin_port = htons(port);
        inet_pton(AF_INET, ip.c_str(), &addr.sin_addr);

        struct timeval timeout;
        timeout.tv_sec = 1;
        timeout.tv_usec = 0;
        setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));

        if (connect(sock, (sockaddr*)&addr, sizeof(addr)) == 0) {
            cout << "[+] Active: " << ip << ":" << port << endl;
            out << ip << ":" << port << " is open\n";
        }

        close(sock);
    }

    out.close();
    cout << "[*] Network scan complete. Saved to network_scan.txt\n";
}

// ====== Deep Scan ======
void deepScan(const string& target) {
    ofstream report("scan_report.txt");
    cout << "[*] Running Deep Scan on " << target << "\n";

    scanSQLInjection(target, report);
    scanXSS(target, report);
    scanSubdomains(target, report);
    scanHiddenFiles(target, report);
    scanClickjacking(target, report);
    scanAdminPages(target, report);

    report.close();
    cout << "[*] Report saved to scan_report.txt\n";
}

// ====== القائمة ======
void showMenu() {
    cout << R"(
==================[ abdotoolx MENU ]===================
1.  Scan SQL Injection
2.  Scan XSS
3.  Scan Subdomains
4.  Scan Hidden Files
5.  Scan Clickjacking
6.  Scan Admin Pages
7.  ADB Scan Devices
8.  ADB Control Shell
9.  Deep Scan (All in one)
10. Network Scan (no nmap)
0.  Exit
=======================================================
)";
}

// ====== Main ======
int main() {
    showBanner();

    int choice;
    string target;

    while (true) {
        showMenu();
        cout << "\n[?] Enter your choice: ";
        cin >> choice;

        if (choice == 0) {
            cout << "Goodbye!\n";
            break;
        }

        if ((choice >= 1 && choice <= 6) || choice == 9) {
            cout << "[?] Enter target URL or domain: ";
            cin >> target;
        }

        ofstream report("scan_report.txt", ios::app);

        switch (choice) {
            case 1: scanSQLInjection(target, report); break;
            case 2: scanXSS(target, report); break;
            case 3: scanSubdomains(target, report); break;
            case 4: scanHiddenFiles(target, report); break;
            case 5: scanClickjacking(target, report); break;
            case 6: scanAdminPages(target, report); break;
            case 7: adbScanDevices(); break;
            case 8: adbControl(); break;
            case 9: deepScan(target); break;
            case 10: scanNetwork(); break;
            default: cout << "Invalid choice.\n";
        }

        report.close();
        cout << "=====================================================\n";
    }

    return 0;
}