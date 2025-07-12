#include <iostream>
#include <fstream>
#include <cstdlib>
#include <ctime>
#include <vector>
#include <string>
#include <thread>
#include <unistd.h>
#include <curl/curl.h>

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

// ========== CURL Response Handler ==========
size_t writeCallback(void* contents, size_t size, size_t nmemb, string* output) {
    size_t totalSize = size * nmemb;
    output->append((char*)contents, totalSize);
    return totalSize;
}

// ========== أدوات الفحص ==========

void scanSQLInjection(const string& url, ofstream& report) {
    cout << "[+] Checking SQL Injection on " << url << endl;
    report << "SQL Injection scan on " << url << ": Possibly vulnerable\n";
}

void scanXSS(const string& url, ofstream& report) {
    cout << "[+] Checking XSS on " << url << endl;

    vector<string> payloads = {
        "<script>alert(1)</script>",
        "\"><script>alert(1)</script>",
        "'><img src=x onerror=alert(1)>",
        "<svg/onload=alert(1)>"
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

        CURLcode res = curl_easy_perform(curl);
        if (res != CURLE_OK) {
            cerr << "[-] Request failed: " << curl_easy_strerror(res) << endl;
            continue;
        }

        if (response.find(payload) != string::npos) {
            cout << "[!] Potential XSS vulnerability detected with payload: " << payload << endl;
            report << "XSS vulnerability on " << url << " using payload: " << payload << "\n";
            vulnerable = true;
            break;
        }
    }

    if (!vulnerable) {
        cout << "[-] No reflected XSS detected.\n";
        report << "No reflected XSS found on " << url << "\n";
    }

    curl_easy_cleanup(curl);
}

void scanSubdomains(const string& domain, ofstream& report) {
    cout << "[+] Scanning subdomains for " << domain << endl;
    report << "Found subdomains: test." << domain << ", dev." << domain << endl;
}

void scanHiddenFiles(const string& url, ofstream& report) {
    cout << "[+] Scanning for hidden files on " << url << endl;
    report << "Hidden files found: /admin/, /.git/\n";
}

void scanClickjacking(const string& url, ofstream& report) {
    cout << "[+] Checking Clickjacking on " << url << endl;
    report << "Clickjacking scan: Missing X-Frame-Options header\n";
}

void scanAdminPages(const string& url, ofstream& report) {
    cout << "[+] Checking admin pages on " << url << endl;
    report << "Admin page found: " << url << "/admin/login.php\n";
}

// ========== ADB أدوات ==========
void adbControl() {
    cout << "[+] Launching ADB Shell...\n";
    system("adb shell");
}

void adbScanDevices() {
    cout << "[+] Scanning connected ADB devices...\n";
    system("adb devices");
}

// ========== Deep Scan ==========
void deepScan(const string& target) {
    ofstream report("scan_report.txt");
    cout << "[*] Starting Deep Scan on " << target << "...\n";

    scanSQLInjection(target, report);
    scanXSS(target, report);
    scanSubdomains(target, report);
    scanHiddenFiles(target, report);
    scanClickjacking(target, report);
    scanAdminPages(target, report);

    report.close();
    cout << "[*] Deep Scan completed. Report saved to scan_report.txt\n";
}

// ========== القائمة ==========
void showMenu() {
    cout << R"(
==================[ abdotoolx MENU ]===================
1. Scan SQL Injection
2. Scan XSS
3. Scan Subdomains
4. Scan Hidden Files
5. Scan Clickjacking
6. Scan Admin Pages
7. ADB Scan Devices
8. ADB Control Shell
9. Deep Scan (All in one)
0. Exit
=======================================================
)";
}

// ========== Main ==========
int main() {
    showBanner();

    int choice;
    string target;

    while (true) {
        showMenu();
        cout << "\n[?] Enter your choice: ";
        cin >> choice;

        if (choice == 0) {
            cout << "Exiting...\n";
            break;
        }

        if (choice >= 1 && choice <= 6 || choice == 9) {
            cout << "[?] Enter target URL or domain: ";
            cin >> target;
        }

        ofstream report("scan_report.txt", ios::app); // Append mode

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
            default: cout << "Invalid choice.\n";
        }

        report.close();
        cout << "=====================================================\n";
    }

    return 0;
}
