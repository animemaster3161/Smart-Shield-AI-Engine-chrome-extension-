#include <iostream>
#include <string>
#include <map>
#include <set>
#include <ctime>
#include <fstream>
#include <sstream>
#include <algorithm>
#include <vector>
#include <deque>
#include <winsock2.h>
#include <windows.h>
#include <process.h>

#pragma comment(lib,"ws2_32.lib")

using namespace std;

// ============================================================
//  CONFIGURATION
// ============================================================
const double THREAT_THRESHOLD  = 9.0;
const int    TIME_WINDOW       = 8;    // seconds — gap within this = rapid access
const int    RAPID_BLOCK_COUNT = 3;    // block after 3 rapid hits in a row
const int    MAX_LOG_ENTRIES   = 200;
const string BLACKLIST_FILE    = "blacklist.txt";
const string LOG_FILE          = "logs.txt";

// ============================================================
//  WHITELIST
// ============================================================
const set<string> WHITELIST = {
    "www.google.com","google.com","accounts.google.com",
    "mail.google.com","drive.google.com","gemini.google.com",
    "www.youtube.com","youtube.com",
    "www.facebook.com","facebook.com",
    "web.whatsapp.com","whatsapp.com",
    "www.instagram.com","instagram.com",
    "www.twitter.com","twitter.com","x.com",
    "www.linkedin.com","linkedin.com",
    "www.amazon.in","www.amazon.com","amazon.com","amazon.in",
    "www.flipkart.com","flipkart.com",
    "www.olx.in","olx.in",
    "github.com","www.github.com",
    "stackoverflow.com","www.stackoverflow.com",
    "claude.ai","www.claude.ai",
    "chat.openai.com","openai.com",
    "www.microsoft.com","microsoft.com",
    "login.microsoftonline.com",
    "outlook.live.com","outlook.office.com",
    "www.apple.com","apple.com","appleid.apple.com",
    "www.paypal.com","paypal.com",
    "www.netflix.com","netflix.com",
    "www.wikipedia.org","wikipedia.org",
    "iconscout.com","icons8.com",
    "www.search.ask.com"
};

// ============================================================
//  SUSPICIOUS TLDs
// ============================================================
const set<string> SUSPICIOUS_TLDS = {
    ".xyz",".tk",".ml",".ga",".cf",".gq",
    ".top",".work",".click",".link",".live",
    ".online",".site",".website",".tech",
    ".buzz",".icu",".monster",".rest",".fun",
    ".cam",".cfd",".cyou"
};

// ============================================================
//  BRAND KEYWORDS
// ============================================================
const vector<string> BRAND_KEYWORDS = {
    "paypal","amazon","google","facebook","microsoft",
    "apple","netflix","instagram","whatsapp","twitter",
    "linkedin","youtube","gmail","outlook","onedrive",
    "icloud","dropbox","ebay","walmart","hdfc","icici",
    "sbi","paytm","phonepe","gpay","razorpay"
};

// ============================================================
//  PHISHING PATTERNS
// ============================================================
const vector<string> PHISHING_PATTERNS = {
    "login-verify","secure-login","account-verify",
    "bank-update","apple-id-","microsoft-verify",
    "free-gift","prize-claim","wallet-unlock","verify-now",
    "update-info","support-help","claim-reward",
    "-login.","-signin.","-secure.","-verify.",
    "confirm-","unlock-","restore-account",
    "security-alert","suspicious-activity","your-account"
};

// ============================================================
//  STATS & LOG ENTRY STRUCTURES
// ============================================================
struct SiteStats {
    int    hits      = 0;
    int    rapidHits = 0;  // consecutive rapid hits
    time_t lastSeen  = 0;
};

struct LogEntry {
    string timestamp;
    string domain;
    string status;   // SAFE / BLOCKED / WHITELISTED / HTTP_WARNING
    double score;
    string reason;
};

// ============================================================
//  GLOBAL STATE
// ============================================================
map<string, SiteStats> trafficData;
set<string>            blacklist;
deque<LogEntry>        recentLogs;       // for dashboard
long long              totalChecked  = 0;
long long              totalBlocked  = 0;
long long              totalSafe     = 0;
long long              httpWarnings  = 0;
CRITICAL_SECTION       mtx_cs;

// ============================================================
//  PERSISTENCE
// ============================================================
void loadBlacklist() {
    ifstream f(BLACKLIST_FILE);
    string line;
    while (getline(f, line))
        if (!line.empty()) blacklist.insert(line);
    cout << "[SmartShield] Loaded " << blacklist.size() << " blacklisted domains.\n";
}

void saveToBlacklist(const string& domain) {
    ofstream f(BLACKLIST_FILE, ios::app);
    f << domain << "\n";
}

// ============================================================
//  LOGGING
// ============================================================
string getTimestamp() {
    time_t now = time(0);
    char* dt = ctime(&now);
    string ts(dt);
    if (!ts.empty() && ts.back() == '\n') ts.pop_back();
    return ts;
}

void addLog(const string& domain, const string& status, double score, const string& reason = "") {
    // Write to file
    ofstream file(LOG_FILE, ios::app);
    string ts = getTimestamp();
    file << "[" << ts << "] " << domain
         << " | " << status << " | Score: " << score;
    if (!reason.empty()) file << " | " << reason;
    file << "\n";

    // Keep in memory for dashboard
    LogEntry e;
    e.timestamp = ts;
    e.domain    = domain;
    e.status    = status;
    e.score     = score;
    e.reason    = reason;

    recentLogs.push_front(e);
    if ((int)recentLogs.size() > MAX_LOG_ENTRIES)
        recentLogs.pop_back();
}

// ============================================================
//  URL UTILITIES
// ============================================================
string urlDecode(const string& src) {
    string result;
    for (size_t i = 0; i < src.size(); ++i) {
        if (src[i] == '%' && i + 2 < src.size()) {
            int val = 0;
            sscanf(src.substr(i + 1, 2).c_str(), "%x", &val);
            result += (char)val;
            i += 2;
        } else if (src[i] == '+') {
            result += ' ';
        } else {
            result += src[i];
        }
    }
    return result;
}

string extractDomain(string url) {
    url = urlDecode(url);
    transform(url.begin(), url.end(), url.begin(), ::tolower);
    size_t proto = url.find("://");
    if (proto != string::npos) url = url.substr(proto + 3);
    for (char c : { '/', '?', '#' }) {
        size_t p = url.find(c);
        if (p != string::npos) url = url.substr(0, p);
    }
    size_t colon = url.find(":");
    if (colon != string::npos) url = url.substr(0, colon);
    if (!url.empty() && url.back() == '.') url.pop_back();
    return url;
}

string getTLD(const string& domain) {
    size_t dot = domain.rfind(".");
    if (dot == string::npos) return "";
    return domain.substr(dot);
}

bool isIPAddress(const string& domain) {
    int dots = 0;
    for (char c : domain) {
        if (c == '.') dots++;
        else if (!isdigit(c)) return false;
    }
    return dots == 3;
}

bool isHTTP(const string& rawUrl) {
    string lower = rawUrl;
    transform(lower.begin(), lower.end(), lower.begin(), ::tolower);
    // Starts with http:// but NOT https://
    return (lower.substr(0, 7) == "http://" &&
            lower.substr(0, 8) != "https://");
}

// ============================================================
//  HEURISTIC SCORING ENGINE
// ============================================================
pair<double, string> heuristicScore(const string& domain, const string& fullUrl) {
    double score = 0.0;
    vector<string> reasons;

    if (isIPAddress(domain)) {
        score += 9.0; reasons.push_back("IP_HOST");
    }
    string tld = getTLD(domain);
    if (SUSPICIOUS_TLDS.count(tld)) {
        score += 4.0; reasons.push_back("SUSPICIOUS_TLD:" + tld);
    }
    for (const auto& pat : PHISHING_PATTERNS) {
        if (domain.find(pat) != string::npos) {
            score += 5.0; reasons.push_back("PHISHING_PATTERN"); break;
        }
    }
    for (const auto& brand : BRAND_KEYWORDS) {
        if (domain.find(brand) != string::npos) {
            bool isReal = (domain == brand + ".com" ||
                           domain == "www." + brand + ".com" ||
                           domain == brand + ".in"  ||
                           domain == "www." + brand + ".in");
            if (!isReal) {
                score += 5.0; reasons.push_back("BRAND_IMPERSONATION:" + brand); break;
            }
        }
    }
    if ((int)domain.length() > 40) {
        score += 2.5; reasons.push_back("LONG_DOMAIN");
    }
    int hyphens = (int)count(domain.begin(), domain.end(), '-');
    if (hyphens >= 3) {
        score += (hyphens - 2) * 1.5; reasons.push_back("HYPHENS:" + to_string(hyphens));
    }
    int dots = (int)count(domain.begin(), domain.end(), '.');
    if (dots >= 3) {
        score += (dots - 2) * 2.0; reasons.push_back("DEEP_SUBDOMAIN");
    }
    int digits = 0;
    for (char c : domain) if (isdigit(c)) digits++;
    if (digits >= 3) {
        score += 2.0; reasons.push_back("NUMERIC_OBFUSCATION");
    }
    string lurl = fullUrl;
    transform(lurl.begin(), lurl.end(), lurl.begin(), ::tolower);
    for (const auto& pat : PHISHING_PATTERNS) {
        if (lurl.find(pat) != string::npos) {
            score += 3.0; reasons.push_back("PATH_PATTERN"); break;
        }
    }

    // HTTP (no TLS) — add to score
    if (isHTTP(fullUrl)) {
        score += 4.0; reasons.push_back("HTTP_NO_TLS");
    }

    string reasonStr;
    for (size_t i = 0; i < reasons.size(); i++) {
        if (i > 0) reasonStr += ", ";
        reasonStr += reasons[i];
    }
    return { score, reasonStr };
}

// ============================================================
//  ESCAPE JSON STRING
// ============================================================
string jsonEscape(const string& s) {
    string out;
    for (char c : s) {
        if (c == '"')       out += "\\\"";
        else if (c == '\\') out += "\\\\";
        else if (c == '\n') out += "\\n";
        else if (c == '\r') out += "\\r";
        else                out += c;
    }
    return out;
}

// ============================================================
//  MAIN CHECK FUNCTION
// ============================================================
string checkURL(const string& rawUrl) {
    string domain = extractDomain(rawUrl);

    if (domain.empty() ||
        rawUrl.substr(0, 9)  == "chrome://" ||
        rawUrl.substr(0, 19) == "chrome-extension://" ||
        rawUrl.substr(0, 7)  == "file://"  ||
        rawUrl.substr(0, 6)  == "about:")
    {
        return "{\"status\":\"SAFE\",\"domain\":\"\",\"score\":0}";
    }

    totalChecked++;

    // Whitelist check — but still warn if HTTP
    if (WHITELIST.count(domain)) {
        if (isHTTP(rawUrl)) {
            httpWarnings++;
            addLog(domain, "HTTP_WARNING", 4.0, "HTTP_NO_TLS (whitelisted domain)");
            return "{\"status\":\"HTTP_WARNING\",\"domain\":\"" + domain + "\",\"score\":4,\"reason\":\"HTTP_NO_TLS\"}";
        }
        totalSafe++;
        addLog(domain, "WHITELISTED", 0.0);
        return "{\"status\":\"SAFE\",\"domain\":\"" + domain + "\",\"score\":0}";
    }

    EnterCriticalSection(&mtx_cs);

    if (blacklist.count(domain)) {
        totalBlocked++;
        LeaveCriticalSection(&mtx_cs);
        addLog(domain, "BLACKLISTED", 99.0);
        return "{\"status\":\"BLOCKED\",\"domain\":\"" + domain + "\",\"score\":99}";
    }

    // Heuristic
    pair<double,string> hresult = heuristicScore(domain, rawUrl);
    double hscore = hresult.first;
    string reason = hresult.second;

    // Frequency + Rapid-hit scoring
    time_t now = time(0);
    SiteStats& stats = trafficData[domain];
    double gap = (stats.hits == 0) ? 9999.0 : difftime(now, stats.lastSeen);
    stats.hits++;
    stats.lastSeen = now;

    // Track consecutive rapid hits (reset if gap was large)
    if (gap <= TIME_WINDOW) {
        stats.rapidHits++;
    } else {
        stats.rapidHits = 1; // reset streak
    }

    // Base frequency score
    double fscore = stats.hits * 0.8;

    // Rapid access bonus — each rapid hit adds more
    if (stats.rapidHits >= 2) {
        fscore += stats.rapidHits * 3.5;
        string tag = "RAPID_x" + to_string(stats.rapidHits);
        reason += reason.empty() ? tag : ", " + tag;
    }

    // Hard override: if rapidHits reaches RAPID_BLOCK_COUNT, force block
    if (stats.rapidHits >= RAPID_BLOCK_COUNT) {
        fscore += 15.0; // force past threshold
        reason += ", FORCE_BLOCK_RAPID";
    }

    double total = hscore + fscore;

    // HTTP-only site (score >= 4 from HTTP alone but below threshold) — warn
    if (isHTTP(rawUrl) && total < THREAT_THRESHOLD) {
        httpWarnings++;
        addLog(domain, "HTTP_WARNING", total, reason);
        LeaveCriticalSection(&mtx_cs);
        ostringstream oss;
        oss << "{\"status\":\"HTTP_WARNING\",\"domain\":\"" << jsonEscape(domain)
            << "\",\"score\":" << total
            << ",\"reason\":\"" << jsonEscape(reason) << "\"}";
        return oss.str();
    }

    if (total >= THREAT_THRESHOLD) {
        blacklist.insert(domain);
        saveToBlacklist(domain);
        totalBlocked++;
        addLog(domain, "THREAT_DETECTED", total, reason);
        LeaveCriticalSection(&mtx_cs);

        ostringstream oss;
        oss << "{\"status\":\"BLOCKED\",\"domain\":\"" << jsonEscape(domain)
            << "\",\"score\":" << total
            << ",\"reason\":\"" << jsonEscape(reason) << "\"}";
        return oss.str();
    }

    totalSafe++;
    addLog(domain, "SAFE_VISIT", total, reason.empty() ? "OK" : reason);
    LeaveCriticalSection(&mtx_cs);

    ostringstream oss;
    oss << "{\"status\":\"SAFE\",\"domain\":\"" << jsonEscape(domain)
        << "\",\"score\":" << total << "}";
    return oss.str();
}

// ============================================================
//  DASHBOARD API HANDLERS
// ============================================================

// GET /stats  → JSON stats object
string handleStats() {
    EnterCriticalSection(&mtx_cs);

    ostringstream oss;
    oss << "{"
        << "\"total\":" << totalChecked << ","
        << "\"safe\":"  << totalSafe    << ","
        << "\"blocked\":" << totalBlocked << ","
        << "\"http_warnings\":" << httpWarnings << ","
        << "\"blacklist_size\":" << blacklist.size()
        << "}";

    LeaveCriticalSection(&mtx_cs);
    return oss.str();
}

// GET /logs  → JSON array of recent log entries
string handleLogs() {
    EnterCriticalSection(&mtx_cs);

    ostringstream oss;
    oss << "[";
    bool first = true;
    for (const auto& e : recentLogs) {
        if (!first) oss << ",";
        first = false;
        oss << "{"
            << "\"ts\":\""     << jsonEscape(e.timestamp) << "\","
            << "\"domain\":\"" << jsonEscape(e.domain)    << "\","
            << "\"status\":\"" << jsonEscape(e.status)    << "\","
            << "\"score\":"    << e.score                 << ","
            << "\"reason\":\"" << jsonEscape(e.reason)    << "\""
            << "}";
    }
    oss << "]";

    LeaveCriticalSection(&mtx_cs);
    return oss.str();
}

// GET /blacklist  → JSON array of blacklisted domains
string handleBlacklist() {
    EnterCriticalSection(&mtx_cs);

    ostringstream oss;
    oss << "[";
    bool first = true;
    for (const auto& d : blacklist) {
        if (!first) oss << ",";
        first = false;
        oss << "\"" << jsonEscape(d) << "\"";
    }
    oss << "]";

    LeaveCriticalSection(&mtx_cs);
    return oss.str();
}

// GET /unblock?domain=xxx  — remove domain from blacklist (user override)
string handleUnblock(const string& path) {
    // Extract domain param
    string domain = "";
    size_t p = path.find("domain=");
    if (p != string::npos) {
        domain = path.substr(p + 7);
        size_t amp = domain.find("&"); if (amp != string::npos) domain = domain.substr(0, amp);
        // url-decode basic
        string decoded;
        for (size_t i = 0; i < domain.size(); ++i) {
            if (domain[i] == '%' && i+2 < domain.size()) {
                int v = 0; sscanf(domain.substr(i+1,2).c_str(),"%x",&v);
                decoded += (char)v; i += 2;
            } else decoded += domain[i];
        }
        domain = decoded;
    }

    if (domain.empty()) return "{\"ok\":false,\"msg\":\"no domain\"}";

    EnterCriticalSection(&mtx_cs);
    blacklist.erase(domain);
    // Rewrite blacklist file without this domain
    ofstream f(BLACKLIST_FILE, ios::trunc);
    for (const auto& d : blacklist) f << d << "\n";
    LeaveCriticalSection(&mtx_cs);

    addLog(domain, "UNBLOCKED_BY_USER", 0.0, "Manual override");
    cout << "[SmartShield] User unblocked: " << domain << "\n";
    return "{\"ok\":true,\"domain\":\"" + jsonEscape(domain) + "\"}";
}

// Build an HTTP/1.1 response
string buildResponse(const string& body, const string& contentType = "application/json") {
    ostringstream oss;
    oss << "HTTP/1.1 200 OK\r\n"
        << "Content-Type: " << contentType << "\r\n"
        << "Content-Length: " << body.length() << "\r\n"
        << "Access-Control-Allow-Origin: *\r\n"
        << "Access-Control-Allow-Methods: GET, OPTIONS\r\n"
        << "Access-Control-Allow-Headers: Content-Type, Authorization\r\n"
        << "Connection: close\r\n\r\n"
        << body;
    return oss.str();
}

// CORS preflight — OPTIONS request se pehle browser yeh maangta hai
string buildOptionsResponse() {
    return "HTTP/1.1 200 OK\r\n"
           "Access-Control-Allow-Origin: *\r\n"
           "Access-Control-Allow-Methods: GET, OPTIONS\r\n"
           "Access-Control-Allow-Headers: Content-Type, Authorization\r\n"
           "Content-Length: 0\r\n"
           "Connection: close\r\n\r\n";
}

// ============================================================
//  PER-CLIENT THREAD
// ============================================================
struct ClientData { SOCKET socket; };

unsigned __stdcall handleClient(void* arg) {
    ClientData* cd = (ClientData*)arg;
    SOCKET client  = cd->socket;
    delete cd;

    char buffer[8192] = {0};
    int bytes = recv(client, buffer, 8191, 0);

    if (bytes > 0) {
        string request(buffer);

        // Handle OPTIONS preflight (CORS) — browser sends this before fetch
        if (request.substr(0, 7) == "OPTIONS") {
            string optResp = buildOptionsResponse();
            send(client, optResp.c_str(), (int)optResp.length(), 0);
            closesocket(client);
            return 0;
        }

        // Parse request path: "GET /path?query HTTP/1.1"
        string path = "/";
        size_t get_pos = request.find("GET ");
        if (get_pos != string::npos) {
            size_t start = get_pos + 4;
            size_t end   = request.find(" ", start);
            if (end != string::npos) path = request.substr(start, end - start);
        }

        string responseBody;

        // Route: /stats
        if (path == "/stats" || path.substr(0, 6) == "/stats") {
            responseBody = buildResponse(handleStats());
        }
        // Route: /logs
        else if (path == "/logs" || path.substr(0, 5) == "/logs") {
            responseBody = buildResponse(handleLogs());
        }
        // Route: /blacklist
        else if (path == "/blacklist" || path.substr(0, 10) == "/blacklist") {
            responseBody = buildResponse(handleBlacklist());
        }
        // Route: /unblock?domain=xxx
        else if (path.substr(0, 8) == "/unblock") {
            responseBody = buildResponse(handleUnblock(path));
        }
        // Route: /?url=  (main check)
        else {
            string url = "";
            size_t pos = request.find("url=");
            if (pos != string::npos) {
                url = request.substr(pos + 4);
                size_t sp  = url.find(" ");  if (sp  != string::npos) url = url.substr(0, sp);
                size_t amp = url.find("&");  if (amp != string::npos) url = url.substr(0, amp);
            }
            responseBody = buildResponse(checkURL(url));
        }

        send(client, responseBody.c_str(), (int)responseBody.length(), 0);
    }

    closesocket(client);
    return 0;
}

// ============================================================
//  MAIN
// ============================================================
int main() {
    InitializeCriticalSection(&mtx_cs);
    loadBlacklist();

    WSADATA wsa;
    if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0) {
        cout << "WinSock failed.\n"; return 1;
    }

    SOCKET server_fd = socket(AF_INET, SOCK_STREAM, 0);
    int opt = 1;
    setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, (char*)&opt, sizeof(opt));

    sockaddr_in server{};
    server.sin_family      = AF_INET;
    server.sin_addr.s_addr = INADDR_ANY;
    server.sin_port        = htons(8080);

    if (bind(server_fd, (struct sockaddr*)&server, sizeof(server)) == SOCKET_ERROR) {
        cout << "Bind failed. Port 8080 in use?\n"; return 1;
    }
    listen(server_fd, SOMAXCONN);

    cout << "\n";
    cout << "  ╔═══════════════════════════════════════════════════╗\n";
    cout << "  ║   SmartShield AI IPS Engine  v4.0                 ║\n";
    cout << "  ║   Port: 8080  |  Heuristic Engine: ACTIVE         ║\n";
    cout << "  ║   HTTP Detection: ON  |  Dashboard API: ON        ║\n";
    cout << "  ║                                                   ║\n";
    cout << "  ║   Endpoints:                                      ║\n";
    cout << "  ║     /?url=<URL>    → Check URL                    ║\n";
    cout << "  ║     /stats         → Live statistics              ║\n";
    cout << "  ║     /logs          → Recent log entries           ║\n";
    cout << "  ║     /blacklist     → Blocked domains list         ║\n";
    cout << "  ║                                                   ║\n";
    cout << "  ║   Dashboard: Open dashboard.html in browser       ║\n";
    cout << "  ╚═══════════════════════════════════════════════════╝\n\n";

    while (true) {
        SOCKET client = accept(server_fd, NULL, NULL);
        if (client == INVALID_SOCKET) continue;
        ClientData* cd = new ClientData{client};
        HANDLE h = (HANDLE)_beginthreadex(NULL, 0, handleClient, cd, 0, NULL);
        if (h) CloseHandle(h);
    }

    DeleteCriticalSection(&mtx_cs);
    WSACleanup();
    return 0;
}