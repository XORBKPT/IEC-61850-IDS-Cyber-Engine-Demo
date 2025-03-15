// transformer_monitor.cpp
// Cybersecurity monitoring program for Advantec MIC-7700 to process Goose SV data from 50 fibre ports

#include <iostream>         // Standard I/O operations
#include <vector>           // Dynamic arrays for risk results
#include <string>           // String handling
#include <thread>           // Multi-threading support
#include <mutex>            // Thread synchronization
#include <condition_variable> // Thread signaling
#include <queue>            // Message queuing
#include <unordered_map>    // Efficient lookup for heartbeat and rate data
#include <unordered_set>    // Whitelist of authorized MACs
#include <chrono>           // High-precision timing
#include <cstring>          // C-style string operations
#include <cstdint>          // For int64_t (ensures portability)
#include <sys/socket.h>     // Socket programming (POSIX)
#include <netinet/in.h>     // Internet address structures
#include <unistd.h>         // POSIX system calls (e.g., close)
#include <openssl/hmac.h>   // HMAC computation (OpenSSL)
#include <openssl/evp.h>    // Cryptographic functions
#include <openssl/err.h>    // OpenSSL error handling
#include <ncurses.h>        // Terminal-based UI
#include <signal.h>         // Signal handling

// Constants for security and performance
#define HMAC_KEY "secret_hmac_key_32_bytes_long!!"  // Hardcoded HMAC key (WARNING: Use secure key management in production)
#define MAX_RATE_PER_SOURCE 100                    // Max messages per second per source to prevent DDoS
#define BUFFER_SIZE 1024                           // Buffer size for receiving messages
#define PORT_BASE 1000                             // Base port (1000-1049 for 50 ports)
#define NUM_PORTS 50                               // Number of fibre ports

// Structure for Goose SV data
struct GooseData {
    float voltage;              // Voltage value (e.g., 230V)
    float current;              // Current value (e.g., 50A)
    // Add more fields as per IEC 61850 Goose SV spec if needed
};

// Secure message structure
struct SecureMessage {
    std::string mac_address;    // Source MAC address
    std::string data;           // Plaintext Goose SV data
    unsigned char hmac[32];     // HMAC-SHA256 (32 bytes)
    int64_t timestamp;          // Timestamp in milliseconds
    GooseData goose_data;       // Parsed Goose SV data
};

// Risk levels for threat categorization
enum class RiskLevel { LOW, MEDIUM, HIGH, CRITICAL };

// Risk result structure for display
struct RiskResult {
    std::string source;         // Port identifier (e.g., "Port 1000")
    RiskLevel risk_level;       // Assessed risk level
    std::string details;        // Details including MAC and issue
};

// Global variables with thread safety
std::mutex queue_mtx;               // Protects message queue
std::mutex display_mtx;             // Protects display updates
std::condition_variable queue_cv;   // Signals new messages
std::queue<SecureMessage> message_queue; // Incoming message queue
std::unordered_map<std::string, int64_t> last_heartbeat; // Tracks heartbeats
std::unordered_map<std::string, int> message_count_per_sec; // Tracks message rates
std::unordered_set<std::string> whitelist = {"00:11:22:33:44:55"}; // Authorized MACs
std::vector<RiskResult> risk_results(NUM_PORTS); // Risk results per port
volatile sig_atomic_t running = 1;  // Shutdown flag

// Signal handler for Ctrl+C or termination
void signal_handler(int sig) {
    running = 0; // Gracefully stop the program
}

// Compute HMAC-SHA256 for message integrity
void computeHMAC(const std::string& data, unsigned char* hmac_output, unsigned int& hmac_len) {
    HMAC(EVP_sha256(), (const unsigned char*)HMAC_KEY, strlen(HMAC_KEY),
         (const unsigned char*)data.c_str(), data.size(), hmac_output, &hmac_len);
}

// Verify HMAC to ensure authenticity and integrity
bool verifyHMAC(const std::string& data, const unsigned char* received_hmac, unsigned int hmac_len) {
    unsigned char computed_hmac[32];
    unsigned int computed_len;
    computeHMAC(data, computed_hmac, computed_len);
    return (computed_len == hmac_len && memcmp(computed_hmac, received_hmac, hmac_len) == 0);
}

// Check if MAC is authorized
bool isAuthorized(const std::string& mac) {
    return whitelist.find(mac) != whitelist.end();
}

// Validate timestamp to prevent replay attacks (1-second tolerance)
bool validateTimestamp(int64_t received_time) {
    auto now = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::system_clock::now().time_since_epoch()).count();
    return std::abs(now - received_time) < 1000;
}

// Enforce rate limiting to prevent DDoS
bool checkRateLimit(const std::string& mac) {
    auto now = std::chrono::duration_cast<std::chrono::seconds>(
        std::chrono::system_clock::now().time_since_epoch()).count();
    static int64_t last_reset = now;
    if (now > last_reset) {
        message_count_per_sec.clear();
        last_reset = now;
    }
    int& count = message_count_per_sec[mac];
    return ++count <= MAX_RATE_PER_SOURCE;
}

// Validate Goose SV data ranges
bool checkRanges(const GooseData& data) {
    return (data.voltage >= 220 && data.voltage <= 240) &&
           (data.current >= 0 && data.current <= 100);
}

// Placeholder for sensor data reading (to be implemented by engineer)
GooseData read_sensor_data() {
    // TODO: Replace with actual sensor reading logic for MIC-7700
    return {230.0f, 50.0f}; // Simulated values
}

// Process message and assess risks
RiskResult processMessage(const SecureMessage& msg, int port_idx) {
    RiskResult result;
    result.source = "Port " + std::to_string(port_idx + PORT_BASE);
    result.risk_level = RiskLevel::LOW;
    result.details = "MAC: " + msg.mac_address + " - No issues detected";

    if (!isAuthorized(msg.mac_address)) {
        result.risk_level = RiskLevel::CRITICAL;
        result.details = "MAC: " + msg.mac_address + " - Unauthorized sender";
        return result;
    }
    if (!verifyHMAC(msg.data, msg.hmac, 32)) {
        result.risk_level = RiskLevel::HIGH;
        result.details = "MAC: " + msg.mac_address + " - HMAC verification failed";
        return result;
    }
    if (!checkRateLimit(msg.mac_address)) {
        result.risk_level = RiskLevel::HIGH;
        result.details = "MAC: " + msg.mac_address + " - Rate limit exceeded";
        return result;
    }
    if (!validateTimestamp(msg.timestamp)) {
        result.risk_level = RiskLevel::MEDIUM;
        result.details = "MAC: " + msg.mac_address + " - Invalid timestamp";
        return result;
    }
    if (!checkRanges(msg.goose_data)) {
        result.risk_level = RiskLevel::HIGH;
        result.details = "MAC: " + msg.mac_address + " - Fake values detected";
        return result;
    }
    return result;
}

// Handle client connections
void handleClient(int client_socket, int port_idx) {
    char buffer[BUFFER_SIZE];
    while (running) {
        int bytes_received = recv(client_socket, buffer, BUFFER_SIZE - 1, 0);
        if (bytes_received <= 0) {
            std::lock_guard<std::mutex> lock(display_mtx);
            risk_results[port_idx] = {"Port " + std::to_string(port_idx + PORT_BASE),
                                      RiskLevel::HIGH, "Connection lost"};
            break;
        }

        // Use exact length to handle binary data with possible nulls
        SecureMessage msg;
        msg.mac_address = "00:11:22:33:44:55"; // TODO: Extract from actual message
        msg.data = std::string(buffer, bytes_received);
        computeHMAC(msg.data, msg.hmac, 32);
        msg.timestamp = std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::system_clock::now().time_since_epoch()).count();
        msg.goose_data = read_sensor_data(); // Replace with real parsing if needed

        {
            std::lock_guard<std::mutex> lock(queue_mtx);
            message_queue.push(msg);
        }
        queue_cv.notify_one();
    }
    close(client_socket);
}

// Update ncurses display
void updateDisplay() {
    std::lock_guard<std::mutex> lock(display_mtx);
    clear();
    printw("Current Risk Levels:\n");
    printw("Port       | Risk Level | Details\n");
    printw("-----------|------------|---------\n");
    for (const auto& result : risk_results) {
        const char* level_str = (result.risk_level == RiskLevel::LOW) ? "LOW" :
                                (result.risk_level == RiskLevel::MEDIUM) ? "MEDIUM" :
                                (result.risk_level == RiskLevel::HIGH) ? "HIGH" : "CRITICAL";
        printw("%-10s | %-10s | %s\n", result.source.c_str(), level_str, result.details.c_str());
    }
    refresh();
}

int main() {
    // Register signal handlers
    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);

    // Initialize ncurses
    initscr();
    cbreak();
    noecho();
    keypad(stdscr, TRUE);

    // Initialize OpenSSL
    OpenSSL_add_all_algorithms();
    ERR_load_crypto_strings();

    // Initialize risk results
    for (int i = 0; i < NUM_PORTS; ++i) {
        risk_results[i] = {"Port " + std::to_string(PORT_BASE + i), RiskLevel::LOW, "Initializing"};
    }

    // Set up server sockets
    std::vector<int> server_sockets(NUM_PORTS);
    for (int i = 0; i < NUM_PORTS; ++i) {
        int sock = socket(AF_INET, SOCK_STREAM, 0);
        if (sock < 0) {
            endwin();
            std::cerr << "Error: Socket creation failed for port " << (PORT_BASE + i) << std::endl;
            return 1;
        }
        int opt = 1;
        setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)); // Allow port reuse
        struct sockaddr_in addr;
        addr.sin_family = AF_INET;
        addr.sin_addr.s_addr = INADDR_ANY;
        addr.sin_port = htons(PORT_BASE + i);
        if (bind(sock, (struct sockaddr*)&addr, sizeof(addr)) < 0 || listen(sock, 5) < 0) {
            endwin();
            std::cerr << "Error: Bind/listen failed for port " << (PORT_BASE + i) << std::endl;
            close(sock);
            return 1;
        }
        server_sockets[i] = sock;
    }

    // Start accept threads
    std::vector<std::thread> threads;
    for (int i = 0; i < NUM_PORTS; ++i) {
        threads.emplace_back([i, &server_sockets]() {
            while (running) {
                struct sockaddr_in client_addr;
                socklen_t client_len = sizeof(client_addr);
                int client_sock = accept(server_sockets[i], (struct sockaddr*)&client_addr, &client_len);
                if (client_sock < 0) continue;
                std::thread client_thread(handleClient, client_sock, i);
                client_thread.detach();
            }
        });
    }

    // Main loop to process messages
    while (running) {
        std::unique_lock<std::mutex> lock(queue_mtx);
        queue_cv.wait(lock, [] { return !message_queue.empty() || !running; });
        if (!running) break;

        SecureMessage msg = message_queue.front();
        message_queue.pop();
        lock.unlock();

        int port_idx = std::stoi(msg.source.substr(5)) - PORT_BASE; // Note: Adjusted below
        risk_results[port_idx] = processMessage(msg, port_idx);     // Pass port_idx explicitly
        updateDisplay();
    }

    // Cleanup
    for (int sock : server_sockets) close(sock);
    for (auto& t : threads) if (t.joinable()) t.join();
    endwin();
    EVP_cleanup();
    ERR_free_strings();
    return 0;
}
