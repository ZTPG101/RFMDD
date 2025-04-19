#define _DEFAULT_SOURCE // Required on some systems for strdup, etc.

#include <pcap.h>           // Main libpcap header
#include <stdio.h>          // Standard I/O (printf, fprintf, fopen, etc.)
#include <stdlib.h>         // Standard library (exit, malloc, free, strtol)
#include <string.h>         // String manipulation (strcmp, strcpy, snprintf, strdup)
#include <time.h>           // For timestamp formatting (time, localtime, strftime)
#include <errno.h>          // For error numbers (errno)
#include <limits.h>         // For INT_MAX etc. (used indirectly by strtol)
#include <signal.h>         // For handling Ctrl+C (SIGINT) - Optional but good practice

// Network header files (order can sometimes matter)
#include <netinet/if_ether.h> // Ethernet header structures (struct ether_header)
#include <netinet/ip.h>       // IP header structure (struct ip)
#include <netinet/tcp.h>      // TCP header structure (struct tcphdr) and flags (TH_*)
#include <netinet/udp.h>      // UDP header structure (struct udphdr)
#include <arpa/inet.h>      // For inet_ntop (IP address conversion)
#include <net/ethernet.h>   // Often included by if_ether.h, defines ETHERTYPE_IP etc.


// --- Configuration Constants ---
#define LOG_FILE_PATH "./capture_log.tsv" // Output log file path
#define SNAP_LEN 256                      // Max bytes to capture per packet (snapshot length)
                                          // Should be enough for common headers (Eth+IP+TCP/UDP)
#define MAX_FILTER_LEN 150                // Max length of the generated filter string
#define DEFAULT_PROMISC 1                 // Capture in promiscuous mode (1=yes, 0=no)
#define DEFAULT_TIMEOUT_MS 1000           // Read timeout for pcap_open_live (milliseconds)
// --- End Configuration ---


// --- Global Variables ---
FILE *log_file = NULL;                    // File pointer for the log file
volatile sig_atomic_t stop_capture = 0;   // Flag to signal capture loop termination (used by signal handler)
pcap_t *pcap_handle = NULL;               // Global handle for pcap session (used by signal handler)
volatile int packet_count = 0;            // Counter for processed packets
// --- End Global Variables ---


// --- Function Declarations ---
void print_usage(const char *prog_name);
void format_tcp_flags(uint8_t flags, char *buf, size_t len);
void packet_handler(u_char *user_args, const struct pcap_pkthdr *header, const u_char *packet);
void signal_handler(int signum);
char* find_default_device(char *errbuf);
// --- End Function Declarations ---


// --- Helper to get TCP flags as a string ---
void format_tcp_flags(uint8_t flags, char *buf, size_t len) {
    snprintf(buf, len, "%s%s%s%s%s%s",
             (flags & TH_URG) ? "U" : "-",
             (flags & TH_ACK) ? "A" : "-",
             (flags & TH_PUSH) ? "P" : "-",
             (flags & TH_RST) ? "R" : "-",
             (flags & TH_SYN) ? "S" : "-",
             (flags & TH_FIN) ? "F" : "-");
}


// --- Packet Handler Callback Function ---
// This function is called by pcap_loop() for each captured packet.
void packet_handler(u_char *user_args, const struct pcap_pkthdr *header, const u_char *packet) {
    // Silence unused parameter warning if user_args is not needed
    (void)user_args;

    // Pointers to network headers
    const struct ether_header *eth_header;
    const struct ip *ip_header;
    const struct tcphdr *tcp_header;
    const struct udphdr *udp_header;

    // Variables to store extracted data
    char timestamp_buf[64];
    char src_ip_str[INET_ADDRSTRLEN];
    char dst_ip_str[INET_ADDRSTRLEN];
    int ip_header_len;
    uint8_t ip_proto = 0; // IP protocol number (TCP=6, UDP=17, ICMP=1, etc.)
    uint16_t src_port = 0; // Source port (0 if not TCP/UDP)
    uint16_t dst_port = 0; // Destination port (0 if not TCP/UDP)
    char flags_str[10] = "-"; // TCP flags string ("-" for non-TCP)

    packet_count++; // Increment packet counter

    // --- 1. Timestamp ---
    struct timeval tv = header->ts; // Packet timestamp from libpcap
    time_t nowtime = tv.tv_sec;
    struct tm *nowtm = localtime(&nowtime);
    char time_str_part[30];
    strftime(time_str_part, sizeof time_str_part, "%Y-%m-%d %H:%M:%S", nowtm);
    snprintf(timestamp_buf, sizeof timestamp_buf, "%s.%06ld", time_str_part, tv.tv_usec);

    // --- 2. Ethernet Header Parsing ---
    // Check if enough data was captured for the Ethernet header
    if (header->caplen < ETHER_HDR_LEN) {
        fprintf(stderr, "Warning: Incomplete Ethernet header (caplen %u)\n", header->caplen);
        return; // Skip this packet
    }
    eth_header = (const struct ether_header *)packet;

    // --- 3. Check for IP Packet ---
    // We are primarily interested in IP packets for this logger
    if (ntohs(eth_header->ether_type) != ETHERTYPE_IP) {
        // Optional: Log or print message about non-IP packets if needed
        // fprintf(stderr, "Debug: Non-IP Packet (EtherType: 0x%x)\n", ntohs(eth_header->ether_type));
        return; // Skip non-IP packets (like ARP, IPv6 etc.)
    }

    // --- 4. IP Header Parsing ---
    // Check if enough data was captured for the *minimum* IP header
    if (header->caplen < ETHER_HDR_LEN + sizeof(struct ip)) {
        fprintf(stderr, "Warning: Incomplete IP packet captured (caplen %u)\n", header->caplen);
        return;
    }
    ip_header = (const struct ip *)(packet + ETHER_HDR_LEN);

    // Calculate the actual IP header length (IP header length field * 4 bytes)
    ip_header_len = ip_header->ip_hl * 4;
    if (ip_header_len < 20) { // Basic sanity check for minimum IP header size
        fprintf(stderr, "Warning: Invalid IP header length: %d bytes\n", ip_header_len);
        return;
    }

    // Check if enough data was captured for the *actual* IP header length
    if (header->caplen < ETHER_HDR_LEN + ip_header_len) {
        fprintf(stderr, "Warning: Incomplete IP header captured (caplen %u, needed %d)\n",
                header->caplen, ETHER_HDR_LEN + ip_header_len);
        return;
    }

    // Extract IP addresses and protocol
    inet_ntop(AF_INET, &(ip_header->ip_src), src_ip_str, INET_ADDRSTRLEN);
    inet_ntop(AF_INET, &(ip_header->ip_dst), dst_ip_str, INET_ADDRSTRLEN);
    ip_proto = ip_header->ip_p;

    // --- 5. TCP/UDP Header Parsing ---
    if (ip_proto == IPPROTO_TCP) {
        // Check if enough data for TCP header
        if (header->caplen >= ETHER_HDR_LEN + ip_header_len + sizeof(struct tcphdr)) {
            tcp_header = (const struct tcphdr *)(packet + ETHER_HDR_LEN + ip_header_len);
            src_port = ntohs(tcp_header->th_sport);
            dst_port = ntohs(tcp_header->th_dport);
            format_tcp_flags(tcp_header->th_flags, flags_str, sizeof(flags_str));
        } else {
            fprintf(stderr, "Warning: Incomplete TCP header (caplen %u)\n", header->caplen);
            // Keep src/dst port as 0, flags as "-"
        }
    } else if (ip_proto == IPPROTO_UDP) {
        // Check if enough data for UDP header
        if (header->caplen >= ETHER_HDR_LEN + ip_header_len + sizeof(struct udphdr)) {
            udp_header = (const struct udphdr *)(packet + ETHER_HDR_LEN + ip_header_len);
            src_port = ntohs(udp_header->uh_sport);
            dst_port = ntohs(udp_header->uh_dport);
            // flags_str remains "-" for UDP
        } else {
             fprintf(stderr, "Warning: Incomplete UDP header (caplen %u)\n", header->caplen);
             // Keep src/dst port as 0
        }
    } else {
        // Other protocols (ICMP, IGMP, etc.) - ports are not applicable in the same way
        // Keep src/dst port as 0, flags as "-"
    }

    // --- 6. Log Data to File (TSV Format) ---
    if (log_file) {
        fprintf(log_file, "%s\t%s\t%s\t%u\t%u\t%u\t%d\t%s\n",
                timestamp_buf,
                src_ip_str,
                dst_ip_str,
                ip_proto,
                src_port,
                dst_port,
                header->len, // Original packet length (on the wire)
                flags_str);
        // fflush(log_file); // Uncomment if immediate writes are needed, but impacts performance
    }
}


// --- Signal Handler for Ctrl+C (SIGINT) ---
// Gracefully stops the capture loop.
void signal_handler(int signum) {
    if (signum == SIGINT || signum == SIGTERM) {
        printf("\nSignal %d received, stopping capture...\n", signum);
        stop_capture = 1;
        // If pcap_loop is blocking, pcap_breakloop wakes it up
        if (pcap_handle) {
            pcap_breakloop(pcap_handle);
        }
    }
}


// --- Find Default Network Device ---
// Finds the first suitable non-loopback device.
// Returns an allocated string (needs free()) or NULL on error.
char* find_default_device(char *errbuf) {
    pcap_if_t *alldevs = NULL, *d;
    char *dev_name = NULL;

    // Retrieve the device list
    if (pcap_findalldevs(&alldevs, errbuf) == -1 || alldevs == NULL) {
        fprintf(stderr, "Error finding devices: %s\n", errbuf);
        return NULL;
    }

    // Iterate through the list and find the first non-loopback interface
    for (d = alldevs; d != NULL; d = d->next) {
        if (d->name && !(d->flags & PCAP_IF_LOOPBACK)) {
            // Found a non-loopback device
            dev_name = strdup(d->name); // Allocate memory and copy name
            if (!dev_name) {
                perror("strdup failed while selecting device");
                // Continue searching just in case another works
            } else {
                 break; // Found one, stop searching
            }
        }
    }

    // If no non-loopback found, maybe fallback to the first device overall?
    if (dev_name == NULL && alldevs && alldevs->name) {
         fprintf(stderr, "Warning: No non-loopback interface found. Using first device: %s\n", alldevs->name);
         dev_name = strdup(alldevs->name);
         if (!dev_name) {
             perror("strdup failed for fallback device");
         }
    }

    pcap_freealldevs(alldevs); // Free the device list

    if (dev_name == NULL && errbuf[0] == '\0') {
         // If errbuf wasn't set by pcap_findalldevs but we still have no device
         snprintf(errbuf, PCAP_ERRBUF_SIZE, "Couldn't find any suitable network device.");
    }

    return dev_name; // Return allocated string or NULL
}


// --- Print Usage Instructions ---
void print_usage(const char *prog_name) {
    fprintf(stderr, "Usage: %s -d <destination_ip> [-p <port>] [-i <interface>]\n", prog_name);
    fprintf(stderr, "\n");
    fprintf(stderr, "  -d <destination_ip> : IP address to filter destination (required).\n");
    fprintf(stderr, "  -p <port>           : Destination port to filter (optional, 1-65535).\n");
    fprintf(stderr, "                        If omitted, captures all ports for the destination IP.\n");
    fprintf(stderr, "  -i <interface>      : Network interface to capture on (optional).\n");
    fprintf(stderr, "                        If omitted, defaults to the first non-loopback interface.\n");
    fprintf(stderr, "\n");
    fprintf(stderr, "Example (capture traffic to 192.168.1.100 on port 80):\n");
    fprintf(stderr, "  sudo %s -d 192.168.1.100 -p 80\n", prog_name);
    fprintf(stderr, "\n");
     fprintf(stderr, "Example (capture all traffic to 10.0.0.5 on eth0):\n");
    fprintf(stderr, "  sudo %s -d 10.0.0.5 -i eth0\n", prog_name);
    fprintf(stderr, "\n");
    fprintf(stderr, "Logs output to: %s\n", LOG_FILE_PATH);
}


// --- Main Function ---
int main(int argc, char *argv[]) {
    char errbuf[PCAP_ERRBUF_SIZE]; // Buffer for libpcap error messages
    char *dev_name = NULL;         // Name of the device to capture on (needs free)
    char *interface_arg = NULL;    // Interface name from -i option
    char *dest_ip_str = NULL;      // Destination IP from -d option
    int dest_port = 0;             // Destination port from -p option (0 if not specified)
    char filter_exp[MAX_FILTER_LEN]; // BPF filter expression string
    struct bpf_program fp;         // Compiled BPF filter program
    bpf_u_int32 net = 0;           // IP address of the network interface (network byte order)
    bpf_u_int32 mask = 0;          // Netmask of the network interface (network byte order)
    int header_needed = 1;         // Flag: Does the log file need a header row?
    int opt;                       // For getopt (optional, manual parsing used here)

    printf("Simple Packet Capture Tool\n");
    printf("--------------------------\n");

    // --- 1. Argument Parsing ---
    // Manual parsing loop (alternative: use getopt)
    for (int i = 1; i < argc; ++i) {
        if (strcmp(argv[i], "-i") == 0 && i + 1 < argc) {
            if (interface_arg != NULL) {
                 fprintf(stderr, "Error: Interface (-i) specified multiple times.\n");
                 print_usage(argv[0]); return 1;
            }
            interface_arg = argv[++i];
        } else if (strcmp(argv[i], "-d") == 0 && i + 1 < argc) {
             if (dest_ip_str != NULL) {
                 fprintf(stderr, "Error: Destination IP (-d) specified multiple times.\n");
                 print_usage(argv[0]); return 1;
            }
            dest_ip_str = argv[++i];
            // Basic validation could be added here (e.g., is it a valid IP format?)
        } else if (strcmp(argv[i], "-p") == 0 && i + 1 < argc) {
             if (dest_port != 0) {
                 fprintf(stderr, "Error: Port (-p) specified multiple times.\n");
                 print_usage(argv[0]); return 1;
            }
            char *endptr;
            errno = 0;
            long port_long = strtol(argv[++i], &endptr, 10);
            if (errno != 0 || *endptr != '\0' || port_long < 1 || port_long > 65535) {
                 fprintf(stderr, "Error: Invalid port number '%s'. Must be 1-65535.\n", argv[i]);
                 print_usage(argv[0]); return 1;
            }
            dest_port = (int)port_long;
        } else if (strcmp(argv[i], "-h") == 0 || strcmp(argv[i], "--help") == 0) {
             print_usage(argv[0]);
             return 0; // Normal exit for help
        }
        else {
            fprintf(stderr, "Error: Unknown or invalid argument '%s'.\n", argv[i]);
            print_usage(argv[0]);
            return 1;
        }
    }

    // Check if mandatory destination IP was provided
    if (dest_ip_str == NULL) {
        fprintf(stderr, "Error: Destination IP address (-d option) is required.\n");
        print_usage(argv[0]);
        return 1;
    }

    // --- 2. Select Network Device ---
    errbuf[0] = '\0'; // Clear error buffer
    if (interface_arg != NULL) {
        // User specified an interface
        dev_name = strdup(interface_arg);
        if (!dev_name) {
            perror("strdup failed for interface name");
            return 2;
        }
        printf("Using specified interface: %s\n", dev_name);
    } else {
        // Find default device
        printf("Interface not specified, finding default device...\n");
        dev_name = find_default_device(errbuf);
        if (dev_name == NULL) {
            fprintf(stderr, "Error finding default device: %s\n", errbuf);
            return 2;
        }
        printf("Using automatically selected device: %s\n", dev_name);
    }

    // --- 3. Get Network Mask ---
    // Required for pcap_compile on some systems, good practice regardless
    if (pcap_lookupnet(dev_name, &net, &mask, errbuf) == -1) {
        fprintf(stderr, "Warning: Couldn't get netmask for device %s: %s. Using 0.0.0.0\n", dev_name, errbuf);
        net = 0; // Use default netmask if lookup fails
        mask = 0;
    }

    // --- 4. Open Device for Capturing ---
    printf("Opening device %s for capture...\n", dev_name);
    pcap_handle = pcap_open_live(dev_name, SNAP_LEN, DEFAULT_PROMISC, DEFAULT_TIMEOUT_MS, errbuf);
    if (pcap_handle == NULL) {
        fprintf(stderr, "Error opening device %s: %s\n", dev_name, errbuf);
        free(dev_name); // Clean up allocated device name
        return 2;
    }
    printf("Device opened successfully.\n");

    // Check data link type (optional but informative)
    int dlt = pcap_datalink(pcap_handle);
    if (dlt != DLT_EN10MB && dlt != DLT_NULL && dlt != DLT_LOOP && dlt != DLT_LINUX_SLL) {
        // DLT_EN10MB is Ethernet. NULL/LOOP are common for loopback. LINUX_SLL is "Linux cooked capture".
        fprintf(stderr, "Warning: Unsupported data link type %d (%s) on device %s. Packet parsing might fail.\n",
                dlt, pcap_datalink_val_to_name(dlt) ? pcap_datalink_val_to_name(dlt) : "?", dev_name);
        // This parser assumes Ethernet-like headers (or simple IP like on loopback/null).
    } else {
         printf("Data link type: %s\n", pcap_datalink_val_to_name(dlt));
    }


    // --- 5. Construct and Compile BPF Filter ---
    if (dest_port > 0) { // If port was specified
         snprintf(filter_exp, sizeof(filter_exp), "dst host %s and dst port %d", dest_ip_str, dest_port);
    } else { // Only destination IP
         snprintf(filter_exp, sizeof(filter_exp), "dst host %s", dest_ip_str);
    }
    printf("Compiling filter: \"%s\"\n", filter_exp);

    if (pcap_compile(pcap_handle, &fp, filter_exp, 0, mask) == -1) { // Optimization=0
        fprintf(stderr, "Error compiling filter \"%s\": %s\n", filter_exp, pcap_geterr(pcap_handle));
        free(dev_name);
        pcap_close(pcap_handle);
        return 2;
    }

    // --- 6. Apply Compiled Filter ---
    if (pcap_setfilter(pcap_handle, &fp) == -1) {
        fprintf(stderr, "Error applying filter \"%s\": %s\n", filter_exp, pcap_geterr(pcap_handle));
        pcap_freecode(&fp); // Free compiled code before exiting
        free(dev_name);
        pcap_close(pcap_handle);
        return 2;
    }
    printf("Filter applied successfully.\n");

    pcap_freecode(&fp); // Free the compiled code *after* it has been applied


    // --- 7. Open Log File ---
    // Check if file exists and is empty to decide if header is needed
    FILE *check_file = fopen(LOG_FILE_PATH, "r");
    if (check_file == NULL) {
        if (errno != ENOENT) { // Report error only if it's not "file not found"
             perror("Warning: Error checking log file status");
        }
        header_needed = 1; // File doesn't exist, need header
    } else {
        // Check if file is empty
        fseek(check_file, 0, SEEK_END);
        header_needed = (ftell(check_file) == 0); // Need header if empty
        fclose(check_file);
    }

    // Open the log file in append mode
    log_file = fopen(LOG_FILE_PATH, "a");
    if (log_file == NULL) {
        perror("Error opening log file for appending");
        // Cleanup before exiting
        free(dev_name);
        pcap_close(pcap_handle);
        return 3;
    }

    // Write header if needed
    if (header_needed) {
        fprintf(log_file, "Timestamp\tSrcIP\tDstIP\tProto\tSrcPort\tDstPort\tLength\tFlags\n");
        fflush(log_file); // Ensure header is written immediately
        printf("Log file did not exist or was empty. Writing header.\n");
    } else {
        printf("Appending to existing log file: %s\n", LOG_FILE_PATH);
    }

    // Add a start marker to the log
    time_t start_time = time(NULL);
    fprintf(log_file, "# Log Started: Device %s | Filter '%s' | Time: %s",
            dev_name, filter_exp, ctime(&start_time)); // ctime adds newline
    fflush(log_file);


    // --- 8. Setup Signal Handling ---
    signal(SIGINT, signal_handler);  // Handle Ctrl+C
    signal(SIGTERM, signal_handler); // Handle termination signal


    // --- 9. Start Packet Capture Loop ---
    printf("Starting capture... Press Ctrl+C to stop.\n");
    // pcap_loop returns -1 on error, -2 if broken by pcap_breakloop, or 0 if count is reached (not applicable here)
    int loop_status = pcap_loop(pcap_handle, -1, packet_handler, NULL); // Capture indefinitely (-1)


    // --- 10. Cleanup ---
    printf("\nCapture loop finished.\n");
    if (loop_status == -1) {
        fprintf(stderr,"Error occurred during capture loop: %s\n", pcap_geterr(pcap_handle));
    } else if (loop_status == -2) {
        // This is expected when stopped by signal handler calling pcap_breakloop
        printf("Capture loop interrupted by signal.\n");
    }

    printf("Processed approximately %d packets matching the filter.\n", packet_count);

    // Add end marker to log file
    if (log_file != NULL) {
        time_t end_time = time(NULL);
        fprintf(log_file, "# Log Ended: Total Packets %d | Time: %s", packet_count, ctime(&end_time));
        fflush(log_file);
        if (fclose(log_file) != 0) {
             perror("Error closing log file");
        }
        log_file = NULL; // Mark as closed
    }

    // Close the pcap session
    if (pcap_handle) {
        pcap_close(pcap_handle);
        pcap_handle = NULL; // Mark as closed
    }

    // Free allocated device name string
    free(dev_name);
    dev_name = NULL;

    printf("Cleanup complete. Exiting.\n");
    return 0; // Success
}
