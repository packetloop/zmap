/*
 * ZMap Copyright 2013 Regents of the University of Michigan
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not
 * use this file except in compliance with the License. You may obtain a copy
 * of the License at http://www.apache.org/licenses/LICENSE-2.0
 */

/* DNS Resolver Detection Module for ZMap v0.68
 * Identifies open DNS resolvers that can be exploited for DNS reflection/amplification attacks
 * Sends specially crafted DNS queries with encoded correlation data
 * Validates responses to confirm recursive resolution capability
 *
 * v0.68 Changes:
 * - Fixed timestamp encoding to use microseconds since epoch
 * - Removed incorrect bit-shifting that caused future dates
 * - Timestamps now properly represent actual time of packet generation
 *
 * v0.67 Changes:
 * - Fixed timestamp encoding format specifier from %016lx to %016PRIx64
 * - Added inttypes.h include for portable 64-bit formatting
 * - Ensures full 64-bit timestamp is properly encoded on all platforms
 *
 * v0.66 Changes:
 * - Removed app_success field entirely
 * - Monitor now correctly shows success count instead of app_success
 * - No functional changes to validation logic
 *
 * v0.65 Changes:
 * - Removed debug logging added in v0.6d/v0.61d
 * - Production-ready version with IP extraction fix
 * - No functional changes from v0.61d
 *
 * v0.61d Changes:
 * - Fixed off-by-one error in extract_target_ip() function
 * - IP address is extracted from between 2nd and 3rd dots, not 3rd and 4th
 * - This fix resolves Step 4.3 validation failures in target IP extraction
 * - All debug logging from v0.6d preserved
 *
 * v0.6d Changes:
 * - Added comprehensive debug logging throughout validation pipeline
 * - Added debug output for validation-to-logging handoff
 * - Added granular sub-step logging for complex validation operations
 * - Debug output uses [DNS_DEBUG] prefix for easy filtering
 *
 * v0.6 Changes:
 * - Fixed field registration conflict by removing custom saddr field definition
 * - Eliminated memory corruption causing app_success field name corruption
 * - Restored proper validation result logging for confirmed open resolvers
 * - Aligned field definitions with standard ZMap module patterns
 *
 * v0.5 Changes:
 * - Fixed saddr field formatting from integer to readable IP address string
 * - Changed saddr field type from "int" to "string" in field definitions
 * - Updated saddr field population to use inet_ntoa() for human-readable format
 *
 * v0.4 Changes:
 * - Converted to standard ZMap logging routines
 * - Logs ALL UDP responses from port 53 (successful and failed)
 * - Replaced custom fields with standard ZMap fields  
 * - Enabled runtime filtering through success flags
 * - Moved validation logic from validate_packet to process_packet
 *
 * v0.3 Changes:
 * - Added saddr field for ZMap output system compatibility
 * - Fixed empty output file issue
 *
 * v0.2 Changes:
 * - Restructured validation pipeline with centralized domain parsing
 * - Fixed redundant IP validation between Stage 2 and Stage 5
 * - Eliminated duplicate domain parsing operations
 * - Improved efficiency through single-pass domain data extraction
 */

#include <stdbool.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <assert.h>
#include <sys/time.h>
#include <time.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <errno.h>
#include <inttypes.h>

#include "../../lib/blocklist.h"
#include "../../lib/includes.h"
#include "../../lib/xalloc.h"
#include "../../lib/lockfd.h"
#include "logger.h"
#include "probe_modules.h"
#include "packet.h"
#include "aesrand.h"
#include "state.h"
#include "module_dns.h"  // Import existing DNS structures

#define MAX_DNS_PAYLOAD_LEN 512
#define DNS_HEADER_SIZE 12
#define DNS_QUESTION_TAIL_SIZE 4
#define MAX_DOMAIN_LENGTH 253
#define EPHEMERAL_PORT_MIN 49152
#define EPHEMERAL_PORT_MAX 65535
#define DNS_PORT 53
#define BASE_DOMAIN "asertdnsresearch.com"
#define ICMP_HEADER_SIZE 8

// Module state
static uint16_t scan_identifier = 0;
static int num_ports;
static char *template_packet = NULL;

probe_module_t module_dnsresolver;

// Domain data structure for centralized parsing (from v0.2)
typedef struct {
    char *query_domain;
    uint32_t extracted_target_ip;
    uint16_t extracted_scan_id;
    bool valid_base_domain;
} domain_data_t;

// Validation result structure for packaging step results (NEW in v0.4)
typedef struct {
    bool step1_udp_structure;      // UDP format and ports
    bool step2_source_ip;          // Blocklist check
    bool step3_dns_header;         // DNS response format and transaction ID
    bool step4_domain_extraction;  // Domain parsing and validation
    bool step5_ip_correlation;     // Response IP matches target IP
    bool step6_scan_correlation;   // Scan ID matches current scan
    bool step7_resolver_check;     // RA=1, RCODE=0
    bool overall_success;          // All steps passed
} validation_result_t;

// Utility functions (unchanged from v0.5)

// Generate pseudorandom ephemeral port
static uint16_t get_ephemeral_port(aesrand_t *aes)
{
    uint32_t rand_val = aesrand_getword(aes);
    uint16_t port_range = EPHEMERAL_PORT_MAX - EPHEMERAL_PORT_MIN + 1;
    return EPHEMERAL_PORT_MIN + (rand_val % port_range);
}

// Convert IP address to dash-separated format for domain encoding
static void ip_to_dashes(uint32_t ip_addr, char *output, size_t output_len)
{
    struct in_addr addr;
    addr.s_addr = ip_addr;
    char ip_str[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &addr, ip_str, INET_ADDRSTRLEN);

    // Replace dots with dashes
    strncpy(output, ip_str, output_len - 1);
    output[output_len - 1] = '\0';

    for (char *p = output; *p; p++) {
        if (*p == '.') {
            *p = '-';
        }
    }
}

// Generate microsecond timestamp as hex string
static void get_timestamp_hex(char *output, size_t output_len)
{
    struct timeval tv;
    gettimeofday(&tv, NULL);

    // Convert to microseconds since epoch
    uint64_t timestamp = ((uint64_t)tv.tv_sec * 1000000) + tv.tv_usec;

    snprintf(output, output_len, "%016" PRIx64, timestamp);
}

// Convert domain name to DNS wire format (adapted from module_dns.c domain_to_qname)
static uint16_t domain_to_wire_format(char **wire_handle, const char *domain)
{
    // String + 1byte header + null byte
    uint16_t len = strlen(domain) + 1 + 1;
    char *wire_format = xmalloc(len);
    // Add a . before the domain. This will make the following simpler.
    wire_format[0] = '.';
    // Move the domain into the wire_format buffer.
    strcpy(wire_format + 1, domain);
    for (int i = 0; i < len; i++) {
        if (wire_format[i] == '.') {
            int j;
            for (j = i + 1; j < (len - 1); j++) {
                if (wire_format[j] == '.') {
                    break;
                }
            }
            wire_format[i] = j - i - 1;
        }
    }
    *wire_handle = wire_format;
    assert((*wire_handle)[len - 1] == '\0');
    return len;
}

// Build complete DNS query domain name
static int build_query_domain(uint32_t target_ip, char *domain, size_t domain_len)
{
    char timestamp_hex[17];
    char scan_id_hex[5];
    char ip_dashes[16];

    get_timestamp_hex(timestamp_hex, sizeof(timestamp_hex));
    snprintf(scan_id_hex, sizeof(scan_id_hex), "%04x", scan_identifier);
    ip_to_dashes(target_ip, ip_dashes, sizeof(ip_dashes));

    int ret = snprintf(domain, domain_len, "%s.%s.%s.%s",
                       timestamp_hex, scan_id_hex, ip_dashes, BASE_DOMAIN);

    if (ret >= (int)domain_len) {
        log_error("dnsresolver", "Domain name too long for target IP");
        return -1;
    }

    return 0;
}

// Create DNS query packet using existing DNS header structure
static int make_dns_query(char *payload, const char *domain, uint16_t txid, size_t *payload_len)
{
    dns_header *dns_hdr = (dns_header *)payload;

    // Initialize DNS header using correct structure from module_dns.h
    memset(dns_hdr, 0, DNS_HEADER_SIZE);
    dns_hdr->id = htons(txid);
    dns_hdr->rd = 1;  // Recursion desired
    dns_hdr->qr = 0;  // Query (not response)
    dns_hdr->qdcount = htons(1); // One question

    // Convert domain to wire format using adapted function from dns.c
    char *qname;
    uint16_t qname_len = domain_to_wire_format(&qname, domain);

    if (qname_len == 0 || qname_len > MAX_DNS_PAYLOAD_LEN - DNS_HEADER_SIZE - DNS_QUESTION_TAIL_SIZE) {
        log_error("dnsresolver", "Failed to convert domain to wire format or domain too long");
        if (qname) free(qname);
        return -1;
    }

    // Copy qname after DNS header
    char *qname_start = payload + DNS_HEADER_SIZE;
    memcpy(qname_start, qname, qname_len);

    // Add question tail (QTYPE=A, QCLASS=IN) using existing structure
    dns_question_tail *qtail = (dns_question_tail *)(qname_start + qname_len);
    qtail->qtype = htons(1);   // A record
    qtail->qclass = htons(1);  // IN class

    *payload_len = DNS_HEADER_SIZE + qname_len + DNS_QUESTION_TAIL_SIZE;

    free(qname);
    return 0;
}

// Domain parsing and extraction functions

// Parse domain from DNS wire format back to string
static int parse_wire_domain(const char *wire_data, size_t wire_len,
                            char *domain, size_t domain_len)
{
    size_t pos = 0;
    size_t out_pos = 0;
    bool first_label = true;

    while (pos < wire_len) {
        uint8_t label_len = (uint8_t)wire_data[pos];

        if (label_len == 0) {
            // End of domain
            break;
        }

        if (label_len >= 0xc0) {
            // Pointer - not supported in our simple parser
            log_debug("dnsresolver", "DNS compression pointer encountered");
            return -1;
        }

        if (pos + 1 + label_len >= wire_len) {
            // Invalid label length
            return -1;
        }

        // Add dot separator (except for first label)
        if (!first_label) {
            if (out_pos >= domain_len - 1) return -1;
            domain[out_pos++] = '.';
        }
        first_label = false;

        // Copy label
        if (out_pos + label_len >= domain_len) return -1;
        memcpy(domain + out_pos, wire_data + pos + 1, label_len);
        out_pos += label_len;
        pos += 1 + label_len;
    }

    domain[out_pos] = '\0';
    return 0;
}

// Extract and validate scan ID from domain
static int extract_scan_id(const char *domain, uint16_t *extracted_scan_id)
{
    // Domain format: timestamp.scanid.target-ip.asertdnsresearch.com
    // Find the second dot to get scan ID
    const char *first_dot = strchr(domain, '.');
    if (!first_dot) return -1;

    const char *second_dot = strchr(first_dot + 1, '.');
    if (!second_dot) return -1;

    // Extract scan ID (4 hex characters)
    size_t scan_id_len = second_dot - (first_dot + 1);
    if (scan_id_len != 4) return -1;

    char scan_id_str[5];
    memcpy(scan_id_str, first_dot + 1, 4);
    scan_id_str[4] = '\0';

    char *endptr;
    unsigned long scan_id_val = strtoul(scan_id_str, &endptr, 16);
    if (*endptr != '\0' || scan_id_val > 0xFFFF) return -1;

    *extracted_scan_id = (uint16_t)scan_id_val;
    return 0;
}

// Extract target IP from domain
// v0.61d: Fixed off-by-one error - IP is between 2nd and 3rd dots, not 3rd and 4th
static int extract_target_ip(const char *domain, uint32_t *extracted_ip)
{
    // Domain format: timestamp.scanid.target-ip.asertdnsresearch.com
    // The IP address is between the 2nd and 3rd dots
    
    // Find the second dot to get target IP section
    const char *first_dot = strchr(domain, '.');
    if (!first_dot) return -1;

    const char *second_dot = strchr(first_dot + 1, '.');
    if (!second_dot) return -1;

    const char *third_dot = strchr(second_dot + 1, '.');
    if (!third_dot) return -1;

    // Extract IP section (between second and third dots)
    // v0.61d fix: Changed from (third_dot + 1) to (second_dot + 1)
    size_t ip_section_len = third_dot - (second_dot + 1);
    if (ip_section_len >= 64) return -1; // Reasonable limit

    char ip_section[64];
    memcpy(ip_section, second_dot + 1, ip_section_len);
    ip_section[ip_section_len] = '\0';

    // Convert dashes back to dots
    for (char *p = ip_section; *p; p++) {
        if (*p == '-') {
            *p = '.';
        }
    }

    // Parse IP address
    struct in_addr addr;
    if (inet_pton(AF_INET, ip_section, &addr) != 1) {
        return -1;
    }

    *extracted_ip = addr.s_addr;
    return 0;
}

// Query section validation
static int validate_query_section(const dns_header *dns_hdr, uint16_t udp_payload_len,
                                 char *query_domain, size_t domain_len)
{
    const char *qname_start = (const char *)dns_hdr + DNS_HEADER_SIZE;
    size_t remaining_len = udp_payload_len - DNS_HEADER_SIZE;

    if (remaining_len < 1) {
        return -1; // No space for qname
    }

    // Calculate actual qname wire length by walking through labels
    size_t qname_wire_len = 0;
    const char *pos = qname_start;
    while (qname_wire_len < remaining_len) {
        uint8_t label_len = (uint8_t)*pos;
        if (label_len == 0) {
            qname_wire_len++; // Include null terminator
            break;
        }
        if (label_len >= 0xc0) {
            return -1; // Compression not supported
        }
        pos += 1 + label_len;
        qname_wire_len += 1 + label_len;
        if (qname_wire_len >= remaining_len) {
            return -1; // Malformed qname
        }
    }

    // Now parse with correct length
    if (parse_wire_domain(qname_start, qname_wire_len, query_domain, domain_len) != 0) {
        return -1;
    }

    // Check if there's space for question tail
    if (qname_wire_len + DNS_QUESTION_TAIL_SIZE > remaining_len) {
        return -1;
    }

    // Validate question tail (QTYPE=A, QCLASS=IN) using correct structure
    const dns_question_tail *qtail = (const dns_question_tail *)(qname_start + qname_wire_len);
    uint16_t qtype = ntohs(qtail->qtype);
    uint16_t qclass = ntohs(qtail->qclass);
    
    if (qtype != 1 || qclass != 1) {
        return -1;
    }

    return 0;
}

// Cleanup function for domain data structure (unchanged from v0.5)
static void cleanup_domain_data(domain_data_t *domain_data)
{
    if (domain_data->query_domain) {
        free(domain_data->query_domain);
        domain_data->query_domain = NULL;
    }
}

// Individual validation step functions

// STEP 1: UDP Structure Validation
static bool validate_step1_udp_structure(const struct ip *ip_hdr, uint32_t len,
                                         struct udphdr **udp_out)
{
    if (ip_hdr->ip_p != IPPROTO_UDP) {
        return false;
    }

    struct udphdr *udp_hdr = get_udp_header(ip_hdr, len);
    if (!udp_hdr) {
        return false;
    }

    // Source port must be 53 (DNS port)
    uint16_t sport = ntohs(udp_hdr->uh_sport);
    uint16_t dport = ntohs(udp_hdr->uh_dport);

    if (sport != DNS_PORT) {
        return false;
    }

    // Destination port must be in ephemeral range (49152-65535)
    if (dport < EPHEMERAL_PORT_MIN) {
        return false;
    }

    *udp_out = udp_hdr;
    return true;
}

// STEP 2: Source IP Validation
static bool validate_step2_source_ip(const struct ip *ip_hdr, uint32_t *src_ip)
{
    *src_ip = ip_hdr->ip_src.s_addr;
    bool allowed = blocklist_is_allowed(*src_ip);
    
    return allowed;
}

// STEP 3: DNS Header Validation
static bool validate_step3_dns_header(const struct udphdr *udp_hdr, UNUSED uint32_t len,
                                      dns_header **dns_out, uint16_t expected_txid)
{
    uint16_t udp_len = ntohs(udp_hdr->uh_ulen);
    uint16_t min_required = sizeof(struct udphdr) + DNS_HEADER_SIZE;
    
    if (udp_len < min_required) {
        return false; // Too short for DNS header
    }

    dns_header *dns_hdr = (dns_header *)((char *)udp_hdr + sizeof(struct udphdr));

    // QR bit must be 1 (response, not query)
    if (dns_hdr->qr != 1) {
        return false;
    }

    // Transaction ID must match expected (bitwise inverse of UDP dest port)
    uint16_t actual_txid = ntohs(dns_hdr->id);
    if (actual_txid != expected_txid) {
        return false;
    }

    // Must have at least one question
    uint16_t qdcount = ntohs(dns_hdr->qdcount);
    if (qdcount == 0) {
        return false;
    }

    *dns_out = dns_hdr;
    return true;
}

// STEP 4: Domain Extraction and Validation
static bool validate_step4_domain_extraction(const dns_header *dns_hdr, 
                                            uint16_t udp_payload_len,
                                            domain_data_t *domain_data)
{
    // Extract query domain from DNS response using existing query section validation
    char query_domain[MAX_DOMAIN_LENGTH];
    
    // Sub-step 4.1: Query section validation
    if (validate_query_section(dns_hdr, udp_payload_len, query_domain,
                              sizeof(query_domain)) != 0) {
        return false;  // Failed to parse query section
    }

    // Sub-step 4.2: Validate base domain format (must end with "asertdnsresearch.com")
    const char *base_domain_pos = strstr(query_domain, BASE_DOMAIN);
    if (!base_domain_pos || strcmp(base_domain_pos, BASE_DOMAIN) != 0) {
        return false;  // Invalid base domain
    }

    // Sub-step 4.3: Extract target IP from domain
    if (extract_target_ip(query_domain, &domain_data->extracted_target_ip) != 0) {
        return false;  // Failed to parse target IP
    }

    // Sub-step 4.4: Extract scan ID from domain
    if (extract_scan_id(query_domain, &domain_data->extracted_scan_id) != 0) {
        return false;  // Failed to parse scan ID
    }

    // Store domain string for later use if needed
    domain_data->query_domain = strdup(query_domain);
    domain_data->valid_base_domain = true;

    return true;
}

// STEP 5: IP Address Correlation
static bool validate_step5_ip_correlation(const struct ip *ip_hdr, 
                                         uint32_t extracted_target_ip)
{
    // Verify response source matches target we queried (from domain)
    bool match = (ip_hdr->ip_src.s_addr == extracted_target_ip);
    
    return match;
}

// STEP 6: Scan Correlation
static bool validate_step6_scan_correlation(uint16_t extracted_scan_id)
{
    // Verify scan ID matches current scan
    bool match = (extracted_scan_id == scan_identifier);
    
    return match;
}

// STEP 7: Open Resolver Confirmation
static bool validate_step7_resolver_check(const dns_header *dns_hdr)
{
    // RA bit must be 1 (recursion available)
    // RCODE must be 0 (no error)
    bool ra_ok = (dns_hdr->ra == 1);
    bool rcode_ok = (dns_hdr->rcode == 0);
    bool overall = ra_ok && rcode_ok;
    
    return overall;
}

// Master validation function that calls all step functions
static validation_result_t validate_dns_response(const struct ip *ip_hdr, uint32_t len,
                                                 uint32_t *src_ip)
{
    validation_result_t result = {0}; // Initialize all fields to false
    struct udphdr *udp_hdr;
    dns_header *dns_hdr;
    domain_data_t domain_data = {0};

    // STEP 1: UDP Structure Validation
    result.step1_udp_structure = validate_step1_udp_structure(ip_hdr, len, &udp_hdr);
    if (!result.step1_udp_structure) {
        goto final_results;  // Early exit, but still log final results
    }

    // STEP 2: Source IP Validation
    result.step2_source_ip = validate_step2_source_ip(ip_hdr, src_ip);
    if (!result.step2_source_ip) {
        goto final_results;
    }

    // Calculate expected transaction ID for Step 3 (same logic as v0.5)
    uint16_t expected_txid = ~ntohs(udp_hdr->uh_dport);

    // STEP 3: DNS Header Validation
    uint16_t udp_payload_len = ntohs(udp_hdr->uh_ulen) - sizeof(struct udphdr);
    result.step3_dns_header = validate_step3_dns_header(udp_hdr, len, &dns_hdr, expected_txid);
    if (!result.step3_dns_header) {
        goto final_results;
    }

    // STEP 4: Domain Extraction and Validation
    result.step4_domain_extraction = validate_step4_domain_extraction(dns_hdr, udp_payload_len, &domain_data);
    if (!result.step4_domain_extraction) {
        cleanup_domain_data(&domain_data);
        goto final_results;
    }

    // STEP 5: IP Address Correlation (using pre-extracted target IP)
    result.step5_ip_correlation = validate_step5_ip_correlation(ip_hdr, domain_data.extracted_target_ip);

    // STEP 6: Scan Correlation (using pre-extracted scan ID)
    result.step6_scan_correlation = validate_step6_scan_correlation(domain_data.extracted_scan_id);

    // STEP 7: Open Resolver Confirmation
    result.step7_resolver_check = validate_step7_resolver_check(dns_hdr);

    // Calculate overall success (ALL steps must pass - same criteria as v0.5)
    result.overall_success = result.step1_udp_structure && 
                            result.step2_source_ip && 
                            result.step3_dns_header &&
                            result.step4_domain_extraction && 
                            result.step5_ip_correlation &&
                            result.step6_scan_correlation && 
                            result.step7_resolver_check;

    cleanup_domain_data(&domain_data);

final_results:
    return result;
}

// Initialize per-thread packet template (unchanged from v0.5)
int dnsresolver_init_perthread(void **arg_ptr)
{
    // Seed random number generator with global generator
    uint32_t seed = aesrand_getword(zconf.aes);
    aesrand_t *aes = aesrand_init_from_seed(seed);
    *arg_ptr = aes;

    return EXIT_SUCCESS;
}

// Core packet generation and preparation functions (unchanged from v0.5)

int dnsresolver_prepare_packet(void *buf, macaddr_t *src, macaddr_t *gw,
                               UNUSED void *arg_ptr)
{
    memset(buf, 0, MAX_PACKET_SIZE);

    // Setup Ethernet header
    struct ether_header *eth_header = (struct ether_header *)buf;
    make_eth_header(eth_header, src, gw);

    // Setup IP header (will be modified per packet)
    struct ip *ip_header = (struct ip *)(&eth_header[1]);
    uint16_t ip_len = htons(sizeof(struct ip) + sizeof(struct udphdr) + MAX_DNS_PAYLOAD_LEN);
    make_ip_header(ip_header, IPPROTO_UDP, ip_len);

    // Setup UDP header (will be modified per packet)
    struct udphdr *udp_header = (struct udphdr *)(&ip_header[1]);
    uint16_t udp_len = sizeof(struct udphdr) + MAX_DNS_PAYLOAD_LEN;
    make_udp_header(udp_header, udp_len);

    return EXIT_SUCCESS;
}

int dnsresolver_make_packet(void *buf, size_t *buf_len, ipaddr_n_t src_ip,
                           ipaddr_n_t dst_ip, port_n_t dport, uint8_t ttl,
                           uint32_t *validation, int probe_num, uint16_t ip_id,
                           void *arg)
{
    struct ether_header *eth_header = (struct ether_header *)buf;
    struct ip *ip_header = (struct ip *)(&eth_header[1]);
    struct udphdr *udp_header = (struct udphdr *)&ip_header[1];
    char *dns_payload = (char *)&udp_header[1];

    // Get per-thread random state
    aesrand_t *aes = (aesrand_t *)arg;

    // Generate ephemeral source port
    uint16_t src_port = get_ephemeral_port(aes);

    // Calculate transaction ID as bitwise inverse of source port
    uint16_t txid = ~src_port;

    // Build query domain for target IP
    char query_domain[MAX_DOMAIN_LENGTH];
    if (build_query_domain(dst_ip, query_domain, sizeof(query_domain)) != 0) {
        log_error("dnsresolver", "Failed to build query domain for target IP");
        return EXIT_FAILURE;
    }

    // Create DNS query
    size_t dns_payload_len;
    if (make_dns_query(dns_payload, query_domain, txid, &dns_payload_len) != 0) {
        log_error("dnsresolver", "Failed to create DNS query");
        return EXIT_FAILURE;
    }

    // Update IP header
    ip_header->ip_src.s_addr = src_ip;
    ip_header->ip_dst.s_addr = dst_ip;
    ip_header->ip_ttl = ttl;
    ip_header->ip_id = ip_id;

    // Calculate correct IP length
    uint16_t total_ip_len = sizeof(struct ip) + sizeof(struct udphdr) + dns_payload_len;
    ip_header->ip_len = htons(total_ip_len);

    // Update UDP header - HARDCODED to port 53, ignoring dport parameter
    udp_header->uh_sport = htons(src_port);
    udp_header->uh_dport = htons(DNS_PORT);  // Always 53, ignore dport parameter

    // Calculate correct UDP length
    uint16_t udp_len = sizeof(struct udphdr) + dns_payload_len;
    udp_header->uh_ulen = htons(udp_len);

    // Calculate IP checksum only (UDP checksum left as 0 per existing modules)
    ip_header->ip_sum = 0;
    ip_header->ip_sum = zmap_ip_checksum((unsigned short *)ip_header);

    // Set total packet length
    *buf_len = sizeof(struct ether_header) + total_ip_len;

    return EXIT_SUCCESS;
}

void dnsresolver_print_packet(FILE *fp, void *packet)
{
    struct ether_header *ethh = (struct ether_header *)packet;
    struct ip *iph = (struct ip *)&ethh[1];
    struct udphdr *udph = (struct udphdr *)(&iph[1]);

    fprintf(fp, "dnsresolver { source: %u | dest: %u | checksum: %#04X }\n",
            ntohs(udph->uh_sport), ntohs(udph->uh_dport), ntohs(udph->uh_sum));
    fprintf_ip_header(fp, iph);
    fprintf_eth_header(fp, ethh);
    fprintf(fp, PRINT_PACKET_SEP);
}

// Module initialization and cleanup functions

int dnsresolver_global_initialize(struct state_conf *conf)
{
    // Initialize scan identifier
    scan_identifier = 0;

    // Parse probe arguments if provided
    if (conf->probe_args) {
        // Parse scan identifier from probe args
        // Format: scanid:XXXX
        if (strncmp(conf->probe_args, "scanid:", 7) == 0) {
            char *endptr;
            unsigned long scan_id_val = strtoul(conf->probe_args + 7, &endptr, 16);
            if (*endptr == '\0' && scan_id_val <= 0xFFFF) {
                scan_identifier = (uint16_t)scan_id_val;
                log_info("dnsresolver", "Using scan identifier: %04x", scan_identifier);
            } else {
                log_fatal("dnsresolver", "Invalid scan identifier format. Use scanid:XXXX (hex)");
                return EXIT_FAILURE;
            }
        } else {
            log_fatal("dnsresolver", "Invalid probe args. Use scanid:XXXX");
            return EXIT_FAILURE;
        }
    } else {
        // Auto-generate pseudorandom scan identifier (independent of ZMap seed)
        struct timeval tv;
        gettimeofday(&tv, NULL);
        uint32_t random_seed = (uint32_t)(tv.tv_sec ^ tv.tv_usec ^ getpid());
        aesrand_t *tmp_aes = aesrand_init_from_seed(random_seed);
        scan_identifier = (uint16_t)(aesrand_getword(tmp_aes) & 0xFFFF);
        free(tmp_aes);
        log_info("dnsresolver", "Auto-generated scan identifier: %04x", scan_identifier);
    }

    // Calculate number of source ports (inherited from zmap framework)
    num_ports = conf->source_port_last - conf->source_port_first + 1;

    // Calculate maximum packet length
    // Ethernet + IP + UDP + DNS header + max domain + question tail
    size_t max_domain_wire = MAX_DOMAIN_LENGTH + 1; // +1 for wire format overhead
    size_t max_dns_payload = DNS_HEADER_SIZE + max_domain_wire + DNS_QUESTION_TAIL_SIZE;

    module_dnsresolver.max_packet_length = sizeof(struct ether_header) +
                                          sizeof(struct ip) +
                                          sizeof(struct udphdr) +
                                          max_dns_payload;

    assert(module_dnsresolver.max_packet_length <= MAX_PACKET_SIZE);

    log_info("dnsresolver", "DNS resolver detection module v0.68 initialized");
    log_info("dnsresolver", "Base domain: %s", BASE_DOMAIN);
    log_info("dnsresolver", "Max packet length: %zu bytes", module_dnsresolver.max_packet_length);

    return EXIT_SUCCESS;
}

int dnsresolver_global_cleanup(UNUSED struct state_conf *zconf,
                              UNUSED struct state_send *zsend,
                              UNUSED struct state_recv *zrecv)
{
    if (template_packet) {
        free(template_packet);
        template_packet = NULL;
    }

    log_info("dnsresolver", "DNS resolver detection module v0.68 cleanup completed");
    return EXIT_SUCCESS;
}

// Main packet processing and validation functions

int dnsresolver_validate_packet(const struct ip *ip_hdr, uint32_t len,
                                uint32_t *src_ip, UNUSED uint32_t *validation,
                                UNUSED const struct port_conf *ports)
{
    // Completely ignore non-UDP packets (including ICMP)
    if (ip_hdr->ip_p != IPPROTO_UDP) {
        return PACKET_INVALID;
    }

    struct udphdr *udp_hdr = get_udp_header(ip_hdr, len);
    if (!udp_hdr) {
        return PACKET_INVALID;  // Malformed UDP
    }

    // Only allow packets from DNS port 53
    if (ntohs(udp_hdr->uh_sport) != DNS_PORT) {
        return PACKET_INVALID;
    }

    // Set src_ip for process_packet (required by ZMap framework)
    *src_ip = ip_hdr->ip_src.s_addr;
    
    // Let ALL UDP/53 packets reach process_packet for logging
    // (validation moved to process_packet function)
    return PACKET_VALID;
}

void dnsresolver_process_packet(const u_char *packet, uint32_t len, fieldset_t *fs,
                               UNUSED uint32_t *validation, UNUSED struct timespec ts)
{
    struct ip *ip_hdr = (struct ip *)&packet[sizeof(struct ether_header)];
    
    // Only process UDP packets - all others completely ignored (no logging)
    if (ip_hdr->ip_p != IPPROTO_UDP) {
        return;  // No logging for non-UDP
    }

    struct udphdr *udp_hdr = get_udp_header(ip_hdr, len);
    if (!udp_hdr) {
        return;  // Malformed UDP
    }

    // Only process packets from DNS port 53
    if (ntohs(udp_hdr->uh_sport) != DNS_PORT) {
        return;  // Not from DNS port
    }

    // Run complete validation (SAME logic as v0.5, just moved from validate_packet)
    uint32_t src_ip;
    validation_result_t result = validate_dns_response(ip_hdr, len, &src_ip);

    // v0.6 CHANGE: Remove custom saddr field population
    // ZMap framework handles saddr field automatically
    
    // Standard classification and success fields
    fs_add_constchar(fs, "classification", "dns");
    fs_add_bool(fs, "success", result.overall_success);
    
    // Standard UDP fields
    fs_add_uint64(fs, "sport", ntohs(udp_hdr->uh_sport));
    fs_add_uint64(fs, "dport", ntohs(udp_hdr->uh_dport));
    fs_add_uint64(fs, "udp_pkt_size", ntohs(udp_hdr->uh_ulen));
    
    // DNS response payload as binary data
    uint16_t dns_payload_len = ntohs(udp_hdr->uh_ulen) - sizeof(struct udphdr);
    char *dns_payload = (char *)udp_hdr + sizeof(struct udphdr);
    fs_add_binary(fs, "data", dns_payload_len, dns_payload, 0);
}

// v0.6 CHANGE: Removed custom saddr field definition to eliminate field registration conflict
static fielddef_t fields[] = {
    CLASSIFICATION_SUCCESS_FIELDSET_FIELDS,  // Provides: classification, success
    {.name = "sport", .type = "int", .desc = "UDP source port"},
    {.name = "dport", .type = "int", .desc = "UDP destination port"},
    {.name = "udp_pkt_size", .type = "int", .desc = "UDP packet length"},
    {.name = "data", .type = "binary", .desc = "DNS response payload"},
};

// Module definition
probe_module_t module_dnsresolver = {
    .name = "dnsresolver",
    .max_packet_length = 0, // Set in global_initialize
    .pcap_filter = "udp port 53",
    .pcap_snaplen = 1500,
    .port_args = 0, // No port arguments - hardcoded to 53
    .global_initialize = &dnsresolver_global_initialize,
    .thread_initialize = &dnsresolver_init_perthread,
    .prepare_packet = &dnsresolver_prepare_packet,
    .make_packet = &dnsresolver_make_packet,
    .print_packet = &dnsresolver_print_packet,
    .validate_packet = &dnsresolver_validate_packet,
    .process_packet = &dnsresolver_process_packet,
    .close = &dnsresolver_global_cleanup,
    .output_type = OUTPUT_TYPE_STATIC,
    .fields = fields,
    .numfields = sizeof(fields) / sizeof(fields[0]),
    .helptext =
        "DNS Resolver Detection Module v0.68\n"
        "\n"
        "This module identifies open DNS resolvers that can be exploited for DNS\n"
        "reflection/amplification attacks. It sends specially crafted DNS queries\n"
        "with encoded correlation data to test recursive resolution capabilities.\n"
        "\n"
        "v0.68 Changes:\n"
        "  - Fixed timestamp encoding to use microseconds since epoch\n"
        "  - Removed incorrect bit-shifting that caused future dates\n"
        "  - Timestamps now properly represent actual time of packet generation\n"
        "\n"
        "v0.67 Changes:\n"
        "  - Fixed timestamp encoding format specifier from %016lx to %016PRIx64\n"
        "  - Added inttypes.h include for portable 64-bit formatting\n"
        "  - Ensures full 64-bit timestamp is properly encoded on all platforms\n"
        "\n"
        "v0.66 Changes:\n"
        "  - Removed app_success field entirely\n"
        "  - Monitor now correctly shows success count instead of app_success\n"
        "  - No functional changes to validation logic\n"
        "\n"
        "v0.65 Changes:\n"
        "  - Removed debug logging added in v0.6d/v0.61d\n"
        "  - Production-ready version with IP extraction fix\n"
        "  - No functional changes from v0.61d\n"
        "\n"
        "v0.61d Changes:\n"
        "  - Fixed off-by-one error in extract_target_ip() function\n"
        "  - IP address is extracted from between 2nd and 3rd dots, not 3rd and 4th\n"
        "  - This fix resolves Step 4.3 validation failures in target IP extraction\n"
        "  - All debug logging from v0.6d preserved\n"
        "\n"
        "v0.6d Changes:\n"
        "  - Added comprehensive debug logging throughout validation pipeline\n"
        "  - Added debug output for validation-to-logging handoff\n"
        "  - Added granular sub-step logging for complex validation operations\n"
        "  - Debug output uses [DNS_DEBUG] prefix for easy filtering\n"
        "\n"
        "v0.6 Changes:\n"
        "  - Fixed field registration conflict by removing custom saddr field definition\n"
        "  - Eliminated memory corruption causing app_success field name corruption\n"
        "  - Restored proper validation result logging for confirmed open resolvers\n"
        "  - Aligned field definitions with standard ZMap module patterns\n"
        "\n"
        "v0.5 Changes:\n"
        "  - Fixed saddr field formatting from integer to readable IP address string\n"
        "  - Changed saddr field type from \"int\" to \"string\" in field definitions\n"
        "  - Updated saddr field population to use inet_ntoa() for human-readable format\n"
        "\n"
        "v0.4 Changes:\n"
        "  - Converted to standard ZMap logging routines\n"
        "  - Logs ALL UDP responses from port 53 (successful and failed)\n"
        "  - Replaced custom fields with standard ZMap fields\n"
        "  - Enabled runtime filtering through success flags\n"
        "  - Moved validation logic from validate_packet to process_packet\n"
        "\n"
        "IMPORTANT: This module ignores the -p/--target-port flag. All DNS queries\n"
        "are automatically sent to UDP port 53. Non-UDP packets are completely ignored.\n"
        "\n"
        "The module sends DNS A record queries with domain names containing encoded\n"
        "timestamps, scan identifiers, and target IP addresses. All responses from\n"
        "port 53 are logged with success flags indicating validation results.\n"
        "\n"
        "Usage:\n"
        "  zmap -M dnsresolver [target_list]              # Auto-generated scan ID\n"
        "  zmap -M dnsresolver --probe-args=scanid:1234 [target_list]  # Custom scan ID\n"
        "\n"
        "Note: The -p flag has no effect with this module. All queries target UDP/53.\n"
        "\n"
        "Output Fields (Standard ZMap Format):\n"
        "  - saddr: Source IP address (framework-provided)\n"
        "  - classification: Always 'dns' for DNS responses\n"
        "  - success: 1 for confirmed open resolvers, 0 for validation failures\n"
        "  - sport: UDP source port (always 53)\n"
        "  - dport: UDP destination port (ephemeral)\n"
        "  - udp_pkt_size: UDP packet length in bytes\n"
        "  - data: Raw DNS response payload (binary)\n"
        "\n"
        "Runtime Filtering Examples:\n"
        "  --output-filter=\"success = 1\"               # Only confirmed open resolvers\n"
        "  --output-filter=\"success = 0\"               # Only validation failures\n"
        "  (No filter)                                 # All DNS responses\n"
        "\n"
        "7-Step Validation Pipeline (Preserved from v0.5):\n"
        "  1. UDP structure validation (port 53 source, ephemeral destination)\n"
        "  2. Source IP blocklist validation\n"
        "  3. DNS header validation (QR=1, correct transaction ID)\n"
        "  4. Domain extraction and base domain validation\n"
        "  5. IP address correlation (response source matches encoded target)\n"
        "  6. Scan correlation (scan ID matches current scan)\n"
        "  7. Open resolver confirmation (RA=1, RCODE=0)\n"
        "\n"
        "Success requires all seven steps to pass, confirming an abusable open resolver.\n"
        "\n"
        "Packet Processing:\n"
        "  - Logs ALL UDP responses from port 53\n"
        "  - Non-UDP packets completely ignored (no logging)\n"
        "  - Non-port-53 UDP packets completely ignored (no logging)\n"
        "  - Success flags indicate validation results\n"
        "\n"
        "The module is designed for defensive purposes to identify misconfigured\n"
        "resolvers for remediation and to create filter lists for blocking\n"
        "attack traffic from these sources.\n"
};
