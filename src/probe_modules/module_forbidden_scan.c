/*
 * ZMap Copyright 2024 Regents of the University of Michigan
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not
 * use this file except in compliance with the License. You may obtain a copy
 * of the License at http://www.apache.org/licenses/LICENSE-2.0
 */

// probe module for performing TCP forbidden payload scans

#include <stdbool.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <unistd.h>
#include <string.h>
#include <assert.h>

#include "../../lib/includes.h"
#include "../fieldset.h"
#include "logger.h"
#include "probe_modules.h"
#include "packet.h"
#include "validate.h"
#include "module_tcp_synscan.h"

#define DEFAULT_HOST "example.com"
#define PAYLOAD_FMT "GET / HTTP/1.1\r\nHost: %s\r\n\r\n"
#define MAX_PAYLOAD_LEN 512

#define ETHER_LEN sizeof(struct ether_header)
#define IP_LEN sizeof(struct ip)
#define TCP_LEN sizeof(struct tcphdr)

// probe 0 opens the connection, probe 1 carries the request
#define PROBE_SYN 0
#define REQUIRED_PACKET_STREAMS 2

#define SOURCE_PORT_VALIDATION_MODULE_DEFAULT true; // default to validating source port
static bool should_validate_src_port = SOURCE_PORT_VALIDATION_MODULE_DEFAULT

probe_module_t module_forbidden_scan;

static uint16_t num_source_ports;
static char payload[MAX_PAYLOAD_LEN];
static size_t payload_len;

// Rejects anything that could smuggle extra headers into the request line.
static bool host_is_valid(const char *host)
{
	if (*host == '\0') {
		return false;
	}
	for (const char *c = host; *c; c++) {
		if (*c <= ' ' || *c > '~') {
			return false;
		}
	}
	return true;
}

static int forbiddenscan_global_initialize(struct state_conf *state)
{
	num_source_ports =
	    state->source_port_last - state->source_port_first + 1;
	if (state->validate_source_port_override ==
	    VALIDATE_SRC_PORT_DISABLE_OVERRIDE) {
		log_debug("forbidden_scan", "disabling source port validation");
		should_validate_src_port = false;
	}
	if (state->packet_streams != REQUIRED_PACKET_STREAMS) {
		log_fatal(
		    "forbidden_scan",
		    "this module sends a two-packet sequence and must be run "
		    "with \"--probes=%d\"",
		    REQUIRED_PACKET_STREAMS);
	}
	const char *host = state->probe_args ? state->probe_args : DEFAULT_HOST;
	if (!host_is_valid(host)) {
		log_fatal("forbidden_scan",
			  "--probe-args must be a bare host name, e.g. "
			  "\"--probe-args=example.com\"");
	}
	int written = snprintf(payload, sizeof(payload), PAYLOAD_FMT, host);
	if (written < 0 || (size_t)written >= sizeof(payload)) {
		log_fatal("forbidden_scan",
			  "--probe-args host name is too long");
	}
	payload_len = (size_t)written;
	module_forbidden_scan.max_packet_length =
	    ETHER_LEN + IP_LEN + TCP_LEN + payload_len;
	return EXIT_SUCCESS;
}

static int forbiddenscan_prepare_packet(void *buf, macaddr_t *src,
					macaddr_t *gw, UNUSED void *arg_ptr)
{
	memset(buf, 0, MAX_PACKET_SIZE);
	struct ether_header *eth_header = (struct ether_header *)buf;
	make_eth_header(eth_header, src, gw);
	struct ip *ip_header = (struct ip *)(&eth_header[1]);
	make_ip_header(ip_header, IPPROTO_TCP, htons(IP_LEN + TCP_LEN));
	struct tcphdr *tcp_header = (struct tcphdr *)(&ip_header[1]);
	make_tcp_header(tcp_header, TH_SYN);
	return EXIT_SUCCESS;
}

static int forbiddenscan_make_packet(void *buf, size_t *buf_len,
				     ipaddr_n_t src_ip, ipaddr_n_t dst_ip,
				     port_n_t dport, uint8_t ttl,
				     uint32_t *validation, int probe_num,
				     uint16_t ip_id, UNUSED void *arg)
{
	struct ether_header *eth_header = (struct ether_header *)buf;
	struct ip *ip_header = (struct ip *)(&eth_header[1]);
	struct tcphdr *tcp_header = (struct tcphdr *)(&ip_header[1]);

	ip_header->ip_src.s_addr = src_ip;
	ip_header->ip_dst.s_addr = dst_ip;
	ip_header->ip_ttl = ttl;
	ip_header->ip_id = ip_id;

	// both probes must share a source port to look like a single flow
	tcp_header->th_sport =
	    htons(get_src_port(num_source_ports, PROBE_SYN, validation));
	tcp_header->th_dport = dport;

	size_t tcp_len;
	if (probe_num == PROBE_SYN) {
		tcp_header->th_flags = TH_SYN;
		tcp_header->th_seq = ntohl(htonl(validation[0]) - 1);
		tcp_header->th_ack = 0;
		tcp_len = TCP_LEN;
	} else {
		tcp_header->th_flags = TH_PUSH | TH_ACK;
		tcp_header->th_seq = validation[0];
		tcp_header->th_ack = validation[2];
		memcpy(&tcp_header[1], payload, payload_len);
		tcp_len = TCP_LEN + payload_len;
	}

	ip_header->ip_len = htons((uint16_t)(IP_LEN + tcp_len));
	// checksum value must be zero when calculating the packet's checksum
	tcp_header->th_sum = 0;
	tcp_header->th_sum =
	    tcp_checksum((unsigned short)tcp_len, ip_header->ip_src.s_addr,
			 ip_header->ip_dst.s_addr, tcp_header);
	ip_header->ip_sum = 0;
	ip_header->ip_sum = zmap_ip_checksum((unsigned short *)ip_header);

	*buf_len = ETHER_LEN + IP_LEN + tcp_len;
	return EXIT_SUCCESS;
}

static int forbiddenscan_validate_packet(const struct ip *ip_hdr, uint32_t len,
					 uint32_t *src_ip, uint32_t *validation,
					 const struct port_conf *ports)
{
	if (ip_hdr->ip_p != IPPROTO_TCP) {
		return PACKET_INVALID;
	}
	struct tcphdr *tcp = get_tcp_header(ip_hdr, len);
	if (!tcp) {
		return PACKET_INVALID;
	}
	port_h_t sport = ntohs(tcp->th_sport);
	port_h_t dport = ntohs(tcp->th_dport);
	if (should_validate_src_port && !check_src_port(sport, ports)) {
		return PACKET_INVALID;
	}
	if (!check_dst_port(dport, num_source_ports, validation)) {
		return PACKET_INVALID;
	}
	// check whether we'll ever send to this IP during the scan
	if (!blocklist_is_allowed(*src_ip)) {
		return PACKET_INVALID;
	}
	// accept an ack of the SYN, of the request, or a reset bearing our ack
	uint32_t ack = ntohl(tcp->th_ack);
	uint32_t seq = ntohl(tcp->th_seq);
	uint32_t sent_seq = ntohl(validation[0]);
	if (ack != sent_seq && ack != sent_seq + 1 &&
	    ack != sent_seq + payload_len && seq != ntohl(validation[2])) {
		return PACKET_INVALID;
	}
	return PACKET_VALID;
}

static void forbiddenscan_process_packet(const u_char *packet, uint32_t len,
					 fieldset_t *fs, uint32_t *validation,
					 UNUSED struct timespec ts)
{
	struct ip *ip_hdr = get_ip_header(packet, len);
	assert(ip_hdr);
	struct tcphdr *tcp = get_tcp_header(ip_hdr, len);
	assert(tcp);

	uint16_t ip_len = ntohs(ip_hdr->ip_len);
	int payloadlen = (int)ip_len - (4 * ip_hdr->ip_hl) - (4 * tcp->th_off);
	if (payloadlen < 0) {
		payloadlen = 0;
	}

	fs_add_uint64(fs, "sport", (uint64_t)ntohs(tcp->th_sport));
	fs_add_uint64(fs, "dport", (uint64_t)ntohs(tcp->th_dport));
	fs_add_uint64(fs, "seqnum", (uint64_t)ntohl(tcp->th_seq));
	fs_add_uint64(fs, "acknum", (uint64_t)ntohl(tcp->th_ack));
	fs_add_uint64(fs, "window", (uint64_t)ntohs(tcp->th_win));
	fs_add_uint64(fs, "payloadlen", (uint64_t)payloadlen);
	fs_add_uint64(fs, "len", (uint64_t)(ip_len + ETHER_LEN));
	fs_add_uint64(fs, "flags", (uint64_t)tcp->th_flags);

	// Distinguishes a reply to the request from a reply to the bare SYN.
	uint32_t ack = ntohl(tcp->th_ack);
	uint32_t seq = ntohl(tcp->th_seq);
	uint32_t sent_seq = ntohl(validation[0]);
	if (ack == sent_seq + payload_len) {
		fs_add_uint64(fs, "validation_type", 0);
	} else if (ack == sent_seq || ack == sent_seq + 1 ||
		   seq == ntohl(validation[2])) {
		fs_add_uint64(fs, "validation_type", 1);
	} else {
		fs_add_uint64(fs, "validation_type", 2);
	}

	if (tcp->th_flags & TH_RST) {
		fs_add_constchar(fs, "classification", "rst");
	} else if (payloadlen > 0) {
		fs_add_constchar(fs, "classification", "data");
	} else if ((tcp->th_flags & TH_SYN) && (tcp->th_flags & TH_ACK)) {
		fs_add_constchar(fs, "classification", "synack");
	} else {
		fs_add_constchar(fs, "classification", "other");
	}
	// every validated response is reported; resets are a signal, not a failure
	fs_add_bool(fs, "success", 1);
}

static fielddef_t fields[] = {
    {.name = "sport", .type = "int", .desc = "TCP source port"},
    {.name = "dport", .type = "int", .desc = "TCP destination port"},
    {.name = "seqnum", .type = "int", .desc = "TCP sequence number"},
    {.name = "acknum", .type = "int", .desc = "TCP acknowledgement number"},
    {.name = "window", .type = "int", .desc = "TCP window"},
    {.name = "payloadlen", .type = "int", .desc = "TCP payload length"},
    {.name = "len", .type = "int", .desc = "packet size"},
    {.name = "flags", .type = "int", .desc = "TCP flags"},
    {.name = "validation_type",
     .type = "int",
     .desc =
	 "0 if the response acknowledges the request, 1 if it only acknowledges the SYN, 2 otherwise"},
    CLASSIFICATION_SUCCESS_FIELDSET_FIELDS,
};

probe_module_t module_forbidden_scan = {
    .name = "forbidden_scan",
    .max_packet_length = ETHER_LEN + IP_LEN + TCP_LEN + MAX_PAYLOAD_LEN,
    .pcap_filter = "tcp",
    .pcap_snaplen = 96,
    .port_args = 1,
    .global_initialize = &forbiddenscan_global_initialize,
    .prepare_packet = &forbiddenscan_prepare_packet,
    .make_packet = &forbiddenscan_make_packet,
    .print_packet = &synscan_print_packet,
    .process_packet = &forbiddenscan_process_packet,
    .validate_packet = &forbiddenscan_validate_packet,
    .close = NULL,
    .helptext =
	"Probe module that sends a TCP SYN immediately followed by a PSH/ACK "
	"carrying an HTTP request, without waiting for the handshake to "
	"complete. Used to observe how on-path middleboxes react to a "
	"particular Host header. Must be run with \"--probes=2\"; probe 0 is "
	"the SYN and probe 1 is the request. Use \"--probe-args=<host>\" to set "
	"the Host header (default: " DEFAULT_HOST "). Responses are classified "
	"as data, rst, synack, or other; all validated responses are reported "
	"as successes so that injected resets are not filtered out.",
    .output_type = OUTPUT_TYPE_STATIC,
    .fields = fields,
    .numfields = sizeof(fields) / sizeof(fields[0])};
