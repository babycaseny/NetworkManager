/*
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the
 * Free Software Foundation, Inc., 51 Franklin Street, Fifth Floor,
 * Boston, MA 02110-1301 USA.
 *
 * (C) Copyright 2019 Red Hat, Inc.
 */

#ifndef __NETWORKMANAGER_DHCP_OPTIONS_H__
#define __NETWORKMANAGER_DHCP_OPTIONS_H__

#define DHCP_OPTION_PAD                              0
#define DHCP_OPTION_SUBNET_MASK                      1
#define DHCP_OPTION_TIME_OFFSET                      2
#define DHCP_OPTION_ROUTER                           3
#define DHCP_OPTION_TIME_SERVERS                     4
#define DHCP_OPTION_IEN116_NAME_SERVERS              5
#define DHCP_OPTION_DOMAIN_NAME_SERVER               6
#define DHCP_OPTION_LOG_SERVERS                      7
#define DHCP_OPTION_COOKIE_SERVERS                   8
#define DHCP_OPTION_LPR_SERVERS                      9
#define DHCP_OPTION_IMPRESS_SERVERS                 10
#define DHCP_OPTION_RESOURCE_LOCATION_SERVERS       11
#define DHCP_OPTION_HOST_NAME                       12
#define DHCP_OPTION_BOOT_FILE_SIZE                  13
#define DHCP_OPTION_MERIT_DUMP                      14
#define DHCP_OPTION_DOMAIN_NAME                     15
#define DHCP_OPTION_SWAP_SERVER                     16
#define DHCP_OPTION_ROOT_PATH                       17
#define DHCP_OPTION_EXTENSIONS_PATH                 18
#define DHCP_OPTION_ENABLE_IP_FORWARDING            19
#define DHCP_OPTION_ENABLE_SRC_ROUTING              20
#define DHCP_OPTION_POLICY_FILTER                   21
#define DHCP_OPTION_INTERFACE_MDR                   22
#define DHCP_OPTION_INTERFACE_TTL                   23
#define DHCP_OPTION_INTERFACE_MTU_AGING_TIMEOUT     24
#define DHCP_OPTION_PATH_MTU_PLATEAU_TABLE          25
#define DHCP_OPTION_INTERFACE_MTU                   26
#define DHCP_OPTION_ALL_SUBNETS_LOCAL               27
#define DHCP_OPTION_BROADCAST                       28
#define DHCP_OPTION_PERFORM_MASK_DISCOVERY          29
#define DHCP_OPTION_MASK_SUPPLIER                   30
#define DHCP_OPTION_ROUTER_DISCOVERY                31
#define DHCP_OPTION_ROUTER_SOLICITATION_ADDR        32
#define DHCP_OPTION_STATIC_ROUTE                    33
#define DHCP_OPTION_TRAILER_ENCAPSULATION           34
#define DHCP_OPTION_ARP_CACHE_TIMEOUT               35
#define DHCP_OPTION_IEEE802_3_ENCAPSULATION         36
#define DHCP_OPTION_DEFAULT_TCP_TTL                 37
#define DHCP_OPTION_TCP_KEEPALIVE_INTERVAL          38
#define DHCP_OPTION_TCP_KEEPALIVE_GARBAGE           39
#define DHCP_OPTION_NIS_DOMAIN                      40
#define DHCP_OPTION_NIS_SERVERS                     41
#define DHCP_OPTION_NTP_SERVER                      42
#define DHCP_OPTION_VENDOR_SPECIFIC                 43
#define DHCP_OPTION_NETBIOS_NAMESERVER              44
#define DHCP_OPTION_NETBIOS_DD_SERVER               45
#define DHCP_OPTION_FONT_SERVERS                    48
#define DHCP_OPTION_X_DISPLAY_MANAGER               49
#define DHCP_OPTION_IP_ADDRESS_LEASE_TIME           51
#define DHCP_OPTION_SERVER_ID                       54
#define DHCP_OPTION_RENEWAL_T1_TIME                 58
#define DHCP_OPTION_REBINDING_T2_TIME               59
#define DHCP_OPTION_NWIP_DOMAIN                     62
#define DHCP_OPTION_NWIP_SUBOPTIONS                 63
#define DHCP_OPTION_NISPLUS_DOMAIN                  64
#define DHCP_OPTION_NISPLUS_SERVERS                 65
#define DHCP_OPTION_TFTP_SERVER_NAME                66
#define DHCP_OPTION_BOOTFILE_NAME                   67
#define DHCP_OPTION_MOBILE_IP_HOME_AGENT            68
#define DHCP_OPTION_SMTP_SERVER                     69
#define DHCP_OPTION_POP_SERVER                      70
#define DHCP_OPTION_NNTP_SERVER                     71
#define DHCP_OPTION_WWW_SERVER                      72
#define DHCP_OPTION_FINGER_SERVER                   73
#define DHCP_OPTION_IRC_SERVER                      74
#define DHCP_OPTION_STREETTALK_SERVER               75
#define DHCP_OPTION_STREETTALK_DIR_ASSIST_SERVER    76
#define DHCP_OPTION_SLP_DIRECTORY_AGENT             78
#define DHCP_OPTION_SLP_SERVICE_SCOPE               79
#define DHCP_OPTION_RELAY_AGENT_INFORMATION         82
#define DHCP_OPTION_NDS_SERVERS                     85
#define DHCP_OPTION_NDS_TREE_NAME                   86
#define DHCP_OPTION_NDS_CONTEXT                     87
#define DHCP_OPTION_BCMS_CONTROLLER_NAMES           88
#define DHCP_OPTION_BCMS_CONTROLLER_ADDRESS         89
#define DHCP_OPTION_CLIENT_LAST_TRANSACTION         91
#define DHCP_OPTION_ASSOCIATED_IP                   92
#define DHCP_OPTION_PXE_SYSTEM_TYPE                 93
#define DHCP_OPTION_PXE_INTERFACE_ID                94
#define DHCP_OPTION_PXE_CLIENT_ID                   97
#define DHCP_OPTION_UAP_SERVERS                     98
#define DHCP_OPTION_GEOCONF_CIVIC                   99
#define DHCP_OPTION_NEW_TZDB_TIMEZONE              101
#define DHCP_OPTION_NETINFO_SERVER_ADDRESS         112
#define DHCP_OPTION_NETINFO_SERVER_TAG             113
#define DHCP_OPTION_DEFAULT_URL                    114
#define DHCP_OPTION_AUTO_CONFIG                    116
#define DHCP_OPTION_NAME_SERVICE_SEARCH            117
#define DHCP_OPTION_SUBNET_SELECTION               118
#define DHCP_OPTION_DOMAIN_SEARCH_LIST             119
#define DHCP_OPTION_CLASSLESS_STATIC_ROUTE         121
#define DHCP_OPTION_VIVCO                          124
#define DHCP_OPTION_VIVSO                          125
#define DHCP_OPTION_PANA_AGENT                     136
#define DHCP_OPTION_V4_LOST                        137
#define DHCP_OPTION_SIP_UA_CS_DOMAINS              141
#define DHCP_OPTION_IPV4_ADDRESS_ANDSF             142
#define DHCP_OPTION_RDNSS_SELECTION                146
#define DHCP_OPTION_TFTP_SERVER_ADDRESS            150
#define DHCP_OPTION_V4_PORTPARAMS                  159
#define DHCP_OPTION_V4_CAPTIVE_PORTAL              160
#define DHCP_OPTION_LOADER_CONFIGFILE              209
#define DHCP_OPTION_LOADER_PATHPREFIX              210
#define DHCP_OPTION_LOADER_REBOOTTIME              211
#define DHCP_OPTION_OPTION_6RD                     212
#define DHCP_OPTION_V4_ACCESS_DOMAIN               213
#define DHCP_OPTION_PRIVATE_224                    224
#define DHCP_OPTION_PRIVATE_225                    225
#define DHCP_OPTION_PRIVATE_226                    226
#define DHCP_OPTION_PRIVATE_227                    227
#define DHCP_OPTION_PRIVATE_228                    228
#define DHCP_OPTION_PRIVATE_229                    229
#define DHCP_OPTION_PRIVATE_230                    230
#define DHCP_OPTION_PRIVATE_231                    231
#define DHCP_OPTION_PRIVATE_232                    232
#define DHCP_OPTION_PRIVATE_233                    233
#define DHCP_OPTION_PRIVATE_234                    234
#define DHCP_OPTION_PRIVATE_235                    235
#define DHCP_OPTION_PRIVATE_236                    236
#define DHCP_OPTION_PRIVATE_237                    237
#define DHCP_OPTION_PRIVATE_238                    238
#define DHCP_OPTION_PRIVATE_239                    239
#define DHCP_OPTION_PRIVATE_240                    240
#define DHCP_OPTION_PRIVATE_241                    241
#define DHCP_OPTION_PRIVATE_242                    242
#define DHCP_OPTION_PRIVATE_243                    243
#define DHCP_OPTION_PRIVATE_244                    244
#define DHCP_OPTION_PRIVATE_245                    245
#define DHCP_OPTION_PRIVATE_246                    246
#define DHCP_OPTION_PRIVATE_247                    247
#define DHCP_OPTION_PRIVATE_248                    248
#define DHCP_OPTION_PRIVATE_CLASSLESS_STATIC_ROUTE 249
#define DHCP_OPTION_PRIVATE_250                    250
#define DHCP_OPTION_PRIVATE_251                    251
#define DHCP_OPTION_PRIVATE_PROXY_AUTODISCOVERY    252
#define DHCP_OPTION_PRIVATE_253                    253
#define DHCP_OPTION_PRIVATE_254                    254
#define DHCP_OPTION_END                            255

#define DHCP6_OPTION_CLIENTID            1
#define DHCP6_OPTION_SERVERID            2
#define DHCP6_OPTION_DNS_SERVERS        23
#define DHCP6_OPTION_DOMAIN_LIST        24
#define DHCP6_OPTION_SNTP_SERVERS       31

/* Internal values */
#define DHCP_OPTION_IP_ADDRESS       1024
#define DHCP_OPTION_EXPIRY           1025

#define DHCP6_OPTION_IP_ADDRESS      1026
#define DHCP6_OPTION_PREFIXLEN       1027
#define DHCP6_OPTION_PREFERRED_LIFE  1028
#define DHCP6_OPTION_MAX_LIFE        1029
#define DHCP6_OPTION_STARTS          1030
#define DHCP6_OPTION_LIFE_STARTS     1031
#define DHCP6_OPTION_RENEW           1032
#define DHCP6_OPTION_REBIND          1033
#define DHCP6_OPTION_IAID            1034

typedef struct {
	const char *name;
	uint16_t option_num;
	bool include;
} ReqOption;

#define REQPREFIX "requested_"

#define REQ(_num, _name, _include) \
	{ \
		.name = REQPREFIX""_name, \
		.option_num = _num, \
		.include = _include, \
	}

static const ReqOption dhcp4_requests[] = {
	REQ (DHCP_OPTION_SUBNET_MASK,                       "subnet_mask",                     TRUE ),
	REQ (DHCP_OPTION_TIME_OFFSET,                       "time_offset",                     TRUE ),
	REQ (DHCP_OPTION_DOMAIN_NAME_SERVER,                "domain_name_servers",             TRUE ),
	REQ (DHCP_OPTION_HOST_NAME,                         "host_name",                       TRUE ),
	REQ (DHCP_OPTION_DOMAIN_NAME,                       "domain_name",                     TRUE ),
	REQ (DHCP_OPTION_INTERFACE_MTU,                     "interface_mtu",                   TRUE ),
	REQ (DHCP_OPTION_BROADCAST,                         "broadcast_address",               TRUE ),
	/* RFC 3442: The Classless Static Routes option code MUST appear in the parameter
	 *   request list prior to both the Router option code and the Static
	 *   Routes option code, if present. */
	REQ (DHCP_OPTION_CLASSLESS_STATIC_ROUTE,            "rfc3442_classless_static_routes", TRUE ),
	REQ (DHCP_OPTION_ROUTER,                            "routers",                         TRUE ),
	REQ (DHCP_OPTION_STATIC_ROUTE,                      "static_routes",                   TRUE ),
	REQ (DHCP_OPTION_NIS_DOMAIN,                        "nis_domain",                      TRUE ),
	REQ (DHCP_OPTION_NIS_SERVERS,                       "nis_servers",                     TRUE ),
	REQ (DHCP_OPTION_NTP_SERVER,                        "ntp_servers",                     TRUE ),
	REQ (DHCP_OPTION_SERVER_ID,                         "dhcp_server_identifier",          TRUE ),
	REQ (DHCP_OPTION_DOMAIN_SEARCH_LIST,                "domain_search",                   TRUE ),
	REQ (DHCP_OPTION_PRIVATE_CLASSLESS_STATIC_ROUTE,    "ms_classless_static_routes",      TRUE ),
	REQ (DHCP_OPTION_PRIVATE_PROXY_AUTODISCOVERY,       "wpad",                            TRUE ),
	REQ (DHCP_OPTION_ROOT_PATH,                         "root_path",                       TRUE ),

	REQ (DHCP_OPTION_TIME_SERVERS,                      "time_servers",                    FALSE ),
	REQ (DHCP_OPTION_IEN116_NAME_SERVERS,               "ien116_name_servers",             FALSE ),
	REQ (DHCP_OPTION_LOG_SERVERS,                       "log_servers",                     FALSE ),
	REQ (DHCP_OPTION_COOKIE_SERVERS,                    "cookie_servers",                  FALSE ),
	REQ (DHCP_OPTION_LPR_SERVERS,                       "lpr_servers",                     FALSE ),
	REQ (DHCP_OPTION_IMPRESS_SERVERS,                   "impress_servers",                 FALSE ),
	REQ (DHCP_OPTION_RESOURCE_LOCATION_SERVERS,         "resource_location_servers",       FALSE ),
	REQ (DHCP_OPTION_BOOT_FILE_SIZE,                    "boot_size",                       FALSE ),
	REQ (DHCP_OPTION_MERIT_DUMP,                        "merit_dump",                      FALSE ),
	REQ (DHCP_OPTION_SWAP_SERVER,                       "swap_server",                     FALSE ),
	REQ (DHCP_OPTION_EXTENSIONS_PATH,                   "extensions_path",                 FALSE ),
	REQ (DHCP_OPTION_ENABLE_IP_FORWARDING,              "ip_forwarding",                   FALSE ),
	REQ (DHCP_OPTION_ENABLE_SRC_ROUTING,                "non_local_source_routing",        FALSE ),
	REQ (DHCP_OPTION_POLICY_FILTER,                     "policy_filter",                   FALSE ),
	REQ (DHCP_OPTION_INTERFACE_MDR,                     "max_dgram_reassembly",            FALSE ),
	REQ (DHCP_OPTION_INTERFACE_TTL,                     "default_ip_ttl",                  FALSE ),
	REQ (DHCP_OPTION_INTERFACE_MTU_AGING_TIMEOUT,       "path_mtu_aging_timeout",          FALSE ),
	REQ (DHCP_OPTION_PATH_MTU_PLATEAU_TABLE,            "path_mtu_plateau_table",          FALSE ),
	REQ (DHCP_OPTION_ALL_SUBNETS_LOCAL,                 "all_subnets_local",               FALSE ),
	REQ (DHCP_OPTION_PERFORM_MASK_DISCOVERY,            "perform_mask_discovery",          FALSE ),
	REQ (DHCP_OPTION_MASK_SUPPLIER,                     "mask_supplier",                   FALSE ),
	REQ (DHCP_OPTION_ROUTER_DISCOVERY,                  "router_discovery",                FALSE ),
	REQ (DHCP_OPTION_ROUTER_SOLICITATION_ADDR,          "router_solicitation_address",     FALSE ),
	REQ (DHCP_OPTION_TRAILER_ENCAPSULATION,             "trailer_encapsulation",           FALSE ),
	REQ (DHCP_OPTION_ARP_CACHE_TIMEOUT,                 "arp_cache_timeout",               FALSE ),
	REQ (DHCP_OPTION_IEEE802_3_ENCAPSULATION,           "ieee802_3_encapsulation",         FALSE ),
	REQ (DHCP_OPTION_DEFAULT_TCP_TTL,                   "default_tcp_ttl",                 FALSE ),
	REQ (DHCP_OPTION_TCP_KEEPALIVE_INTERVAL,            "tcp_keepalive_internal",          FALSE ),
	REQ (DHCP_OPTION_TCP_KEEPALIVE_GARBAGE,             "tcp_keepalive_garbage",           FALSE ),
	REQ (DHCP_OPTION_VENDOR_SPECIFIC,                   "vendor_encapsulated_options",     FALSE ),
	REQ (DHCP_OPTION_NETBIOS_NAMESERVER,                "netbios_name_servers",            FALSE ),
	REQ (DHCP_OPTION_NETBIOS_DD_SERVER,                 "netbios_dd_server",               FALSE ),
	REQ (DHCP_OPTION_FONT_SERVERS,                      "font_servers",                    FALSE ),
	REQ (DHCP_OPTION_X_DISPLAY_MANAGER,                 "x_display_manager",               FALSE ),
	REQ (DHCP_OPTION_IP_ADDRESS_LEASE_TIME,             "dhcp_lease_time",                 FALSE ),
	REQ (DHCP_OPTION_RENEWAL_T1_TIME,                   "dhcp_renewal_time",               FALSE ),
	REQ (DHCP_OPTION_REBINDING_T2_TIME,                 "dhcp_rebinding_time",             FALSE ),
	REQ (DHCP_OPTION_NEW_TZDB_TIMEZONE,                 "tcode",                           FALSE ),
	REQ (DHCP_OPTION_NWIP_DOMAIN,                       "nwip_domain",                     FALSE ),
	REQ (DHCP_OPTION_NWIP_SUBOPTIONS,                   "nwip_suboptions",                 FALSE ),
	REQ (DHCP_OPTION_NISPLUS_DOMAIN,                    "nisplus_domain",                  FALSE ),
	REQ (DHCP_OPTION_NISPLUS_SERVERS,                   "nisplus_servers",                 FALSE ),
	REQ (DHCP_OPTION_TFTP_SERVER_NAME,                  "tftp_server_name",                FALSE ),
	REQ (DHCP_OPTION_BOOTFILE_NAME,                     "bootfile_name",                   FALSE ),
	REQ (DHCP_OPTION_MOBILE_IP_HOME_AGENT,              "mobile_ip_home_agent",            FALSE ),
	REQ (DHCP_OPTION_SMTP_SERVER,                       "smtp_server",                     FALSE ),
	REQ (DHCP_OPTION_POP_SERVER,                        "pop_server",                      FALSE ),
	REQ (DHCP_OPTION_NNTP_SERVER,                       "nntp_server",                     FALSE ),
	REQ (DHCP_OPTION_WWW_SERVER,                        "www_server",                      FALSE ),
	REQ (DHCP_OPTION_FINGER_SERVER,                     "finger_server",                   FALSE ),
	REQ (DHCP_OPTION_IRC_SERVER,                        "irc_server",                      FALSE ),
	REQ (DHCP_OPTION_STREETTALK_SERVER,                 "streettalk_server",               FALSE ),
	REQ (DHCP_OPTION_STREETTALK_DIR_ASSIST_SERVER,      "streettalk_directory_assistance_server", FALSE ),
	REQ (DHCP_OPTION_SLP_DIRECTORY_AGENT,               "slp_directory_agent",             FALSE ),
	REQ (DHCP_OPTION_SLP_SERVICE_SCOPE,                 "slp_service_scope",               FALSE ),
	REQ (DHCP_OPTION_RELAY_AGENT_INFORMATION,           "relay_agent_information",         FALSE ),
	REQ (DHCP_OPTION_NDS_SERVERS,                       "nds_servers",                     FALSE ),
	REQ (DHCP_OPTION_NDS_TREE_NAME,                     "nds_tree_name",                   FALSE ),
	REQ (DHCP_OPTION_NDS_CONTEXT,                       "nds_context",                     FALSE ),
	REQ (DHCP_OPTION_BCMS_CONTROLLER_NAMES,             "bcms_controller_names",           FALSE ),
	REQ (DHCP_OPTION_BCMS_CONTROLLER_ADDRESS,           "bcms_controller_address",         FALSE ),
	REQ (DHCP_OPTION_CLIENT_LAST_TRANSACTION,           "client_last_transaction_time",    FALSE ),
	REQ (DHCP_OPTION_ASSOCIATED_IP,                     "associated_ip",                   FALSE ),
	REQ (DHCP_OPTION_PXE_SYSTEM_TYPE,                   "pxe_system_type",                 FALSE ),
	REQ (DHCP_OPTION_PXE_INTERFACE_ID,                  "pxe_interface_id",                FALSE ),
	REQ (DHCP_OPTION_PXE_CLIENT_ID,                     "pxe_client_id",                   FALSE ),
	REQ (DHCP_OPTION_UAP_SERVERS,                       "uap_servers",                     FALSE ),
	REQ (DHCP_OPTION_GEOCONF_CIVIC,                     "geoconf_civic",                   FALSE ),
	REQ (DHCP_OPTION_NETINFO_SERVER_ADDRESS,            "netinfo_server_address",          FALSE ),
	REQ (DHCP_OPTION_NETINFO_SERVER_TAG,                "netinfo_server_tag",              FALSE ),
	REQ (DHCP_OPTION_DEFAULT_URL,                       "default_url",                     FALSE ),
	REQ (DHCP_OPTION_AUTO_CONFIG,                       "auto_config",                     FALSE ),
	REQ (DHCP_OPTION_NAME_SERVICE_SEARCH,               "name_service_search",             FALSE ),
	REQ (DHCP_OPTION_SUBNET_SELECTION,                  "subnet_selection",                FALSE ),
	REQ (DHCP_OPTION_VIVCO,                             "vivco",                           FALSE ),
	REQ (DHCP_OPTION_VIVSO,                             "vivso",                           FALSE ),
	REQ (DHCP_OPTION_PANA_AGENT,                        "pana_agent",                      FALSE ),
	REQ (DHCP_OPTION_V4_LOST,                           "v4_lost",                         FALSE ),
	REQ (DHCP_OPTION_SIP_UA_CS_DOMAINS,                 "sip_ua_cs_domains",               FALSE ),
	REQ (DHCP_OPTION_IPV4_ADDRESS_ANDSF,                "ipv4_address_andsf",              FALSE ),
	REQ (DHCP_OPTION_RDNSS_SELECTION,                   "rndss_selection",                 FALSE ),
	REQ (DHCP_OPTION_TFTP_SERVER_ADDRESS,               "tftp_server_address",             FALSE ),
	REQ (DHCP_OPTION_V4_PORTPARAMS,                     "v4_portparams",                   FALSE ),
	REQ (DHCP_OPTION_V4_CAPTIVE_PORTAL,                 "v4_captive_portal",               FALSE ),
	REQ (DHCP_OPTION_LOADER_CONFIGFILE,                 "loader_configfile",               FALSE ),
	REQ (DHCP_OPTION_LOADER_PATHPREFIX,                 "loader_pathprefix",               FALSE ),
	REQ (DHCP_OPTION_LOADER_REBOOTTIME,                 "loader_reboottime",               FALSE ),
	REQ (DHCP_OPTION_OPTION_6RD,                        "option_6rd",                      FALSE ),
	REQ (DHCP_OPTION_V4_ACCESS_DOMAIN,                  "v4_access_domain",                FALSE ),
	REQ (DHCP_OPTION_PRIVATE_224,                       "private_224",                     FALSE ),
	REQ (DHCP_OPTION_PRIVATE_225,                       "private_225",                     FALSE ),
	REQ (DHCP_OPTION_PRIVATE_226,                       "private_226",                     FALSE ),
	REQ (DHCP_OPTION_PRIVATE_227,                       "private_227",                     FALSE ),
	REQ (DHCP_OPTION_PRIVATE_228,                       "private_228",                     FALSE ),
	REQ (DHCP_OPTION_PRIVATE_229,                       "private_229",                     FALSE ),
	REQ (DHCP_OPTION_PRIVATE_230,                       "private_230",                     FALSE ),
	REQ (DHCP_OPTION_PRIVATE_231,                       "private_231",                     FALSE ),
	REQ (DHCP_OPTION_PRIVATE_232,                       "private_232",                     FALSE ),
	REQ (DHCP_OPTION_PRIVATE_233,                       "private_233",                     FALSE ),
	REQ (DHCP_OPTION_PRIVATE_234,                       "private_234",                     FALSE ),
	REQ (DHCP_OPTION_PRIVATE_235,                       "private_235",                     FALSE ),
	REQ (DHCP_OPTION_PRIVATE_236,                       "private_236",                     FALSE ),
	REQ (DHCP_OPTION_PRIVATE_237,                       "private_237",                     FALSE ),
	REQ (DHCP_OPTION_PRIVATE_238,                       "private_238",                     FALSE ),
	REQ (DHCP_OPTION_PRIVATE_239,                       "private_239",                     FALSE ),
	REQ (DHCP_OPTION_PRIVATE_240,                       "private_240",                     FALSE ),
	REQ (DHCP_OPTION_PRIVATE_241,                       "private_241",                     FALSE ),
	REQ (DHCP_OPTION_PRIVATE_242,                       "private_242",                     FALSE ),
	REQ (DHCP_OPTION_PRIVATE_243,                       "private_243",                     FALSE ),
	REQ (DHCP_OPTION_PRIVATE_244,                       "private_244",                     FALSE ),
	REQ (DHCP_OPTION_PRIVATE_245,                       "private_245",                     FALSE ),
	REQ (DHCP_OPTION_PRIVATE_246,                       "private_246",                     FALSE ),
	REQ (DHCP_OPTION_PRIVATE_247,                       "private_247",                     FALSE ),
	REQ (DHCP_OPTION_PRIVATE_248,                       "private_248",                     FALSE ),
	/* DHCP_OPTION_PRIVATE_CLASSLESS_STATIC_ROUTE */
	REQ (DHCP_OPTION_PRIVATE_250,                       "private_250",                     FALSE ),
	REQ (DHCP_OPTION_PRIVATE_251,                       "private_251",                     FALSE ),
	/* DHCP_OPTION_PRIVATE_PROXY_AUTODISCOVERY */
	REQ (DHCP_OPTION_PRIVATE_253,                       "private_253",                     FALSE ),
	REQ (DHCP_OPTION_PRIVATE_254,                       "private_254",                     FALSE ),

	/* Internal values */
	REQ (DHCP_OPTION_IP_ADDRESS,                        "ip_address",                      FALSE ),
	REQ (DHCP_OPTION_EXPIRY,                            "expiry",                          FALSE ),

	{ 0 }
};

static const ReqOption dhcp6_requests[] = {
	REQ (DHCP6_OPTION_CLIENTID,                         "dhcp6_client_id",     FALSE ),

	/* Don't request server ID by default; some servers don't reply to
	 * Information Requests that request the Server ID.
	 */
	REQ (DHCP6_OPTION_SERVERID,                         "dhcp6_server_id",     FALSE ),

	REQ (DHCP6_OPTION_DNS_SERVERS,                      "dhcp6_name_servers",  TRUE ),
	REQ (DHCP6_OPTION_DOMAIN_LIST,                      "dhcp6_domain_search", TRUE ),
	REQ (DHCP6_OPTION_SNTP_SERVERS,                     "dhcp6_sntp_servers",  TRUE ),

	/* Internal values */
	REQ (DHCP6_OPTION_IP_ADDRESS,                       "ip6_address",         FALSE ),
	REQ (DHCP6_OPTION_PREFIXLEN,                        "ip6_prefixlen",       FALSE ),
	REQ (DHCP6_OPTION_PREFERRED_LIFE,                   "preferred_life",      FALSE ),
	REQ (DHCP6_OPTION_MAX_LIFE,                         "max_life",            FALSE ),
	REQ (DHCP6_OPTION_STARTS,                           "starts",              FALSE ),
	REQ (DHCP6_OPTION_LIFE_STARTS,                      "life_starts",         FALSE ),
	REQ (DHCP6_OPTION_RENEW,                            "renew",               FALSE ),
	REQ (DHCP6_OPTION_REBIND,                           "rebind",              FALSE ),
	REQ (DHCP6_OPTION_IAID,                             "iaid",                FALSE ),

	{ 0 }
};


const char *request_string (const ReqOption *requests, guint option);
void take_option (GHashTable *options, const ReqOption *requests, guint option, char *value);
void add_option (GHashTable *options, const ReqOption *requests, guint option, const char *value);
void add_option_u64 (GHashTable *options, const ReqOption *requests, guint option, guint64 value);
void add_requests_to_options (GHashTable *options, const ReqOption *requests);
GHashTable *create_options_dict (void);







#endif /* __NETWORKMANAGER_DHCP_OPTIONS_H__ */
