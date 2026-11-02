#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include "application_protocol.h"

// ---------------------------------------------------------
// Hjälpfunktioner
// ---------------------------------------------------------

static int starts_with(const uint8_t *payload, size_t len, const char *prefix) {
    size_t plen = strlen(prefix);
    return payload && len >= plen && memcmp(payload, prefix, plen) == 0;
}

static int contains_prefix(const uint8_t *payload, size_t len, const char *prefix) {
    size_t plen = strlen(prefix);
    if (!payload || len < plen) return 0;

    for (size_t i = 0; i + plen <= len; i++)
        if (memcmp(payload + i, prefix, plen) == 0)
            return 1;

    return 0;
}

// ---------------------------------------------------------
// Payloaddetektorer (FTP, SMTP, HTTP, SSH, DNS, DHCP)
// ---------------------------------------------------------

static int detect_ftp_payload(const uint8_t *p, size_t l) {
    if (!p || !l) return 0;

    const char *ftp_server_codes[] = {
        "220 ", "220-", "221 ", "230 ", "250 ", "331 ", "332 ", "350 ",
        "425 ", "426 ", "450 ", "451 ", "452 ", "500 ", "501 ", "502 ",
        "503 ", "504 ", "530 ", "532 ", "550 ", "551 ", "552 ", "553 ", "554 "
    };

    for (size_t i = 0; i < sizeof(ftp_server_codes)/sizeof(char*); i++)
        if (starts_with(p, l, ftp_server_codes[i]))
            return 1;

    const char *ftp_client_cmds[] = {
        "USER ", "PASS ", "ACCT ", "CWD ", "CDUP", "SMNT ", "QUIT", "REIN",
        "PORT ", "PASV", "TYPE ", "STRU ", "MODE ", "RETR ", "STOR ", "STOU",
        "APPE ", "ALLO ", "REST ", "RNFR ", "RNTO ", "ABOR", "DELE ", "RMD ",
        "MKD ", "PWD", "LIST", "NLST", "SITE ", "SYST", "STAT", "HELP", "NOOP"
    };

    for (size_t i = 0; i < sizeof(ftp_client_cmds)/sizeof(char*); i++)
        if (starts_with(p, l, ftp_client_cmds[i]))
            return 1;

    return 0;
}

static int detect_smtp_payload(const uint8_t *p, size_t l) {
    if (!p || !l) return 0;

    const char *smtp_server_codes[] = {
        "220 ", "220-", "221 ", "221-", "250 ", "250-", "251 ", "354 ",
        "421 ", "450 ", "451 ", "452 ", "500 ", "501 ", "502 ", "503 ",
        "504 ", "550 ", "551 ", "552 ", "553 "
    };

    for (size_t i = 0; i < sizeof(smtp_server_codes)/sizeof(char*); i++)
        if (starts_with(p, l, smtp_server_codes[i]))
            return 1;

    const char *smtp_client_cmds[] = {
        "HELO ", "EHLO ", "MAIL FROM:", "RCPT TO:", "DATA", "RSET", "NOOP",
        "QUIT", "VRFY ", "EXPN ", "HELP", "AUTH ", "STARTTLS"
    };

    for (size_t i = 0; i < sizeof(smtp_client_cmds)/sizeof(char*); i++)
        if (starts_with(p, l, smtp_client_cmds[i]))
            return 1;

    return 0;
}

static int detect_http_payload(const uint8_t *p, size_t l) {
    if (!p || !l) return 0;

    const char *http_cmds[] = {
        "GET ", "POST ", "PUT ", "DELETE ", "HEAD ", "OPTIONS ", "PATCH ",
        "HTTP/1.", "HTTP/2"
    };

    for (size_t i = 0; i < sizeof(http_cmds)/sizeof(char*); i++)
        if (starts_with(p, l, http_cmds[i]))
            return 1;

    return 0;
}

static int detect_ssh_payload(const uint8_t *p, size_t l) {
    return starts_with(p, l, "SSH-");
}

static int detect_dns_payload(const uint8_t *p, size_t l) {
    return l >= 12; // DNS header minimum
}

static int detect_dhcp_payload(const uint8_t *p, size_t l) {
    return l >= 240; // DHCP minimum
}

// ---------------------------------------------------------
// Tabell-driven protokollmatchning
// ---------------------------------------------------------

typedef int (*payload_detector_t)(const uint8_t*, size_t);

typedef struct {
    protocol_type_t proto;
    uint16_t ports[4];
    payload_detector_t detector;
} proto_rule_t;

static proto_rule_t rules[] = {
    { PROTO_FTP,   {21},          detect_ftp_payload },
    { PROTO_SMTP,  {25, 587},     detect_smtp_payload },
    { PROTO_HTTP,  {80},          detect_http_payload },
    { PROTO_HTTPS, {443},         NULL },
    { PROTO_SSH,   {22},          detect_ssh_payload },
    { PROTO_IMAP,  {993},         NULL },
    { PROTO_DNS,   {53},          detect_dns_payload },
    { PROTO_DHCP,  {67, 68},      detect_dhcp_payload }
};

// ---------------------------------------------------------
// Huvuddetektor
// ---------------------------------------------------------

protocol_type_t detect_application_protocol(
    uint8_t transport_protocol,
    uint16_t src_port,
    uint16_t dst_port,
    const uint8_t *payload,
    size_t payload_length
) {
    uint16_t ports[2] = { src_port, dst_port };

    for (size_t i = 0; i < sizeof(rules)/sizeof(rules[0]); i++) {
        const proto_rule_t *r = &rules[i];

        for (size_t p = 0; p < 4 && r->ports[p] != 0; p++) {
            if (ports[0] == r->ports[p] || ports[1] == r->ports[p]) {

                if (!r->detector)
                    return r->proto;

                if (r->detector(payload, payload_length))
                    return r->proto;
            }
        }
    }

    return PROTO_UNKNOWN;
}
