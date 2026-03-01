#!/usr/bin/env python3
"""
risk.py — Risk scoring engine based on service exposure and known vulnerability categories
"""

# ─── Risk database ───────────────────────────────────────────────────────────────
# Format: "SERVICE": ("RISK_LEVEL", "human-readable detail")
RISK_DB = {
    # ── CRITICAL / HIGH ─────────────────────────────────────────────────────────
    "TELNET":          ("HIGH",   "Unencrypted remote login. Credentials sent in plaintext. Replace with SSH immediately."),
    "FTP":             ("HIGH",   "Unencrypted file transfer. Credentials exposed. Use SFTP or FTPS."),
    "FTP-DATA":        ("HIGH",   "Active FTP data channel. See FTP risk."),
    "RDP":             ("HIGH",   "Remote Desktop exposed. Common target for brute-force and BlueKeep (CVE-2019-0708)."),
    "SMB":             ("HIGH",   "SMB exposed. Vulnerable to EternalBlue (MS17-010) / WannaCry if unpatched."),
    "NETBIOS-SSN":     ("HIGH",   "NetBIOS session service. Information leakage and lateral movement risk."),
    "NETBIOS":         ("HIGH",   "NetBIOS name service. Network enumeration risk."),
    "MSRPC":           ("HIGH",   "Microsoft RPC. Attack surface for DCOM exploits and lateral movement."),
    "SNMP":            ("HIGH",   "SNMP v1/v2c uses community strings (default: 'public'). Full device config leakage."),
    "REXEC":           ("HIGH",   "Remote execution without strong auth. Extremely dangerous on internet-facing hosts."),
    "RLOGIN":          ("HIGH",   "Remote login without strong auth. No encryption."),
    "VNC":             ("HIGH",   "VNC often uses weak/no passwords. Direct desktop access if compromised."),
    "DOCKER":          ("HIGH",   "Docker daemon API exposed without TLS. Full container and host takeover possible."),
    "DOCKER-TLS":      ("HIGH",   "Docker TLS API exposed. Verify certs are properly configured."),
    "MONGODB":         ("HIGH",   "MongoDB default install has no auth. Millions of DBs breached historically."),
    "REDIS":           ("HIGH",   "Redis default: no auth, no bind restriction. RCE possible via config write."),
    "ELASTICSEARCH":   ("HIGH",   "Elasticsearch default: no auth. Full data exfiltration possible."),
    "MEMCACHED":       ("HIGH",   "Memcached exposed externally. No auth by default. Used in DDoS amplification."),
    "COUCHDB":         ("HIGH",   "CouchDB admin panel may be exposed. Check for Futon/Fauxton access."),
    "WEBLOGIC":        ("HIGH",   "Oracle WebLogic has critical deserialization RCE CVEs (CVE-2017-10271 etc)."),
    "JUPYTER":         ("HIGH",   "Jupyter Notebook often runs without auth. Direct code execution on host."),
    "HADOOP":          ("HIGH",   "Hadoop NameNode UI exposed. Data exfiltration and job execution risk."),
    "ACTIVEMQ":        ("HIGH",   "ActiveMQ vulnerable to deserialization RCE (CVE-2015-5254)."),
    "ZOOKEEPER":       ("HIGH",   "ZooKeeper no auth by default. Exposes cluster internals."),
    "ERLANG-EPMD":     ("HIGH",   "Erlang Port Mapper. Leads to full Erlang node RCE if cookie guessed."),
    "K8S-API":         ("HIGH",   "Kubernetes API server exposed. Full cluster takeover if misconfigured."),
    "KUBELET":         ("HIGH",   "Kubelet API exposed. Can exec into pods and access secrets."),
    "MQTT":            ("HIGH",   "MQTT broker often has no auth. IoT command injection risk."),
    "ORACLE-DB":       ("HIGH",   "Oracle DB exposed. Default credentials and TNS poisoning risk."),
    "PORTAINER":       ("HIGH",   "Portainer Docker management UI. Full container fleet access if breached."),

    # ── MEDIUM ──────────────────────────────────────────────────────────────────
    "SSH":             ("MEDIUM", "SSH exposed. Secure but can be brute-forced. Enforce key-only auth and fail2ban."),
    "SMTP":            ("MEDIUM", "SMTP open. Check for open relay which enables spam abuse."),
    "SMTP-SUBMISSION": ("MEDIUM", "SMTP submission port. Verify auth is enforced."),
    "HTTP":            ("MEDIUM", "HTTP unencrypted. Redirect to HTTPS. Check for admin panels, outdated CMS."),
    "HTTP-ALT":        ("MEDIUM", "Alt HTTP port. Verify not exposing dev/admin interfaces."),
    "HTTP-ALT2":       ("MEDIUM", "Alt HTTP port. Verify not exposing dev/admin interfaces."),
    "HTTP-PROXY":      ("MEDIUM", "HTTP proxy port. Verify not an open proxy."),
    "MYSQL":           ("MEDIUM", "MySQL port exposed. Should not be internet-facing. Enforce strong passwords."),
    "POSTGRESQL":      ("MEDIUM", "PostgreSQL exposed. Restrict to localhost or VPN. Verify pg_hba.conf."),
    "MSSQL":           ("MEDIUM", "MSSQL exposed. Brute-force and xp_cmdshell abuse risk."),
    "DNS":             ("MEDIUM", "DNS exposed. Check for open resolver (amplification DDoS) or zone transfer."),
    "LDAP":            ("MEDIUM", "LDAP exposed. Anonymous bind may expose directory data."),
    "LDAPS":           ("MEDIUM", "LDAPS. Encrypted LDAP. Verify TLS cert validity and bind restrictions."),
    "NFS":             ("MEDIUM", "NFS share may be improperly exported. Verify /etc/exports."),
    "RSYNC":           ("MEDIUM", "Rsync can expose files without auth if misconfigured."),
    "ISAKMP":          ("MEDIUM", "IPSec IKE. Verify implementation is patched against known CVEs."),
    "PPTP":            ("MEDIUM", "PPTP VPN. Broken cryptography (MS-CHAPv2). Migrate to OpenVPN or WireGuard."),
    "OPENVPN":         ("MEDIUM", "OpenVPN exposed. Ensure up-to-date version."),
    "RABBITMQ":        ("MEDIUM", "RabbitMQ AMQP port. Verify auth is enabled (default guest/guest credential risk)."),
    "RABBITMQ-MGMT":   ("MEDIUM", "RabbitMQ management UI. Default guest/guest login is a critical misconfiguration."),
    "SVN":             ("MEDIUM", "SVN repository exposed. Source code disclosure risk."),
    "RPCBIND":         ("MEDIUM", "RPC portmapper. Can be used to enumerate NFS shares and other RPC services."),
    "VMWARE":          ("MEDIUM", "VMware service port. Verify patched against ESXi CVEs."),
    "SOCKS":           ("MEDIUM", "SOCKS proxy exposed. Verify auth is required."),
    "PROMETHEUS":      ("MEDIUM", "Prometheus metrics endpoint. Exposes internal metrics. Should not be public."),
    "DEV-SERVER":      ("MEDIUM", "Development server port (3000). Must not be exposed in production."),
    "FLASK-DEV":       ("MEDIUM", "Flask dev server (5000). Debug mode may be on. RCE via Werkzeug debugger PIN."),

    # ── LOW ─────────────────────────────────────────────────────────────────────
    "HTTPS":           ("LOW",    "HTTPS encrypted. Verify TLS version (≥1.2) and certificate."),
    "HTTPS-ALT":       ("LOW",    "Alt HTTPS port. Same as HTTPS — verify TLS config."),
    "IMAPS":           ("LOW",    "IMAP over SSL. Encrypted mail access."),
    "POP3S":           ("LOW",    "POP3 over SSL. Encrypted mail access."),
    "SMTPS":           ("LOW",    "SMTP over SSL. Encrypted mail relay."),
    "FTPS":            ("LOW",    "FTPS — encrypted FTP. Verify certificate."),
    "FTPS-DATA":       ("LOW",    "FTPS data channel."),
    "NTP":             ("LOW",    "NTP time service. Verify monlist is disabled (DDoS amplification)."),
    "BGP":             ("LOW",    "BGP routing protocol. Only expected on routers/network equipment."),
    "CUPS-IPP":        ("LOW",    "CUPS printing service. Verify not publicly exposed."),
    "KERBEROS":        ("LOW",    "Kerberos auth service. Expected on domain controllers."),

    # ── INFO / UNKNOWN ───────────────────────────────────────────────────────────
    "UNKNOWN":         ("INFO",   "Unrecognized service. Investigate with banner grab."),
}

# Port-specific overrides (when service name resolves to UNKNOWN but port is known risky)
PORT_RISK_OVERRIDE = {
    4444: ("HIGH",  "Common Metasploit handler port. Likely active C2 or pentest shell."),
    1337: ("HIGH",  "Leet/hacker port. Often used by backdoors or RATs."),
    31337: ("HIGH", "Back Orifice backdoor port. Investigate immediately."),
    6666: ("HIGH",  "IRC / malware C2 channel."),
    6667: ("HIGH",  "IRC — common malware C2 channel."),
    9001: ("HIGH",  "Tor OR port. May indicate Tor relay on this host."),
    9030: ("HIGH",  "Tor directory port."),
    8888: ("HIGH",  "Jupyter Notebook default. Often no auth."),
}


def get_risk(service: str, port: int = 0) -> str:
    """Return risk level string for a given service/port."""
    entry = RISK_DB.get(service.upper())
    if entry:
        return entry[0]
    override = PORT_RISK_OVERRIDE.get(port)
    if override:
        return override[0]
    return "INFO"


def get_risk_detail(service: str, risk: str, port: int = 0) -> str:
    """Return human-readable risk detail string."""
    entry = RISK_DB.get(service.upper())
    if entry:
        return entry[1]
    override = PORT_RISK_OVERRIDE.get(port)
    if override:
        return override[1]
    if risk == "INFO":
        return "Unknown service on this port. Manual investigation recommended."
    return ""

