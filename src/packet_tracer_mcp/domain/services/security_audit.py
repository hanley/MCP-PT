"""
Security posture audit on PT live topology. 

Pure logic, without bridge — testable with synthetic dicts, just like topology_diff. 

DESIGN NOTE — This module never receives or returns credentials. The bridge classifies 
each credential by its prefix and sends ONLY the label of the algorithm 
("md5", "type7",...). A hash in the output of a tool ends in the context of the LLM 
and in the MCP client logs; the label reaches for auditing and there's no reason to 
pay that risk. 

Algorithm classification (verified against PT 9.0.0.0810):
  $1$...  -> "md5"      `enable secret` / `username X secret` (type 5)
  $8$...  -> "pbkdf2"   type 8
  $9$...  -> "scrypt"   type 9
  hex     -> "type7"    `password` with service-password-encryption — REVERSIBLE
  resto   -> "plaintext"
"""

from __future__ import annotations

# Algorithms that an attacker can revert to the original password: type 7 is 
# a Vigenère cipher with a published key (there are online decoders), and 
# plaintext doesn't even try.
REVERSIBLE_ALGOS = frozenset({"type7", "plaintext"})

# MD5 without salt per device is crackable offline with modern hardware. It is not 
# reversible, so it's a less severe grade than Type 7, but Cisco recommends 
# # type 8/9 for years.
WEAK_HASH_ALGOS = frozenset({"md5"})

#0x2102 (8450) is the normal value. 0x2142 (8514) jumps the startup-config in the 
# Boot: is the procedure of recovering the password, and leaving it in place
# means that a reboot discards all security settings.
CONFIG_REGISTER_NORMAL = 0x2102
CONFIG_REGISTER_BYPASS = 0x2142


def _finding(device: str, code: str, severity: str, message: str, suggestion: str) -> dict:
    return {
        "device": device,
        "code": code,
        "severity": severity,
        "message": message,
        "suggestion": suggestion,
    }


def _audit_device(dev: dict) -> list[dict]:
    name = dev.get("name", "?")
    findings: list[dict] = []

    # --- Privileged Mode Access ---
    if not dev.get("enable_secret_set"):
        findings.append(_finding(
            name, "NO_ENABLE_SECRET", "high", 
            "No `enable secret`: anyone with access to the console enters privileged mode.", 
            "Set up `enable secret <key>` (or use pt_apply_hardening with enable_secret).",
        ))
    else:
        algo = dev.get("enable_secret_algo")
        if algo in REVERSIBLE_ALGOS:
            findings.append(_finding(
                name, "ENABLE_SECRET_REVERSIBLE", "high", 
                f"The `enable secret` is saved with a reversible algorithm ({algo}).", 
                "Reconfigure it with `enable secret` (hash) instead of `enable password`.",
            ))
        elif algo in WEAK_HASH_ALGOS:
            findings.append(_finding(
                name, "ENABLE_SECRET_WEAK_ALGO", "medium", 
                "The `enable secret` uses MD5 (type 5), crackable offline.", 
                "If IOS supports it, use `enable algorithm-type scrypt secret <key>`.",
            ))

    # `enable password`` and `enable secret`` can coexist; the password is 
    # reversible and remains in the config even if the secret is the one that commands.
    if dev.get("enable_password_set"):
        findings.append(_finding(
            name, "ENABLE_PASSWORD_PRESENT", "medium", 
            "There is an `enable password` configured, which is stored reversibly.", 
            "Delete it with `no enable password` and leave only `enable secret`.",
        ))

    #--- Local Credentials ---
    users = dev.get("users") or []
    for user in users:
        uname = user.get("name", "?")
        ualgo = user.get("algo")
        if ualgo in REVERSIBLE_ALGOS:
            findings.append(_finding(
                name, "USER_CREDENTIAL_REVERSIBLE", "high", 
                f"The local user '{uname}' saves his credential reversibly ({ualgo}).", 
                f"Recreate it with `username {uname} secret <key>` instead of `password`.",
            ))
        elif ualgo in WEAK_HASH_ALGOS:
            findings.append(_finding(
                name, "USER_CREDENTIAL_WEAK_ALGO", "low", 
                f"Local user '{uname}' uses MD5 (type 5).", 
                f"If IOS supports it: 'username {uname} algorithm-type scrypt secret <key>`.",
            ))

    if not users:
        findings.append(_finding(
            name, "NO_LOCAL_USERS", "low", 
            "No local users: you can't enforce 'local login' on VTY or use SSH.", 
            "Create at least one user with 'username <user> secret <key>'.",
        ))

    # --- Config global ---
    if not dev.get("service_password_encryption"):
        findings.append(_finding(
            name, "NO_SERVICE_PASSWORD_ENCRYPTION", "medium", 
            "'Service Password-Encryption' is turned off: the keys are clear in the config.", 
            "Activate it with 'service password-encryption' (it does not replace 'secret', it complements it).",
        ))

    if not dev.get("banner_set"):
        findings.append(_finding(
            name, "NO_BANNER_MOTD", "low", 
            "No MOTD banner. In several jurisdictions, the legal notice is required to prosecute unauthorized access.", 
            "Set up 'banner motd' (or use pt_apply_hardening with banner_motd).",
        ))

    reg = dev.get("config_register")
    if reg == CONFIG_REGISTER_BYPASS:
        findings.append(_finding(
            name, "CONFIG_REGISTER_BYPASS", "high", 
            f"The config-register is 0x{reg:04x}: in the next reboot the team IGNORES the startup-config.", 
            "Restore it with 'config-register 0x2102' and save the settings.",
        ))

    return findings


def audit_security(devices: list[dict]) -> dict:
    """Audit the security posture of the devices read from the bridge. 
    
    'devices' is the output of the pt_audit_security reader: a list of dicts with 
    flags that are already classified (never credentials). Devices that are not 
    expose IOS configuration (PCs, servers) are discarded before getting here. 
    """
    
    findings: list[dict] = []
    for dev in devices:
        findings.extend(_audit_device(dev))

    counts = {"high": 0, "medium": 0, "low": 0}
    for f in findings:
        sev = f["severity"]
        if sev in counts:
            counts[sev] += 1

    # Sort by gravity so that what's important comes first: the consumer 
    # is an LLM that can truncate, and we don't want you to miss a high finding.
    order = {"high": 0, "medium": 1, "low": 2}
    findings.sort(key=lambda f: (order.get(f["severity"], 9), f["device"], f["code"]))

    return {
        "secure": counts["high"] == 0 and counts["medium"] == 0,
        "devices_audited": len(devices),
        "counts": counts,
        "findings": findings,
    }
