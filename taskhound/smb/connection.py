# SMB connection helpers.
#
# Small wrapper around Impacket's SMBConnection to handle cleartext
# passwords, NTLM hashes (LM:NT or NT-only), and optional Kerberos
# authentication. The intent is to keep calling code concise and
# centralize parsing of the different credential formats.
# This is horribly vibe-y but it works. Feel free to PR.

from impacket.smbconnection import SMBConnection


def _parse_hashes(password: str):
    # Parse a provided password or NTLM hash string.
    #
    # Accepts:
    #   - None/empty -> (None, '', '')
    #   - 'lm:nt' format -> (None, lm, nt)
    #   - 32-hex NT-only -> (None, '', nt)
    #   - cleartext -> (password, '', '')
    #
    # Returns a tuple suitable for passing into Impacket's login APIs.
    if not password:
        return None, '', ''

    if ':' in password:
        lm, nt = password.split(':', 1)
        return None, lm.strip(), nt.strip()

    # If it's hex length 32, treat as NT hash
    p = password.strip()
    if len(p) == 32 and all(c in '0123456789abcdefABCDEF' for c in p):
        return None, '', p

    # Otherwise treat as cleartext password
    return password, '', ''


def smb_connect(target: str, domain: str, username: str, password: str = None,
                kerberos: bool = False, dc_ip: str = None) -> SMBConnection:
    # Create and authenticate an SMBConnection to `target`.
    #
    # This function prefers passing an explicit lm/nthash when provided and
    # falls back to a cleartext password. For Kerberos mode we delegate to
    # Impacket's kerberosLogin (which supports a KDC host if provided).
    smb = SMBConnection(remoteName=target, remoteHost=target, sess_port=445)

    pwd, lmhash, nthash = _parse_hashes(password)

    if kerberos:
        smb.kerberosLogin(
            user=username,
            password=pwd,
            domain=domain,
            lmhash=lmhash,
            nthash=nthash,
            aesKey=None,
            TGT=None,
            TGS=None,
            kdcHost=dc_ip
        )
    else:
        if lmhash or nthash:
            # When presenting hashes to SMB, the cleartext password is empty
            smb.login(username, '', domain, lmhash=lmhash, nthash=nthash)
        else:
            smb.login(username, pwd, domain)
    return smb
