# SID Resolution utilities for TaskHound
#
# This module handles resolving Windows SIDs to human-readable usernames
# using BloodHound data first, then falling back to LDAP queries when available.

import re
import socket
from typing import Optional, Tuple, Dict, Any
from ..utils.logging import warn, info
from ..parsers.highvalue import HighValueLoader


def is_sid(value: str) -> bool:
    """Check if a string looks like a Windows SID."""
    if not value:
        return False
    # SID pattern: S-1-5-... (simplified check)
    return bool(re.match(r'^S-1-5-[\d-]+$', value.strip()))


def resolve_sid_from_bloodhound(sid: str, hv_loader: Optional[HighValueLoader]) -> Optional[str]:
    """
    Resolve SID to username using BloodHound data.
    
    Args:
        sid: Windows SID to resolve
        hv_loader: Loaded BloodHound data (can be None)
        
    Returns:
        Username if found in BloodHound data, None otherwise
    """
    if not hv_loader or not hv_loader.loaded:
        return None
        
    # Check if SID exists in BloodHound data
    user_data = hv_loader.hv_sids.get(sid)
    if user_data:
        # Try to get samaccountname or name
        username = user_data.get("samaccountname") or user_data.get("name")
        if username:
            info(f"Resolved SID {sid} to {username} via BloodHound data")
            return username.strip().strip('"')
    
    return None


def resolve_sid_via_ldap(sid: str, domain: str, dc_ip: Optional[str] = None, 
                        username: Optional[str] = None, password: Optional[str] = None,
                        hashes: Optional[str] = None, kerberos: bool = False) -> Optional[str]:
    """
    Resolve SID to username using LDAP query.
    
    Args:
        sid: Windows SID to resolve
        domain: Domain name
        dc_ip: Domain controller IP (optional)
        username: Authentication username
        password: Authentication password
        hashes: NTLM hashes for authentication
        kerberos: Use Kerberos authentication
        
    Returns:
        Username if resolved via LDAP, None otherwise
    """
    try:
        # Import ldap3 only when needed to avoid dependency issues
        from ldap3 import Server, Connection, ALL, NTLM, SASL, KERBEROS
        from ldap3.core.exceptions import LDAPException
        
        # Determine DC address
        if not dc_ip:
            try:
                dc_ip = socket.gethostbyname(domain)
            except socket.gaierror:
                warn(f"Could not resolve domain {domain} to IP for LDAP query")
                return None
        
        # Create LDAP server connection
        server = Server(dc_ip, get_info=ALL)
        
        # Determine authentication method
        if kerberos:
            # Kerberos authentication
            conn = Connection(server, authentication=SASL, sasl_mechanism=KERBEROS)
        elif hashes:
            # NTLM hash authentication
            if ':' in hashes:
                lm_hash, nt_hash = hashes.split(':', 1)
            else:
                lm_hash, nt_hash = '', hashes
            conn = Connection(server, user=f"{domain}\\{username}", 
                            authentication=NTLM, auto_bind=True,
                            ntlm_credentials=(username, password, domain, lm_hash, nt_hash))
        else:
            # Username/password authentication
            conn = Connection(server, user=f"{domain}\\{username}", 
                            password=password, authentication=NTLM, auto_bind=True)
        
        if not conn.bind():
            warn(f"Failed to bind to LDAP server for SID resolution: {conn.last_error}")
            return None
        
        # Search for the SID
        base_dn = ','.join([f"DC={part}" for part in domain.split('.')])
        search_filter = f"(objectSid={sid})"
        
        if conn.search(base_dn, search_filter, attributes=['samAccountName', 'name']):
            if conn.entries:
                entry = conn.entries[0]
                sam_account_name = str(entry.samAccountName) if entry.samAccountName else None
                name = str(entry.name) if entry.name else None
                username_resolved = sam_account_name or name
                
                if username_resolved:
                    info(f"Resolved SID {sid} to {username_resolved} via LDAP")
                    return username_resolved.strip()
        
        conn.unbind()
        return None
        
    except ImportError:
        warn("ldap3 library not available - SID resolution via LDAP disabled")
        return None
    except LDAPException as e:
        warn(f"LDAP error during SID resolution: {e}")
        return None
    except Exception as e:
        warn(f"Unexpected error during LDAP SID resolution: {e}")
        return None


def resolve_sid(sid: str, hv_loader: Optional[HighValueLoader] = None,
               no_ldap: bool = False, domain: Optional[str] = None,
               dc_ip: Optional[str] = None, username: Optional[str] = None,
               password: Optional[str] = None, hashes: Optional[str] = None,
               kerberos: bool = False) -> Tuple[str, Optional[str]]:
    """
    Comprehensive SID resolution with fallback chain.
    
    Args:
        sid: Windows SID to resolve
        hv_loader: BloodHound data loader (optional)
        no_ldap: Disable LDAP resolution
        domain: Domain name for LDAP
        dc_ip: Domain controller IP
        username: Authentication username
        password: Authentication password  
        hashes: NTLM hashes
        kerberos: Use Kerberos
        
    Returns:
        Tuple of (display_name, resolved_username)
        - display_name: What to show in output (SID + username or just SID)
        - resolved_username: Just the resolved username (for internal use)
    """
    if not is_sid(sid):
        # Not a SID, return as-is
        return sid, None
    
    # Try BloodHound first
    resolved = resolve_sid_from_bloodhound(sid, hv_loader)
    if resolved:
        return f"{resolved} ({sid})", resolved
    
    # Try LDAP if enabled and we have domain info
    if not no_ldap and domain and username:
        resolved = resolve_sid_via_ldap(sid, domain, dc_ip, username, password, hashes, kerberos)
        if resolved:
            return f"{resolved} ({sid})", resolved
    
    # Could not resolve - return SID with explanation
    if no_ldap:
        return f"{sid} (SID - LDAP resolution disabled)", None
    elif not domain or not username:
        return f"{sid} (SID - insufficient auth for LDAP resolution)", None
    else:
        return f"{sid} (SID - could not resolve: deleted user, cross-domain, or access denied)", None


def format_runas_with_sid_resolution(runas: str, hv_loader: Optional[HighValueLoader] = None,
                                   no_ldap: bool = False, domain: Optional[str] = None,
                                   dc_ip: Optional[str] = None, username: Optional[str] = None,
                                   password: Optional[str] = None, hashes: Optional[str] = None,
                                   kerberos: bool = False) -> Tuple[str, Optional[str]]:
    """
    Format RunAs field with SID resolution if needed.
    
    Returns:
        Tuple of (display_runas, resolved_username)
    """
    if not runas:
        return runas, None
        
    # Check if it's a SID
    if is_sid(runas):
        return resolve_sid(runas, hv_loader, no_ldap, domain, dc_ip, username, password, hashes, kerberos)
    else:
        # Regular username, return as-is
        return runas, None