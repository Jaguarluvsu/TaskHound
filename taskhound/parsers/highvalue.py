# High-value (BloodHound) loader and lookup helpers.
#
# This module loads a CSV or JSON export (from BloodHound/Neo4j) that lists
# high-value users and their SIDs. It provides a small in-memory lookup
# so the rest of the tool can mark tasks that run as those accounts.
#
# The expected schema is simple: rows must contain `SamAccountName` and
# `sid`. The loader is intentionally tolerant of common export quirks
# (UTF-8 BOM, quoted fields, NETBIOS prefixes like DOMAIN\user).

import os
import csv
import json
from typing import Dict, Any, Iterable
from ..utils.logging import warn

# Tier 0 group names (both English and German)
TIER0_GROUPS = [
    # Schema Admins
    "Schema Admins", "Schema-Admins",
    # Enterprise Admins  
    "Enterprise Admins", "Unternehmens-Admins",
    # Domain Admins
    "Domain Admins", "Domänen-Admins",
    # Administrators (local)
    "Administrators", "Administratoren",
    # Backup Operators
    "Backup Operators", "Sicherungsoperatoren",
    # Server Operators
    "Server Operators", "Server-Operatoren",
    # Account Operators
    "Account Operators", "Konto-Operatoren",
    # Print Operators
    "Print Operators", "Druck-Operatoren",
]


class HighValueLoader:
    # Load and query a high-value users export (CSV or JSON).
    #
    # Attributes:
    #     path: source file path
    #     hv_users: mapping from samaccountname -> metadata (currently only sid)
    #     hv_sids: mapping from sid -> metadata (currently only sam)
    #     loaded: True if load() succeeded

    def __init__(self, path: str):
        self.path = path
        self.hv_users: Dict[str, Dict[str, Any]] = {}
        self.hv_sids: Dict[str, Dict[str, Any]] = {}
        self.loaded = False

    def load(self) -> bool:
    # Detect file type and populate internal maps.
    #
    # Returns True on success, False on any error or unsupported format.
        ext = os.path.splitext(self.path)[1].lower()
        try:
            if ext == ".json":
                ok = self._load_json()
            elif ext == ".csv":
                ok = self._load_csv()
            else:
                warn(f"Unsupported file type for --bh-data: {ext}")
                return False
        except Exception as e:
            warn(f"Failed to load High Value data: {e}")
            return False
        self.loaded = ok
        return ok

    @staticmethod
    def _has_fields(headers: Iterable[str]) -> bool:
        # Return True if headers contain the required fields.
        #
        # Header names are checked case-insensitively.
        if not headers:
            return False
        lower = {h.strip().lower() for h in headers}
        need = {"samaccountname", "sid"}
        return need.issubset(lower)

    @staticmethod
    def _schema_help():
        # Print a small help if the schema is wrong
        print("[!] Invalid schema in custom HV file!")
        print("    Expected fields: SamAccountName, sid")
        print("    Optional fields: groups, group_names")
        print("    Please generate with this Neo4j query:")
        print("MATCH (u:User {highvalue:true})")
        print("OPTIONAL MATCH (u)-[:MemberOf*1..]->(g:Group)")
        print("WITH u, collect(g.name) as groups, collect(g.objectid) as group_sids")
        print("RETURN u.samaccountname AS SamAccountName, u.objectid as sid,")
        print("       groups as group_names, group_sids as groups")
        print("ORDER BY u.samaccountname")

    def _load_json(self) -> bool:
        with open(self.path, "r", encoding="utf-8-sig") as f:
            data = json.load(f)
        if not data:
            return False
        # Expect a list of objects; validate the first row for required fields
        if not self._has_fields(data[0].keys()):
            self._schema_help()
            return False
        for row in data:
            sam_raw = (row.get("SamAccountName") or "").strip().lower()
            # Accept DOMAIN\user or just user
            if "\\" in sam_raw:
                sam = sam_raw.split("\\", 1)[1]
            else:
                sam = sam_raw
            sid = (row.get("sid") or "").strip()
            
            # Extract group information
            groups = []
            group_names = []
            
            # Handle group_names field (array of strings)
            if "group_names" in row and row["group_names"]:
                if isinstance(row["group_names"], list):
                    group_names = [str(g).strip() for g in row["group_names"] if g]
                else:
                    # Handle single string case
                    group_names = [str(row["group_names"]).strip()]
            
            # Handle groups field - can be either SIDs or names
            if "groups" in row and row["groups"]:
                if isinstance(row["groups"], list):
                    groups_raw = [str(g).strip() for g in row["groups"] if g]
                    # If groups contains names (not SIDs), use them as group names
                    if groups_raw and not groups_raw[0].startswith('S-1-5-'):
                        group_names.extend(groups_raw)
                    else:
                        groups = groups_raw
                else:
                    # Handle single string case
                    groups_str = str(row["groups"]).strip()
                    if groups_str.startswith('S-1-5-'):
                        groups = [groups_str]
                    else:
                        group_names.append(groups_str)
            
            self.hv_users[sam] = {
                "sid": sid,
                "groups": groups,
                "group_names": group_names
            }
            self.hv_sids[sid] = {
                "sam": sam,
                "groups": groups,
                "group_names": group_names
            }
        return True

    def _load_csv(self) -> bool:
        # csv.DictReader handles quoted fields; support UTF-8 BOM via utf-8-sig
        with open(self.path, "r", encoding="utf-8-sig", newline="") as f:
            reader = csv.DictReader(f)
            if not self._has_fields(reader.fieldnames):
                self._schema_help()
                return False
            for row in reader:
                raw_sam = (row.get("SamAccountName") or "").strip().strip('"').lower()
                if "\\" in raw_sam:
                    sam = raw_sam.split("\\", 1)[1]
                else:
                    sam = raw_sam
                sid = (row.get("sid") or "").strip().strip('"')
                
                # Extract group information
                groups = []
                group_names = []
                
                # Handle group_names field 
                if "group_names" in row and row["group_names"]:
                    group_names_raw = row["group_names"].strip().strip('"')
                    if group_names_raw.startswith('[') and group_names_raw.endswith(']'):
                        # JSON array format
                        try:
                            group_names = json.loads(group_names_raw)
                        except:
                            group_names = [group_names_raw.strip('[]').strip('"')]
                    else:
                        group_names = [group_names_raw]
                
                # Handle groups field (SIDs)
                if "groups" in row and row["groups"]:
                    groups_raw = row["groups"].strip().strip('"')
                    if groups_raw.startswith('[') and groups_raw.endswith(']'):
                        # JSON array format
                        try:
                            groups = json.loads(groups_raw)
                        except:
                            groups = [groups_raw.strip('[]').strip('"')]
                    else:
                        groups = [groups_raw]
                
                self.hv_users[sam] = {
                    "sid": sid,
                    "groups": groups,
                    "group_names": group_names
                }
                self.hv_sids[sid] = {
                    "sam": sam,
                    "groups": groups,
                    "group_names": group_names
                }
        return True

    def check_highvalue(self, runas: str) -> bool:
        # Return True if the given RunAs value matches a known high-value account.
        #
        # Accepts SIDs (S-1-5-...) or NETBIOS\sam or plain sam.
        if not runas:
            return False
        val = runas.strip()
        # SID form
        if val.upper().startswith("S-1-5-"):
            return val in self.hv_sids
        # NETBIOS\sam or just sam
        if "\\" in val:
            sam = val.split("\\", 1)[1].lower()
        else:
            sam = val.lower()
        return sam in self.hv_users

    def check_tier0(self, runas: str) -> tuple[bool, list[str]]:
        # Return (True, matching_groups) if the given RunAs value belongs to Tier 0 groups.
        #
        # Accepts SIDs (S-1-5-...) or NETBIOS\sam or plain sam.
        if not runas:
            return False, []
        
        val = runas.strip()
        user_data = None
        
        # SID form
        if val.upper().startswith("S-1-5-"):
            user_data = self.hv_sids.get(val)
        else:
            # NETBIOS\sam or just sam
            if "\\" in val:
                sam = val.split("\\", 1)[1].lower()
            else:
                sam = val.lower()
            user_data = self.hv_users.get(sam)
        
        if not user_data:
            return False, []
        
        # Check group memberships
        group_names = user_data.get("group_names", [])
        matching_groups = []
        
        for group_name in group_names:
            if group_name in TIER0_GROUPS:
                matching_groups.append(group_name)
        
        return len(matching_groups) > 0, matching_groups
