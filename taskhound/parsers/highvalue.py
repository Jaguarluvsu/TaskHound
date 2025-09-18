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
        print("    Please generate with this Neo4j query:")
        print("MATCH (u:User {highvalue:true})")
        print("RETURN u.samaccountname AS SamAccountName, u.objectid as sid")
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
            self.hv_users[sam] = {"sid": sid}
            self.hv_sids[sid] = {"sam": sam}
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
                self.hv_users[sam] = {"sid": sid}
                self.hv_sids[sid] = {"sam": sam}
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
