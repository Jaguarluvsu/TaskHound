# Parse a Scheduled Task XML blob and extract a small set of fields.
#
# The function is intentionally forgiving: malformed XML or missing
# elements result in None values rather than exceptions. Only the fields
# we care about for privilege analysis are extracted.
# Can be extended later if needed.

import xml.etree.ElementTree as ET
from typing import Dict


def parse_task_xml(xml_bytes: bytes) -> Dict[str, str]:
    res = {"runas": None, "author": None, "date": None, "command": None, "arguments": None, "logon_type": None}
    try:
        root = ET.fromstring(xml_bytes)
        # Handle default namespace if present by binding it to prefix 'ns'
        ns = {"ns": root.tag.split('}')[0].strip('{')} if '}' in root.tag else {}

        def grab(path):
            node = root.find(path, ns)
            return node.text.strip() if (node is not None and node.text) else None

        # Principal/UserId holds the account the task runs as
        res["runas"]     = grab(".//ns:Principal/ns:UserId")
        res["author"]    = grab(".//ns:RegistrationInfo/ns:Author")
        res["date"]      = grab(".//ns:RegistrationInfo/ns:Date")
        # Command and Arguments can be nested under different nodes in some schemas;
        # this covers the common Task Scheduler schema used by Windows.
        res["command"]   = grab(".//ns:Command")
        res["arguments"] = grab(".//ns:Arguments")
        # LogonType indicates whether credentials are stored (Password) or if S4U/token is used
        res["logon_type"] = grab(".//ns:Principal/ns:LogonType")
    except Exception:
        # Be permissive: return default dict with None values on parse errors
        pass
    return res
