from easyzone import easyzone
from typing import Optional
from local_domains import DOMAIN1, DOMAIN2, DOMAIN3


def get_appropriate_zone_file(domain: str, conf: str) -> Optional[easyzone.Zone]:
    z1 = easyzone.zone_from_file(DOMAIN1, conf + DOMAIN1 + ".conf")
    z2 = easyzone.zone_from_file(DOMAIN2, conf + DOMAIN2 + ".conf")
    z3 = easyzone.zone_from_file(DOMAIN3, conf + DOMAIN3 + ".conf")
    if domain.endswith(DOMAIN1 + "."):
        return z1
    elif domain.endswith(DOMAIN2 + "."):
        return z2
    elif domain.endswith(DOMAIN3 + "."):
        return z3
    else:
        return None


def get_ctype_str(ctype: int) -> str:
    if ctype == 1:
        return "A"
    elif ctype == 28:
        return "AAAA"
    elif ctype == 5:
        return "CNAME"
    elif ctype == 15:
        return "MX"
    elif ctype == 2:
        return "NS"
    elif ctype == 16:
        return "TXT"
    else:
        return "SOA"


def get_resource_from_zone_file(question: list, CONFIG: str) -> Optional[list]:
    domain, ctype, cclass = question
    zone_file = get_appropriate_zone_file(domain, CONFIG)
    if zone_file is None:
        return None
    ctype_str = get_ctype_str(ctype)
    records = zone_file.names[domain]
    if (records is not None) and (records.records(ctype_str) is not None):
        return records.records(ctype_str).items
    return None
