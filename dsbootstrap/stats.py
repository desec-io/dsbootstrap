from enum import Enum, auto
from collections import defaultdict
from queue import SimpleQueue

_RECORDS = defaultdict(list)
_rq = SimpleQueue()


class Event(Enum):
    CHILD_CDS_INCONSISTENT = auto()
    CHILD_CDNSKEY_INCONSISTENT = auto()
    CHILD_DNSKEY_INCONSISTENT = auto()
    BOOT_CDS_INCONSISTENT = auto()
    BOOT_CDNSKEY_INCONSISTENT = auto()
    BOOT_NOOP = auto()
    DNS_FAILURE = auto()
    DNS_BOGUS = auto()
    DNS_LAME = auto()
    DNS_TIMEOUT = auto()
    HAVE_DS = auto()
    HAVE_CDS = auto()
    NO_CDS = auto()
    NO_CDNSKEY = auto()
    OLD_SIG = auto()
    NOT_SIGNED_BY_KSK = auto()
    CDS_DELETE = auto()
    CONTINUITY_ERR = auto()
    CDS_NOOP = auto()


def record(domain: str, event: Event):
    """Record an event during processing a domain name"""
    _rq.put((domain, event, ))


def _process_queue():
    while not _rq.empty():
        domain, event = _rq.get_nowait()
        _RECORDS[event].append(domain)


def report_counts():
    """Return simple report of recorded events"""
    _process_queue()
    output = []
    for name, event in Event.__members__.items():
        count = len(_RECORDS[event])
        output.append(f"{name:<20} {count}")
    return "\n".join(output)


def report_domains():
    """Return dictionary with all recorded events."""
    _process_queue()
    return dict(_RECORDS)
