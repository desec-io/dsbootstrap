from base64 import b32encode
import datetime
from hashlib import sha256
from itertools import chain, groupby
import random
from collections import defaultdict

import dns
import dns.resolver
import dns.dnssec
from dns.rdtypes.ANY.NSEC3 import b32_normal_to_hex

from .log import logger
from .stats import record, Event


global_auths_map = defaultdict(set)


# https://docs.python.org/3/library/itertools.html#itertools-recipes
# We can't use len(set(...)) == 1 because set elements need to be hashable,
# but the RRsets we want to check aren't.
def all_equal(iterable):
    "Returns True if all the elements are equal to each other"
    g = groupby(iterable)
    return next(g, True) and not next(g, False)


def signaling_hash(domain):
    suffix_wire_format = domain.to_wire()
    suffix_digest = sha256(suffix_wire_format).digest()
    suffix_digest = b32encode(suffix_digest).translate(b32_normal_to_hex).rstrip(b'=')
    return suffix_digest.lower()


def next_nsec_prefix(prefix, ancestor):
    qname = prefix + ancestor
    res = query_dns(qname, 'NSEC')
    try:
        rrset, = [rrset for rrset in chain(res.response.answer, res.response.authority)
                  if rrset.rdtype == dns.rdatatype.RdataType.NSEC]
    except AttributeError:
        record(qname, Event.DNS_FAILURE)
        return None
    next_name = rrset[0].next
    return next_name - ancestor if next_name.is_subdomain(ancestor) else None


def check_auths(domain, auths):
    logger.warning(f"Confirming NS RRset for delegation {domain} via DNS. "
                   f"In production, the parental agent MUST retrieve this from its local database!")
    parent = dns.name.from_text(domain).parent()  # tentative parent
    parent = dns.resolver.zone_for_name(parent, resolver=get_resolver())  # real parent (perhaps higher up)

    res = query_dns(parent, 'NS')
    if res is None:
        record(parent, Event.DNS_FAILURE)
        return False

    ns = [rr.target.to_text() for rr in res.rrset]
    update_auths_map(ns)
    nameservers = [global_auths_map[target] for target in ns]  # list of list of IPs
    nameservers = list({ip for nameserver in nameservers for ip in nameserver})  # flat list of IPs

    res = query_dns(domain, 'NS', nameservers=nameservers)
    if res is None:
        logger.info(f'Skipping {domain} (could not retrieve NS records from parent).')
        record(parent, Event.DNS_FAILURE)
        return False

    rrset, = [rrset for rrset in res.response.authority if rrset.rdtype == dns.rdatatype.RdataType.NS]
    if sorted(auths) != sorted([ns.target.to_text() for ns in rrset]):
        logger.info(f'Skipping {domain} which is delegated to other nameservers.')
        return False
    else:
        return True


def walk_ancestor(ancestor, auths):
    prefix_map = {auth: set() for auth in auths}
    for auth in auths:
        entrypoint = dns.name.Name([signaling_hash(ancestor), '_boot']) + dns.name.from_text(auth)
        next_prefix = next_nsec_prefix(dns.name.Name([]), entrypoint)
        while next_prefix:
            prefix_map[auth].add(next_prefix)
            next_prefix = next_nsec_prefix(next_prefix, entrypoint)
    candidates = {str(prefix + ancestor) for prefix in set.intersection(*prefix_map.values())}
    return [' '.join([candidate, *auths]) for candidate in candidates if check_auths(candidate, auths)]


def update_auths_map(auths):
    for auth in auths:
        if auth not in global_auths_map:
            for rdtype in ["AAAA", "A"]:
                r = dns.resolver.resolve(auth, rdtype, raise_on_no_answer=False)
                global_auths_map[auth] |= {a.address for a in r}


def do_scan(obj):
    """
    Scan for CDS/CDNSKEY records for given tuple of child domain and its
    authoritative nameserver hostnames.
    If all checks are passed, construct and return a DS record set.
    Otherwise, return None
    """
    domain, *auths = obj
    if domain[0] == '.':
        domain = domain[1:]
        logger.info(f'Performing NSEC walk of {domain} on {auths} ...')
        return walk_ancestor(dns.name.from_text(domain), auths)

    domain = dns.name.from_text(domain.lower())
    logger.info(f"Processing domain: {domain}")

    # TODO move steps to separate functions, add unit tests

    ### Step 1
    ds = query_dns(domain, 'DS')
    if ds is None:
        record(domain, Event.DNS_FAILURE)
        return
    elif ds:
        record(domain, Event.HAVE_DS)
        return

    # Fetch auth IP addresses
    update_auths_map(auths)
    auths_map = {k: v for k, v in global_auths_map.items() if k in auths}

    ### Step 2
    res = fetch_rrset_with_consistency(domain, 'CDS', auths_map)
    if res is None:
        record(domain, Event.CHILD_CDS_INCONSISTENT)
        return
    cds_map = {None: res}

    res = fetch_rrset_with_consistency(domain, 'CDNSKEY', auths_map)
    if res is None:
        record(domain, Event.CHILD_CDNSKEY_INCONSISTENT)
        return
    cdnskey_map = {None: res}

    ### Step 3
    signaling_name = dns.name.Name([domain[0], signaling_hash(domain.parent())])
    signaling_fqdns = {signaling_name + dns.name.Name(['_boot']) + dns.name.from_text(auth) for auth in auths}

    for signaling_fqdn in signaling_fqdns:
        res = query_dns_and_extract_rdata(signaling_fqdn, 'CDS')
        if res is None:
            record(domain, Event.NO_CDS)
        else:
            cds_map[signaling_fqdn] = res
    for signaling_fqdn in signaling_fqdns:
        res = query_dns_and_extract_rdata(signaling_fqdn, 'CDNSKEY')
        if res is None:
            record(domain, Event.NO_CDNSKEY)
        else:
            cdnskey_map[signaling_fqdn] = res

    ### Step 4
    if not all_equal(cds_map.values()):
        record(domain, Event.BOOT_CDS_INCONSISTENT)
        return
    if not all_equal(cdnskey_map.values()):
        record(domain, Event.BOOT_CDNSKEY_INCONSISTENT)
        return

    cds = next(iter(cds_map.values()))
    cdnskey = next(iter(cdnskey_map.values()))
    if not cds and not cdnskey:
        record(domain, Event.BOOT_NOOP)
        return
    logger.debug(f"CDS rdataset: {cds}")
    logger.debug(f"CDNSKEY rdataset: {cdnskey}")

    ### Step 5
    ds = dns.rrset.RRset(domain, dns.rdataclass.IN, dns.rdatatype.DS)
    for rdata in cds:
        ds.add(dns.rdata.from_text(dns.rdataclass.IN, dns.rdatatype.DS, rdata))
    # TODO do something with CDNSKEY?
    logger.debug(f"DS set: {ds}")

    ### Step 6
    dnskeyset = {
        auth: query_dns(domain, 'DNSKEY', nameservers)
        for auth, nameservers in auths_map.items()
    }
    if not all_equal([dnskey.rrset for dnskey in dnskeyset.values()]):
        record(domain, Event.CHILD_DNSKEY_INCONSISTENT)
        return
    dnskeyset = next(iter(dnskeyset.values()))

    if not check_continuity(ds, dnskeyset):
        record(domain, Event.CONTINUITY_ERR)
        logger.warning(f"DNSKEY of {domain} not properly signed")
        return

    return ds


def get_resolver(nameservers=None):
    default_resolver = dns.resolver.get_default_resolver()
    # We use separate resolver instance per query
    resolver = dns.resolver.Resolver(configure=False)
    if nameservers is None:
        resolver.nameservers = default_resolver.nameservers
        if default_resolver.rotate:
            random.shuffle(resolver.nameservers)
        resolver.flags = dns.flags.RD
    else:
        resolver.nameservers = list(nameservers)
        # TODO When querying auths directly, there's no resolver doing validation.  Add timestamp check etc.
    resolver.use_edns(0, dns.flags.DO, 1200)
    return resolver


def query_dns(domain, rdtype, nameservers=None):
    """Make a query to the local resolver. Return answer object."""
    logger.debug(f'Querying {rdtype} for {domain} ...')
    resolver = get_resolver(nameservers)
    try:
        return resolver.resolve(domain, rdtype, raise_on_no_answer=False)
    except dns.resolver.NoNameservers:
        # Is this a DNSSEC failure?
        try:
            try:
                resolver.flags |= dns.flags.CD
            except TypeError:  # None
                resolver.flags = dns.flags.CD
            resolver.resolve(domain, rdtype, raise_on_no_answer=False)
            logger.warning(f"Bogus DNSSEC for domain: {domain}")
            record(domain, Event.DNS_BOGUS)
        except dns.exception.DNSException as e:
            logger.warning(f"Non-DNSSEC related exception: {e}")
            record(domain, Event.DNS_LAME)
    except dns.resolver.Timeout:
        logger.warning(f"DNS timeout for domain: {domain}")
        record(domain, Event.DNS_TIMEOUT)
    except dns.exception.DNSException as e:
        logger.debug(f"DNS exception: {e}")


def get_rrsigset(response):
    """Return Rdataset of RRSIGs covering queried RRTYPE"""
    return response.find_rrset(
        response.answer,
        response.question[0].name,
        response.question[0].rdclass,
        dns.rdatatype.RRSIG,
        response.question[0].rdtype,
    )


def filter_dnskey_set(dnskeyset, dsset):
    """
    Return a set of DNSKEYs with only keys
    matching fingerprints in the dsset.
    """
    s = set()
    for dnskey in dnskeyset:
        key_id = dns.dnssec.key_id(dnskey)
        for ds in dsset:
            if ds.key_tag != key_id:
                continue
            try:
                if ds == dns.dnssec.make_ds(
                    dnskeyset.name,
                    dnskey,
                    ds.digest_type,
                ):
                    s.add(dnskey)
            except dns.dnssec.UnsupportedAlgorithm:
                pass
    return s


def fetch_rrset_with_consistency(domain, rdtype, auths_map):
    rds = [query_dns(domain, rdtype, nameservers) for nameservers in auths_map.values()]
    if not all_equal([v.rrset for v in rds]):
        return
    return {rd.to_text() for rd in rds[0]}


def query_dns_and_extract_rdata(qname, rdtype):
    res = query_dns(qname, rdtype)
    if res is None:
        record(qname, Event.DNS_FAILURE)
    elif res.rrset is None:
        return None
    return {rd.to_text() for rd in res}


def check_continuity(cds, dnskeyset):
    """
    Check if the CDS, when applied, will not break the current delegation
    as per RFC 7344 section 4.1

    In a nutshell this means that at least one of the CDS rdata must be
    used to sign zone's DNSKEY record for each signature algorithm present.
    """
    dssets = defaultdict(set)
    for ds in (
        dns.rdata.from_text(
            dns.rdataclass.IN,
            dns.rdatatype.DS,
            rdata.to_text(),
        ) for rdata in cds
    ):
        dssets[ds.algorithm].add(ds)
    try:
        for alg, dsset in dssets.items():
            logger.debug(
                "Validating CDS continuity for algorithm %s.",
                dns.dnssec.algorithm_to_text(alg),
            )
            keyset = filter_dnskey_set(dnskeyset, dsset)
            dns.dnssec.validate(
                dnskeyset.rrset,
                get_rrsigset(dnskeyset.response),
                {cds.name: keyset},
            )
        return True
    except dns.dnssec.ValidationFailure:
        return False
