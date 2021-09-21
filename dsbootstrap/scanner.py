from base64 import b32encode
import datetime
from hashlib import sha256
from itertools import groupby
import random
from collections import defaultdict

import dns
import dns.resolver
import dns.dnssec
from dns.rdtypes.ANY.NSEC3 import b32_normal_to_hex

from .log import logger
from .stats import record, Event


# https://docs.python.org/3/library/itertools.html#itertools-recipes
# We can't use len(set(...)) == 1 because set elements need to be hashable,
# but the RRsets we want to check aren't.
def all_equal(iterable):
    "Returns True if all the elements are equal to each other"
    g = groupby(iterable)
    return next(g, True) and not next(g, False)


def do_scan(obj):
    """
    Scan for CDS/CDNSKEY records for given tuple of child domain and its
    authoritative nameserver hostnames.
    If all checks are passed, construct and return a DS record set.
    Otherwise, return None
    """
    domain, *auths = obj
    domain = domain.rstrip('.').lower() + '.'
    logger.info(f"Processing domain: {domain}")

    # TODO move steps to separate functions, at unit tests

    ### Step 1
    ds = query_dns(domain, 'DS')
    if ds:
        record(domain, Event.HAVE_DS)
        return

    # Fetch auth IP addresses
    # TODO share across tasks
    auths_map = defaultdict(set)
    for auth in auths:
        for rdtype in ["AAAA", "A"]:
            r = dns.resolver.resolve(auth, rdtype, raise_on_no_answer=False)
            auths_map[auth] |= {a.address for a in r}

    ### Step 2
    # TODO check opt out?
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
    prefix, suffix = domain.split('.', 1)
    suffix_wire_format = dns.name.from_text(suffix).to_wire()
    suffix_digest = sha256(suffix_wire_format).digest()
    suffix_digest = b32encode(suffix_digest).translate(b32_normal_to_hex).rstrip(b'=')
    signaling_name = prefix + '.' + suffix_digest.lower().decode()
    signaling_fqdns = {f'{signaling_name}._boot.{auth}' for auth in auths}

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
    ds = dns.rrset.RRset(dns.name.from_text(domain), dns.rdataclass.IN, dns.rdatatype.DS)
    for rdata in cds:
        ds.add(dns.rdata.from_text(dns.rdataclass.IN, dns.rdatatype.DS, rdata))
    # TODO do something with cdnskey?
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


def query_dns(domain, rdtype, nameservers=None):
    """Make a query to the local resolver. Return answer object."""
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
    try:
        return resolver.resolve(domain, rdtype, raise_on_no_answer=False)
    except dns.resolver.NoNameservers:
        # Is this a DNSSEC failure?
        try:
            resolver.flags |= dns.flags.CD
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
