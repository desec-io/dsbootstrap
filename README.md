DS Bootstrapping Scanner
========================

This utility implements automated scanning of CDS/CDNSKEY bootstrapping
records and generates DS record sets from them.  The algorithm is described
at https://desec-io.github.io/draft-thomassen-dnsop-dnssec-bootstrapping/.

It reads a file with one zone name per line, followed by columns enumerating
the zone's authoritative nameservers (these must be known a priori).  Columns
are sparated by whitespace.  The utility output DS record sets for each zone
whose bootstrapping records could be retrieved and validated.

CDS records are scanned using default resolver of the host, which MUST be
DNSSEC-aware and MUST perform DNSSEC-validation.


DNSSEC algorithm support
------------------------

For each zone, the utility validates that for each signing algorithm that
appears in the DS record set, the zone's DNSKEY record set is signed by at
least one key.  This is done using [dnspython](https://www.dnspython.org/).
Therefore, the list of supported algorithms is same as the list of supported
DNSSEC algorithms of `dnspython`.

Installation and usage
----------------------

This package can be installed using [`pip`](https://pypi.org/project/pip/),
preferably into its own
[`virtualenv`](https://docs.python.org/3/tutorial/venv.html).

    $ python3 -m venv venv
    $ source venv/bin/activate
    (venv)$ pip install -e .
    (venv)$ dsbootstrap --help

