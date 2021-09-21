# DS Bootstrapping Scanner

This utility implements automated scanning of CDS/CDNSKEY bootstrapping
records and generates DS record sets from them.  The algorithm is described
at https://desec-io.github.io/draft-thomassen-dnsop-dnssec-bootstrapping/.

It reads a file with one zone name per line, followed by columns enumerating
the zone's authoritative nameservers (these must be known a priori).  Columns
are sparated by whitespace.  The scanner outputs DS record sets for each zone
whose bootstrapping records could be retrieved and validated.

CDS records are scanned using default resolver of the host, which MUST be
DNSSEC-aware and MUST perform DNSSEC-validation.


## Installation and Usage

This package can be installed using [`pip`](https://pypi.org/project/pip/),
preferably into its own
[`virtualenv`](https://docs.python.org/3/tutorial/venv.html).

    $ python3 -m venv venv
    $ source venv/bin/activate
    (venv)$ pip install -e .
    (venv)$ dsbootstrap --help

### Bootstrap an explicit list of delegations

    (venv)$ $ dsbootstrap <<EOF
    > dnssec-bootstrap-test1.cl. ns1.desec.io. ns2.desec.org.
    # ... add more child zones and their NS hostnames here ...
    > EOF
    dnssec-bootstrap-test1.cl. 0 IN DS 36169 13 2 7b5c698234bb872aa32d9550f386f364821f27c6042c2462b477296639ba2bc5
    dnssec-bootstrap-test1.cl. 0 IN DS 36169 13 4 6bbb9cdc008c0c588a68bdcc44a2f0484d28bb6576ee9128367833a7a4526041d127c781b8b7eeb5d526e675c6af62eb

### Bulk bootstrap

`dsbootstrap` can scan the DNS operator's signaling zones for bootstrappable
delegations based on the name of the immediate ancestor (i.e. one level up)
by prefixing the ancestor's name with a dot.

For example, a scan for second-level delegations within the `cl.` TLD can be
done like this:

    (venv)$ dsbootstrap <<< ".cl. ns1.desec.io. ns2.desec.org."
    2021-09-21 19:53:08,590 WARNING: Performing NSEC walk of cl. on ['ns1.desec.io.', 'ns2.desec.org.'] ...
    dnssec-bootstrap-test1.cl. 0 IN DS 36169 13 2 7b5c698234bb872aa32d9550f386f364821f27c6042c2462b477296639ba2bc5
    dnssec-bootstrap-test1.cl. 0 IN DS 36169 13 4 6bbb9cdc008c0c588a68bdcc44a2f0484d28bb6576ee9128367833a7a4526041d127c781b8b7eeb5d526e675c6af62eb
    # ... other delegations follow ...

The two modes of operation can be mixed.


## DNSSEC algorithm support

For each zone, the utility validates that for each signing algorithm that
appears in the DS record set, the zone's DNSKEY record set is signed by at
least one key.  This is done using [dnspython](https://www.dnspython.org/).
Therefore, the list of supported algorithms is same as the list of supported
DNSSEC algorithms of `dnspython`.
