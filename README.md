# Authenticated DS Bootstrapping Scanner

This utility implements RFC 8078 bootstrapping of DS records via CDS/CDNSKEY
processing, but with added authentication.

The algorithm presupposes an existing DNSSEC chain of trust to the NS
records' target hostnames.
The DNS operator can publish authentication information under the subdomains
of these hostnames.
For the specification, see
https://datatracker.ietf.org/doc/draft-thomassen-dnsop-dnssec-bootstrapping/.

CDS records are scanned using default resolver of the host, which MUST be
DNSSEC-aware and MUST perform DNSSEC-validation.


## Installation

This package can be installed using [`pip`](https://pypi.org/project/pip/),
preferably into its own
[`virtualenv`](https://docs.python.org/3/tutorial/venv.html).

    $ python3 -m venv venv
    $ source venv/bin/activate
    (venv)$ pip install -e .
    (venv)$ dsbootstrap --help


## Usage

It is assumed that the tool is run by a parental agent (registry/registrar),
so that the user knows each delegation's NS records in advance.
They have to be specified as an input and form the trust anchor for
CDS/CDNSKEY authentication.

- **Input:**
  The tool reads from standard input, expecting (in each line) a zone name
  (e.g. `example.co.uk.`) followed by the delegations NS hostnames.
  Columns are separated by whitespace.

  Instead of a zone name, it is also possible to specify the immediate
  ancestor (one level up from the child) prefixed with a dot (e.g. `.co.uk.`),
  to request processing of all delegations at that ancestor name for which the
  given nameservers can provide authenticated bootstrapping of DS records.
  (This requires that the DNS operator's nameserver zones support NSEC
  walking.)

  The two modes of operation can be mixed across input lines.

- **Output:** The scanner outputs DS record sets for each zone whose
  bootstrapping records could be retrieved and validated.

  It is currently based on CDS records only (CDNSKEY is ignored).

### Bootstrap an explicit list of delegations

    (venv)$ $ dsbootstrap <<EOF
    > test-dnssec-bootstrap.cl. ns1.desec.io. ns2.desec.org.
    # ... add more child zones and their NS hostnames here ...
    > EOF
    test-dnssec-bootstrap.cl. 0 IN DS 65147 13 4 732f4a906d044e4e176d44b9ca9add3f71ef1e0e84c2792fe257727604010e2814654133defab56fc2fa7258100ffd27
    test-dnssec-bootstrap.cl. 0 IN DS 65147 13 2 15c19a6aaa4dfdee56ba0e6e8042765a2c4abeca2f69109f63149e5291ec6c75

### Bulk bootstrap

A scan for second-level delegations under the `cl.` TLD can be done as follows.

**Note:** The signaling zones need to operate in NSEC mode to allow iterating
over the bootstrapping names. (This is indicated by nameservers `ns1-with-nsec`
etc. for illustration. They do not really exist; you would have to set up your
own nameservers accordingly.)

    (venv)$ dsbootstrap <<< ".cl. ns1-with-nsec.desec.io. ns2-with-nsec.desec.org."
    2021-11-03 14:16:40.267 WARNING: Performing NSEC walk of cl. on ['ns1-with-nsec.desec.io.', 'ns2-with-nsec.desec.org.'] ...
    2021-11-03 14:16:41.129 WARNING: Confirming NS RRset for delegation dnssec-bootstrap-test1.cl. via DNS. In production, the parental agent MUST retrieve this from its local database!
    2021-11-03 14:16:42.657 WARNING: Skipping dnssec-bootstrap-test1.cl. (could not retrieve NS records from parent).
    2021-11-03 14:16:42.657 WARNING: Confirming NS RRset for delegation vulcano.cl. via DNS. In production, the parental agent MUST retrieve this from its local database!
    2021-11-03 14:16:44.342 WARNING: Skipping vulcano.cl. which is delegated to other nameservers.
    2021-11-03 14:16:44.343 WARNING: Confirming NS RRset for delegation test-dnssec-bootstrap.cl. via DNS. In production, the parental agent MUST retrieve this from its local database!
    # ... other delegations follow ...
    test-dnssec-bootstrap.cl. 0 IN DS 65147 13 2 15c19a6aaa4dfdee56ba0e6e8042765a2c4abeca2f69109f63149e5291ec6c75
    test-dnssec-bootstrap.cl. 0 IN DS 65147 13 4 732f4a906d044e4e176d44b9ca9add3f71ef1e0e84c2792fe257727604010e2814654133defab56fc2fa7258100ffd27
    # ... other delegations follow ...


## DNSSEC algorithm support

For each zone, the utility validates that for each signing algorithm that
appears in the DS record set, the zone's DNSKEY record set is signed by at
least one key.  This is done using [dnspython](https://www.dnspython.org/).
Therefore, the list of supported algorithms is the same as the list of
supported DNSSEC algorithms of dnspython.
