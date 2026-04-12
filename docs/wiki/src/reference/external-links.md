# External Links and References

## NDN Project

- [named-data.net](https://named-data.net/) -- official NDN project site
- [NDN Publications](https://named-data.net/publications/) -- research papers, technical reports, and presentations
- [NDN Testbed Status](https://testbed-status.named-data.net/) -- live status of the global NDN testbed

## Specifications

> **Note:** RFC 8569 and RFC 8609 are **CCNx** specifications (Content-Centric
> Networking, a related but distinct architecture). They are not NDN
> specifications. NDN specs are published by the named-data.net project.

- [NDN Packet Format v0.3](https://docs.named-data.net/NDN-packet-spec/current/) -- canonical TLV encoding for Interest, Data, and LpPacket; type assignments
- [NDN Architecture (NDN-0001)](https://named-data.net/techreports/) -- forwarding semantics, PIT/FIB/CS behaviour, Nack handling
- [NDNLPv2 Link Protocol](https://redmine.named-data.net/projects/nfd/wiki/NDNLPv2) -- fragmentation, reliability, congestion marking
- [NDN Certificate Format v2](https://docs.named-data.net/NDN-packet-spec/current/certificate.html) -- certificate naming convention, content format, validity period
- [NDNCERT 0.3](https://github.com/named-data/ndncert/blob/master/docs/NDNCERT-protocol-0.3.pdf) -- automated certificate issuance protocol

## Reference Implementations

- [NFD (NDN Forwarding Daemon)](https://github.com/named-data/NFD) -- the reference C++ forwarder
- [NFD Developer Guide](https://named-data.github.io/NFD/current/) -- architecture and internals of NFD
- [ndn-cxx](https://github.com/named-data/ndn-cxx) -- C++ client library for NDN (used by NFD and NDN applications)
- [ndn-cxx Documentation](https://docs.named-data.net/ndn-cxx/current/) -- API reference and tutorials
- [ndnd](https://github.com/named-data/ndnd) -- Go implementation of an NDN forwarder
- [python-ndn](https://github.com/named-data/python-ndn) -- Python NDN client library

## NDN Community

- [named-data Mailing List](https://www.lists.cs.ucla.edu/mailman/listinfo/ndn-interest) -- ndn-interest mailing list for technical discussion
- [NDN GitHub Organization](https://github.com/named-data) -- source code for all official NDN software
- [NDN Frequently Asked Questions](https://named-data.net/project/faq/)

## Related Research

- [NDN Technical Memos](https://named-data.net/techreports/) -- design rationale and protocol analysis
- [ICN Research Group (ICNRG)](https://datatracker.ietf.org/rg/icnrg/about/) -- IRTF research group on Information-Centric Networking (parent research area of NDN)
- [RFC 7927: Information-Centric Networking Research Challenges](https://datatracker.ietf.org/doc/rfc7927/) -- overview of ICN challenges and open problems

## Rust Ecosystem (used by ndn-rs)

- [Tokio](https://tokio.rs/) -- async runtime
- [bytes](https://docs.rs/bytes/) -- zero-copy byte buffers
- [DashMap](https://docs.rs/dashmap/) -- concurrent hash map (used for PIT)
- [Criterion.rs](https://github.com/bheisler/criterion.rs) -- microbenchmark framework
- [tracing](https://docs.rs/tracing/) -- structured logging and diagnostics
- [smallvec](https://docs.rs/smallvec/) -- stack-allocated small vectors (used for names and forwarding actions)
