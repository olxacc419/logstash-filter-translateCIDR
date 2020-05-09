This implementation is a crossover between the official logstasn translate filter and cidr filter.
The purpose is to make cidr translation (if an IP is a subnet proceed to an enrichment).

Performance has been improbed compared to cidr filter using a binary search instead of a sequential one
