# Cryptographic Task for CTFZone Finals 2019

## team_server.py
Contains high-level logic of the challenge. Team server, receives connections from other teams and from the checker.
Commands:
+ update_graph (Needed for the checker to update graph and flag)
+ initiate_zkn (Start Zero Knowledge Proof of Knowledge protocol)

## Libzkn
Contains low-level functionality:
+ Graph function
+ Legendre PRNG