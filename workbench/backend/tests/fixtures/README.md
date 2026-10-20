# Test fixtures: real command output

Captured on 2026-10-20 from the same tools the lab uses, not written by hand:

| File | How it was produced |
| --- | --- |
| ospf_full.json | FRR `show ip ospf neighbor json`, two routers in Linux namespaces, adjacency Full |
| ospf_exstart.json, ospf_exchange.json | same pair after setting one side's MTU to 1400 (both ends of the stuck adjacency) |
| nft_ok.txt | `nft list table inet labfw` after loading services/router/r3/nftables.nft |
| nft_with_drop.txt | the same after the firewall-drop scenario's `nft insert rule` |
| bao_unsealed.json, bao_sealed.json | OpenBao 2.4.4 `bao status -format=json` |
| bao_down.txt | `bao status` with the server stopped |
| pg_noresponse.txt | `pg_isready` against a port with nothing listening |
| ldap_cantcontact.txt | `ldapwhoami -x -ZZ` against a port with nothing listening |
| curl_refused.txt | `curl -sS` to a closed port |

FRR was 8.4.4 locally (the lab runs 10.2.1); the parser accepts both JSON styles and the tests cover both.
