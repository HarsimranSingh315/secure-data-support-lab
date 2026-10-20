# Interview stories from the lab

Always say these are from your own lab. Interviewers respect that more than vague "experience".
Practise each one out loud in about 90 seconds: situation, what you checked, what you found, the fix,
what you learned.

## 1. "Tell me about a complex network issue you troubleshot."
In my lab I have two sites joined by three OSPF routers. After a simulated maintenance change, the
app got slow and one OSPF neighbour never came up. Traceroute showed traffic had moved to the slow
backup link. On the routers the neighbour was stuck in ExStart, and the OSPF log said the
neighbour's MTU was larger than ours. One side had been set to 1400. I fixed the MTU on both ends
instead of using mtu-ignore, because that only hides the problem. Now when I see ExStart, MTU is
the first thing I check.

## 2. "How do you tell a firewall problem from an application problem?"
I look at whether the connection is refused or times out. In my lab, analysts couldn't reach the
database and psql just hung. Ping and traceroute worked, so routing was fine. A timeout means
something is dropping packets, so I took a capture on the edge router: SYNs arrived and nothing
came back. In the nftables ruleset there was a "temporary" rule from a change ticket above the
allow-list, with its hit counter going up. Removing it fixed it. If it had been refused, I would have
checked whether the service was listening.

## 3. "Tell me about a certificate problem."
After a certificate renewal in my lab, the app started failing and psql refused to connect. The
error said the certificate name didn't match. With openssl s_client I saw the new certificate was
valid and from our CA, but it only had the name db01, not the name clients connect with. So the chain
was fine and the hostname check was doing its job. I re-issued it with the right SANs. I would never
fix that by lowering clients to sslmode=require, because that switches off server identity checks.

## 4. "What do you know about key management or HSMs?"
My lab app never sees the encryption key: it sends card numbers to a KMS (OpenBao, the open-source
Vault fork) and stores only the ciphertext and the last 4 digits. The app's token can only encrypt
and decrypt with that one key. I also practised the sealed state: after a restart the KMS can't
encrypt until it's unsealed, which is by design. Separately, I used SoftHSM over PKCS#11, the same
interface Luna HSMs use, to generate a key inside a token, sign with it and confirm the private key
can't be exported.

## 5. "Have you worked with database activity monitoring or auditing?"
I set up pgAudit on PostgreSQL and wrote a small monitoring tool in Python that follows the audit
log and raises alerts. When an analyst ran select * and COPY on the cardholder table, it flagged both
as a possible export, with the user, source IP and statement. It also catches brute-force logins and
privilege changes. The root cause was an over-broad grant, so the fix was least privilege. Because
cards were encrypted through the KMS, the exported data didn't include card numbers.

## If they ask about the gaps
"I haven't supported Thales products in production yet. I built this lab to practise the same
skills: Linux, networking, databases, TLS and key management. I'd expect a few months to learn your
products properly."
