# Seeing the lab: visual tools

The lab is mostly command line on purpose (that is how support engineers work), but four visual
tools make it much easier to see what is going on. `make ui` prints the addresses and logins.

## 1. Docker Desktop (no setup)
Open the Docker Desktop app and click **Containers -> securedata-lab**.
- Every service with its status. Click one (for example **r3**) to see:
  - **Logs**: live output (routers log OSPF changes, the app logs every request as JSON)
  - **Exec**: a terminal inside that container (try `vtysh -c "show ip ospf neighbor"` on r1)
  - **Inspect**: its IP addresses, networks and settings
- **Volumes** shows where the database, KMS and audit logs live.
Tip: keep the r1 and app logs open while you run `make break S=core-link-down`.

## 2. KMS web UI (OpenBao)
The lab uses OpenBao 2.4.4; older release builds (such as 2.1.0) shipped without the web UI.

One-time setup on the Mac:
1. Make the name resolve to your Mac:
   `echo "127.0.0.1 kms.site-b.lab" | sudo tee -a /etc/hosts`
2. Trust the lab's root CA so the browser accepts the certificate (lab only):
   `sudo security add-trusted-cert -d -r trustRoot -k /Library/Keychains/System.keychain certs/root-ca.crt`
   (Or skip this and click through the browser warning.)
3. Open **https://kms.site-b.lab:8200/ui**, choose **Token**, and paste the root token from `make ui`.

What to look at: **Secrets engines -> transit -> cards** (the encryption key and its versions),
**Policies -> app-cards** (what the app may do), and try `make break S=kms-sealed` then refresh:
the UI shows the KMS as sealed and asks for the unseal key (`jq -r '.unseal_keys_b64[0]' secrets/kms-init.json`).
Paste it to unseal from the browser, the same job `make kms-unseal` does.

Undo later: remove the line from `/etc/hosts`, and delete "SecureData Lab Root CA" in Keychain Access.

## 3. Database GUI (TablePlus, DBeaver or pgAdmin, all free)
The connection goes Mac -> toolbox (Site A) -> routers -> firewall -> database, like a jump host.

| Setting | Value |
| --- | --- |
| Host / port | 127.0.0.1 / 5433 |
| Database | appdb |
| User / password | alice / Lab-alice-2026! (or bob / Lab-bob-2026!) |
| SSL | require |

Things to try: browse `cardholders` (only last 4 digits and `vault:v1:...` ciphertext), then run
`select * from cardholders` as **bob** and check `make alerts`: the DAM watcher flags it.
During `make break S=firewall-drop` the GUI cannot connect either, because it goes through the same firewall.

## 4. Wireshark (packet captures)
Install from wireshark.org. Then:
`make capture R=r3 F='port 5432' D=20` and connect with the database GUI during those 20 seconds.
Open the file from `captures/` in Wireshark and look for the TCP handshake and the TLS handshake.
During the firewall incident you will see the SYN arrive and never get an answer.
