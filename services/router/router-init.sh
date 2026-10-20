#!/bin/sh
# Router start-up: render frr.conf from its template (mapping %%IF:prefix%% to real interface
# names), load the firewall ruleset if this router has one, then start FRR.
set -eu

TEMPLATE="${LAB_TEMPLATE:-/etc/lab/frr.conf.tmpl}"
FRR_CONF="${FRR_CONF:-/etc/frr/frr.conf}"
NFT_RULES="${LAB_NFT_RULES:-/etc/lab/nftables.nft}"

iface_for() {
  ip -o -4 addr show | awk -v p="$1" 'index($4, p) == 1 { print $2; exit }'
}

cp "$TEMPLATE" "$FRR_CONF.tmp"
grep -o '%%IF:[0-9.]*%%' "$TEMPLATE" | sort -u > "$FRR_CONF.placeholders"
while read -r ph; do
  prefix=$(echo "$ph" | sed 's/^%%IF:\(.*\)%%$/\1/')
  ifname=$(iface_for "$prefix")
  if [ -z "$ifname" ]; then
    echo "router-init: no interface has an address starting with $prefix" >&2
    exit 1
  fi
  sed -i "s/$ph/$ifname/g" "$FRR_CONF.tmp"
  echo "router-init: $prefix* -> $ifname"
done < "$FRR_CONF.placeholders"
rm -f "$FRR_CONF.placeholders"
mv "$FRR_CONF.tmp" "$FRR_CONF"

if [ -f "$NFT_RULES" ]; then
  nft -f "$NFT_RULES"
  echo "router-init: loaded firewall rules from $NFT_RULES"
fi

[ "${LAB_RENDER_ONLY:-0}" = "1" ] && exit 0

mkdir -p /var/log/frr
touch /var/log/frr/frr.log
chown -R frr:frr /etc/frr /var/log/frr 2>/dev/null || true
/usr/lib/frr/frrinit.sh start
exec tail -F /var/log/frr/frr.log
