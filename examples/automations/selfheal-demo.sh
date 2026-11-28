#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-only
#
# Self-heal Pi-hole demo (docs/automations.md, "Self-heal Pi-hole"; #49, #53).
# Run it from a workstation on the LAN, by hand, to watch (and record) the
# shipped automations pihole-watchdog and pihole-selfheal heal a Pi-hole:
#
#   scene 1: the primary's Pi-hole stops; the watchdog on the primary restarts it.
#   scene 2: the primary's Pi-hole stops and cannot start; the hub moves the
#            virtual IP to the standby and notifies.
#   restore: puts the primary's Pi-hole and the virtual IP back.
#
# It breaks DNS on purpose: run it on a lab you own, with the setup of the docs
# done (both automations loaded, the dangerous grant, Virtual IPs on both
# devices). Nothing runs it in CI.
#
# Needs: ssh to both devices as a user with sudo, dig on the workstation,
# arping (iputils-arping) on the primary for restore, and optionally ssh to a
# hub host for `hearth automation runs`.
#
#   PRIMARY=pi@pihole-primary STANDBY=pi@pihole-standby VIP=192.168.1.53/24 \
#     IFACE=eth0 HUB=pi@hub examples/automations/selfheal-demo.sh [scene1|scene2|restore|all]
set -euo pipefail

: "${PRIMARY:?set PRIMARY to the primary Pi-hole, as an ssh target (user@host)}"
: "${STANDBY:?set STANDBY to the standby Pi-hole, as an ssh target (user@host)}"
: "${VIP:?set VIP to the virtual IP with its prefix, such as 192.168.1.53/24}"
IFACE="${IFACE:-eth0}"
HUB="${HUB:-}"
FTL="${FTL:-pihole-FTL.service}"
WAIT="${WAIT:-120}" # seconds to wait for each scene to heal

vip_addr="${VIP%/*}"

say() { printf '\n\033[1m== %s\033[0m\n' "$*"; }

# remote runs a command on an ssh target; arguments are quoted for its shell.
remote() {
	local target=$1
	shift
	ssh -o BatchMode=yes "$target" "$(printf '%q ' "$@")"
}

# answers reports whether the virtual IP answers DNS now.
answers() {
	# dig +short prints its errors as ";;" lines on stdout.
	[[ -n "$(dig +short +time=1 +tries=1 @"$vip_addr" pi.hole A 2>/dev/null | grep -v '^;' || true)" ]]
}

holder() {
	local p s
	p=$(remote "$PRIMARY" ip -4 -o address show dev "$IFACE" | grep -cF " $vip_addr/" || true)
	s=$(remote "$STANDBY" ip -4 -o address show dev "$IFACE" | grep -cF " $vip_addr/" || true)
	echo "virtual IP $vip_addr: primary holds it: $p, standby holds it: $s"
}

# watch prints, every second, whether the virtual IP answers, until it has
# answered again after failing, or WAIT seconds pass.
watch_dns() {
	local failed=0 start=$SECONDS
	while ((SECONDS - start < WAIT)); do
		if answers; then
			printf '%3ds  %s answers\n' $((SECONDS - start)) "$vip_addr"
			if ((failed)); then
				return 0
			fi
		else
			printf '%3ds  %s does NOT answer\n' $((SECONDS - start)) "$vip_addr"
			failed=1
		fi
		sleep 1
	done
	echo "not healed within ${WAIT}s" >&2
	return 1
}

runs() {
	if [[ -n "$HUB" ]]; then
		remote "$HUB" hearth automation runs "$1" | head -n 20 || true
	fi
}

scene1() {
	say "scene 1: stop the primary's Pi-hole; the watchdog on the device restarts it"
	holder
	remote "$PRIMARY" sudo systemctl stop "$FTL"
	watch_dns
	runs pihole-watchdog
}

scene2() {
	say "scene 2: the primary's Pi-hole stops and cannot start; the hub fails over"
	holder
	# A runtime mask makes the watchdog's restart fail, until a reboot or restore.
	remote "$PRIMARY" sudo systemctl mask --runtime "$FTL"
	remote "$PRIMARY" sudo systemctl stop "$FTL"
	watch_dns
	holder
	runs pihole-selfheal
}

restore() {
	say "restore: the primary's Pi-hole and the virtual IP back on the primary"
	remote "$PRIMARY" sudo systemctl unmask --runtime "$FTL" || true
	remote "$PRIMARY" sudo systemctl start "$FTL"
	remote "$STANDBY" sudo ip -4 address del "$VIP" dev "$IFACE" 2>/dev/null || true
	remote "$PRIMARY" sudo ip -4 address replace "$VIP" dev "$IFACE"
	# Linux does not announce an address added by hand: without this, hosts
	# keep sending to the standby until their ARP entry expires.
	if remote "$PRIMARY" sh -c 'command -v arping' >/dev/null; then
		remote "$PRIMARY" sudo arping -U -c 3 -I "$IFACE" "$vip_addr" >/dev/null || true
	else
		echo "no arping on the primary (apt install iputils-arping): hosts may keep the standby for a minute" >&2
	fi
	holder
	if answers; then echo "$vip_addr answers"; else echo "$vip_addr does NOT answer yet" >&2; fi
}

case "${1:-all}" in
scene1) scene1 ;;
scene2) scene2 ;;
restore) restore ;;
all)
	scene1
	sleep 10
	scene2
	sleep 5
	restore
	;;
*)
	echo "usage: $0 [scene1|scene2|restore|all]" >&2
	exit 2
	;;
esac
