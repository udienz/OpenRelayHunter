#!/bin/bash
#
# Not-So-Quick and dirty script to scan a selection of IP ranges for
# Open SMTP, DNS resolvers plus a few other useful utilities
#
# Prerequisite: 'prips' utility (aptitude install prips)
# Prerequisite: 'mail' utility (aptitude install mutt)
#
# Authors: Johnathan Williamson / Shane Mc Cormack
# Credits: Alain Kelder (http://goo.gl/TNQXSq)
#
# OpenRelayHunter is licensed under a Creative Commons Attribution-NonCommercial-ShareAlike 4.0 International License.
# http://creativecommons.org/licenses/by-nc-sa/4.0/
#


# Defaults.
# To Address (if blank, just output results)
TOADDR=""
# From Address (if blank, just output results)
FROMADDR=""
# IPs to scan.
IPADDRS=()
# Check for SNMP
CHECKSMTP=0
# Check for DNS
CHECKDNS=0
# Check for Heartbleed
CHECKHEART=0
# Check for SuperMicro IPMI Vuln
CHECKSUPIPMI=0
# Blacklist Check
CHECKBLACK=0
# Show help?
SHOWHELP=0

# Parse CLI Args.
while [ $# -gt 0 ]; do
	case "$1" in
		-t|--to)
			TOADDR="$2"
			shift
			;;
		-f|--from)
			FROMADDR="$2"
			shift
			;;
		-s|--smtp)
			CHECKSMTP="1"
			;;
		-d|--dns)
			CHECKDNS="1"
			;;
		-b|--heartbleed)
			CHECKHEART="1"
			;;
		-i|--superipmi)
			CHECKSUPIPMI="1"
			;;
		-B|--blacklist)
			CHECKBLACK="1"
			;;
		-M|--mikrotik)
			CHECKMIKROTIK="1"
			;;
		-h|--help)
			SHOWHELP="1"
			;;
		*)
			# Add to IP Addrs
			IPADDRS+=("$1")
			;;
	esac
	shift
done;

if [ "${SHOWHELP}" = "1" ]; then
	echo "OpenRelay Hunter." >&2
	echo "" >&2
	echo "Usage: ${0} [flags] <IP> [IP [IP] ... [IP]]" >&2
	echo "" >&2
	echo "Accepted flags:" >&2
	echo "" >&2
	echo " -h, --help                      Show this help." >&2
	echo " -d, --dns                       Check for Open DNS Resolver." >&2
	echo " -s, --smtp                      Check for Open Relay." >&2
	echo " -b, --heartbleed		       Check for SSL Heartbleed Vulnerability." >&2
	echo " -i, --superipmi		       Check for SuperMicro IPMI Vulnerability." >&2
	echo " -B, --blacklist		       Check for entries on Blacklists." >&2
	echo " -M, --mikrotik		       Check for entries on Winbox open port." >&2
	echo " -t <addr>, --to <addr>          Email address to send report to." >&2
	echo " -f <addr>, --from <addr>        Email address to send report from." >&2
	echo "" >&2
	echo "Anything param passed that isn't a flag is considered an IP address range to scan" >&2
	echo "" >&2
	echo "Address ranges must be a CIDR range of /31 or larger, or individual IPs (without '/32')" >&2

	exit 0;
fi;

# Pull list of RBL's for Blacklist Check if required
if [ "${CHECKBLACK}" -eq 1 ]; then
	# Remote List
	WPURL="https://en.wikipedia.org/wiki/Comparison_of_DNS_blacklists"
	WPLIST=$(curl -s $WPURL | egrep "<td>([a-z]+\.){1,7}[a-z]+</td>" | sed -r 's|</?td>||g;/$Exclude/d')

	# Local List - list any custom RBL's here
	LOCALLIST='
		dnsbl-1.uceprotect.net
		dnsbl-2.uceprotect.net
		dnsbl-3.uceprotect.net
		psbl.surriel.com
	'
fi;

# Store output.
OUTFILE=`mktemp /tmp/hunterlist.XXXXXXXX`

# Iterate through each range and push the IP's into a new array
for i in "${IPADDRS[@]}"; do

	# prips doesn't like non-cidr, so for single IPs just use the IP as the start/end
	if [ "$(echo "${i}" | grep -i "/")" = "" ]; then
		i="$i $i"
	fi;

	# Check each IP for open relay status
	for IP in `prips $i`; do
		echo "Checking $IP"

		if [ "${CHECKSMTP}" -eq 1 ]; then
			if [ "$(nmap -pT:25 --script smtp-open-relay $IP | grep "Server is an open relay")" != "" ]; then
				echo "$IP is an open SMTP relay." >> "${OUTFILE}"
			fi
		fi;

		if [ "${CHECKMIKROTIK}" -eq 1 ]; then
			if [ "$(nmap -pT:8291 --script routeros-mikrotik $IP | grep "Winbox Port is Open")" != "" ]; then
				echo "$IP exposed winbox port to public" >> "${OUTFILE}"
			fi
		fi;


		if [ "${CHECKDNS}" -eq 1 ]; then
			if [ "$(dig +time=1 +tries=1 +short google.com @$IP | grep -v ';;')" != "" ]; then
				echo "$IP is an open DNS Resolver." >> "${OUTFILE}"
			fi;
		fi;

		if [ "${CHECKHEART}" -eq 1 ]; then
			if [ "$(nmap -p 443 --script ssl-heartbleed $IP | grep "VULNERABLE")" != "" ]; then
				echo "$IP is vulnerable to SSL Heartbleed." >> "${OUTFILE}"
			fi;
		fi;

		if [ "${CHECKSUPIPMI}" -eq 1 ]; then
			if [ "$(nmap -p 49152 --script supermicro-ipmi-conf $IP | grep "VULNERABLE")" != "" ]; then
				echo "$IP has a vulnerable IPMI." >> "${OUTFILE}"
			fi;
		fi;

		if [ "${CHECKBLACK}" -eq 1 ]; then
			# Reverse our IP
			RIP=`echo $IP | awk -F. '{print $4"."$3"."$2"."$1}'`

			# Check IP against each RBL from Wikipedia
			for BL in $WPLIST; do
				RESULT=$(dig +short $RIP.$BL)
				if [ -n "$RESULT" ]; then 
					echo "$IP may be listed on $BL" >> "${OUTFILE}"
				fi
			done

			# Check IP against each RBL from Wikipedia
			for BL in $LOCALLIST; do
				RESULT=$(dig +short $RIP.$BL)
				if [ -n "$RESULT" ]; then
					echo "$IP may be listed on $BL" >> "${OUTFILE}"
				fi
			done
		fi;
	done
done

# Did we catch anybody? If yes, email somebody to do something about them.
if [ $(cat "${OUTFILE}" | wc -l) -gt 0 ]; then
	if [ "${TOADDR}" = "" -o "${FROMADDR}" = "" ]; then
		cat "${OUTFILE}"
	else
		mail -r "${FROMADDR}" -s "List of Open DNS and SMTP Servers" "${TOADDR}" < "${OUTFILE}"
	fi;
fi

rm -rf "${OUTFILE}"
