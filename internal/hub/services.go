// SPDX-License-Identifier: AGPL-3.0-only

package hub

// wellKnownPorts names the services a homelab's TCP connections commonly go
// to, by server port. It is a label, not a fact: whatever listens on the
// port may be something else.
var wellKnownPorts = map[uint16]string{
	21:    "ftp",
	22:    "ssh",
	23:    "telnet",
	25:    "smtp",
	53:    "dns",
	80:    "http",
	110:   "pop3",
	111:   "rpcbind",
	139:   "netbios",
	143:   "imap",
	389:   "ldap",
	443:   "https",
	445:   "smb",
	465:   "smtps",
	548:   "afp",
	587:   "submission",
	631:   "ipp",
	636:   "ldaps",
	853:   "dns-over-tls",
	873:   "rsync",
	993:   "imaps",
	995:   "pop3s",
	1883:  "mqtt",
	2049:  "nfs",
	2375:  "docker",
	2376:  "docker-tls",
	2379:  "etcd",
	2380:  "etcd-peer",
	3306:  "mysql",
	3389:  "rdp",
	5432:  "postgres",
	5900:  "vnc",
	6379:  "redis",
	6443:  "kube-api",
	7080:  "hearth-ui",
	7443:  "hearth",
	7444:  "hearth-cluster",
	8006:  "proxmox",
	8080:  "http-alt",
	8086:  "influxdb",
	8123:  "home-assistant",
	8443:  "https-alt",
	8883:  "mqtts",
	9090:  "prometheus",
	9100:  "node-exporter",
	10250: "kubelet",
	27017: "mongodb",
	32400: "plex",
	50000: "talos-api",
	50001: "talos-trustd",
}

// serviceName is the well-known service of a TCP server port; empty when
// the port is not in the table.
func serviceName(port uint16) string { return wellKnownPorts[port] }
