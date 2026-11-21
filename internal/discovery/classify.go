// SPDX-License-Identifier: AGPL-3.0-only

package discovery

import (
	"slices"
	"strings"
)

// Kind is what sort of thing a discovered host is (see Classify).
type Kind string

// The kinds of host.
const (
	// KindRouter is the gateway, or other network gear: a switch, an
	// access point, a modem.
	KindRouter Kind = "router"
	// KindPrinter is a printer or scanner.
	KindPrinter Kind = "printer"
	// KindMedia is a TV, streamer, speaker or console.
	KindMedia Kind = "media"
	// KindPhone is a phone or tablet.
	KindPhone Kind = "phone"
	// KindComputer is a desktop, laptop, server, single-board computer or
	// virtual machine.
	KindComputer Kind = "computer"
	// KindNAS is network storage.
	KindNAS Kind = "nas"
	// KindIoT is a smart-home device: a plug, bulb, sensor, camera or
	// microcontroller.
	KindIoT Kind = "iot"
	// KindUnknown is a host nothing gives away.
	KindUnknown Kind = "unknown"
)

// Classify guesses a host's kind from what discovery learned of it: the mDNS
// service types it answers for, its MAC's vendor, its hostname and whether
// it is the scanner's default gateway. It also reports whether the host
// looks able to run a Hearth agent: a computer, or anything offering a shell
// (_ssh._tcp, _sftp-ssh._tcp) or announcing itself as a workstation.
//
// The first rule that matches wins (docs/discovery.md, "Kinds"):
//
//  1. the gateway is a router;
//  2. a print service makes a printer;
//  3. a telling hostname ("iphone", "macbook", "synology", ...);
//  4. a vendor that makes one sort of thing (Synology, Sonos, Espressif,
//     Raspberry Pi, ...);
//  5. the services: file shares without desktop signs make a NAS, a shell
//     or workstation a computer, casting and AirPlay media, smart-home
//     protocols IoT, iOS pairing a phone;
//  6. else unknown.
//
// Hostnames come before services because a Mac answers for AirPlay like an
// Apple TV does, and vendors because a NAS offers a shell like a computer
// does. Apple, Samsung, Google and Amazon's Ring make every kind, and are
// left to the services.
func Classify(services []string, vendor, host string, gateway bool) (kind Kind, agentCapable bool) {
	kind = classify(services, strings.ToLower(vendor), parseHostname(host), gateway)
	agentCapable = kind == KindComputer || hasAny(services, shellServices)
	return kind, agentCapable
}

func classify(services []string, vendor string, host hostname, gateway bool) Kind {
	if gateway {
		return KindRouter
	}
	if hasAny(services, printerServices) {
		return KindPrinter
	}
	for _, h := range hostnameHints {
		if h.match(host) {
			return h.kind
		}
	}
	for _, v := range vendorKinds {
		if slices.ContainsFunc(v.prefixes, func(p string) bool { return strings.HasPrefix(vendor, p) }) {
			return v.kind
		}
	}
	switch {
	case hasAny(services, fileServices) && !hasAny(services, desktopServices):
		return KindNAS
	case hasAny(services, shellServices) || hasAny(services, desktopServices):
		return KindComputer
	case hasAny(services, mediaServices):
		return KindMedia
	case hasAny(services, iotServices):
		return KindIoT
	case hasAny(services, phoneServices):
		return KindPhone
	}
	return KindUnknown
}

var (
	printerServices = []string{
		"_ipp._tcp", "_ipps._tcp", "_printer._tcp", "_pdl-datastream._tcp", "_uscan._tcp", "_scanner._tcp",
	}
	// fileServices are file shares; a NAS offers them, so does a desktop
	// sharing a folder.
	fileServices = []string{"_smb._tcp", "_afpovertcp._tcp", "_adisk._tcp", "_nfs._tcp"}
	// shellServices offer a shell: whatever runs them can run an agent.
	shellServices = []string{"_ssh._tcp", "_sftp-ssh._tcp", "_workstation._tcp"}
	// desktopServices are announced by desktops (avahi's _workstation,
	// screen sharing), not by a NAS.
	desktopServices = []string{"_workstation._tcp", "_rfb._tcp"}
	mediaServices   = []string{
		"_googlecast._tcp", "_airplay._tcp", "_raop._tcp", "_spotify-connect._tcp", "_sonos._tcp",
		"_amzn-wplay._tcp", "_androidtvremote2._tcp", "_sleep-proxy._udp",
	}
	iotServices = []string{
		"_esphomelib._tcp", "_hap._tcp", "_matter._tcp", "_hue._tcp", "_shelly._tcp",
	}
	// phoneServices are announced by iPhones and iPads: Wi-Fi sync and
	// developer pairing.
	phoneServices = []string{"_apple-mobdev2._tcp", "_remotepairing._tcp"}
)

// hostnameHint matches a hostname that gives its kind away: one containing
// any of substrings (distinctive words), or having any of words as a whole
// word (short ones, which would match inside other words).
type hostnameHint struct {
	kind       Kind
	substrings []string
	words      []string
}

func (h hostnameHint) match(host hostname) bool {
	return slices.ContainsFunc(h.substrings, func(s string) bool { return strings.Contains(host.name, s) }) ||
		slices.ContainsFunc(host.words, func(w string) bool { return slices.Contains(h.words, w) })
}

// hostnameHints are tried in order: a print server named "printer-pi" is a
// printer, a "nas-backup-pc" a NAS.
var hostnameHints = []hostnameHint{
	{KindPrinter, []string{"printer", "laserjet", "officejet", "deskjet", "pixma", "ecotank"}, nil},
	{KindNAS, []string{"synology", "diskstation", "truenas", "unraid", "qnap", "readynas"}, []string{"nas"}},
	{KindMedia, []string{
		"appletv", "chromecast", "roku", "firetv", "homepod", "playstation", "xbox", "nintendo", "sonos", "bravia",
	}, []string{"tv", "ps4", "ps5", "echo", "shield", "speaker", "kodi"}},
	{KindRouter, []string{"router", "gateway", "openwrt", "fritz", "unifi", "mikrotik", "tl-sg"}, nil},
	{KindPhone, []string{"iphone", "ipad", "android", "oneplus", "redmi"}, []string{"galaxy", "pixel", "phone"}},
	{KindComputer, []string{
		"macbook", "imac", "macmini", "mac-mini", "macpro", "mac-pro", "macstudio", "mac-studio", "thinkpad",
		"desktop", "laptop", "workstation", "raspberrypi", "ubuntu", "debian", "fedora", "proxmox",
	}, []string{"pc", "nuc", "pve", "server"}},
	{
		KindIoT,
		[]string{"esphome", "esp32", "esp8266", "shelly", "tasmota", "sonoff", "tuya", "wled", "doorbell", "thermostat"},
		[]string{"esp", "hue", "plug", "bulb", "cam", "camera", "sensor", "vacuum"},
	},
}

// vendorKinds are vendors that make one sort of thing, as lower-case
// prefixes of the vendor names in the OUI table (which are cut at 24
// characters). Apple, Samsung, Google, Amazon's Ring, HP, TP-Link and the
// module makers (Hon Hai, AzureWave, Murata) make several, and name none.
var vendorKinds = []struct {
	kind     Kind
	prefixes []string
}{
	{KindPrinter, []string{"brother", "seiko epson", "canon", "lexmark", "xerox", "ricoh", "konica"}},
	{KindNAS, []string{"synology", "qnap", "asustor", "terramaster"}},
	{KindRouter, []string{
		"arcadyan", "sagemcom", "avm", "fritz!", "ubiquiti", "routerboard", "mikrotik", "zyxel", "draytek", "eero",
		"cisco", "linksys", "juniper", "fortinet", "aruba", "technicolor", "netgear", "asus network",
	}},
	{KindPhone, []string{
		"oneplus", "fairphone", "guangdong oppo", "vivo mobile", "honor device", "htc", "beijing xiaomi mobile",
		"motorola mobility", "huawei device", "lenovo mobile", "hisense mobile",
	}},
	{KindMedia, []string{
		"sonos", "roku", "amazon", "sony interactive", "sony computer", "nintendo", "bose", "vizio", "hisense",
		"qingdao hisense", "qingdao intelligent",
	}},
	{KindIoT, []string{
		"espressif", "tuya", "shelly", "allterco", "signify", "philips lighting", "ikea", "itead", "ecobee",
		"nest labs", "wyze", "tado", "lumi united",
	}},
	{KindComputer, []string{
		"raspberry pi", "intel", "dell", "lenovo", "lcfc", "micro-star", "gigabyte", "asrock", "asustek computer",
		"framework computer", "elitegroup", "super micro", "vmware", "xensource", "proxmox", "parallels",
		"pegatron", "quanta computer", "wistron",
	}},
}

// hostname is a hostname in lower case, without a .local, .lan, .home or
// .internal suffix, and its words: "Vladlens-iPhone.local" is
// vladlens-iphone, with the words vladlens and iphone.
type hostname struct {
	name  string
	words []string
}

func parseHostname(s string) hostname {
	h := strings.ToLower(strings.TrimSuffix(s, "."))
	for _, suffix := range []string{".local", ".lan", ".home", ".internal"} {
		h = strings.TrimSuffix(h, suffix)
	}
	return hostname{name: h, words: strings.FieldsFunc(h, func(r rune) bool {
		return (r < 'a' || r > 'z') && (r < '0' || r > '9')
	})}
}

func hasAny(services, of []string) bool {
	return slices.ContainsFunc(services, func(s string) bool { return slices.Contains(of, s) })
}
