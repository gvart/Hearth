// SPDX-License-Identifier: AGPL-3.0-only

package discovery

import "testing"

func TestClassify(t *testing.T) {
	type in struct {
		services []string
		vendor   string
		hostname string
		gateway  bool
	}
	cases := []struct {
		name  string
		in    in
		kind  Kind
		agent bool
	}{
		// router
		{"the gateway", in{nil, "Arcadyan", "", true}, KindRouter, false},
		{"the gateway wins over anything", in{[]string{"_ipp._tcp", "_ssh._tcp"}, "Raspberry Pi", "printer", true}, KindRouter, true},
		{"router vendor", in{nil, "Ubiquiti", "", false}, KindRouter, false},
		{"router vendor, any case", in{nil, "FRITZ!", "", false}, KindRouter, false},
		{"router by its own name", in{nil, "", "fritz.box", false}, KindRouter, false},
		{"switch by name", in{nil, "TP-LINK", "TL-SG108E.lan", false}, KindRouter, false},
		{"openwrt", in{[]string{"_ssh._tcp"}, "", "OpenWrt.lan", false}, KindRouter, true},

		// printer
		{"print service", in{[]string{"_http._tcp", "_ipp._tcp"}, "Hewlett Packard", "HP1A2B3C.local", false}, KindPrinter, false},
		{"print service beats a phone-ish name", in{[]string{"_printer._tcp"}, "", "Galaxy-Printer", false}, KindPrinter, false},
		{"printer vendor", in{nil, "Seiko Epson", "", false}, KindPrinter, false},
		{"printer by name", in{nil, "", "officejet-pro.lan", false}, KindPrinter, false},

		// nas
		{"nas vendor with ssh", in{[]string{"_ssh._tcp", "_http._tcp"}, "Synology", "", false}, KindNAS, true},
		{"nas by name", in{[]string{"_ssh._tcp"}, "Intel", "truenas.local", false}, KindNAS, true},
		{"nas by word", in{nil, "", "nas-01", false}, KindNAS, false},
		{"file shares without a desktop", in{[]string{"_smb._tcp", "_adisk._tcp"}, "", "", false}, KindNAS, false},

		// media
		{"cast", in{[]string{"_googlecast._tcp"}, "Google", "", false}, KindMedia, false},
		{"apple tv: airplay, sleep proxy", in{
			[]string{"_airplay._tcp", "_companion-link._tcp", "_raop._tcp", "_sleep-proxy._udp"}, "Apple", "Bedroom.local", false,
		}, KindMedia, false},
		{"tv with matter and homekit", in{[]string{"_airplay._tcp", "_hap._tcp", "_matter._tcp"}, "Qingdao Intelligent&Prec", "LinuxTV.local", false}, KindMedia, false},
		{"console by name", in{[]string{"_spotify-connect._tcp"}, "Hon Hai Precision Ind.", "PS4-61ED17.local", false}, KindMedia, false},
		{"console maker by name", in{nil, "", "Nintendo-Switch", false}, KindMedia, false},
		{"media vendor, any case", in{nil, "SONOS", "", false}, KindMedia, false},
		{"echo", in{[]string{"_spotify-connect._tcp"}, "Amazon", "none-2.local", false}, KindMedia, false},
		{"tv by word", in{nil, "", "living-room-tv", false}, KindMedia, false},

		// phone
		{"iphone by name", in{[]string{"_remotepairing._tcp"}, "", "Vladlens-iPhone.local", false}, KindPhone, false},
		{"android by name", in{nil, "", "android-3f2a9c1d", false}, KindPhone, false},
		{"pixel by word", in{nil, "Google", "Pixel-7", false}, KindPhone, false},
		{"ios pairing service", in{[]string{"_apple-mobdev2._tcp"}, "Apple", "Anna", false}, KindPhone, false},
		{"phone vendor", in{nil, "OnePlus", "", false}, KindPhone, false},
		{"lenovo mobile is a phone, not a computer", in{nil, "Lenovo Mobile", "", false}, KindPhone, false},

		// computer
		{"mac by name, though it airplays", in{
			[]string{"_airplay._tcp", "_companion-link._tcp", "_raop._tcp"}, "Apple", "MacBook-Air-von-Anna.local", false,
		}, KindComputer, true},
		{"ssh", in{[]string{"_ssh._tcp"}, "", "", false}, KindComputer, true},
		{"workstation with shares", in{[]string{"_smb._tcp", "_workstation._tcp"}, "", "", false}, KindComputer, true},
		{"raspberry pi", in{nil, "Raspberry Pi", "pi.hole", false}, KindComputer, true},
		{"laptop oem", in{nil, "LCFC", "parleyroom.k8s.lan", false}, KindComputer, true},
		{"virtual machine", in{nil, "Proxmox Server", "", false}, KindComputer, true},
		{"intel, more words", in{nil, "Intel Corporate", "", false}, KindComputer, true},
		{"pc by word", in{nil, "", "gaming-pc", false}, KindComputer, true},
		{"mac by word", in{nil, "", "Mac.lan", false}, KindComputer, true},
		{"a word inside another word does not count", in{nil, "", "pixelbook", false}, KindUnknown, false},

		// iot
		{"esphome", in{[]string{"_esphomelib._tcp"}, "Espressif", "", false}, KindIoT, false},
		{"homekit accessory", in{[]string{"_hap._tcp"}, "", "", false}, KindIoT, false},
		{"iot vendor", in{nil, "Tuya Smart", "wlan0.lan", false}, KindIoT, false},
		{"shelly by name", in{[]string{"_http._tcp"}, "", "shellyplus1-a8032ab12345", false}, KindIoT, false},
		{"camera by word", in{nil, "", "garage-cam", false}, KindIoT, false},

		// unknown
		{"nothing", in{nil, "", "", false}, KindUnknown, false},
		{"the domain says nothing of the host", in{nil, "", "anna-7.fritz.box", false}, KindUnknown, false},
		{"a vendor matches in whole words", in{nil, "Intelbras", "", false}, KindUnknown, false},
		{"sonosite is no sonos", in{nil, "SonoSite", "", false}, KindUnknown, false},
		{"apple says nothing alone", in{nil, "Apple", "", false}, KindUnknown, false},
		{"a randomized mac with a quiet service", in{[]string{"_asquic._udp"}, "", "Anechka.local", false}, KindUnknown, false},
		{"http alone says nothing", in{[]string{"_http._tcp"}, "TP-LINK", "", false}, KindUnknown, false},
	}
	seen := map[Kind]bool{}
	for _, c := range cases {
		kind, agent := Classify(c.in.services, c.in.vendor, c.in.hostname, c.in.gateway)
		if kind != c.kind || agent != c.agent {
			t.Errorf("%s: Classify(%v, %q, %q, %v) = %s, %v; want %s, %v",
				c.name, c.in.services, c.in.vendor, c.in.hostname, c.in.gateway, kind, agent, c.kind, c.agent)
		}
		seen[c.kind] = true
	}
	for _, k := range []Kind{KindRouter, KindPrinter, KindMedia, KindPhone, KindComputer, KindNAS, KindIoT, KindUnknown} {
		if !seen[k] {
			t.Errorf("no case of %s", k)
		}
	}
}
