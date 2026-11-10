// SPDX-FileCopyrightText: 2026 Balázs Toldi
//
// SPDX-License-Identifier: Apache-2.0

package sbiaddr

import (
	"strings"
	"testing"
)

// Values shared by the tests in this package.
const (
	hostAMF    = "amf"
	hostSMF    = "smf"
	fqdnAMF    = "amf.omec.svc.cluster.local"
	ipv4Any    = "0.0.0.0"
	ipv4AMF    = "127.0.0.18"
	ipv4Doc    = "192.0.2.1"
	ipv6Doc    = "2001:db8::1"
	ipv6Loop   = "::1"
	zonedV6    = "fe80::1%eth0"
	notAnAddr  = "not an address"
	schemeHTTP = "http"
	schemeTLS  = "https"
	spaceOnly  = "space only"
)

func TestClassify(t *testing.T) {
	label63 := strings.Repeat("a", 63)
	name253 := strings.Repeat(label63+".", 3) + strings.Repeat("b", 61) // 3*64 + 61 = 253

	tests := []struct {
		name string
		in   string
		want string
		kind Kind
	}{
		// IPv4
		{name: "dotted quad", in: litV4, kind: IPv4, want: litV4},
		{name: "IPv4 with surrounding space", in: "  " + litV4 + "\t", kind: IPv4, want: litV4},
		{name: "IPv4 wildcard", in: ipv4Any, kind: IPv4, want: ipv4Any},
		{name: "IPv4 loopback", in: ipv4AMF, kind: IPv4, want: ipv4AMF},
		{name: "IPv4 broadcast", in: "255.255.255.255", kind: IPv4, want: "255.255.255.255"},
		{name: "IPv4-mapped IPv6", in: "::ffff:" + ipv4Doc, kind: IPv4, want: ipv4Doc},
		{name: "IPv4-mapped IPv6 in hex", in: "::ffff:c000:201", kind: IPv4, want: ipv4Doc},
		{name: "bracketed IPv4-mapped IPv6", in: "[::ffff:" + ipv4Doc + "]", kind: IPv4, want: ipv4Doc},

		// IPv6
		{name: "IPv6 text", in: ipv6Doc, kind: IPv6, want: ipv6Doc},
		{name: "IPv6 is put in RFC 5952 form", in: "2001:DB8:0:0:0:0:0:1", kind: IPv6, want: ipv6Doc},
		{name: "IPv6 wildcard", in: "::", kind: IPv6, want: "::"},
		{name: "IPv6 loopback", in: ipv6Loop, kind: IPv6, want: ipv6Loop},
		{name: "IPv6 ULA", in: "fd00::5", kind: IPv6, want: "fd00::5"},
		{name: "IPv6 in brackets", in: "[" + ipv6Doc + "]", kind: IPv6, want: ipv6Doc},
		{name: "bracketed IPv6 with space", in: " [" + ipv6Doc + "] ", kind: IPv6, want: ipv6Doc},
		{name: "NAT64 is not IPv4-mapped", in: "64:ff9b::192.0.2.1", kind: IPv6, want: "64:ff9b::c000:201"},
		{name: "IPv4-compatible is not IPv4-mapped", in: "::192.0.2.1", kind: IPv6, want: "::c000:201"},
		{name: "IPv6 with zone", in: zonedV6, kind: IPv6, want: zonedV6},
		{name: "bracketed IPv6 with zone", in: "[" + zonedV6 + "]", kind: IPv6, want: zonedV6},
		{name: "bracketed IPv6 with encoded zone", in: "[fe80::1%25eth0]", kind: IPv6, want: zonedV6},

		// FQDN
		{name: "single label", in: hostAMF, kind: FQDN, want: hostAMF},
		{name: "case is kept", in: "AmF", kind: FQDN, want: "AmF"},
		{name: "service FQDN", in: fqdnAMF, kind: FQDN, want: fqdnAMF},
		{name: "trailing dot", in: fqdnAMF + ".", kind: FQDN, want: fqdnAMF + "."},
		{name: "hyphen inside", in: "upf-adapter", kind: FQDN, want: "upf-adapter"},
		{name: "underscore (docker compose names)", in: "omec_amf", kind: FQDN, want: "omec_amf"},
		{name: "digits in labels", in: "nf1.site2.example", kind: FQDN, want: "nf1.site2.example"},
		{name: "leading digit label", in: "5gc.example", kind: FQDN, want: "5gc.example"},
		{name: "63-character label", in: label63, kind: FQDN, want: label63},
		{name: "253-character name", in: name253, kind: FQDN, want: name253},
		{name: "env var name is a valid name", in: "POD_IP", kind: FQDN, want: "POD_IP"},

		// Invalid
		{name: "empty", in: "", kind: Invalid},
		{name: spaceOnly, in: "   ", kind: Invalid},
		{name: "bracketed IPv4", in: "[" + litV4 + "]", kind: Invalid},
		{name: "bracketed name", in: "[amf]", kind: Invalid},
		{name: "empty brackets", in: "[]", kind: Invalid},
		{name: "open bracket only", in: "[" + ipv6Doc, kind: Invalid},
		{name: "close bracket only", in: ipv6Doc + "]", kind: Invalid},
		{name: "single bracket", in: "[", kind: Invalid},
		{name: "IPv6 with port", in: "[" + ipv6Doc + "]:80", kind: Invalid},
		{name: "IPv4 with port", in: litV4 + ":80", kind: Invalid},
		{name: "name with port", in: "amf:29518", kind: Invalid},
		{name: "IPv4 with zone", in: litV4 + "%eth0", kind: Invalid},
		{name: "IPv4 octet out of range", in: "10.0.0.256", kind: Invalid},
		{name: "short IPv4", in: "1.2.3", kind: Invalid},
		{name: "IPv4 with leading zero", in: "010.0.0.1", kind: Invalid},
		{name: "numeric only", in: "123", kind: Invalid},
		{name: "bad IPv6 digit", in: "2001:db8::g", kind: Invalid},
		{name: "two double colons", in: "2001::db8::1", kind: Invalid},
		{name: "CIDR", in: "10.0.0.0/24", kind: Invalid},
		{name: "list", in: litV4 + "," + ipv6Doc, kind: Invalid},
		{name: "empty label", in: "amf..omec", kind: Invalid},
		{name: "leading dot", in: ".amf", kind: Invalid},
		{name: "two trailing dots", in: "amf..", kind: Invalid},
		{name: "dot only", in: ".", kind: Invalid},
		{name: "leading hyphen", in: "-amf", kind: Invalid},
		{name: "trailing hyphen", in: "amf-", kind: Invalid},
		{name: "64-character label", in: label63 + "a", kind: Invalid},
		{name: "254-character name", in: name253 + "b", kind: Invalid},
		{name: "space inside", in: notAnAddr, kind: Invalid},
		{name: "URL", in: "http://amf", kind: Invalid},
		{name: "path", in: "amf/nnrf", kind: Invalid},
		{name: "non-ASCII", in: "ámf", kind: Invalid},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			kind, got := Classify(tc.in)
			if kind != tc.kind || got != tc.want {
				t.Fatalf("Classify(%q) = (%v, %q), want (%v, %q)", tc.in, kind, got, tc.kind, tc.want)
			}
		})
	}
}

func TestKindString(t *testing.T) {
	for kind, want := range map[Kind]string{
		Invalid:  "invalid",
		IPv4:     "IPv4",
		IPv6:     "IPv6",
		FQDN:     "FQDN",
		Kind(99): "invalid",
	} {
		if got := kind.String(); got != want {
			t.Errorf("Kind(%d).String() = %q, want %q", uint8(kind), got, want)
		}
	}
}
