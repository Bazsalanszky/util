// SPDX-FileCopyrightText: 2026 Balázs Toldi
//
// SPDX-License-Identifier: Apache-2.0

// Package sbiaddr holds the address handling shared by the SBI (HTTP/2) side
// of the network functions: classifying a configured host as an IPv4 address,
// an IPv6 address or a host name, resolving the addresses an NF registers at
// the NRF (including the POD_IP and POD_IPS environment variables), choosing
// the listen address, and building scheme://host:port URIs with IPv6 hosts in
// brackets.
//
// The package has no dependency on the OpenAPI models, so it can be used by
// any NF and by the libraries the NFs share.
package sbiaddr

import (
	"net/netip"
	"strings"
)

// Kind is what a configured host value turned out to be.
type Kind uint8

const (
	// Invalid is a value that is neither an IP address nor a host name.
	Invalid Kind = iota
	// IPv4 is an IPv4 address, including one written as an IPv4-mapped
	// IPv6 address (::ffff:a.b.c.d).
	IPv4
	// IPv6 is an IPv6 address.
	IPv6
	// FQDN is a host name: a single label such as "amf" or a fully
	// qualified domain name.
	FQDN
)

// String returns "IPv4", "IPv6", "FQDN" or "invalid".
func (k Kind) String() string {
	switch k {
	case IPv4:
		return "IPv4"
	case IPv6:
		return "IPv6"
	case FQDN:
		return "FQDN"
	default:
		return "invalid"
	}
}

// Classify reports what s is and returns it in canonical form:
//   - IPv4: dotted decimal. An IPv4-mapped IPv6 address (::ffff:192.0.2.1)
//     is returned as the IPv4 address it maps, because that is the family
//     the socket uses and TS 29.510 does not allow the mixed notation in an
//     Ipv6Addr (RFC 5952 §5).
//   - IPv6: the RFC 5952 text form, without brackets. A zone
//     ("fe80::1%eth0") is kept.
//   - FQDN: the name as given. Labels may contain letters, digits, '-' and
//     '_' (as Go's resolver accepts); a single trailing dot is allowed.
//
// Surrounding white space is ignored. An IPv6 address may be written in
// brackets ("[2001:db8::1]"); any other bracketed value, a value with a
// port, an empty value, and a name whose last label is all digits (for
// example the malformed IPv4 address "10.0.0.256") are Invalid, and the
// returned string is then empty.
func Classify(s string) (Kind, string) {
	s = strings.TrimSpace(s)
	if s == "" {
		return Invalid, ""
	}
	if strings.HasPrefix(s, "[") || strings.HasSuffix(s, "]") {
		inner, ok := unbracket(s)
		if !ok {
			return Invalid, ""
		}
		// A zone in a URI-style literal is percent-encoded (RFC 6874).
		addr, err := netip.ParseAddr(strings.Replace(inner, "%25", "%", 1))
		if err != nil || !addr.Is6() {
			return Invalid, ""
		}
		return classifyAddr(addr)
	}
	if addr, err := netip.ParseAddr(s); err == nil {
		return classifyAddr(addr)
	}
	if isHostName(s) {
		return FQDN, s
	}
	return Invalid, ""
}

func classifyAddr(addr netip.Addr) (Kind, string) {
	addr = addr.Unmap()
	if addr.Is4() {
		return IPv4, addr.String()
	}
	return IPv6, addr.String()
}

// unbracket returns the text inside one pair of surrounding brackets.
func unbracket(s string) (string, bool) {
	if len(s) < 2 || s[0] != '[' || s[len(s)-1] != ']' {
		return "", false
	}
	return s[1 : len(s)-1], true
}

// stripBrackets removes one pair of surrounding brackets, if present.
func stripBrackets(s string) string {
	if inner, ok := unbracket(s); ok {
		return inner
	}
	return s
}

// isHostName reports whether s is a syntactically valid host name.
func isHostName(s string) bool {
	s = strings.TrimSuffix(s, ".")
	if s == "" || len(s) > 253 {
		return false
	}
	labels := strings.Split(s, ".")
	for _, label := range labels {
		if !isLabel(label) {
			return false
		}
	}
	// A name whose last label is numeric is a mistyped IPv4 address, not a
	// host name (RFC 3696 §2).
	return !isDigits(labels[len(labels)-1])
}

func isLabel(label string) bool {
	if label == "" || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
		return false
	}
	for i := 0; i < len(label); i++ {
		c := label[i]
		switch {
		case 'a' <= c && c <= 'z', 'A' <= c && c <= 'Z', '0' <= c && c <= '9', c == '-', c == '_':
		default:
			return false
		}
	}
	return true
}

func isDigits(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}
	return true
}
