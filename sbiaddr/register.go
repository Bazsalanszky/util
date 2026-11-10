// SPDX-FileCopyrightText: 2026 Balázs Toldi
//
// SPDX-License-Identifier: Apache-2.0

package sbiaddr

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"strings"
)

// Names of the Kubernetes downward-API variables the charts set: POD_IP from
// status.podIP (the primary family only) and POD_IPS from status.podIPs (one
// address per family, comma-separated).
//
// They are placeholders: when one of them is configured but not set in the
// environment it resolves to nothing, instead of being taken for a host name.
const (
	EnvPodIP  = "POD_IP"
	EnvPodIPs = "POD_IPS"
)

// Preference is the address family used when a single host has to be chosen
// and the NF has addresses of both families but no host name.
type Preference uint8

const (
	// PreferIPv4 is the default, and what every NF does today.
	PreferIPv4 Preference = iota
	// PreferIPv6 uses the IPv6 address when there is one.
	PreferIPv6
)

// ParsePreference parses a configured family preference. It accepts "IPv4",
// "IPv6", "v4", "v6", "4" and "6" in any case. An empty value is PreferIPv4.
// For any other value it returns PreferIPv4 and an error.
func ParsePreference(s string) (Preference, error) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "", "ipv4", "v4", "4":
		return PreferIPv4, nil
	case "ipv6", "v6", "6":
		return PreferIPv6, nil
	default:
		return PreferIPv4, fmt.Errorf("unknown address family preference %q, want IPv4 or IPv6", s)
	}
}

// String returns "IPv4" or "IPv6".
func (p Preference) String() string {
	if p == PreferIPv6 {
		return "IPv6"
	}
	return "IPv4"
}

// RegisterAddrs are the addresses an NF advertises in its NF profile and uses
// in its own URIs. Each field is empty or holds a canonical value of its kind
// (see Classify). A zero RegisterAddrs means that nothing usable was
// configured; the NF then applies its own default.
type RegisterAddrs struct {
	// FQDN goes into NFProfile.fqdn and NFService.fqdn.
	FQDN string
	// IPv4 goes into NFProfile.ipv4Addresses and an IpEndPoint.ipv4Address.
	IPv4 string
	// IPv6 goes into NFProfile.ipv6Addresses and an IpEndPoint.ipv6Address.
	IPv6 string
}

// Empty reports whether no address was resolved.
func (a RegisterAddrs) Empty() bool {
	return a.FQDN == "" && a.IPv4 == "" && a.IPv6 == ""
}

// IP returns the address of the preferred family, else the other one, else
// "".
func (a RegisterAddrs) IP(p Preference) string {
	first, second := a.IPv4, a.IPv6
	if p == PreferIPv6 {
		first, second = second, first
	}
	if first != "" {
		return first
	}
	return second
}

// Host returns the host for the NF's own URIs: the FQDN if there is one,
// else IP(p). It is unbracketed; use URI or HostPort to combine it with a
// port.
func (a RegisterAddrs) Host(p Preference) string {
	if a.FQDN != "" {
		return a.FQDN
	}
	return a.IP(p)
}

// URI returns scheme://host:port for the NF's own URIs (ApiPrefix, callback
// and Location URIs), with host = Host(p). It returns "" when a is Empty.
func (a RegisterAddrs) URI(scheme string, port int, p Preference) string {
	host := a.Host(p)
	if host == "" {
		return ""
	}
	return URI(scheme, host, port)
}

// ResolveRegister resolves the registerIPv4 and registerIPv6 settings of an
// NF into the addresses it registers.
//
// Each setting is either a value or the name of an environment variable that
// holds the value; a set, non-empty variable wins over the literal reading
// (the same rule the NFs already apply to bindingIPv4). A value is one item
// or a comma-separated list, so POD_IPS ("10.0.0.5,fd00::5") fills both
// families. Each item is classified (see Classify) and goes to the slot of its
// own kind, whichever setting it came from: an IPv6 POD_IP configured under
// registerIPv4 fills the IPv6 slot.
//
// When both settings provide a value for one slot, the setting named after
// that family wins (registerIPv4 for IPv4, registerIPv6 for IPv6, and
// registerIPv4 for the FQDN, as today); within one setting the first item
// wins.
//
// Items that are not used are reported in err, joined with errors.Join:
// invalid values, IPv6 addresses with a zone (which mean nothing to another
// host), unset POD_IP or POD_IPS, and values that lost to another one. The
// returned addresses are valid even when err is not nil, so callers log err
// as a warning and carry on, applying their default when the result is
// Empty.
func ResolveRegister(registerIPv4, registerIPv6 string) (RegisterAddrs, error) {
	return resolveRegister(registerIPv4, registerIPv6, os.LookupEnv)
}

// ParseRegister is ResolveRegister without the environment: both values are
// read literally. NFs use it to rebuild RegisterAddrs from the hosts kept in
// their context (RegisterIPv4 holding an IPv4 address or a host name, as
// today, and RegisterIPv6), so that code and tests that set those fields
// directly keep working.
func ParseRegister(registerIPv4, registerIPv6 string) (RegisterAddrs, error) {
	return resolveRegister(registerIPv4, registerIPv6, func(string) (string, bool) { return "", false })
}

type candidate struct {
	value  string
	source string
	kind   Kind
}

func resolveRegister(registerIPv4, registerIPv6 string, lookupEnv func(string) (string, bool)) (RegisterAddrs, error) {
	fromV4, errs := expand("registerIPv4", registerIPv4, lookupEnv)
	fromV6, errs6 := expand("registerIPv6", registerIPv6, lookupEnv)
	errs = append(errs, errs6...)

	var addrs RegisterAddrs
	errs = fill(&addrs.IPv4, IPv4, errs, fromV4, fromV6)
	errs = fill(&addrs.IPv6, IPv6, errs, fromV6, fromV4)
	errs = fill(&addrs.FQDN, FQDN, errs, fromV4, fromV6)
	return addrs, errors.Join(errs...)
}

// expand reads one register setting into its classified items.
func expand(key, value string, lookupEnv func(string) (string, bool)) ([]candidate, []error) {
	value = strings.TrimSpace(value)
	if value == "" {
		return nil, nil
	}
	source := key
	items := value
	if env, ok := lookupEnv(value); ok && strings.TrimSpace(env) != "" {
		source = key + " (environment variable " + value + ")"
		items = env
	} else if value == EnvPodIP || value == EnvPodIPs {
		return nil, []error{fmt.Errorf("%s: environment variable %s is empty or not set", key, value)}
	}

	var (
		out  []candidate
		errs []error
	)
	for item := range strings.SplitSeq(items, ",") {
		item = strings.TrimSpace(item)
		if item == "" {
			continue
		}
		kind, canonical := Classify(item)
		switch {
		case kind == Invalid:
			errs = append(errs, fmt.Errorf("%s: %q is not an IPv4 address, an IPv6 address or a host name", source, item))
		case kind == IPv6 && strings.Contains(canonical, "%"):
			errs = append(errs, fmt.Errorf("%s: %q has a zone, so other hosts cannot use it", source, item))
		default:
			out = append(out, candidate{value: canonical, source: source, kind: kind})
		}
	}
	return out, errs
}

// fill sets *slot to the first candidate of the given kind, looking at the
// lists in order, and reports every other, different candidate of that kind.
func fill(slot *string, kind Kind, errs []error, lists ...[]candidate) []error {
	var winner candidate
	for _, list := range lists {
		for _, c := range list {
			switch {
			case c.kind != kind:
			case *slot == "":
				*slot, winner = c.value, c
			case c.value != *slot:
				errs = append(errs, fmt.Errorf("%s: ignoring %s %s, using %s from %s",
					c.source, kind, c.value, winner.value, winner.source))
			}
		}
	}
	return errs
}

// FromInterfaceAddrs picks register addresses from the host's interface
// addresses, typically net.InterfaceAddrs(). It is a fallback for an NF that
// was told to register POD_IP but runs where POD_IP is not set (the SMF does
// this today, for IPv4 only).
//
// IPv4 is the first non-loopback IPv4 address, which is the SMF's current
// choice (Go reports IPv4 interface addresses in their 16-byte, IPv4-mapped
// form, so mapped addresses count as IPv4). IPv6 is the first IPv6 address
// that is not loopback or link-local. FQDN is always empty.
func FromInterfaceAddrs(addrs []net.Addr) RegisterAddrs {
	var out RegisterAddrs
	for _, a := range addrs {
		var ip net.IP
		switch v := a.(type) {
		case *net.IPNet:
			ip = v.IP
		case *net.IPAddr:
			ip = v.IP
		default:
			continue
		}
		addr, ok := netip.AddrFromSlice(ip)
		if !ok {
			continue
		}
		addr = addr.Unmap()
		if addr.IsLoopback() || addr.IsUnspecified() {
			continue
		}
		switch {
		case addr.Is4():
			if out.IPv4 == "" {
				out.IPv4 = addr.String()
			}
		case addr.IsLinkLocalUnicast():
		case out.IPv6 == "":
			out.IPv6 = addr.String()
		}
	}
	return out
}
