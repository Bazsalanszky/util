// SPDX-FileCopyrightText: 2026 Balázs Toldi
//
// SPDX-License-Identifier: Apache-2.0

package sbiaddr

import (
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
)

// DefaultBindHost is the SBI listen host when none is configured, the same
// as today. Go's "tcp" listener on the IPv4 wildcard opens a dual-stack
// socket (IPV6_V6ONLY off), so it also accepts IPv6 connections and works in
// an IPv6-only pod.
const DefaultBindHost = "0.0.0.0"

// BindHost returns the host the SBI server listens on.
//
// bindingAddr is the family-neutral setting and wins when it is set;
// bindingIPv4 is its legacy alias. As with bindingIPv4 today, the value may
// name an environment variable (for example POD_IP), whose value is then used
// when it is set and not empty. A bracketed IPv6 address ("[::]"), which was
// the only way to pass IPv6 through the old "%s:%d" formatting, is unwrapped.
// When nothing is set the result is DefaultBindHost.
//
// One listener binds one address, so a comma-separated list (POD_IPS) is
// rejected: BindHost then returns DefaultBindHost, which covers both
// families, and an error for the caller to log. Other values are returned
// unchanged and left to net.Listen to check, as today.
func BindHost(bindingAddr, bindingIPv4 string) (string, error) {
	return bindHost(bindingAddr, bindingIPv4, os.LookupEnv)
}

func bindHost(bindingAddr, bindingIPv4 string, lookupEnv func(string) (string, bool)) (string, error) {
	key, value := "bindingAddr", strings.TrimSpace(bindingAddr)
	if value == "" {
		key, value = "bindingIPv4", strings.TrimSpace(bindingIPv4)
	}
	if value == "" {
		return DefaultBindHost, nil
	}
	if env, ok := lookupEnv(value); ok && strings.TrimSpace(env) != "" {
		key, value = key+" (environment variable "+value+")", strings.TrimSpace(env)
	}
	if strings.Contains(value, ",") {
		return DefaultBindHost, fmt.Errorf("%s: %q is a list but the SBI server binds one address; using %s, which accepts both families",
			key, value, DefaultBindHost)
	}
	return stripBrackets(value), nil
}

// HostPort joins host and port for net.Listen, net.Dial and friends,
// bracketing an IPv6 host. An already-bracketed host is unwrapped first. For
// an IPv4 address, a host name or an empty host the result is the same as
// fmt.Sprintf("%s:%d", host, port).
func HostPort(host string, port int) string {
	return net.JoinHostPort(stripBrackets(host), strconv.Itoa(port))
}

// URI returns scheme://host:port with an IPv6 host in brackets and its zone,
// if any, percent-encoded (RFC 3986 §3.2.2, RFC 6874). For an IPv4 address,
// a host name or an empty host the result is the same as
// fmt.Sprintf("%s://%s:%d", scheme, host, port). The scheme is used as
// given.
func URI(scheme, host string, port int) string {
	host = stripBrackets(host)
	if strings.Contains(host, ":") && !strings.Contains(host, "%25") {
		host = strings.Replace(host, "%", "%25", 1)
	}
	return scheme + "://" + net.JoinHostPort(host, strconv.Itoa(port))
}
