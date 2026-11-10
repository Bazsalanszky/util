// SPDX-FileCopyrightText: 2026 Balázs Toldi
//
// SPDX-License-Identifier: Apache-2.0

package sbiaddr

import (
	"fmt"
	"net"
	"net/url"
	"strconv"
	"testing"
)

// legacyBindHost is the bindingIPv4 logic every NF has today (for example
// amf util/init_context.go, nrf factory/config.go GetSbiBindingAddr).
func legacyBindHost(bindingIPv4 string, lookupEnv func(string) (string, bool)) string {
	if v, _ := lookupEnv(bindingIPv4); v != "" {
		return v
	}
	if bindingIPv4 == "" {
		return ipv4Any
	}
	return bindingIPv4
}

func TestBindHost(t *testing.T) {
	tests := []struct {
		env         map[string]string
		name        string
		bindingAddr string
		bindingIPv4 string
		want        string
		wantErr     []string
	}{
		{name: "nothing configured", want: DefaultBindHost},
		{name: spaceOnly, bindingAddr: " ", bindingIPv4: "\t", want: DefaultBindHost},
		{name: "chart default", bindingIPv4: ipv4Any, want: ipv4Any},
		{name: "IPv4 alias", bindingIPv4: litV4, want: litV4},
		{name: "host name alias", bindingIPv4: hostAMF, want: hostAMF},
		{name: "IPv6 wildcard", bindingAddr: "::", want: "::"},
		{name: "IPv6 address", bindingAddr: litV6, want: litV6},
		{name: "IPv6 wildcard in brackets", bindingAddr: "[::]", want: "::"},
		{name: "bracketed IPv6 under the alias", bindingIPv4: "[" + litV6 + "]", want: litV6},
		{name: "zoned IPv6", bindingAddr: zonedV6, want: zonedV6},
		{name: "bindingAddr wins", bindingAddr: litV6, bindingIPv4: ipv4Any, want: litV6},
		{name: "empty bindingAddr falls back", bindingAddr: "", bindingIPv4: litV4, want: litV4},
		{
			name: "POD_IP IPv4", bindingIPv4: EnvPodIP, env: map[string]string{EnvPodIP: podV4},
			want: podV4,
		},
		{
			name: "POD_IP IPv6", bindingAddr: EnvPodIP, env: map[string]string{EnvPodIP: podV6},
			want: podV6,
		},
		{
			name: "POD_IP unset is passed through, as today", bindingIPv4: EnvPodIP,
			want: EnvPodIP,
		},
		{
			name: "environment value with space", bindingAddr: EnvPodIP, env: map[string]string{EnvPodIP: " " + podV6 + " "},
			want: podV6,
		},
		{
			name: "POD_IPS dual is refused", bindingAddr: EnvPodIPs, env: map[string]string{EnvPodIPs: podV4 + "," + podV6},
			want: DefaultBindHost, wantErr: []string{"bindingAddr (environment variable POD_IPS)", "is a list"},
		},
		{
			name: "literal list is refused", bindingIPv4: litV4 + "," + litV6,
			want: DefaultBindHost, wantErr: []string{"bindingIPv4", "is a list"},
		},
		{name: "garbage is left to net.Listen", bindingIPv4: notAnAddr, want: notAnAddr},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := bindHost(tc.bindingAddr, tc.bindingIPv4, fakeEnv(tc.env))
			if got != tc.want {
				t.Errorf("bindHost(%q, %q) = %q, want %q", tc.bindingAddr, tc.bindingIPv4, got, tc.want)
			}
			checkErrs(t, err, tc.wantErr)
		})
	}
}

// TestBindHostKeepsLegacyBehaviour checks that, with only bindingIPv4 set and
// a single (non-list, unbracketed) value, the result is exactly what the NFs
// compute today.
func TestBindHostKeepsLegacyBehaviour(t *testing.T) {
	envs := []map[string]string{
		nil,
		{EnvPodIP: podV4},
		{EnvPodIP: ""},
		{"BIND": litV4},
	}
	values := []string{"", ipv4Any, litV4, hostAMF, fqdnAMF, EnvPodIP, "BIND", notAnAddr}
	for _, env := range envs {
		for _, v := range values {
			lookup := fakeEnv(env)
			got, err := bindHost("", v, lookup)
			if err != nil {
				t.Errorf("bindHost(%q) with env %v: unexpected error %v", v, env, err)
			}
			if want := legacyBindHost(v, lookup); got != want {
				t.Errorf("bindHost(%q) with env %v = %q, legacy %q", v, env, got, want)
			}
		}
	}
}

func TestBindHostReadsTheEnvironment(t *testing.T) {
	t.Setenv(EnvPodIP, podV6b)
	got, err := BindHost(EnvPodIP, "")
	if err != nil || got != podV6b {
		t.Fatalf("BindHost = (%q, %v), want %q", got, err, podV6b)
	}
}

func TestHostPort(t *testing.T) {
	tests := []struct {
		host string
		want string
		port int
	}{
		{host: ipv4Any, port: 29518, want: "0.0.0.0:29518"},
		{host: litV4, port: 8000, want: litV4 + ":8000"},
		{host: hostAMF, port: 29518, want: hostAMF + ":29518"},
		{host: "", port: 29518, want: ":29518"},
		{host: "::", port: 29518, want: "[::]:29518"},
		{host: litV6, port: 0, want: "[" + litV6 + "]:0"},
		{host: "[" + litV6 + "]", port: 80, want: "[" + litV6 + "]:80"},
		{host: zonedV6, port: 80, want: "[fe80::1%eth0]:80"},
	}
	for _, tc := range tests {
		got := HostPort(tc.host, tc.port)
		if got != tc.want {
			t.Errorf("HostPort(%q, %d) = %q, want %q", tc.host, tc.port, got, tc.want)
			continue
		}
		host, port, err := net.SplitHostPort(got)
		if err != nil || host != stripBrackets(tc.host) || port != strconv.Itoa(tc.port) {
			t.Errorf("SplitHostPort(%q) = (%q, %q, %v)", got, host, port, err)
		}
	}
}

func TestURI(t *testing.T) {
	tests := []struct {
		scheme   string
		host     string
		want     string
		wantHost string // url.URL.Hostname() of the result
		port     int
	}{
		{scheme: schemeHTTP, host: litV4, port: 29518, want: "http://" + litV4 + ":29518", wantHost: litV4},
		{scheme: schemeTLS, host: hostAMF, port: 29518, want: "https://amf:29518", wantHost: hostAMF},
		{scheme: schemeHTTP, host: litV6, port: 29518, want: "http://[" + litV6 + "]:29518", wantHost: litV6},
		{scheme: schemeHTTP, host: "[" + litV6 + "]", port: 80, want: "http://[" + litV6 + "]:80", wantHost: litV6},
		{scheme: schemeHTTP, host: ipv6Loop, port: 80, want: "http://[::1]:80", wantHost: ipv6Loop},
		{scheme: schemeHTTP, host: zonedV6, port: 80, want: "http://[fe80::1%25eth0]:80", wantHost: zonedV6},
		{scheme: schemeHTTP, host: "[fe80::1%25eth0]", port: 80, want: "http://[fe80::1%25eth0]:80", wantHost: zonedV6},
	}
	for _, tc := range tests {
		got := URI(tc.scheme, tc.host, tc.port)
		if got != tc.want {
			t.Errorf("URI(%q, %q, %d) = %q, want %q", tc.scheme, tc.host, tc.port, got, tc.want)
			continue
		}
		u, err := url.Parse(got)
		if err != nil || u.Hostname() != tc.wantHost || u.Port() != strconv.Itoa(tc.port) {
			t.Errorf("url.Parse(%q) = host %q port %q err %v", got, u.Hostname(), u.Port(), err)
		}
	}
}

// TestURIKeepsLegacyFormat checks that URI and HostPort are byte-identical to
// the fmt.Sprintf formatting the NFs use today for every host that is not an
// IPv6 address.
func TestURIKeepsLegacyFormat(t *testing.T) {
	hosts := []string{ipv4AMF, ipv4Any, litV4, hostAMF, "AMF", fqdnAMF, ""}
	schemes := []string{schemeHTTP, schemeTLS, ""}
	for _, host := range hosts {
		for _, port := range []int{0, 80, 8000, 29518, 65535} {
			if got, want := HostPort(host, port), fmt.Sprintf("%s:%d", host, port); got != want {
				t.Errorf("HostPort(%q, %d) = %q, legacy %q", host, port, got, want)
			}
			for _, scheme := range schemes {
				if got, want := URI(scheme, host, port), fmt.Sprintf("%s://%s:%d", scheme, host, port); got != want {
					t.Errorf("URI(%q, %q, %d) = %q, legacy %q", scheme, host, port, got, want)
				}
			}
		}
	}
}
