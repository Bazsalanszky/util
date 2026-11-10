// SPDX-FileCopyrightText: 2026 Balázs Toldi
//
// SPDX-License-Identifier: Apache-2.0

package sbiaddr

import (
	"errors"
	"net"
	"strings"
	"testing"
)

const (
	hostVar = "HOST_VAR"
	podV4   = "10.42.0.5"
	podV6   = "fd00:600::5"
	podV4b  = "10.42.0.9"
	podV6b  = "fd00:600::9"
	litV4   = "192.0.2.10"
	litV6   = "2001:db8::10"
)

// fakeEnv returns a lookup function backed by a map.
func fakeEnv(env map[string]string) func(string) (string, bool) {
	return func(key string) (string, bool) {
		v, ok := env[key]
		return v, ok
	}
}

// checkErrs fails unless err mentions each of the wanted fragments, or is nil
// when none are wanted.
func checkErrs(t *testing.T, err error, want []string) {
	t.Helper()
	if len(want) == 0 {
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		return
	}
	if err == nil {
		t.Fatalf("expected an error mentioning %q, got nil", want)
	}
	for _, w := range want {
		if !strings.Contains(err.Error(), w) {
			t.Errorf("error %q does not mention %q", err, w)
		}
	}
}

func TestResolveRegister(t *testing.T) {
	tests := []struct {
		env     map[string]string
		name    string
		v4      string
		v6      string
		want    RegisterAddrs
		wantErr []string
	}{
		{name: "nothing configured"},
		{name: spaceOnly, v4: "  ", v6: "\t"},

		// Literals, as every NF accepts today.
		{name: "IPv4 literal", v4: litV4, want: RegisterAddrs{IPv4: litV4}},
		{name: "FQDN (the chart default)", v4: hostAMF, want: RegisterAddrs{FQDN: hostAMF}},
		{name: "service FQDN", v4: fqdnAMF, want: RegisterAddrs{FQDN: fqdnAMF}},
		{name: "IPv4 literal with space", v4: "  " + litV4 + " ", want: RegisterAddrs{IPv4: litV4}},
		{name: "IPv6 literal under registerIPv6", v6: litV6, want: RegisterAddrs{IPv6: litV6}},
		{name: "both literals", v4: litV4, v6: litV6, want: RegisterAddrs{IPv4: litV4, IPv6: litV6}},
		{name: "IPv6 literal under registerIPv4 is routed", v4: litV6, want: RegisterAddrs{IPv6: litV6}},
		{name: "IPv4 literal under registerIPv6 is routed", v6: litV4, want: RegisterAddrs{IPv4: litV4}},
		{name: "IPv6 literal in brackets", v4: "[" + litV6 + "]", want: RegisterAddrs{IPv6: litV6}},
		{name: "upper-case IPv6 is canonicalised", v6: "2001:DB8::10", want: RegisterAddrs{IPv6: litV6}},
		{name: "IPv4-mapped IPv6 is IPv4", v6: "::ffff:" + litV4, want: RegisterAddrs{IPv4: litV4}},
		{name: "FQDN and IPv6", v4: hostAMF, v6: litV6, want: RegisterAddrs{FQDN: hostAMF, IPv6: litV6}},
		{name: "literal list", v4: litV4 + ", " + litV6, want: RegisterAddrs{IPv4: litV4, IPv6: litV6}},
		{name: "list with empty items", v4: "," + litV4 + ",,", want: RegisterAddrs{IPv4: litV4}},

		// POD_IP / POD_IPS.
		{
			name: "POD_IP IPv4", v4: EnvPodIP, env: map[string]string{EnvPodIP: podV4},
			want: RegisterAddrs{IPv4: podV4},
		},
		{
			name: "POD_IP IPv6 goes to the IPv6 slot", v4: EnvPodIP, env: map[string]string{EnvPodIP: podV6},
			want: RegisterAddrs{IPv6: podV6},
		},
		{
			name: "POD_IP under registerIPv6", v6: EnvPodIP, env: map[string]string{EnvPodIP: podV6},
			want: RegisterAddrs{IPv6: podV6},
		},
		{
			name: "POD_IP not set", v4: EnvPodIP,
			wantErr: []string{"registerIPv4", "POD_IP is empty or not set"},
		},
		{
			name: "POD_IP set but empty", v4: EnvPodIP, env: map[string]string{EnvPodIP: ""},
			wantErr: []string{"POD_IP is empty or not set"},
		},
		{
			name: "POD_IPS dual stack", v4: EnvPodIPs, env: map[string]string{EnvPodIPs: podV4 + "," + podV6},
			want: RegisterAddrs{IPv4: podV4, IPv6: podV6},
		},
		{
			name: "POD_IPS dual stack IPv6 first", v4: EnvPodIPs, env: map[string]string{EnvPodIPs: podV6 + "," + podV4},
			want: RegisterAddrs{IPv4: podV4, IPv6: podV6},
		},
		{
			name: "POD_IPS with spaces", v6: EnvPodIPs, env: map[string]string{EnvPodIPs: podV4 + " , " + podV6},
			want: RegisterAddrs{IPv4: podV4, IPv6: podV6},
		},
		{
			name: "POD_IPS single IPv4", v4: EnvPodIPs, env: map[string]string{EnvPodIPs: podV4},
			want: RegisterAddrs{IPv4: podV4},
		},
		{
			name: "POD_IPS not set", v6: EnvPodIPs,
			wantErr: []string{"registerIPv6: environment variable POD_IPS is empty or not set"},
		},
		{
			name: "POD_IP and POD_IPS agree", v4: EnvPodIP, v6: EnvPodIPs,
			env:  map[string]string{EnvPodIP: podV4, EnvPodIPs: podV4 + "," + podV6},
			want: RegisterAddrs{IPv4: podV4, IPv6: podV6},
		},
		{
			name: "same POD_IP under both keys", v4: EnvPodIP, v6: EnvPodIP,
			env:  map[string]string{EnvPodIP: podV6},
			want: RegisterAddrs{IPv6: podV6},
		},
		{
			name: "POD_IP zone", v4: EnvPodIP, env: map[string]string{EnvPodIP: "fe80::5%eth0"},
			wantErr: []string{"has a zone"},
		},
		{
			name: "POD_IP garbage", v4: EnvPodIP, env: map[string]string{EnvPodIP: notAnAddr},
			wantErr: []string{"environment variable POD_IP", `"` + notAnAddr + `"`},
		},

		// Other environment variables.
		{
			name: "custom variable holding IPv6", v6: "MY_ADDR", env: map[string]string{"MY_ADDR": podV6},
			want: RegisterAddrs{IPv6: podV6},
		},
		{
			name: "variable holding a host name", v4: hostVar, env: map[string]string{hostVar: "amf.example.org"},
			want: RegisterAddrs{FQDN: "amf.example.org"},
		},
		{
			name: "unset custom variable is read as a host name", v4: "UNSET_VAR",
			want: RegisterAddrs{FQDN: "UNSET_VAR"},
		},
		{
			name: "a set variable wins over the literal reading", v4: hostAMF, env: map[string]string{hostAMF: podV4},
			want: RegisterAddrs{IPv4: podV4},
		},

		// Conflicts: the key named after the family wins.
		{
			name: "registerIPv6 literal wins over an IPv6 from registerIPv4", v4: EnvPodIPs, v6: litV6,
			env:     map[string]string{EnvPodIPs: podV4 + "," + podV6},
			want:    RegisterAddrs{IPv4: podV4, IPv6: litV6},
			wantErr: []string{"ignoring IPv6 " + podV6, "using " + litV6 + " from registerIPv6"},
		},
		{
			name: "registerIPv4 literal wins over an IPv4 from registerIPv6", v4: litV4, v6: EnvPodIPs,
			env:     map[string]string{EnvPodIPs: podV4 + "," + podV6},
			want:    RegisterAddrs{IPv4: litV4, IPv6: podV6},
			wantErr: []string{"ignoring IPv4 " + podV4},
		},
		{
			name: "registerIPv4 FQDN wins", v4: hostAMF, v6: "amf6",
			want:    RegisterAddrs{FQDN: hostAMF},
			wantErr: []string{"registerIPv6: ignoring FQDN amf6"},
		},
		{
			name: "first item of a list wins", v4: litV4 + "," + podV4,
			want:    RegisterAddrs{IPv4: litV4},
			wantErr: []string{"ignoring IPv4 " + podV4},
		},
		{
			name: "duplicate items are not a conflict", v4: litV4 + "," + litV4,
			want: RegisterAddrs{IPv4: litV4},
		},

		// Invalid values are dropped and reported; the rest is kept.
		{name: "malformed IPv4", v4: "10.0.0.256", wantErr: []string{`"10.0.0.256"`}},
		{name: "value with a port", v4: litV4 + ":29518", wantErr: []string{"not an IPv4 address"}},
		{name: "zone in a literal", v6: zonedV6, wantErr: []string{`registerIPv6: "fe80::1%eth0" has a zone`}},
		{name: "bracketed IPv4", v4: "[" + litV4 + "]", wantErr: []string{"not an IPv4 address"}},
		{
			name: "one bad item in a list", v4: "garbage!," + litV6,
			want: RegisterAddrs{IPv6: litV6}, wantErr: []string{`"garbage!"`},
		},
		{
			name: "both keys bad", v4: "bad host", v6: "::g",
			wantErr: []string{"registerIPv4:", "registerIPv6:"},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := resolveRegister(tc.v4, tc.v6, fakeEnv(tc.env))
			if got != tc.want {
				t.Errorf("resolveRegister(%q, %q) = %+v, want %+v", tc.v4, tc.v6, got, tc.want)
			}
			checkErrs(t, err, tc.wantErr)
		})
	}
}

// TestResolveRegisterClusterModes runs the configurations an operator would
// use against what Kubernetes puts in POD_IP (status.podIP, the primary
// family) and POD_IPS (status.podIPs) in each cluster mode.
func TestResolveRegisterClusterModes(t *testing.T) {
	const (
		modeNone       = "no env"
		modeDualV4     = "dual-v4"
		modeDualV6     = "dual-v6"
		modePodIPOnly  = "POD_IP only, v6"
		modePodIPsOnly = "POD_IPS only, dual"
	)
	modes := []struct {
		env  map[string]string
		name string
	}{
		{name: modeNone, env: map[string]string{}},
		{name: "v4", env: map[string]string{EnvPodIP: podV4, EnvPodIPs: podV4}},
		{name: "v6", env: map[string]string{EnvPodIP: podV6, EnvPodIPs: podV6}},
		{name: modeDualV4, env: map[string]string{EnvPodIP: podV4, EnvPodIPs: podV4 + "," + podV6}},
		{name: modeDualV6, env: map[string]string{EnvPodIP: podV6, EnvPodIPs: podV6 + "," + podV4}},
		{name: modePodIPOnly, env: map[string]string{EnvPodIP: podV6}},
		{name: modePodIPsOnly, env: map[string]string{EnvPodIPs: podV4 + "," + podV6}},
	}
	v4Only := RegisterAddrs{IPv4: podV4}
	v6Only := RegisterAddrs{IPv6: podV6}
	dual := RegisterAddrs{IPv4: podV4, IPv6: podV6}

	// want is by mode; a mode that is not listed wants the zero value. An
	// error is expected exactly when the configuration names POD_IP or
	// POD_IPS and that variable is not set in the mode.
	configs := []struct {
		want map[string]RegisterAddrs
		name string
		v4   string
		v6   string
	}{
		{
			name: "registerIPv4: POD_IP", v4: EnvPodIP,
			want: map[string]RegisterAddrs{
				"v4": v4Only, "v6": v6Only, modeDualV4: v4Only, modeDualV6: v6Only, modePodIPOnly: v6Only,
			},
		},
		{
			name: "registerIPv4: POD_IPS", v4: EnvPodIPs,
			want: map[string]RegisterAddrs{
				"v4": v4Only, "v6": v6Only, modeDualV4: dual, modeDualV6: dual, modePodIPsOnly: dual,
			},
		},
		{
			name: "registerIPv6: POD_IPS", v6: EnvPodIPs,
			want: map[string]RegisterAddrs{
				"v4": v4Only, "v6": v6Only, modeDualV4: dual, modeDualV6: dual, modePodIPsOnly: dual,
			},
		},
		{
			name: "registerIPv4: POD_IP, registerIPv6: POD_IPS", v4: EnvPodIP, v6: EnvPodIPs,
			want: map[string]RegisterAddrs{
				"v4": v4Only, "v6": v6Only, modeDualV4: dual, modeDualV6: dual,
				modePodIPOnly: v6Only, modePodIPsOnly: dual,
			},
		},
		{
			name: "registerIPv4: amf (chart default)", v4: hostAMF,
			want: map[string]RegisterAddrs{
				modeNone: {FQDN: hostAMF}, "v4": {FQDN: hostAMF}, "v6": {FQDN: hostAMF}, modeDualV4: {FQDN: hostAMF},
				modeDualV6: {FQDN: hostAMF}, modePodIPOnly: {FQDN: hostAMF}, modePodIPsOnly: {FQDN: hostAMF},
			},
		},
		{
			name: "registerIPv4: amf, registerIPv6: POD_IP", v4: hostAMF, v6: EnvPodIP,
			want: map[string]RegisterAddrs{
				modeNone: {FQDN: hostAMF}, "v4": {FQDN: hostAMF, IPv4: podV4}, "v6": {FQDN: hostAMF, IPv6: podV6},
				modeDualV4: {FQDN: hostAMF, IPv4: podV4}, modeDualV6: {FQDN: hostAMF, IPv6: podV6},
				modePodIPOnly: {FQDN: hostAMF, IPv6: podV6}, modePodIPsOnly: {FQDN: hostAMF},
			},
		},
	}
	for _, cfg := range configs {
		for _, mode := range modes {
			t.Run(cfg.name+"/"+mode.name, func(t *testing.T) {
				got, err := resolveRegister(cfg.v4, cfg.v6, fakeEnv(mode.env))
				if want := cfg.want[mode.name]; got != want {
					t.Errorf("got %+v, want %+v", got, want)
				}
				wantErr := false
				for _, name := range []string{EnvPodIP, EnvPodIPs} {
					if _, set := mode.env[name]; !set && (cfg.v4 == name || cfg.v6 == name) {
						wantErr = true
					}
				}
				if (err != nil) != wantErr {
					t.Errorf("error = %v, want error: %v", err, wantErr)
				}
			})
		}
	}
}

func TestResolveRegisterReadsTheEnvironment(t *testing.T) {
	t.Setenv(EnvPodIPs, podV6b+","+podV4b)
	got, err := ResolveRegister(EnvPodIPs, "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if want := (RegisterAddrs{IPv4: podV4b, IPv6: podV6b}); got != want {
		t.Fatalf("got %+v, want %+v", got, want)
	}
}

func TestResolveRegisterErrorsAreJoined(t *testing.T) {
	_, err := resolveRegister("bad host", "also bad", fakeEnv(nil))
	var joined interface{ Unwrap() []error }
	if !errors.As(err, &joined) || len(joined.Unwrap()) != 2 {
		t.Fatalf("want two joined errors, got %v", err)
	}
}

func TestRegisterAddrsHostAndURI(t *testing.T) {
	tests := []struct {
		name    string
		scheme  string
		wantIP  string
		want    string
		wantURI string
		addrs   RegisterAddrs
		port    int
		pref    Preference
	}{
		{name: "empty", scheme: schemeHTTP, port: 29518},
		{
			name: "IPv4 only", addrs: RegisterAddrs{IPv4: litV4}, scheme: schemeHTTP, port: 29518,
			wantIP: litV4, want: litV4, wantURI: "http://" + litV4 + ":29518",
		},
		{
			name: "IPv4 with IPv6 preference", addrs: RegisterAddrs{IPv4: litV4}, scheme: schemeHTTP, port: 29518, pref: PreferIPv6,
			wantIP: litV4, want: litV4, wantURI: "http://" + litV4 + ":29518",
		},
		{
			name: "IPv6 only", addrs: RegisterAddrs{IPv6: litV6}, scheme: schemeTLS, port: 443,
			wantIP: litV6, want: litV6, wantURI: "https://[" + litV6 + "]:443",
		},
		{
			name: "dual, default preference", addrs: RegisterAddrs{IPv4: litV4, IPv6: litV6}, scheme: schemeHTTP, port: 80,
			wantIP: litV4, want: litV4, wantURI: "http://" + litV4 + ":80",
		},
		{
			name: "dual, IPv6 preference", addrs: RegisterAddrs{IPv4: litV4, IPv6: litV6}, scheme: schemeHTTP, port: 80, pref: PreferIPv6,
			wantIP: litV6, want: litV6, wantURI: "http://[" + litV6 + "]:80",
		},
		{
			name: "FQDN wins over both", addrs: RegisterAddrs{FQDN: hostSMF, IPv4: litV4, IPv6: litV6}, scheme: schemeHTTP,
			port: 29502, pref: PreferIPv6, wantIP: litV6, want: hostSMF, wantURI: "http://smf:29502",
		},
		{
			name: "FQDN only", addrs: RegisterAddrs{FQDN: hostSMF}, scheme: schemeHTTP, port: 29502,
			want: hostSMF, wantURI: "http://smf:29502",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.addrs.IP(tc.pref); got != tc.wantIP {
				t.Errorf("IP() = %q, want %q", got, tc.wantIP)
			}
			if got := tc.addrs.Host(tc.pref); got != tc.want {
				t.Errorf("Host() = %q, want %q", got, tc.want)
			}
			if got := tc.addrs.URI(tc.scheme, tc.port, tc.pref); got != tc.wantURI {
				t.Errorf("URI() = %q, want %q", got, tc.wantURI)
			}
			if got := tc.addrs.Empty(); got != (tc.want == "") {
				t.Errorf("Empty() = %v", got)
			}
		})
	}
}

func TestParsePreference(t *testing.T) {
	tests := []struct {
		in      string
		want    Preference
		wantErr bool
	}{
		{in: "", want: PreferIPv4},
		{in: "Ipv4", want: PreferIPv4},
		{in: "ipv4", want: PreferIPv4},
		{in: " v4 ", want: PreferIPv4},
		{in: "4", want: PreferIPv4},
		{in: "Ipv6", want: PreferIPv6},
		{in: "IPV6", want: PreferIPv6},
		{in: "v6", want: PreferIPv6},
		{in: "6", want: PreferIPv6},
		{in: "dual", want: PreferIPv4, wantErr: true},
		{in: "inet6", want: PreferIPv4, wantErr: true},
	}
	for _, tc := range tests {
		got, err := ParsePreference(tc.in)
		if got != tc.want || (err != nil) != tc.wantErr {
			t.Errorf("ParsePreference(%q) = (%v, %v), want (%v, error %v)", tc.in, got, err, tc.want, tc.wantErr)
		}
	}
	if PreferIPv4.String() != "IPv4" || PreferIPv6.String() != "IPv6" {
		t.Errorf("String() = %q, %q", PreferIPv4.String(), PreferIPv6.String())
	}
}

func TestFromInterfaceAddrs(t *testing.T) {
	ipNet := func(cidr string) net.Addr {
		ip, n, err := net.ParseCIDR(cidr)
		if err != nil {
			t.Fatal(err)
		}
		n.IP = ip
		return n
	}
	tests := []struct {
		name  string
		want  RegisterAddrs
		addrs []net.Addr
	}{
		{name: "none"},
		{
			name: "typical pod",
			addrs: []net.Addr{
				ipNet("127.0.0.1/8"), ipNet("::1/128"), ipNet("10.42.0.5/24"),
				ipNet("fe80::1/64"), ipNet("fd00:600::5/64"), ipNet("10.42.0.6/24"), ipNet("fd00:600::6/64"),
			},
			want: RegisterAddrs{IPv4: "10.42.0.5", IPv6: "fd00:600::5"},
		},
		{
			name:  "IPv6-only pod",
			addrs: []net.Addr{ipNet("::1/128"), ipNet("fe80::1/64"), ipNet("fd00:600::5/64")},
			want:  RegisterAddrs{IPv6: "fd00:600::5"},
		},
		{
			name:  "only loopback and link-local IPv6",
			addrs: []net.Addr{ipNet("127.0.0.1/8"), ipNet("::1/128"), ipNet("fe80::1/64")},
		},
		{
			name:  "IPv4 link-local counts, as in the SMF today",
			addrs: []net.Addr{ipNet("169.254.1.1/16")},
			want:  RegisterAddrs{IPv4: "169.254.1.1"},
		},
		{
			name:  "4-byte IPv4 and *net.IPAddr",
			addrs: []net.Addr{&net.UnixAddr{Name: "/tmp/x"}, &net.IPAddr{IP: net.IP{192, 0, 2, 1}}, &net.IPAddr{IP: net.ParseIP(litV6)}},
			want:  RegisterAddrs{IPv4: ipv4Doc, IPv6: litV6},
		},
		{
			name:  "unspecified and malformed are skipped",
			addrs: []net.Addr{&net.IPAddr{IP: net.IPv4zero}, &net.IPAddr{IP: net.IPv6unspecified}, &net.IPAddr{IP: net.IP{1, 2, 3}}},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := FromInterfaceAddrs(tc.addrs); got != tc.want {
				t.Fatalf("got %+v, want %+v", got, tc.want)
			}
		})
	}
}

func TestParseRegisterIgnoresTheEnvironment(t *testing.T) {
	t.Setenv(hostVar, podV4b)
	t.Setenv(EnvPodIP, podV6b)
	tests := []struct {
		name    string
		v4      string
		v6      string
		want    RegisterAddrs
		wantErr bool
	}{
		{name: "IPv4 or host name in RegisterIPv4", v4: hostAMF, v6: litV6, want: RegisterAddrs{FQDN: hostAMF, IPv6: litV6}},
		{name: "plain IPv4 address", v4: litV4, want: RegisterAddrs{IPv4: litV4}},
		{name: "a variable name is a host name", v4: hostVar, want: RegisterAddrs{FQDN: hostVar}},
		{name: "POD_IP is still a placeholder", v4: EnvPodIP, wantErr: true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := ParseRegister(tc.v4, tc.v6)
			if got != tc.want || (err != nil) != tc.wantErr {
				t.Fatalf("ParseRegister(%q, %q) = (%+v, %v), want %+v", tc.v4, tc.v6, got, err, tc.want)
			}
		})
	}
}
