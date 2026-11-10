// SPDX-FileCopyrightText: 2026 Balázs Toldi
//
// SPDX-License-Identifier: Apache-2.0

package sbiaddr_test

import (
	"fmt"
	"os"

	"github.com/omec-project/util/sbiaddr"
)

// An NF reads its sbi settings once at start-up. Here the pod is dual-stack
// and the config says registerIPv4: POD_IPS, bindingAddr: "::".
func Example() {
	_ = os.Setenv(sbiaddr.EnvPodIPs, "10.42.0.5,fd00:600::5")
	defer os.Unsetenv(sbiaddr.EnvPodIPs)

	addrs, err := sbiaddr.ResolveRegister(sbiaddr.EnvPodIPs, "")
	if err != nil {
		fmt.Println("warning:", err) // non-fatal: log it and carry on
	}
	if addrs.Empty() {
		addrs.IPv4 = "127.0.0.18" // the NF's own default
	}
	pref, err := sbiaddr.ParsePreference("IPv6") // e.g. sbi.preferredFamily
	if err != nil {
		fmt.Println("warning:", err)
	}

	bind, err := sbiaddr.BindHost("::", "0.0.0.0")
	if err != nil {
		fmt.Println("warning:", err)
	}
	fmt.Println(sbiaddr.HostPort(bind, 29518))
	fmt.Println(addrs.IPv4, addrs.IPv6)
	fmt.Println(addrs.URI("http", 29518, sbiaddr.PreferIPv4))
	fmt.Println(addrs.URI("http", 29518, pref))
	// Output:
	// [::]:29518
	// 10.42.0.5 fd00:600::5
	// http://10.42.0.5:29518
	// http://[fd00:600::5]:29518
}
