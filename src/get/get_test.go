package get

import (
	"fmt"
	"testing"
)

// Testing the GetExistInterface function.
func TestGetExistInterface(t *testing.T) {
	type testCase struct {
		input     string
		wantError bool
	}

	tests := []testCase{
		{input: "lo", wantError: true},
		{input: "", wantError: false},
		{input: "qwerty", wantError: false},
	}

	for _, tc := range tests {
		t.Run(tc.input, func(t *testing.T) {
			t.Log("--------------------------------------")
			t.Logf("info: running test: %s", tc.input)

			ifaceExist, err := GetExistInterface(tc.input)

			if err != nil {
				t.Fatalf("error: unexpected error for network interface '%s': %v", tc.input, err)
			} else {
				t.Logf("info: no error received for '%s', as expected.", tc.input)
			}

			if ifaceExist != tc.wantError {
				t.Errorf("error: expected existence %t, got %t for '%s'", tc.wantError, ifaceExist, tc.input)
			} else {
				t.Logf("info: existence %t matches expected for '%s'.", ifaceExist, tc.input)
			}

			t.Logf("info: end test: %s", tc.input)
			t.Log("--------------------------------------")
		})
	}
}

// Testing the GetIpNetInterface function.
func TestGetIpNetInterfase(t *testing.T) {
	type testCase struct {
		input     string
		wantError bool
	}

	tests := []testCase{
		{input: "lo", wantError: false},
		{input: "", wantError: true},
		{input: "qwerty", wantError: true},
	}

	for _, tc := range tests {
		t.Run(tc.input, func(t *testing.T) {
			t.Log("--------------------------------------")
			t.Logf("Run test: %s", tc.input)

			lenIp, ipNet, err := GetIpNetInterface(tc.input)

			if tc.wantError {
				if err == nil {
					t.Errorf("expected error for network interface '%s', but got none", tc.input)
				} else {
					t.Logf("expected error received for '%s': %v", tc.input, err)
				}
			} else {
				if err != nil {
					t.Errorf("unexpected error for network interface '%s': %v", tc.input, err)
				} else {
					t.Logf("info: test '%s' passed successfully, lenIp=%d, ipNet=%v", tc.input, lenIp, ipNet)
				}
			}

			t.Logf("End test: %s", tc.input)
			t.Log("--------------------------------------")
		})
	}
}

// Testing the GenerateKeys function
func TestGenerateKeys(t *testing.T) {

	var current_privkey string
	var current_pubkey string
	for i := 0; i < 10; i++ {
		t.Run(fmt.Sprintf("GenerateKeys: %d", i), func(t *testing.T) {
			t.Log("--------------------------------------")
			t.Log("Run test: ", i)
			dataMap, err := GenerateKeys()
			if err != nil {
				t.Fatal(err)
			}
			pk := dataMap["private"]
			if current_privkey != "" && current_privkey == pk.String() {
				t.Errorf("error: private key uniqueness violated: %s", current_privkey)
			}
			current_privkey = pk.String()
			t.Logf("info: private key received: %s", pk.String())

			pb := dataMap["public"]
			if current_pubkey != "" && current_pubkey == pb.String() {
				t.Errorf("error: public key uniqueness violated: %s", current_pubkey)
			}
			current_pubkey = pb.String()
			t.Logf("info: public key received: %s", pb.String())

			t.Log("End test: ", i)
			t.Log("--------------------------------------")
		})

	}

}

// Testing the GetIp function.
func TestGetIP(t *testing.T) {
	t.Run("GetIp", func(t *testing.T) {
		t.Log("--------------------------------------")
		t.Log("Run test")

		data, err := GetIp()
		if err != nil {
			t.Fatal("error GetIp: ", err)
		}

		for _, get := range data {
			t.Logf("info: data on network interface '%s' received", get.IfName)
		}

		t.Log("End test")
		t.Log("--------------------------------------")
	})

}

// Testing the GetIpShow function.
func TestGetIpShow(t *testing.T) {
	type testCase struct {
		input     string
		wantError bool
	}

	tests := []testCase{
		{input: "lo", wantError: false},
		{input: "", wantError: false},
		{input: "qwerty", wantError: true},
	}

	for _, tc := range tests {
		t.Run(tc.input, func(t *testing.T) {
			t.Log("--------------------------------------")
			t.Logf("Run test: %s", tc.input)

			data, err := GetIpShow(tc.input)

			if tc.wantError {
				if err == nil {
					t.Errorf("expected error for input '%s', but got none", tc.input)
				} else {
					t.Logf("expected error received for '%s': %v", tc.input, err)
				}
			} else {
				if err != nil {
					t.Errorf("unexpected error for input '%s': %v", tc.input, err)
				} else {
					t.Logf("info: received %d data items for '%s'", len(data), tc.input)
				}
			}

			t.Logf("End test: %s", tc.input)
			t.Log("--------------------------------------")
		})
	}
}

// Testing the GetIptablesFirewall function.
func TestGetIptablesFirewall(t *testing.T) {
	t.Run("GetIptablesFirewall", func(t *testing.T) {
		t.Log("--------------------------------------")
		t.Log("Run test")

		data, err := GetIptablesFirewall()
		if err != nil {
			t.Fatal("error GetIptablesFirewall: ", err)
		}

		t.Logf("info: %d firewall data received: ", len(data.Chains))

		t.Log("End test")
		t.Log("--------------------------------------")
	})
}

// Testing the GetIptablesNA function.
func TestGetIptablesNAT(t *testing.T) {
	t.Run("GetIptablesNAT", func(t *testing.T) {
		t.Log("--------------------------------------")
		t.Log("Run test")

		data, err := GetIptablesNAT()
		if err != nil {
			t.Fatal("error GetIptablesNAT: ", err)
		}
		t.Logf("info: received number of NAT rules: %d", len(data.Chains))

		t.Log("End test")
		t.Log("--------------------------------------")
	})
}

// Testing the GetRuleId method of the firewall's FilterIptablesOutput structure.
func TestFirewallGetRuleId(t *testing.T) {
	type testCase struct {
		name      string
		input     int
		wantError bool
	}

	tests := []testCase{
		{name: "func: GetRuleId", input: 12, wantError: true},
		{name: "func: GetRuleId", input: 1, wantError: true},
		{name: "func: GetRuleId", input: 7, wantError: true},
		{name: "func: GetRuleId", input: 10, wantError: true},
		{name: "func: GetRuleId", input: -100, wantError: true},
		{name: "func: GetRuleId", input: 100, wantError: true},
		{name: "func: GetRuleId", input: 0, wantError: true},
		{name: "func: GetRuleId", input: 1000000000, wantError: true},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Log("--------------------------------------")
			t.Logf("Run test: %s, input: %d", tc.name, tc.input)

			getData, err := GetIptablesFirewall()
			if err != nil {
				t.Fatalf("error: GetIptablesFirewall failed during setup for input=%d: %v", tc.input, err)
			}
			if len(getData.Chains) == 0 {
				t.Fatal("error: add rules to firewall table to start test")
			}

			obj := FilterIptablesOutput{getData}
			data, err := obj.GetRuleId(tc.input)

			if tc.wantError {
				if err == nil {
					t.Logf("info: received data: %v\n", data)
				} else {
					t.Logf("error: expected error %v\n", err)
				}
			} else {
				if err == nil {
					t.Logf("info: received data: %v\n", data)
				} else {
					t.Errorf("error: test failed, %v\n", err)
				}
			}

			t.Logf("End test: %s, input: %d", tc.name, tc.input)
			t.Log("--------------------------------------")
		})
	}
}

// Test function for testing the GetExistingRules function for firewall.
func TestFirewallGetExistingRules(t *testing.T) {
	type testCase struct {
		inIface    string
		outIface   string
		subnetCIDR string
		wantError  bool
	}
	tests := []testCase{
		{inIface: "wg3", outIface: "enp0s3", subnetCIDR: "10.10.10.0/24", wantError: true}, // Rule added to Firewall table.
		{inIface: "qwerty", outIface: "enp0s3", subnetCIDR: "10.10.10.0/24", wantError: true},
		{inIface: "*", outIface: "lo", subnetCIDR: "0.0.0.0/0", wantError: false},
		{inIface: "*", outIface: "*", subnetCIDR: "0.0.0.0/0", wantError: false},
		{inIface: "lo", outIface: "lo", subnetCIDR: "0.0.0.0/0", wantError: true},
		{inIface: "", outIface: "enp0s3", subnetCIDR: "10.10.10.0/24", wantError: true},
		{inIface: "wg0", outIface: "", subnetCIDR: "10.10.10.0/24", wantError: true},
		{inIface: "wg0", outIface: "enp0s3", subnetCIDR: "10.10.10.0", wantError: true},
	}

	for _, tc := range tests {
		t.Run("Firewall", func(t *testing.T) {
			t.Log("--------------------------------------")
			t.Logf("Run test GetExistingRules: inIface=%q, outIface=%q, subnetCIDR=%q", tc.inIface, tc.outIface, tc.subnetCIDR)

			getData, err := GetIptablesFirewall()
			if err != nil {
				t.Fatalf("error: failed to get iptables firewall data: %v", err)
			}
			if len(getData.Chains) == 0 {
				t.Fatal("error: no chains found in firewall table; please add rules before running the test")
			}

			obj := FilterIptablesOutput{getData}
			fwExist, err := obj.GetExistingRules(tc.inIface, tc.outIface, tc.subnetCIDR)
			if tc.wantError {
				if err == nil {
					t.Logf("info: test passed, the port exists: %t", fwExist)
				} else {
					t.Logf("error: test failed, %v", err)
				}
			} else {
				if err == nil {
					t.Logf("info: test passed, the port exists: %t", fwExist)
				} else {
					t.Fatalf("error: test failed, %v", err)
				}
			}

			t.Logf("End test GetExistingRules: inIface=%q, outIface=%q, subnetCIDR=%q", tc.inIface, tc.outIface, tc.subnetCIDR)
			t.Log("--------------------------------------")
		})
	}
}

// Testing the GetRuleId method of the NAT's FilterIptablesOutput structure.
func TestNATGetRuleId(t *testing.T) {
	type testCase struct {
		name      string
		input     int
		wantError bool
	}

	tests := []testCase{
		{name: "func: GetRuleId", input: 12, wantError: true},
		{name: "func: GetRuleId", input: 1, wantError: true},
		{name: "func: GetRuleId", input: 2, wantError: true},
		{name: "func: GetRuleId", input: 3, wantError: true},
		{name: "func: GetRuleId", input: -100, wantError: true},
		{name: "func: GetRuleId", input: 100, wantError: true},
		{name: "func: GetRuleId", input: 0, wantError: true},
		{name: "func: GetRuleId", input: 1000000000, wantError: true},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Log("--------------------------------------")
			t.Logf("Run test: %s, input: %d", tc.name, tc.input)

			getData, err := GetIptablesNAT()
			if err != nil {
				t.Fatalf("error: GetIptablesNAT failed during setup for input=%d: %v", tc.input, err)
			}
			if len(getData.Chains) == 0 {
				t.Fatal("error: add rules to nat table to start test")
			}

			obj := FilterIptablesOutput{getData}
			data, err := obj.GetRuleId(tc.input)

			if tc.wantError {
				if err == nil {
					t.Logf("info: received data: %v\n", data)
				} else {
					t.Logf("error: expected error %v\n", err)
				}
			} else {
				if err == nil {
					t.Logf("info: received data: %v\n", data)
				} else {
					t.Errorf("error: test failed, %v\n", err)
				}
			}

			t.Logf("End test: %s, input: %d", tc.name, tc.input)
			t.Log("--------------------------------------")
		})
	}
}

// Test function for testing the GetExistingRules function for NAT.
func TestNatGetExistingRules(t *testing.T) {
	type testCase struct {
		inIface    string
		outIface   string
		subnetCIDR string
		wantError  bool
	}
	tests := []testCase{
		{
			inIface: "wg0", outIface: "enp0s3", subnetCIDR: "10.10.10.0/24", wantError: true,
		}, // Rule added to nat table.
		{inIface: "qwerty", outIface: "enp0s3", subnetCIDR: "10.10.10.0/24", wantError: true},
		{inIface: "wg0", outIface: "enp0s3", subnetCIDR: "101.0.0.0/24", wantError: true},
		{inIface: "", outIface: "enp0s3", subnetCIDR: "10.10.10.0/24", wantError: true},
		{inIface: "wg0", outIface: "", subnetCIDR: "10.10.10.0/24", wantError: true},
		{inIface: "wg0", outIface: "enp0s3", subnetCIDR: "10.10.10.0", wantError: true},
	}

	for _, tc := range tests {
		t.Run("NAT", func(t *testing.T) {
			t.Log("--------------------------------------")
			t.Logf("Run test GetExistingRules: inIface=%q, outIface=%q, subnetCIDR=%q", tc.inIface, tc.outIface, tc.subnetCIDR)

			getData, err := GetIptablesNAT()
			if err != nil {
				t.Fatalf("error: failed to get iptables nat data: %v", err)
			}
			if len(getData.Chains) == 0 {
				t.Fatal("error: no chains found in nat table; please add rules before running the test")
			}

			obj := FilterIptablesOutput{getData}
			_, err = obj.GetExistingRules(tc.inIface, tc.outIface, tc.subnetCIDR)

			if tc.wantError {
				if err != nil {
					t.Logf("info: expected error, test passed, %v", err)
				}
			} else {
				if err != nil {
					t.Fatalf("error: test failed, %v", err)
				}
			}

			t.Log("info: test successful")

			t.Logf("End test GetExistingRules: inIface=%q, outIface=%q, subnetCIDR=%q", tc.inIface, tc.outIface, tc.subnetCIDR)
			t.Log("--------------------------------------")
		})
	}
}

// Test function for testing the GetExistingPort function for NAT.
func TestGetExistingPort(t *testing.T) {
	type testCase struct {
		port      string
		wantError bool
	}

	tests := []testCase{
		{port: "22", wantError: false},
		{port: "80", wantError: false},
		{port: "43601", wantError: true},
		{port: "port", wantError: true},
	}

	for _, tc := range tests {
		t.Run("NAT", func(t *testing.T) {
			t.Log("--------------------------------------")
			t.Logf("Run test GetExistingPort: %s", tc.port)

			getData, err := GetIptablesFirewall()
			if err != nil {
				t.Fatalf("error: failed to get iptables nat data: %v", err)
			}
			if len(getData.Chains) == 0 {
				t.Fatal(
					"error: no chains found in nat table; please add rules before running the test",
				)
			}

			obj := FilterIptablesOutput{getData}
			portExist, err := obj.GetExistingPort(tc.port)

			if tc.wantError {
				if err == nil {
					t.Logf("info: test passed, the port exists: %t", portExist)
				} else {
					t.Logf("error: test failed, %v", err)
				}
			} else {
				if err == nil {
					t.Logf("info: test passed, the port exists: %t", portExist)
				} else {
					t.Fatalf("error: test failed, %v", err)
				}
			}

			t.Log("info: test successful")
			t.Logf("End test GetExistingPort: %s", tc.port)
			t.Log("--------------------------------------")
		})
	}

}

// Testing the GetIPvForwarding function.
func TestGetIPvForwarding(t *testing.T) {
	t.Run("GetIPvForwarding", func(t *testing.T) {
		t.Log("--------------------------------------")
		t.Log("Run test")

		data, err := GetIPvForwarding()
		if err != nil {
			t.Fatal("error GetIp: ", err)
		}

		if len(data) == 0 {
			t.Errorf("error: no IPv forwarding data received (length=0)")
		} else {
			t.Logf("info: received IPv forwarding data, length=%d", len(data))
		}

		t.Log("End test")
		t.Log("--------------------------------------")
	})

}

// Testing the GetPeer function.
func TestGetPeer(t *testing.T) {
	type testCase struct {
		input     string
		wantError bool
	}

	tests := []testCase{
		{input: "lo", wantError: true},
		{input: "wg0", wantError: true},
		{input: "qwerty", wantError: true},
	}

	for _, tc := range tests {
		t.Run(tc.input, func(t *testing.T) {
			t.Log("--------------------------------------")
			t.Logf("Run test: interface=%q", tc.input)

			devices, err := GetPeer(tc.input)
			if tc.wantError {
				t.Logf("info: expected error received: %v", err)
			} else {
				t.Fatalf("error: unexpected error: %v", err)
			}

			if len(devices) > 0 {
				for _, val := range devices {
					t.Logf("info: received data: %v", val)
				}
			}

			t.Log("End test")
			t.Log("--------------------------------------")
		})
	}
}
