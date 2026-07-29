package api

import (
	"testing"

	"kypost-server/backend/internal/state"
)

func TestMFATransportEligible(t *testing.T) {
	tests := []struct {
		name      string
		transport string
		want      bool
	}{
		{"fcm", "fcm", true},
		{"apns", "apns", true},
		{"unifiedpush excluded", "unifiedpush", false},
		{"case and spacing are not an escape", "  UnifiedPush  ", false},
		// An empty transport is a legacy row written before the column existed.
		// normalizeNativeTransport would have derived one at registration, so
		// treating blank as eligible keeps those pairings working.
		{"legacy blank transport", "", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := MFATransportEligible(state.NativeDevice{Transport: tt.transport})
			if got != tt.want {
				t.Fatalf("MFATransportEligible(%q) = %v, want %v", tt.transport, got, tt.want)
			}
		})
	}
}

// The enable gate and the dispatcher must agree on whether push approval can
// work for a user. They were written separately, applied the approver rule and
// the transport rule in different places, and drifted: a user whose only paired
// device was UnifiedPush could enable push approval, get {"ok":true}, and then
// never be sent a challenge. Both now call mfaApproverDevices; this pins that.
func TestEnableGateAndDispatchAgreeOnEligibility(t *testing.T) {
	cases := []struct {
		name    string
		devices []state.NativeDevice
		want    int
	}{
		{
			name:    "only a UnifiedPush device is not eligible",
			devices: []state.NativeDevice{{DeviceID: "linux-1", Transport: "unifiedpush", MFAApprover: true}},
			want:    0,
		},
		{
			name: "a UnifiedPush device does not mask an eligible one",
			devices: []state.NativeDevice{
				{DeviceID: "linux-1", Transport: "unifiedpush", MFAApprover: true},
				{DeviceID: "phone-1", Transport: "fcm", MFAApprover: true},
			},
			want: 1,
		},
		{
			name: "legacy pairing with no approver flag still counts",
			devices: []state.NativeDevice{
				{DeviceID: "phone-1", Transport: "fcm"},
			},
			want: 1,
		},
		{
			name: "legacy pairing on an excluded transport does not",
			devices: []state.NativeDevice{
				{DeviceID: "linux-1", Transport: "unifiedpush"},
			},
			want: 0,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := filterMFAEligible(approverCandidates(tc.devices))
			if len(got) != tc.want {
				t.Fatalf("eligible = %d, want %d", len(got), tc.want)
			}
		})
	}
}

// approverCandidates and filterMFAEligible mirror approverDevices and
// mfaApproverDevices without needing a *state.Store, so the shared rule can be
// exercised directly. If these drift from the real ones the test above stops
// meaning anything — keep them in step.
func approverCandidates(all []state.NativeDevice) []state.NativeDevice {
	approvers := make([]state.NativeDevice, 0, len(all))
	for _, d := range all {
		if d.MFAApprover {
			approvers = append(approvers, d)
		}
	}
	if len(approvers) > 0 {
		return approvers
	}
	return all
}

func filterMFAEligible(candidates []state.NativeDevice) []state.NativeDevice {
	eligible := make([]state.NativeDevice, 0, len(candidates))
	for _, d := range candidates {
		if MFATransportEligible(d) {
			eligible = append(eligible, d)
		}
	}
	return eligible
}
