// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package iptables

import (
	"context"
	"log/slog"
	"net"
	"net/netip"

	"github.com/cilium/hive/cell"
	"github.com/cilium/stream"
	"k8s.io/apimachinery/pkg/util/sets"
	"k8s.io/utils/clock"

	"github.com/cilium/cilium/pkg/datapath/tables"
	lb "github.com/cilium/cilium/pkg/loadbalancer"
	"github.com/cilium/cilium/pkg/logging"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/node"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/time"
)

type desiredState struct {
	installRules bool

	devices          sets.Set[string]
	localNodeInfo    localNodeInfo
	proxies          map[string]proxyInfo
	noTrackPods      sets.Set[noTrackPodInfo]
	noTrackHostPorts map[string]sets.Set[lb.L4Addr]
}

type localNodeInfo struct {
	internalIPv4          net.IP
	internalIPv6          net.IP
	ipv4AllocCIDR         string
	ipv6AllocCIDR         string
	ipv4NativeRoutingCIDR string
	ipv6NativeRoutingCIDR string
}

func (lni localNodeInfo) isValid() bool {
	switch {
	case option.Config.EnableIPv4 && (lni.internalIPv4.IsUnspecified() || lni.ipv4AllocCIDR == ""):
		return false
	case option.Config.EnableIPv6 && (lni.internalIPv6.IsUnspecified() || lni.ipv6AllocCIDR == ""):
		return false
	default:
		return true
	}
}

func (lni localNodeInfo) equal(other localNodeInfo) bool {
	if lni.internalIPv4.Equal(other.internalIPv4) &&
		lni.internalIPv6.Equal(other.internalIPv6) &&
		lni.ipv4AllocCIDR == other.ipv4AllocCIDR &&
		lni.ipv6AllocCIDR == other.ipv6AllocCIDR &&
		lni.ipv4NativeRoutingCIDR == other.ipv4NativeRoutingCIDR &&
		lni.ipv6NativeRoutingCIDR == other.ipv6NativeRoutingCIDR {
		return true
	}
	return false
}

func toLocalNodeInfo(n node.LocalNode) localNodeInfo {
	var (
		v4AllocCIDR, v6AllocCIDR                 string
		v4NativeRoutingCIDR, v6NativeRoutingCIDR string
	)

	if n.IPv4AllocCIDR != nil {
		v4AllocCIDR = n.IPv4AllocCIDR.String()
	}
	if n.IPv6AllocCIDR != nil {
		v6AllocCIDR = n.IPv6AllocCIDR.String()
	}
	if n.IPv4NativeRoutingCIDR != nil {
		v4NativeRoutingCIDR = n.IPv4NativeRoutingCIDR.String()
	}
	if n.IPv6NativeRoutingCIDR != nil {
		v6NativeRoutingCIDR = n.IPv6NativeRoutingCIDR.String()
	}

	return localNodeInfo{
		internalIPv4:          n.GetCiliumInternalIP(false),
		internalIPv6:          n.GetCiliumInternalIP(true),
		ipv4AllocCIDR:         v4AllocCIDR,
		ipv6AllocCIDR:         v6AllocCIDR,
		ipv4NativeRoutingCIDR: v4NativeRoutingCIDR,
		ipv6NativeRoutingCIDR: v6NativeRoutingCIDR,
	}
}

// reconciliationRequest is a request to the reconciler to update the
// state with the new info.
// updated is a notification channel that is closed when reconciliation has
// been completed successfully.
type reconciliationRequest[T any] struct {
	info T

	// closed when the state is reconciled successfully
	updated chan struct{}
}

type proxyInfo struct {
	name string
	port uint16
}

type noTrackPodInfo struct {
	ip   netip.Addr
	port uint16
}

func reconciliationLoop(
	ctx context.Context,
	log *slog.Logger,
	health cell.Health,
	installIptRules bool,
	fullReconciliationInterval time.Duration,
	params *reconcilerParams,
	updateRules func(state desiredState, firstInit bool) error,
	updateProxyRules func(proxyPort uint16, name string) error,
	installNoTrackRules func(addr netip.Addr, port uint16) error,
	removeNoTrackRules func(addr netip.Addr, port uint16) error,
	readCurrentState func() (desiredState, error),
) error {
	// The minimum interval between reconciliation attempts
	const minReconciliationInterval = 200 * time.Millisecond

	// log limiter for partial (proxy and no track rules) reconciliation errors
	partialLogLimiter := logging.NewLimiter(10*time.Second, 3)
	// log limiter for full reconciliation errors
	fullLogLimiter := logging.NewLimiter(10*time.Second, 3)

	state := desiredState{
		installRules:     installIptRules,
		proxies:          make(map[string]proxyInfo),
		noTrackPods:      sets.New[noTrackPodInfo](),
		noTrackHostPorts: make(map[string]sets.Set[lb.L4Addr]),
	}

	// Track the last successfully reconciled state to avoid unnecessary reconciliations
	// during periodic checks. This may prevent disrupting connections when nothing has changed.
	var lastReconciledState *desiredState

	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	// Pull the local node until it has been initialized far enough for
	// the reconciliation to proceed.
	localNodeEvents := stream.ToChannel(ctx, params.localNodeStore)
	for localNode := range localNodeEvents {
		state.localNodeInfo = toLocalNodeInfo(localNode)
		if state.localNodeInfo.isValid() {
			break
		}
	}

	devices, devicesWatch := tables.SelectedDevices(params.devices, params.db.ReadTxn())
	state.devices = sets.New(tables.DeviceNames(devices)...)

	// stateChanged is true when the desired state has changed or when reconciling it
	// has failed. It's set to false when reconciling succeeds or when current state matches.
	stateChanged := true

	// Try to read the current iptables state and pre-fill lastReconciledState
	// if it matches the desired state. This avoids disrupting connections on restart
	// when the state hasn't actually changed.
	if readCurrentState != nil {
		if currentState, err := readCurrentState(); err == nil {
			// Build a state with the same structure as our desired state for comparison
			currentState.installRules = installIptRules
			currentState.localNodeInfo = state.localNodeInfo
			currentState.devices = state.devices
			if statesEqual(currentState, state) {
				log.Debug("Current iptables state matches desired state, skipping initial reconciliation")
				lastReconciledState = &currentState
				stateChanged = false
			}
		} else {
			log.Debug("Failed to read current iptables state, will perform initial reconciliation", logfields.Error, err)
		}
	}

	// Use a ticker to limit how often the desired state is reconciled to avoid doing
	// lots of operations when e.g. ipset updates.
	ticker := params.clock.NewTicker(minReconciliationInterval)
	defer ticker.Stop()

	// Refresher is a timer that allows to schedule periodic reconciliations
	// to ensure eventual consistency and correct possible divergences.
	// Only create it if periodic reconciliation is enabled (interval > 0).
	var refresher clock.Timer
	var refresherChan <-chan time.Time
	if fullReconciliationInterval > 0 {
		refresher = params.clock.NewTimer(fullReconciliationInterval)
		defer refresher.Stop()
		refresherChan = refresher.C()
	} else {
		// Create a nil channel that never fires when refresh is disabled
		refresherChan = nil
	}

	firstInit := true

	// Run an initial full reconciliation before listening on partial reconciliation
	// request channels (like proxies and no track rules), but only if state has changed.
	if stateChanged {
		if err := updateRules(state, firstInit); err != nil {
			health.Degraded("iptables rules update failed", err)
			// Keep stateChanged=true and firstInit=true to try again on the next tick.
		} else {
			health.OK("iptables rules update completed")
			firstInit = false
			stateChanged = false
			// Store the current reconciled state for comparison in next check
			reconciledStateCopy := state
			lastReconciledState = &reconciledStateCopy
		}
	} else {
		health.OK("iptables rules already in sync, skipping initial reconciliation")
		firstInit = false
	}

	// list of pending channels waiting for reconciliation
	var updatedChs []chan<- struct{}

stop:
	for {
		select {
		case <-ctx.Done():
			break stop
		case <-devicesWatch:
			devices, devicesWatch = tables.SelectedDevices(params.devices, params.db.ReadTxn())
			newDevices := sets.New(tables.DeviceNames(devices)...)
			if newDevices.Equal(state.devices) {
				continue
			}
			state.devices = newDevices
			stateChanged = true
		case localNode, ok := <-localNodeEvents:
			if !ok {
				break stop
			}
			localNodeInfo := toLocalNodeInfo(localNode)
			if localNodeInfo.equal(state.localNodeInfo) {
				continue
			}
			state.localNodeInfo = localNodeInfo
			stateChanged = true
		case req, ok := <-params.proxies:
			if !ok {
				break stop
			}
			if info, ok := state.proxies[req.info.name]; ok && info == req.info {
				continue
			}

			// if existing, previous rules related to the previous entry for the same proxy name
			// will be deleted by the manager (see Manager.addProxyRules)
			state.proxies[req.info.name] = req.info

			if firstInit {
				// first init not yet completed, proxy rules will be updated as part of that
				stateChanged = true
				updatedChs = append(updatedChs, req.updated)
				continue
			}

			if err := updateProxyRules(req.info.port, req.info.name); err != nil {
				if partialLogLimiter.Allow() {
					log.Error("iptables proxy rules incremental update failed, will retry a full reconciliation", logfields.Error, err)
				}
				// incremental rules update failed, schedule a full iptables reconciliation
				stateChanged = true
				updatedChs = append(updatedChs, req.updated)
			} else {
				close(req.updated)
			}
		case req, ok := <-params.addNoTrackPod:
			if !ok {
				break stop
			}
			if state.noTrackPods.Has(req.info) {
				close(req.updated)
				continue
			}
			state.noTrackPods.Insert(req.info)

			if firstInit {
				// first init not yet completed, no track pod rules will be updated as part of that
				stateChanged = true
				updatedChs = append(updatedChs, req.updated)
				continue
			}

			if err := installNoTrackRules(req.info.ip, req.info.port); err != nil {
				if partialLogLimiter.Allow() {
					log.Error("iptables no track rules incremental install failed, will retry a full reconciliation", logfields.Error, err)
				}
				// incremental rules update failed, schedule a full iptables reconciliation
				stateChanged = true
				updatedChs = append(updatedChs, req.updated)
			} else {
				close(req.updated)
			}
		case req, ok := <-params.delNoTrackPod:
			if !ok {
				break stop
			}
			if !state.noTrackPods.Has(req.info) {
				close(req.updated)
				continue
			}
			state.noTrackPods.Delete(req.info)

			if firstInit {
				// first init not yet completed, no track pod rules will be updated as part of that
				stateChanged = true
				updatedChs = append(updatedChs, req.updated)
				continue
			}

			if err := removeNoTrackRules(req.info.ip, req.info.port); err != nil {
				if partialLogLimiter.Allow() {
					log.Error("iptables no track rules incremental removal failed, will retry a full reconciliation", logfields.Error, err)
				}
				// incremental rules update failed, schedule a full iptables reconciliation
				stateChanged = true
				updatedChs = append(updatedChs, req.updated)
			} else {
				close(req.updated)
			}
		case <-refresherChan:
			// For periodic reconciliation, only trigger if state has actually changed.
			if lastReconciledState != nil && statesEqual(*lastReconciledState, state) {
				log.Debug("Skipping periodic reconciliation - state unchanged since last check")

				if refresher != nil {
					refresher.Reset(fullReconciliationInterval)
				}
				continue
			}
			// State has changed or this is the first periodic check, proceed with reconciliation
			log.Info("Periodic reconciliation triggered - state changed or first periodic check")
			stateChanged = true
		case <-ticker.C():
			if !stateChanged {
				continue
			}

			if err := updateRules(state, firstInit); err != nil {
				if fullLogLimiter.Allow() {
					log.Error("iptables rules full reconciliation failed, will retry another one later", logfields.Error, err)
				}
				health.Degraded("iptables rules full reconciliation failed", err)
				// Keep stateChanged=true to try again on the next tick.
			} else {
				health.OK("iptables rules full reconciliation completed")
				firstInit = false
				stateChanged = false
				// Store the current reconciled state for comparison in next check
				reconciledStateCopy := state
				lastReconciledState = &reconciledStateCopy
			}

			// close all channels waiting for reconciliation
			// do this even in case of a failed reconciliation, to avoid
			// blocking consumer goroutines indefinitely.
			for _, ch := range updatedChs {
				close(ch)
			}
			updatedChs = updatedChs[:0]

			// Reset the timer so that it gets triggered again after fullReconciliationInterval,
			// to avoid introducing unnecessary churn in case a full reconciliation was already
			// triggered due to other reasons. The Stop and select steps can be dropped once
			// switching to using go v1.23: https://go.dev/wiki/Go123Timer
			if refresher != nil {
				if !refresher.Stop() {
					select {
					case <-ticker.C():
					default:
					}
				}

				refresher.Reset(fullReconciliationInterval)
			}
		}
	}

	cancel()

	// close all channels waiting for reconciliation
	for _, ch := range updatedChs {
		close(ch)
	}

	// drain channels
	for range localNodeEvents {
	}
	for range params.proxies {
	}
	for range params.addNoTrackPod {
	}
	for range params.delNoTrackPod {
	}

	return nil
}

// statesEqual compares two desiredState structs to determine if they are equivalent
// for the purpose of periodic reconciliation. Returns true if states are equal.
func statesEqual(a, b desiredState) bool {
	// Compare installRules flag
	if a.installRules != b.installRules {
		return false
	}

	// Compare devices
	if !a.devices.Equal(b.devices) {
		return false
	}

	// Compare localNodeInfo
	if !a.localNodeInfo.equal(b.localNodeInfo) {
		return false
	}

	// Compare proxies (map comparison)
	if len(a.proxies) != len(b.proxies) {
		return false
	}
	for k, v := range a.proxies {
		if bv, ok := b.proxies[k]; !ok || bv != v {
			return false
		}
	}

	// Compare noTrackPods
	if !a.noTrackPods.Equal(b.noTrackPods) {
		return false
	}

	// Compare noTrackHostPorts
	if len(a.noTrackHostPorts) != len(b.noTrackHostPorts) {
		return false
	}
	for k, v := range a.noTrackHostPorts {
		bv, ok := b.noTrackHostPorts[k]
		if !ok {
			return false
		}
		// Compare sets directly - v and bv are already Set[loadbalancer.L4Addr]
		if !v.Equal(bv) {
			return false
		}
	}

	return true
}
