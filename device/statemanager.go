/*
 * Copyright (c) 2022. Proton AG
 *
 * This file is part of ProtonVPN.
 *
 * ProtonVPN is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * ProtonVPN is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with ProtonVPN.  If not, see <https://www.gnu.org/licenses/>.
 */

package device

import (
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

var initialRestartDelay = 4 * time.Second
var maxRestartDelay = 32 * time.Second
var resetRestartDelay = 10 * time.Minute
var timeNow = time.Now

// WireGuardStateManager handles enabling/disabling WireGuard in response to network availability changes, serves
// connection state to the client and resets WireGuard connection in response to socket and handshake errors.
//
// Client should call SetNetworkAvailable every time network changes - WireGuard will remain inactive until
// SetNetworkAvailable(true) is called. When SetNetworkAvailable(true) is called twice in a row it'll be interpreted
// as network change and trigger reset of the connection (on TCP/TLS socket).
//
// GetState is blocking and therefore should run in dedicated thread in a loop. After Close is called GetState will
// return immediately with WireGuardDisabled.
type WireGuardStateManager struct {
	HandshakeStateChan   chan HandshakeState
	SocketErrChan        chan error
	networkAvailableChan chan bool
	closeChan            chan bool

	stateChan      chan WireGuardState
	isNetAvailable atomic.Bool

	lastRestart      time.Time
	udpTransmission  bool

	log              *Logger
	mu               sync.Mutex
	closed           atomic.Bool
	stopping         sync.WaitGroup
	startedTimestamp time.Time
	nextRestartDelay time.Duration
}

type WireGuardState int

const (
	WireGuardDisabled WireGuardState = iota
	WireGuardConnecting
	WireGuardConnected
	WireGuardError
	WireGuardWaitingForNetwork
)

type BaseDevice interface {
	Up() error
	Down() error
}

//goland:noinspection GoUnusedExportedFunction
func NewWireGuardStateManager(log *Logger, udpTransmission bool) *WireGuardStateManager {
	return &WireGuardStateManager{
		networkAvailableChan: make(chan bool, 100),
		SocketErrChan:        make(chan error, 100),
		HandshakeStateChan:   make(chan HandshakeState, 100),
		closeChan:            make(chan bool, 1),
		stateChan:            make(chan WireGuardState, 1),
		udpTransmission:      udpTransmission,
		log:                  log,
		nextRestartDelay:     initialRestartDelay,
		lastRestart:          timeNow(),
	}
}

func (man *WireGuardStateManager) Start(device BaseDevice) {
	man.stopping.Add(1)
	go man.handlerLoop(device)
}

func (man *WireGuardStateManager) GetState() WireGuardState {
	state, ok := <-man.stateChan
	if !ok {
		return -1
	}
	return state
}

func (man *WireGuardStateManager) Close() {
	man.log.Verbosef("StateManager: closing")
	man.closed.Store(true)
	go func() {
		man.closeChan <- true
		man.stopping.Wait() // Wait for handlerLoop and all postState goroutines to finish.
		man.stateChan <- WireGuardDisabled
		close(man.stateChan)
	}()
}

func (man *WireGuardStateManager) SetNetworkAvailable(available bool) {
	man.networkAvailableChan <- available
}

func (man *WireGuardStateManager) handlerLoop(device BaseDevice) {
	defer man.stopping.Done()
	man.log.Verbosef("StateManager: start loop")
	for {
		select {
		case netAvailable := <-man.networkAvailableChan:
			man.onNetworkAvailabilityChange(device, netAvailable)
			man.isNetAvailable.Store(netAvailable)
		case socketErr := <-man.SocketErrChan:
			if man.isNetAvailable.Load() {
				man.handleSocketErr(device, socketErr)
			}
		case handshakeState := <-man.HandshakeStateChan:
			if man.isNetAvailable.Load() {
				man.handleHandshakeState(device, handshakeState)
			}
		case <-man.closeChan:
			man.log.Verbosef("StateManager: end loop")
			return
		}
	}
}

func (man *WireGuardStateManager) onNetworkAvailabilityChange(device BaseDevice, available bool) {
	if !available {
		man.postState(WireGuardWaitingForNetwork)
	}
	var isStarted bool = !man.startedTimestamp.IsZero()
	var wasAvailable bool = man.isNetAvailable.Load() && isStarted
	if available && !isStarted {
		man.log.Verbosef("StateManager: network on")
		man.setActive(device, true)
		man.startedTimestamp = timeNow()
	} else if available && wasAvailable && timeNow().After(man.startedTimestamp.Add(5*time.Second)) {
		// Ignore network changes at the very beginning of connection as those might be false positive
		// (VPN tunnel opening)
		man.log.Verbosef("StateManager: network change detected")
		man.maybeRestart(device)
	} else if available && !wasAvailable {
		man.log.Verbosef("StateManager: network back")
		man.setActive(device, true)
	} else if !available && wasAvailable {
		man.log.Verbosef("StateManager: network gone")
		man.setActive(device, false)
	}
}

func (man *WireGuardStateManager) setActive(device BaseDevice, activate bool) {
	man.mu.Lock()
	defer man.mu.Unlock()

	var err error
	if activate {
		man.postState(WireGuardConnecting)
		err = device.Up()
	} else {
		err = device.Down()
	}
	if err != nil {
		man.log.Errorf("StateManager: setActive(%t) error %v", activate, err)
		man.postState(WireGuardError)
	}
}

func (man *WireGuardStateManager) handleSocketErr(device BaseDevice, err error) {
	if err != nil {
		errStr := err.Error()
		if strings.Contains(errStr, "broken pipe") ||
			strings.Contains(errStr, "connection reset by peer") {
			man.log.Errorf("StateManager: %s", errStr)
			man.maybeRestart(device)
		}
	}
}

func (man *WireGuardStateManager) handleHandshakeState(device BaseDevice, state HandshakeState) {
	switch state {
	case HandshakeInit:
		man.postState(WireGuardConnecting)
	case HandshakeSuccess:
		man.postState(WireGuardConnected)
	case HandshakeFail:
		man.postState(WireGuardError)
		man.maybeRestart(device)
	}
}

func (man *WireGuardStateManager) maybeRestart(device BaseDevice) {
	if man.udpTransmission {
		return
	}

	man.mu.Lock()
	defer man.mu.Unlock()

	if man.shouldRestart() {
		man.log.Verbosef("StateManager: restarting")
		man.postState(WireGuardConnecting)
		device.Down()
		if !man.closed.Load() {
			device.Up()
		}
	}
}

// Don't restart too often, grow delay exponentially up to a limit and after some time reset to small initial value
func (man *WireGuardStateManager) shouldRestart() bool {
	now := timeNow()
	restart := now.After(man.lastRestart.Add(man.nextRestartDelay))
	if restart {
		if now.After(man.lastRestart.Add(resetRestartDelay)) {
			man.nextRestartDelay = initialRestartDelay
		} else {
			man.nextRestartDelay *= 2
			if man.nextRestartDelay > maxRestartDelay {
				man.nextRestartDelay = maxRestartDelay
			}
		}
		man.lastRestart = now
	}
	return restart
}

func (man *WireGuardStateManager) postState(state WireGuardState) {
	man.stopping.Add(1)
	go func() {
		defer man.stopping.Done()
		if !man.closed.Load() && (man.isNetAvailable.Load() || state == WireGuardWaitingForNetwork) {
			man.stateChan <- state
		}
	}()
}
