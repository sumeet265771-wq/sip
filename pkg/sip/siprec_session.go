// Copyright 2024 LiveKit, Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// 	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package sip

import (
	"context"
	"hash/fnv"
	"sync"
	"time"

	"github.com/livekit/protocol/logger"
	"github.com/livekit/sipgo/sip"
)

const (
	// Number of shards for the session map to reduce lock contention
	numSiprecSessionShards = 64
)

// =============================================================================
// SIPREC Session Types
// =============================================================================

// SiprecSession tracks a SIPREC call and its two split legs.
type SiprecSession struct {
	// Unique identifier (original SIP Call-ID)
	ID string

	// Original SIPREC INVITE data
	OriginalInvite *sip.Request
	OriginalTx     sip.ServerTransaction
	OriginalSDP    string

	// Split leg tracking
	LegA *SiprecLeg
	LegB *SiprecLeg

	// Timing
	CreatedAt    time.Time
	LastActivity time.Time

	// State management
	mu        sync.RWMutex
	completed bool
	ctx       context.Context
	cancel    context.CancelFunc

	// Result channels
	resultA chan *SiprecLegResult
	resultB chan *SiprecLegResult

	// Logger
	log logger.Logger
}

// SiprecLeg represents one leg of a split SIPREC call.
type SiprecLeg struct {
	Label     string // "inbound" or "outbound" (from a=label)
	CallID    string // SIP Call-ID for this leg
	Invite    *sip.Request
	AnswerSDP string
	Error     error
	Call      *inboundCall // Reference to the actual inbound call
}

// SiprecLegResult is the result of processing a single SIPREC leg.
type SiprecLegResult struct {
	Leg       string // "A" or "B"
	AnswerSDP string
	Error     error
}

// NewSiprecSession creates a new SIPREC session.
func NewSiprecSession(log logger.Logger, id string, invite *sip.Request, tx sip.ServerTransaction, originalSDP string) *SiprecSession {
	ctx, cancel := context.WithCancel(context.Background())
	now := time.Now()

	return &SiprecSession{
		ID:             id,
		OriginalInvite: invite,
		OriginalTx:     tx,
		OriginalSDP:    originalSDP,
		LegA:           &SiprecLeg{},
		LegB:           &SiprecLeg{},
		CreatedAt:      now,
		LastActivity:   now,
		ctx:            ctx,
		cancel:         cancel,
		resultA:        make(chan *SiprecLegResult, 1),
		resultB:        make(chan *SiprecLegResult, 1),
		log:            log,
	}
}

// SetLegA sets the details for leg A.
func (s *SiprecSession) SetLegA(label, callID string, invite *sip.Request) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.LegA.Label = label
	s.LegA.CallID = callID
	s.LegA.Invite = invite
	s.LastActivity = time.Now()
}

// SetLegB sets the details for leg B.
func (s *SiprecSession) SetLegB(label, callID string, invite *sip.Request) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.LegB.Label = label
	s.LegB.CallID = callID
	s.LegB.Invite = invite
	s.LastActivity = time.Now()
}

// SetLegAResult sets the result for leg A.
func (s *SiprecSession) SetLegAResult(answerSDP string, err error) {
	s.mu.Lock()
	s.LegA.AnswerSDP = answerSDP
	s.LegA.Error = err
	s.LastActivity = time.Now()
	s.mu.Unlock()

	select {
	case s.resultA <- &SiprecLegResult{Leg: "A", AnswerSDP: answerSDP, Error: err}:
	default:
	}
}

// SetLegBResult sets the result for leg B.
func (s *SiprecSession) SetLegBResult(answerSDP string, err error) {
	s.mu.Lock()
	s.LegB.AnswerSDP = answerSDP
	s.LegB.Error = err
	s.LastActivity = time.Now()
	s.mu.Unlock()

	select {
	case s.resultB <- &SiprecLegResult{Leg: "B", AnswerSDP: answerSDP, Error: err}:
	default:
	}
}

// SetLegACall associates the inbound call with leg A.
func (s *SiprecSession) SetLegACall(call *inboundCall) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.LegA.Call = call
}

// SetLegBCall associates the inbound call with leg B.
func (s *SiprecSession) SetLegBCall(call *inboundCall) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.LegB.Call = call
}

// WaitForResults waits for both legs to complete and returns their results.
func (s *SiprecSession) WaitForResults(ctx context.Context) (*SiprecLegResult, *SiprecLegResult, error) {
	var resultA, resultB *SiprecLegResult

	// Wait for result A
	select {
	case resultA = <-s.resultA:
	case <-ctx.Done():
		return nil, nil, ctx.Err()
	case <-s.ctx.Done():
		return nil, nil, s.ctx.Err()
	}

	// Wait for result B
	select {
	case resultB = <-s.resultB:
	case <-ctx.Done():
		return resultA, nil, ctx.Err()
	case <-s.ctx.Done():
		return resultA, nil, s.ctx.Err()
	}

	return resultA, resultB, nil
}

// Context returns the session's context.
func (s *SiprecSession) Context() context.Context {
	return s.ctx
}

// Cancel cancels the session.
func (s *SiprecSession) Cancel() {
	s.cancel()
}

// IsCompleted returns whether the session has been completed.
func (s *SiprecSession) IsCompleted() bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.completed
}

// SetCompleted marks the session as completed.
func (s *SiprecSession) SetCompleted() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.completed = true
	s.LastActivity = time.Now()
}

// GetLabels returns the labels for both legs.
func (s *SiprecSession) GetLabels() (string, string) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.LegA.Label, s.LegB.Label
}

// Close cleans up the session.
func (s *SiprecSession) Close() {
	s.cancel()

	s.mu.Lock()
	defer s.mu.Unlock()

	// Close both legs if they have associated calls
	if s.LegA.Call != nil {
		_ = s.LegA.Call.Close()
	}
	if s.LegB.Call != nil {
		_ = s.LegB.Call.Close()
	}
}

// =============================================================================
// SIPREC Session Store (Sharded for Concurrency)
// =============================================================================

// siprecSessionShard is one shard of the session map.
type siprecSessionShard struct {
	mu       sync.RWMutex
	sessions map[string]*SiprecSession
}

// SiprecSessionStore provides thread-safe storage for SIPREC sessions
// using sharded maps to reduce lock contention at high volume.
type SiprecSessionStore struct {
	shards [numSiprecSessionShards]*siprecSessionShard
	log    logger.Logger
}

// NewSiprecSessionStore creates a new session store with sharded maps.
func NewSiprecSessionStore(log logger.Logger) *SiprecSessionStore {
	store := &SiprecSessionStore{log: log}
	for i := 0; i < numSiprecSessionShards; i++ {
		store.shards[i] = &siprecSessionShard{
			sessions: make(map[string]*SiprecSession),
		}
	}
	return store
}

// getShard returns the shard for a given call ID using FNV hash.
func (s *SiprecSessionStore) getShard(callID string) *siprecSessionShard {
	h := fnv.New32a()
	h.Write([]byte(callID))
	return s.shards[h.Sum32()%numSiprecSessionShards]
}

// Get retrieves a session by call ID.
func (s *SiprecSessionStore) Get(callID string) (*SiprecSession, bool) {
	shard := s.getShard(callID)
	shard.mu.RLock()
	session, exists := shard.sessions[callID]
	shard.mu.RUnlock()
	return session, exists
}

// Set stores a session.
func (s *SiprecSessionStore) Set(callID string, session *SiprecSession) {
	shard := s.getShard(callID)
	shard.mu.Lock()
	shard.sessions[callID] = session
	shard.mu.Unlock()
}

// Delete removes a session.
func (s *SiprecSessionStore) Delete(callID string) {
	shard := s.getShard(callID)
	shard.mu.Lock()
	if session, exists := shard.sessions[callID]; exists {
		session.Close()
		delete(shard.sessions, callID)
	}
	shard.mu.Unlock()
}

// Exists checks if a session exists without retrieving it.
func (s *SiprecSessionStore) Exists(callID string) bool {
	shard := s.getShard(callID)
	shard.mu.RLock()
	_, exists := shard.sessions[callID]
	shard.mu.RUnlock()
	return exists
}

// GetByLegCallID finds a session by one of its leg's Call-ID.
func (s *SiprecSessionStore) GetByLegCallID(legCallID string) (*SiprecSession, string) {
	for i := 0; i < numSiprecSessionShards; i++ {
		shard := s.shards[i]
		shard.mu.RLock()
		for _, session := range shard.sessions {
			if session.LegA.CallID == legCallID {
				shard.mu.RUnlock()
				return session, "A"
			}
			if session.LegB.CallID == legCallID {
				shard.mu.RUnlock()
				return session, "B"
			}
		}
		shard.mu.RUnlock()
	}
	return nil, ""
}

// CleanupStale removes sessions that have exceeded their TTL.
// Returns the number of sessions cleaned up.
func (s *SiprecSessionStore) CleanupStale(ttl time.Duration) int {
	now := time.Now()
	cleaned := 0

	for i := 0; i < numSiprecSessionShards; i++ {
		shard := s.shards[i]
		shard.mu.Lock()
		for callID, session := range shard.sessions {
			if now.Sub(session.LastActivity) > ttl {
				session.Close()
				delete(shard.sessions, callID)
				cleaned++
				if s.log != nil {
					s.log.Debugw("Cleaned up stale SIPREC session",
						"callID", callID,
						"age", now.Sub(session.CreatedAt),
					)
				}
			}
		}
		shard.mu.Unlock()
	}

	return cleaned
}

// Clear removes all sessions (used during shutdown).
func (s *SiprecSessionStore) Clear() {
	for i := 0; i < numSiprecSessionShards; i++ {
		shard := s.shards[i]
		shard.mu.Lock()
		for id, session := range shard.sessions {
			session.Close()
			if s.log != nil {
				s.log.Debugw("Cleaning up SIPREC session on shutdown", "id", id)
			}
		}
		shard.sessions = make(map[string]*SiprecSession)
		shard.mu.Unlock()
	}
}

// Count returns the total number of active SIPREC sessions.
func (s *SiprecSessionStore) Count() int {
	total := 0
	for i := 0; i < numSiprecSessionShards; i++ {
		shard := s.shards[i]
		shard.mu.RLock()
		total += len(shard.sessions)
		shard.mu.RUnlock()
	}
	return total
}
