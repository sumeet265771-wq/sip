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
	"fmt"
	"net/netip"
	"sync"
	"time"

	"github.com/pkg/errors"

	"github.com/livekit/media-sdk/sdp"
	"github.com/livekit/protocol/livekit"
	"github.com/livekit/protocol/logger"
	"github.com/livekit/protocol/rpc"
	lksip "github.com/livekit/protocol/sip"
	"github.com/livekit/protocol/utils/traceid"
	"github.com/livekit/psrpc"
	"github.com/livekit/sipgo/sip"

	"github.com/livekit/sip/pkg/config"
	"github.com/livekit/sip/pkg/stats"
)

const (
	// siprecInviteTimeout is the maximum time to wait for both legs to establish
	siprecInviteTimeout = 30 * time.Second

	// siprecSessionTTL is how long to keep SIPREC sessions before cleanup
	siprecSessionTTL = 5 * time.Minute
)

// processSiprecInvite handles SIPREC INVITEs by splitting them into two regular calls.
func (s *Server) processSiprecInvite(req *sip.Request, tx sip.ServerTransaction) error {
	ctx := context.Background()
	ctx, span := Tracer.Start(ctx, "sip.Server.processSiprecInvite")
	defer span.End()

	s.mon.InviteReqRaw(stats.Inbound)

	// Parse source IP
	src, err := netip.ParseAddrPort(req.Source())
	if err != nil {
		tx.Terminate()
		s.log.Errorw("cannot parse source IP for SIPREC", err, "fromIP", src)
		return psrpc.NewError(psrpc.MalformedRequest, errors.Wrap(err, "cannot parse source IP"))
	}

	// Get Call-ID from request
	sipCallID := ""
	if h := req.CallID(); h != nil {
		sipCallID = h.Value()
	}
	if sipCallID == "" {
		s.respondSiprecError(tx, req, sip.StatusBadRequest, "Missing Call-ID")
		return psrpc.NewErrorf(psrpc.InvalidArgument, "SIPREC INVITE missing Call-ID")
	}

	// Check for duplicate/retransmission
	if s.siprecSessions.Exists(sipCallID) {
		s.log.Debugw("SIPREC INVITE retransmission detected", "sipCallID", sipCallID)
		return nil
	}

	callID := lksip.NewCallID()
	tid := traceid.FromGUID(callID)
	tr := callTransportFromReq(req)

	log := s.log.WithValues(
		"callID", callID,
		"traceID", tid.String(),
		"sipCallID", sipCallID,
		"fromIP", src.Addr(),
		"toIP", req.Destination(),
		"transport", tr,
		"siprec", true,
	)

	log.Infow("Processing SIPREC INVITE")

	// Send 100 Trying immediately
	trying := sip.NewResponseFromRequest(req, sip.StatusTrying, "Trying", nil)
	if err := tx.Respond(trying); err != nil {
		log.Errorw("Failed to send 100 Trying for SIPREC", err)
	}

	// Extract SDP from the SIPREC body (may be multipart)
	originalSDP, err := ExtractSDPFromSiprecBody(req)
	if err != nil {
		log.Errorw("Failed to extract SDP from SIPREC INVITE", err)
		s.respondSiprecError(tx, req, sip.StatusBadRequest, "Invalid SDP")
		return psrpc.NewError(psrpc.InvalidArgument, errors.Wrap(err, "failed to extract SDP"))
	}

	// Parse the SDP to verify it has 2 media sections
	_, mediaBlocks, err := ParseSiprecSDP(originalSDP)
	if err != nil {
		log.Errorw("Failed to parse SIPREC SDP", err)
		s.respondSiprecError(tx, req, sip.StatusBadRequest, "Invalid SDP")
		return psrpc.NewError(psrpc.InvalidArgument, errors.Wrap(err, "failed to parse SDP"))
	}

	if len(mediaBlocks) != 2 {
		log.Warnw("SIPREC SDP does not have exactly 2 media sections",
			nil, "mediaCount", len(mediaBlocks))
		s.respondSiprecError(tx, req, sip.StatusBadRequest, "Expected 2 media sections")
		return psrpc.NewErrorf(psrpc.InvalidArgument, "expected 2 media sections, got %d", len(mediaBlocks))
	}

	// Create SIPREC session to track this call
	session := NewSiprecSession(log, sipCallID, req, tx, originalSDP)
	s.siprecSessions.Set(sipCallID, session)

	// Process the SIPREC call asynchronously
	go s.handleSiprecCall(ctx, tid, log, session, req, tr, src)

	return nil
}

// handleSiprecCall processes a SIPREC call by creating two split legs.
func (s *Server) handleSiprecCall(
	ctx context.Context,
	tid traceid.ID,
	log logger.Logger,
	session *SiprecSession,
	req *sip.Request,
	tr Transport,
	src netip.AddrPort,
) {
	defer func() {
		if r := recover(); r != nil {
			log.Errorw("Panic in handleSiprecCall", fmt.Errorf("%v", r))
			s.cleanupSiprecSession(session.ID)
		}
	}()

	ctx, cancel := context.WithTimeout(ctx, siprecInviteTimeout)
	defer cancel()

	// Get target URI - use the same target as the original request
	// In a real deployment, this would come from configuration
	legTr := legTransportFromReq(req)
	contactURI := s.ContactURI(legTr)

	// Split the SIPREC INVITE into two regular INVITEs
	targetA := req.Recipient
	targetB := req.Recipient

	inviteA, inviteB, err := SplitSiprecInvite(req, targetA, targetB)
	if err != nil {
		log.Errorw("Failed to split SIPREC INVITE", err)
		s.respondSiprecError(session.OriginalTx, req, sip.StatusInternalServerError, "Failed to process SIPREC")
		s.cleanupSiprecSession(session.ID)
		return
	}

	// Extract labels from the split invites
	sdpA := string(inviteA.Body())
	sdpB := string(inviteB.Body())
	_, mediaBlocksA, _ := ParseSiprecSDP(sdpA)
	_, mediaBlocksB, _ := ParseSiprecSDP(sdpB)

	labelA := "inbound"
	labelB := "outbound"
	if len(mediaBlocksA) > 0 {
		if l := ExtractSiprecMediaLabel(mediaBlocksA[0]); l != "" {
			labelA = l
		}
	}
	if len(mediaBlocksB) > 0 {
		if l := ExtractSiprecMediaLabel(mediaBlocksB[0]); l != "" {
			labelB = l
		}
	}

	// Set leg info in session
	callIDA := ""
	callIDB := ""
	if h := inviteA.CallID(); h != nil {
		callIDA = h.Value()
	}
	if h := inviteB.CallID(); h != nil {
		callIDB = h.Value()
	}
	session.SetLegA(labelA, callIDA, inviteA)
	session.SetLegB(labelB, callIDB, inviteB)

	log.Infow("Split SIPREC into two legs",
		"labelA", labelA,
		"labelB", labelB,
		"callIDA", callIDA,
		"callIDB", callIDB,
	)

	// Do a single dispatch call for the SIPREC session to get the shared room name.
	// This ensures both legs join the same room.
	from := req.From()
	to := req.To()
	if from == nil || to == nil {
		log.Errorw("Missing From/To headers in SIPREC INVITE", nil)
		s.respondSiprecError(session.OriginalTx, req, sip.StatusBadRequest, "Missing From/To")
		s.cleanupSiprecSession(session.ID)
		return
	}

	// Create a call info for the session-level dispatch
	sessionCallInfo := &rpc.SIPCall{
		LkCallId:  lksip.NewCallID(),
		SipCallId: session.ID,
		SourceIp:  src.Addr().String(),
		Address:   ToSIPUri("", req.Recipient),
		From:      ToSIPUri("", from.Address),
		To:        ToSIPUri("", to.Address),
	}

	// Get auth credentials for the session
	authResult, err := s.handler.GetAuthCredentials(ctx, sessionCallInfo)
	if err != nil {
		log.Warnw("Failed to get auth credentials for SIPREC session", err)
		s.respondSiprecError(session.OriginalTx, req, sip.StatusForbidden, "Auth failed")
		s.cleanupSiprecSession(session.ID)
		return
	}

	if authResult.Result != AuthAccept && authResult.Result != AuthPassword {
		log.Warnw("SIPREC session auth not accepted", nil, "result", authResult.Result)
		s.respondSiprecError(session.OriginalTx, req, sip.StatusForbidden, "Not authorized")
		s.cleanupSiprecSession(session.ID)
		return
	}

	// Dispatch the SIPREC session to get the shared room configuration
	sessionDispatch := s.handler.DispatchCall(ctx, &CallInfo{
		TrunkID:     authResult.TrunkID,
		Call:        sessionCallInfo,
		Pin:         "",
		NoPin:       true, // SIPREC doesn't use PIN
		IsSiprec:    true,
		SiprecLabel: "session", // Mark as session-level dispatch
	})

	if sessionDispatch.Result != DispatchAccept {
		log.Warnw("SIPREC session dispatch not accepted", nil, "result", sessionDispatch.Result)
		s.respondSiprecError(session.OriginalTx, req, sip.StatusServiceUnavailable, "No dispatch rule")
		s.cleanupSiprecSession(session.ID)
		return
	}

	// Store the shared room name in the session
	// Both legs will use this same room name
	session.SharedRoomName = sessionDispatch.Room.RoomName
	session.SharedDispatch = &sessionDispatch

	log.Infow("SIPREC session dispatched",
		"sharedRoom", session.SharedRoomName,
		"dispatchRule", sessionDispatch.DispatchRuleID,
		"trunkID", sessionDispatch.TrunkID,
	)

	// Process both legs concurrently
	var wg sync.WaitGroup
	wg.Add(2)

	// Process leg A
	go func() {
		defer wg.Done()
		answerSDP, err := s.processSiprecLeg(ctx, tid, log, session, "A", labelA, inviteA, contactURI, tr, src)
		session.SetLegAResult(answerSDP, err)
	}()

	// Process leg B
	go func() {
		defer wg.Done()
		answerSDP, err := s.processSiprecLeg(ctx, tid, log, session, "B", labelB, inviteB, contactURI, tr, src)
		session.SetLegBResult(answerSDP, err)
	}()

	// Wait for both legs with timeout
	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()

	select {
	case <-done:
		// Both legs completed
	case <-ctx.Done():
		log.Warnw("SIPREC processing timeout", nil)
		s.respondSiprecError(session.OriginalTx, req, sip.StatusRequestTimeout, "Timeout")
		s.cleanupSiprecSession(session.ID)
		return
	}

	// Check results
	resultA, resultB, err := session.WaitForResults(ctx)
	if err != nil {
		log.Errorw("Failed to get SIPREC leg results", err)
		s.respondSiprecError(session.OriginalTx, req, sip.StatusInternalServerError, "Internal Error")
		s.cleanupSiprecSession(session.ID)
		return
	}

	// Check for leg errors
	if resultA.Error != nil || resultB.Error != nil {
		log.Warnw("One or both SIPREC legs failed",
			nil,
			"errorA", resultA.Error,
			"errorB", resultB.Error,
		)
		s.respondSiprecError(session.OriginalTx, req, sip.StatusServiceUnavailable, "Service Unavailable")
		s.cleanupSiprecSession(session.ID)
		return
	}

	// Combine the answers into a SIPREC response
	combinedSDP, err := CombineSiprecAnswerSDPs(session.OriginalSDP, resultA.AnswerSDP, resultB.AnswerSDP)
	if err != nil {
		log.Errorw("Failed to combine SIPREC answers", err)
		s.respondSiprecError(session.OriginalTx, req, sip.StatusInternalServerError, "Failed to combine answers")
		s.cleanupSiprecSession(session.ID)
		return
	}

	// Create and send the combined 200 OK response
	resp := CreateSiprecResponse(req, combinedSDP)
	if err := session.OriginalTx.Respond(resp); err != nil {
		log.Errorw("Failed to send SIPREC 200 OK", err)
		s.cleanupSiprecSession(session.ID)
		return
	}

	session.SetCompleted()
	log.Infow("SIPREC call established successfully")
}

// processSiprecLeg processes a single leg of a SIPREC call.
// It creates an inbound call, sets up media, joins the room, and publishes the track.
func (s *Server) processSiprecLeg(
	ctx context.Context,
	tid traceid.ID,
	parentLog logger.Logger,
	session *SiprecSession,
	legID string,
	label string,
	invite *sip.Request,
	contactURI URI,
	tr Transport,
	src netip.AddrPort,
) (string, error) {
	log := parentLog.WithValues(
		"siprecLeg", legID,
		"label", label,
	)

	log.Infow("Processing SIPREC leg")

	// Create a unique call ID for this leg
	callID := lksip.NewCallID()
	legTid := traceid.FromGUID(callID)

	// Get from/to from the split invite
	from := invite.From()
	to := invite.To()
	if from == nil || to == nil {
		return "", errors.New("missing From/To headers in split invite")
	}

	// Create call info for this leg
	callInfo := &rpc.SIPCall{
		LkCallId:  callID,
		SipCallId: session.ID + "_" + legID,
		SourceIp:  src.Addr().String(),
		Address:   ToSIPUri("", invite.Recipient),
		From:      ToSIPUri("", from.Address),
		To:        ToSIPUri("", to.Address),
	}

	// Get auth credentials for this leg
	r, err := s.handler.GetAuthCredentials(ctx, callInfo)
	if err != nil {
		log.Warnw("Failed to get auth credentials for SIPREC leg", err)
		return "", errors.Wrap(err, "auth check failed")
	}

	if r.Result != AuthAccept && r.Result != AuthPassword {
		log.Warnw("SIPREC leg auth not accepted", nil, "result", r.Result)
		return "", errors.New("authentication not accepted")
	}

	// Add project and trunk IDs to log
	if r.ProjectID != "" {
		log = log.WithValues("projectID", r.ProjectID)
	}
	if r.TrunkID != "" {
		log = log.WithValues("sipTrunk", r.TrunkID)
	}

	// Create call state for this leg
	state := NewCallState(s.getIOClient(r.ProjectID), &livekit.SIPCallInfo{
		CallId:        callID,
		Region:        s.region,
		FromUri:       CreateURIFromUserAndAddress(from.Address.User, src.String(), tr).ToSIPUri(),
		ToUri:         CreateURIFromUserAndAddress(to.Address.User, to.Address.Host, tr).ToSIPUri(),
		CallStatus:    livekit.SIPCallStatus_SCS_CALL_INCOMING,
		CallDirection: livekit.SIPCallDirection_SCD_INBOUND,
		CreatedAtNs:   time.Now().UnixNano(),
		TrunkId:       r.TrunkID,
		ProviderInfo:  r.ProviderInfo,
	})
	state.Flush(ctx)

	// Dispatch the call to get room configuration
	// Use SIPREC-specific dispatch info
	disp := s.handler.DispatchCall(ctx, &CallInfo{
		TrunkID:     r.TrunkID,
		Call:        callInfo,
		Pin:         "",
		NoPin:       true, // SIPREC doesn't use PIN
		IsSiprec:    true,
		SiprecLabel: label,
	})

	if disp.Result != DispatchAccept {
		log.Warnw("SIPREC leg dispatch not accepted", nil, "result", disp.Result)
		return "", fmt.Errorf("dispatch not accepted: %v", disp.Result)
	}

	if disp.DispatchRuleID != "" {
		log = log.WithValues("sipRule", disp.DispatchRuleID)
	}

	// Update call state with dispatch info
	// Use the shared room name from the session to ensure consistency
	roomName := session.SharedRoomName
	if roomName == "" {
		roomName = disp.Room.RoomName
	}

	// Use dispatch rule ID from the shared session dispatch for consistency
	dispatchRuleID := disp.DispatchRuleID
	if session.SharedDispatch != nil && session.SharedDispatch.DispatchRuleID != "" {
		dispatchRuleID = session.SharedDispatch.DispatchRuleID
	}

	state.Update(ctx, func(info *livekit.SIPCallInfo) {
		info.TrunkId = disp.TrunkID
		info.DispatchRuleId = dispatchRuleID
		info.RoomName = roomName
		info.ParticipantIdentity = disp.Room.Participant.Identity
		info.ParticipantAttributes = disp.Room.Participant.Attributes
	})

	// Create the inbound call handler for this leg
	legCC := s.newSiprecLegInbound(log, LocalTag(callID), contactURI, invite)
	legLog := LoggerWithParams(log, legCC)
	legCC.log = legLog

	cmon := s.mon.NewCall(stats.Inbound, from.Address.Host, to.Address.Host)
	cmon.InviteReq()

	// Create the inbound call with SIPREC-specific attributes
	siprecAttrs := map[string]string{
		"siprec":                   "true",
		"siprecLabel":              label,
		livekit.AttrSIPCallID:      callID,
		livekit.AttrSIPTrunkID:     r.TrunkID,
		livekit.AttrSIPPhoneNumber: from.Address.User,
	}

	call := s.newInboundCall(ctx, legTid, legLog, cmon, legCC, callInfo, state, time.Now(), siprecAttrs)
	call.projectID = disp.ProjectID

	// Store the call reference in the session
	if legID == "A" {
		session.SetLegACall(call)
	} else {
		session.SetLegBCall(call)
	}

	// Register the call in the server maps
	s.cmu.Lock()
	s.byLocalTag[legCC.ID()] = call
	s.cmu.Unlock()

	// Run the media connection for this leg
	answerData, err := s.runSiprecLegMedia(ctx, legTid, call, invite, disp, s.conf)
	if err != nil {
		log.Errorw("Failed to setup SIPREC leg media", err)
		return "", errors.Wrap(err, "media setup failed")
	}

	// Join the room - use the SHARED room config from the session dispatch
	// This ensures both SIPREC legs (A and B) join the same room with a valid token
	var roomConf RoomConfig
	if session.SharedDispatch != nil {
		// Use the shared dispatch's room config (includes valid token for the shared room)
		roomConf = session.SharedDispatch.Room
	} else {
		// Fallback to per-leg dispatch (shouldn't happen in normal flow)
		roomConf = disp.Room
	}

	// Customize participant identity for SIPREC to include the label
	if roomConf.Participant.Identity == "" {
		roomConf.Participant.Identity = fmt.Sprintf("siprec_%s_%s", label, callID[:8])
	} else {
		roomConf.Participant.Identity = fmt.Sprintf("%s_%s", roomConf.Participant.Identity, label)
	}
	if roomConf.Participant.Name == "" {
		roomConf.Participant.Name = fmt.Sprintf("SIPREC %s", label)
	}

	// Apply headers_to_attributes from the shared dispatch rules (same as regular SIP calls)
	// Use the original SIPREC INVITE headers to extract attributes
	originalHeaders := Headers(session.OriginalInvite.Headers())
	headersToAttrs := disp.HeadersToAttributes
	includeHeaders := disp.IncludeHeaders
	if session.SharedDispatch != nil {
		headersToAttrs = session.SharedDispatch.HeadersToAttributes
		includeHeaders = session.SharedDispatch.IncludeHeaders
	}
	roomConf.Participant.Attributes = HeadersToAttrs(
		roomConf.Participant.Attributes,
		headersToAttrs,
		includeHeaders,
		nil, // No signaling interface, use headers directly
		originalHeaders,
	)

	// Add SIPREC-specific attributes to participant
	if roomConf.Participant.Attributes == nil {
		roomConf.Participant.Attributes = make(map[string]string)
	}
	for k, v := range siprecAttrs {
		roomConf.Participant.Attributes[k] = v
	}

	log.Infow("SIPREC leg joining room",
		"room", roomConf.RoomName,
		"participant", roomConf.Participant.Identity,
	)

	if err := call.joinSiprecRoom(ctx, roomConf); err != nil {
		log.Errorw("Failed to join room for SIPREC leg", err)
		return "", errors.Wrap(err, "room join failed")
	}

	// Publish the audio track
	if err := call.publishSiprecTrack(); err != nil {
		log.Errorw("Failed to publish SIPREC track", err)
		return "", errors.Wrap(err, "track publish failed")
	}

	// Subscribe to other participants (for SIPREC, typically not needed but allows monitoring)
	call.lkRoom.Subscribe()

	log.Infow("SIPREC leg fully established",
		"answerLength", len(answerData),
		"room", roomConf.RoomName,
	)

	return string(answerData), nil
}

// runSiprecLegMedia sets up media for a SIPREC leg.
func (s *Server) runSiprecLegMedia(
	ctx context.Context,
	tid traceid.ID,
	call *inboundCall,
	invite *sip.Request,
	disp CallDispatch,
	conf *config.Config,
) ([]byte, error) {
	rawSDP := invite.Body()
	if len(rawSDP) == 0 {
		return nil, errors.New("no SDP in invite")
	}

	// Use encryption from dispatch, default to none for SIPREC
	enc, err := sdpEncryption(disp.MediaEncryption)
	if err != nil {
		// Default to none for SIPREC (typically internal traffic)
		enc = sdp.EncryptionNone
	}

	call.mon.SDPSize(len(rawSDP), true)
	call.log().Debugw("SIPREC leg SDP offer", "sdp", string(rawSDP))

	mp, err := NewMediaPort(tid, call.log(), call.mon, &MediaOptions{
		IP:                  s.sconf.MediaIP,
		Ports:               conf.RTPPort,
		MediaTimeoutInitial: conf.MediaTimeoutInitial,
		MediaTimeout:        conf.MediaTimeout,
		EnableJitterBuffer:  call.jitterBuf,
		Stats:               &call.stats.Port,
		NoInputResample:     !RoomResample,
	}, RoomSampleRate)
	if err != nil {
		return nil, errors.Wrap(err, "failed to create media port")
	}
	call.media = mp
	call.media.EnableTimeout(false)
	call.media.DisableOut() // SIPREC is receive-only
	call.media.SetDTMFAudio(conf.AudioDTMF)

	answer, mconf, err := mp.SetOffer(rawSDP, enc)
	if err != nil {
		return nil, errors.Wrap(err, "failed to set SDP offer")
	}

	answerData, err := answer.SDP.Marshal()
	if err != nil {
		return nil, errors.Wrap(err, "failed to marshal SDP answer")
	}

	call.mon.SDPSize(len(answerData), false)
	call.log().Debugw("SIPREC leg SDP answer", "sdp", string(answerData))

	mconf.Processor = s.handler.GetMediaProcessor(disp.EnabledFeatures)
	if err = call.media.SetConfig(mconf); err != nil {
		return nil, errors.Wrap(err, "failed to set media config")
	}

	return answerData, nil
}

// joinSiprecRoom joins the LiveKit room for a SIPREC leg.
func (c *inboundCall) joinSiprecRoom(ctx context.Context, rconf RoomConfig) error {
	c.appendLogValues(
		"room", rconf.RoomName,
		"participant", rconf.Participant.Identity,
		"participantName", rconf.Participant.Name,
	)
	c.log().Infow("SIPREC leg joining room")

	partConf := &rconf.Participant
	if partConf.Attributes == nil {
		partConf.Attributes = make(map[string]string)
	}
	for k, v := range c.extraAttrs {
		partConf.Attributes[k] = v
	}
	partConf.Attributes[livekit.AttrSIPCallStatus] = CallActive.Attribute()

	// Don't forward DTMF for SIPREC (receive-only)
	c.forwardDTMF.Store(false)

	err := c.lkRoom.Connect(c.s.conf, rconf)
	if err != nil {
		return errors.Wrap(err, "failed to connect to room")
	}

	c.callDur = c.mon.CallDur()

	return nil
}

// publishSiprecTrack publishes the audio track for a SIPREC leg.
func (c *inboundCall) publishSiprecTrack() error {
	local, err := c.lkRoom.NewParticipantTrack(RoomSampleRate)
	if err != nil {
		c.log().Errorw("Failed to create SIPREC participant track", err)
		return errors.Wrap(err, "failed to create track")
	}

	// For SIPREC, audio flows from SIP to the room
	// Connect the media port's incoming audio to the room track
	c.media.WriteAudioTo(local)

	c.log().Infow("SIPREC audio track published")

	return nil
}

// newSiprecLegInbound creates a sipInbound for a SIPREC leg.
// This is a simplified version since SIPREC legs don't have real SIP transactions.
func (s *Server) newSiprecLegInbound(log logger.Logger, id LocalTag, contact URI, invite *sip.Request) *sipInbound {
	c := &sipInbound{
		log: log,
		s:   s,
		id:  id,
		contact: &sip.ContactHeader{
			Address: *contact.GetContactURI(),
		},
		cancelled: make(chan struct{}),
		referDone: make(chan error),
	}

	c.from = invite.From()
	if c.from != nil {
		c.tag, _ = getTagFrom(c.from.Params)
	}
	c.to = invite.To()

	if callID := invite.CallID(); callID != nil {
		c.sipCallID = callID.Value()
	}

	// For SIPREC legs, we mark them as already "accepted" since they're virtual
	c.invite = invite

	return c
}

// respondSiprecError sends an error response for a SIPREC INVITE.
func (s *Server) respondSiprecError(tx sip.ServerTransaction, req *sip.Request, code sip.StatusCode, reason string) {
	if tx == nil {
		return
	}
	resp := sip.NewResponseFromRequest(req, code, reason, nil)
	if err := tx.Respond(resp); err != nil {
		s.log.Errorw("Failed to send SIPREC error response", err, "code", code)
	}
}

// cleanupSiprecSession removes a SIPREC session and its associated resources.
// This properly closes the LiveKit room connections for each leg.
func (s *Server) cleanupSiprecSession(sipCallID string) {
	session, exists := s.siprecSessions.Get(sipCallID)
	if !exists {
		return
	}

	s.log.Infow("Cleaning up SIPREC session", "sipCallID", sipCallID)

	// Clean up leg A
	if session.LegA != nil && session.LegA.Call != nil {
		s.closeSiprecLeg(session.LegA.Call, "A", session.LegA.Label)
	}

	// Clean up leg B
	if session.LegB != nil && session.LegB.Call != nil {
		s.closeSiprecLeg(session.LegB.Call, "B", session.LegB.Label)
	}

	// Cancel the session context
	session.Cancel()

	// Remove from session store
	s.siprecSessions.Delete(sipCallID)

	s.log.Infow("SIPREC session cleaned up", "sipCallID", sipCallID)
}

// closeSiprecLeg properly closes a single SIPREC leg, including the LiveKit room.
func (s *Server) closeSiprecLeg(call *inboundCall, legID, label string) {
	if call == nil {
		return
	}

	log := call.log()
	if log == nil {
		log = s.log
	}
	log.Infow("Closing SIPREC leg", "legID", legID, "label", label)

	// Update call state to disconnected
	if call.state != nil {
		call.state.Update(context.Background(), func(info *livekit.SIPCallInfo) {
			info.CallStatus = livekit.SIPCallStatus_SCS_DISCONNECTED
			info.EndedAtNs = time.Now().UnixNano()
			info.DisconnectReason = livekit.DisconnectReason_CLIENT_INITIATED
		})
	}

	// Close the media port (stops receiving RTP)
	if call.media != nil {
		call.media.Close()
		log.Debugw("SIPREC leg media closed")
	}

	// Close the LiveKit room connection (removes participant from room)
	if call.lkRoom != nil {
		if err := call.lkRoom.CloseWithReason(livekit.DisconnectReason_CLIENT_INITIATED); err != nil {
			log.Warnw("Error closing SIPREC leg room", err)
		} else {
			log.Debugw("SIPREC leg room closed")
		}
	}

	// Call the session end handler
	if s.handler != nil && call.call != nil {
		go func() {
			ctx := context.Background()
			var callInfo *livekit.SIPCallInfo
			if call.state != nil {
				callInfo = call.state.callInfo
			}
			s.handler.OnSessionEnd(ctx, &CallIdentifier{
				ProjectID: call.projectID,
				CallID:    call.call.LkCallId,
				SipCallID: call.call.SipCallId,
			}, callInfo, "siprec-bye")
		}()
	}

	// Remove from server maps
	if call.cc != nil {
		s.cmu.Lock()
		delete(s.byLocalTag, call.cc.ID())
		s.cmu.Unlock()
	}

	// Cancel the call context
	call.cancel()

	// Update monitor stats
	if call.mon != nil {
		call.mon.CallTerminate("siprec-bye")
		if call.callDur != nil {
			call.callDur()
		}
	}

	log.Infow("SIPREC leg closed", "legID", legID, "label", label)
}

// handleSiprecBye handles BYE requests for SIPREC sessions.
func (s *Server) handleSiprecBye(req *sip.Request, tx sip.ServerTransaction) bool {
	callID := ""
	if h := req.CallID(); h != nil {
		callID = h.Value()
	}

	// Check if this is for a SIPREC session
	session, exists := s.siprecSessions.Get(callID)
	if !exists {
		return false // Not a SIPREC session
	}

	s.log.Infow("Received BYE for SIPREC session", "sipCallID", callID)

	// Respond 200 OK
	resp := sip.NewResponseFromRequest(req, sip.StatusOK, "OK", nil)
	if err := tx.Respond(resp); err != nil {
		s.log.Errorw("Failed to send SIPREC BYE response", err)
	}

	// Clean up the session
	s.cleanupSiprecSession(session.ID)

	return true
}

// handleSiprecAck handles ACK requests for SIPREC sessions.
func (s *Server) handleSiprecAck(req *sip.Request) bool {
	callID := ""
	if h := req.CallID(); h != nil {
		callID = h.Value()
	}

	// Check if this is for a SIPREC session
	session, exists := s.siprecSessions.Get(callID)
	if !exists {
		return false // Not a SIPREC session
	}

	s.log.Infow("Received ACK for SIPREC session", "sipCallID", callID)

	// Enable media timeout now that ACK is received
	if session.LegA != nil && session.LegA.Call != nil && session.LegA.Call.media != nil {
		session.LegA.Call.media.EnableTimeout(true)
	}
	if session.LegB != nil && session.LegB.Call != nil && session.LegB.Call.media != nil {
		session.LegB.Call.media.EnableTimeout(true)
	}

	return true
}
