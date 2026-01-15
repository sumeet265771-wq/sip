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
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"io"
	"mime"
	"mime/multipart"
	"strings"

	"github.com/livekit/sipgo/sip"
)

// =============================================================================
// SIPREC Detection
// =============================================================================

// IsSiprecInvite checks if the given SIP request is a SIPREC INVITE.
// SIPREC INVITEs are identified by the "Require: siprec" header.
func IsSiprecInvite(req *sip.Request) bool {
	if req == nil || req.Method != sip.INVITE {
		return false
	}

	// Check for "Require: siprec" header
	requireHeader := req.GetHeader("Require")
	if requireHeader != nil {
		value := strings.ToLower(requireHeader.Value())
		if strings.Contains(value, "siprec") {
			return true
		}
	}

	// Also check for "+sip.src" in Contact header (some implementations use this)
	contactHeader := req.Contact()
	if contactHeader != nil {
		contactStr := contactHeader.String()
		if strings.Contains(contactStr, "+sip.src") {
			return true
		}
	}

	return false
}

// =============================================================================
// SIPREC INVITE Splitting
// =============================================================================

// SplitSiprecInvite takes a SIPREC INVITE with 2 audio media lines and
// returns two regular SIP INVITEs, one for each participant/stream.
func SplitSiprecInvite(invite *sip.Request, targetA, targetB sip.Uri) (*sip.Request, *sip.Request, error) {
	if invite.Body() == nil || len(invite.Body()) == 0 {
		return nil, nil, fmt.Errorf("INVITE has no body")
	}

	// Extract and parse SDP from the (possibly multipart) body
	rawSDP, err := ExtractSDPFromSiprecBody(invite)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to extract SDP: %w", err)
	}

	session, mediaBlocks, err := ParseSiprecSDP(rawSDP)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to parse SDP: %w", err)
	}

	if len(mediaBlocks) != 2 {
		return nil, nil, fmt.Errorf("expected 2 media sections for SIPREC, got %d", len(mediaBlocks))
	}

	// Extract labels to differentiate streams
	labelA := ExtractSiprecMediaLabel(mediaBlocks[0])
	labelB := ExtractSiprecMediaLabel(mediaBlocks[1])
	if labelA == "" {
		labelA = "streamA"
	}
	if labelB == "" {
		labelB = "streamB"
	}

	// Build individual SDPs for each split call
	sdpA := BuildSiprecSDP(session, mediaBlocks[0], false)
	sdpB := BuildSiprecSDP(session, mediaBlocks[1], true)

	// Create INVITEs with unique From addresses for differentiation
	inviteA, err := createSplitInvite(invite, targetA, sdpA, labelA)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create invite A: %w", err)
	}

	inviteB, err := createSplitInvite(invite, targetB, sdpB, labelB)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create invite B: %w", err)
	}

	return inviteA, inviteB, nil
}

// createSplitInvite creates a new SIP INVITE for a split SIPREC stream.
func createSplitInvite(original *sip.Request, target sip.Uri, sdpBody, streamLabel string) (*sip.Request, error) {
	origFrom := original.From()
	if origFrom == nil {
		return nil, fmt.Errorf("original INVITE missing From header")
	}

	// Create unique From address using stream label
	fromAddr := sip.Uri{
		User: streamLabel,
		Host: origFrom.Address.Host,
		Port: origFrom.Address.Port,
	}

	req := sip.NewRequest(sip.INVITE, target)

	// From header with unique address and new tag
	newFrom := &sip.FromHeader{
		DisplayName: streamLabel,
		Address:     fromAddr,
		Params:      sip.NewParams(),
	}
	newFrom.Params.Add("tag", generateSiprecTag())
	req.AppendHeader(newFrom)

	// To header (no tag for new request)
	req.AppendHeader(&sip.ToHeader{
		Address: target,
		Params:  sip.NewParams(),
	})

	// Call-ID (unique per dialog)
	callID := sip.CallIDHeader(generateSiprecCallID())
	req.AppendHeader(&callID)

	// CSeq
	req.AppendHeader(&sip.CSeqHeader{SeqNo: 1, MethodName: sip.INVITE})

	// Max-Forwards
	maxFwd := sip.MaxForwardsHeader(70)
	req.AppendHeader(&maxFwd)

	// Contact
	req.AppendHeader(&sip.ContactHeader{Address: fromAddr, Params: sip.NewParams()})

	// Copy optional headers from original
	if ua := original.GetHeader("User-Agent"); ua != nil {
		req.AppendHeader(sip.NewHeader("User-Agent", ua.Value()))
	}
	if supported := original.GetHeader("Supported"); supported != nil {
		req.AppendHeader(sip.NewHeader("Supported", supported.Value()))
	}
	if allow := original.GetHeader("Allow"); allow != nil {
		req.AppendHeader(sip.NewHeader("Allow", allow.Value()))
	}

	// Content-Type and body (regular SDP, not multipart)
	ct := sip.ContentTypeHeader("application/sdp")
	req.AppendHeader(&ct)
	req.SetBody([]byte(sdpBody))

	return req, nil
}

// =============================================================================
// SIPREC Answer Combining
// =============================================================================

// CombineSiprecAnswerSDPs combines two SDP answer strings into a single SIPREC answer SDP.
// The labels from the original offer are preserved in the combined answer.
func CombineSiprecAnswerSDPs(originalOfferSDP string, answerSDPA, answerSDPB string) (string, error) {
	// Parse the original offer to get the labels
	_, originalMediaBlocks, err := ParseSiprecSDP(originalOfferSDP)
	if err != nil {
		return "", fmt.Errorf("failed to parse original offer SDP: %w", err)
	}

	var labelA, labelB string
	if len(originalMediaBlocks) >= 1 {
		labelA = ExtractSiprecMediaLabel(originalMediaBlocks[0])
	}
	if len(originalMediaBlocks) >= 2 {
		labelB = ExtractSiprecMediaLabel(originalMediaBlocks[1])
	}

	// Parse the answer SDPs
	sessionA, mediaBlocksA, err := ParseSiprecSDP(answerSDPA)
	if err != nil {
		return "", fmt.Errorf("failed to parse answer SDP A: %w", err)
	}

	_, mediaBlocksB, err := ParseSiprecSDP(answerSDPB)
	if err != nil {
		return "", fmt.Errorf("failed to parse answer SDP B: %w", err)
	}

	if len(mediaBlocksA) != 1 {
		return "", fmt.Errorf("expected 1 media section in answer A, got %d", len(mediaBlocksA))
	}
	if len(mediaBlocksB) != 1 {
		return "", fmt.Errorf("expected 1 media section in answer B, got %d", len(mediaBlocksB))
	}

	// Build the combined SIPREC answer SDP
	combinedSDP := BuildCombinedSiprecSDP(sessionA, mediaBlocksA[0], mediaBlocksB[0], labelA, labelB)
	return combinedSDP, nil
}

// CreateSiprecResponse creates a SIP 200 OK response for a SIPREC INVITE
// with the combined SDP from two split call answers.
func CreateSiprecResponse(originalInvite *sip.Request, combinedSDP string) *sip.Response {
	resp := sip.NewResponseFromRequest(originalInvite, 200, "OK", []byte(combinedSDP))

	// Add To tag for dialog establishment
	if toHeader := resp.To(); toHeader != nil {
		if _, exists := toHeader.Params.Get("tag"); !exists {
			toHeader.Params.Add("tag", generateSiprecTag())
		}
	}

	// Set Contact header
	resp.RemoveHeader("Contact")
	contactParams := sip.NewParams()
	contactParams.Add("transport", "udp")
	resp.AppendHeader(&sip.ContactHeader{
		Address: originalInvite.Recipient,
		Params:  contactParams,
	})

	// Set required headers
	resp.RemoveHeader("Content-Type")
	ct := sip.ContentTypeHeader("application/sdp")
	resp.AppendHeader(&ct)

	resp.RemoveHeader("Allow")
	resp.AppendHeader(sip.NewHeader("Allow", "INVITE, ACK, BYE, CANCEL, OPTIONS"))

	resp.RemoveHeader("Supported")
	resp.AppendHeader(sip.NewHeader("Supported", "siprec"))

	return resp
}

// =============================================================================
// SDP Extraction Helpers
// =============================================================================

// ExtractSDPFromSiprecBody extracts SDP from a SIP request body.
// SIPREC bodies are often multipart/mixed containing both SDP and XML metadata.
func ExtractSDPFromSiprecBody(req *sip.Request) (string, error) {
	body := req.Body()
	if body == nil || len(body) == 0 {
		return "", fmt.Errorf("request has no body")
	}

	contentType := req.ContentType()
	if contentType == nil {
		// No content type specified, assume it's plain SDP
		return string(body), nil
	}

	ct := contentType.Value()
	if strings.HasPrefix(ct, "application/sdp") {
		return string(body), nil
	}
	if strings.HasPrefix(ct, "multipart/") {
		return extractSDPFromMultipart(ct, body)
	}

	// Unknown content type, try to use as-is
	return string(body), nil
}

// ExtractSDPFromSiprecResponse extracts SDP from a SIP response body.
func ExtractSDPFromSiprecResponse(resp *sip.Response) (string, error) {
	if resp.Body() == nil || len(resp.Body()) == 0 {
		return "", fmt.Errorf("response has no body")
	}

	contentType := resp.ContentType()
	if contentType == nil {
		return string(resp.Body()), nil
	}

	ct := contentType.Value()
	if strings.HasPrefix(ct, "application/sdp") {
		return string(resp.Body()), nil
	}
	if strings.HasPrefix(ct, "multipart/") {
		return extractSDPFromMultipart(ct, resp.Body())
	}

	return string(resp.Body()), nil
}

// extractSDPFromMultipart parses a multipart MIME body and extracts the SDP part.
func extractSDPFromMultipart(contentType string, body []byte) (string, error) {
	mediaType, params, err := mime.ParseMediaType(contentType)
	if err != nil {
		return "", fmt.Errorf("failed to parse Content-Type: %w", err)
	}

	if !strings.HasPrefix(mediaType, "multipart/") {
		return "", fmt.Errorf("expected multipart Content-Type, got: %s", mediaType)
	}

	boundary, ok := params["boundary"]
	if !ok {
		return "", fmt.Errorf("multipart Content-Type missing boundary parameter")
	}

	reader := multipart.NewReader(strings.NewReader(string(body)), boundary)
	for {
		part, err := reader.NextPart()
		if err == io.EOF {
			break
		}
		if err != nil {
			return "", fmt.Errorf("failed to read multipart part: %w", err)
		}

		partContentType := part.Header.Get("Content-Type")
		if strings.HasPrefix(partContentType, "application/sdp") {
			var buf strings.Builder
			if _, err := io.Copy(&buf, part); err != nil {
				return "", fmt.Errorf("failed to read SDP part: %w", err)
			}
			return buf.String(), nil
		}
	}

	return "", fmt.Errorf("no application/sdp part found in multipart body")
}

// =============================================================================
// SIPREC Metadata Extraction (optional, for future use)
// =============================================================================

// ExtractSiprecMetadata extracts the rs-metadata XML from a SIPREC multipart body.
// This contains participant information, session IDs, and stream associations.
func ExtractSiprecMetadata(req *sip.Request) (string, error) {
	body := req.Body()
	if body == nil || len(body) == 0 {
		return "", fmt.Errorf("request has no body")
	}

	contentType := req.ContentType()
	if contentType == nil {
		return "", fmt.Errorf("no content type header")
	}

	ct := contentType.Value()
	if !strings.HasPrefix(ct, "multipart/") {
		return "", fmt.Errorf("not a multipart body")
	}

	mediaType, params, err := mime.ParseMediaType(ct)
	if err != nil {
		return "", fmt.Errorf("failed to parse Content-Type: %w", err)
	}

	if !strings.HasPrefix(mediaType, "multipart/") {
		return "", fmt.Errorf("expected multipart Content-Type, got: %s", mediaType)
	}

	boundary, ok := params["boundary"]
	if !ok {
		return "", fmt.Errorf("multipart Content-Type missing boundary parameter")
	}

	reader := multipart.NewReader(strings.NewReader(string(body)), boundary)
	for {
		part, err := reader.NextPart()
		if err == io.EOF {
			break
		}
		if err != nil {
			return "", fmt.Errorf("failed to read multipart part: %w", err)
		}

		partContentType := part.Header.Get("Content-Type")
		// SIPREC metadata can be application/rs-metadata+xml or application/sdp+rs
		if strings.Contains(partContentType, "rs-metadata") ||
			strings.Contains(partContentType, "recording-session") {
			var buf strings.Builder
			if _, err := io.Copy(&buf, part); err != nil {
				return "", fmt.Errorf("failed to read metadata part: %w", err)
			}
			return buf.String(), nil
		}
	}

	return "", fmt.Errorf("no SIPREC metadata found in multipart body")
}

// =============================================================================
// SIP Identifier Generation
// =============================================================================

// generateSiprecTag generates a random tag for SIP headers.
func generateSiprecTag() string {
	b := make([]byte, 8)
	if _, err := rand.Read(b); err != nil {
		return "tag-fallback"
	}
	return hex.EncodeToString(b)
}

// generateSiprecCallID generates a unique Call-ID for SIP dialogs.
func generateSiprecCallID() string {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "callid-fallback"
	}
	return hex.EncodeToString(b)
}
