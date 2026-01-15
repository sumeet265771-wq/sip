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
	"strings"
	"testing"
	"time"

	"github.com/livekit/sipgo/sip"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// =============================================================================
// Test SDP Data
// =============================================================================

const testSiprecSDP = `v=0
o=root 151827427 151827427 IN IP4 172.18.170.75
s=Twilio Media Gateway
c=IN IP4 168.86.139.0
t=0 0
m=audio 17588 RTP/AVP 0 8 101
a=rtpmap:0 PCMU/8000
a=rtpmap:8 PCMA/8000
a=rtpmap:101 telephone-event/8000
a=fmtp:101 0-16
a=ptime:20
a=maxptime:20
a=sendonly
a=label:inbound
m=audio 11248 RTP/AVP 0 8 101
a=rtpmap:0 PCMU/8000
a=rtpmap:8 PCMA/8000
a=rtpmap:101 telephone-event/8000
a=fmtp:101 0-16
a=ptime:20
a=maxptime:20
a=sendonly
a=label:outbound`

const testSingleMediaSDP = `v=0
o=- 151827427 151827429 IN IP4 161.115.181.250
s=LiveKit
c=IN IP4 161.115.181.250
t=0 0
m=audio 51134 RTP/AVP 0 101
a=rtpmap:0 PCMU/8000
a=rtpmap:101 telephone-event/8000
a=fmtp:101 0-16
a=ptime:20
a=recvonly
a=label:inbound`

const testSingleMediaSDPOutbound = `v=0
o=- 151827427 151827429 IN IP4 161.115.181.250
s=LiveKit
c=IN IP4 161.115.181.250
t=0 0
m=audio 58181 RTP/AVP 0 101
a=rtpmap:0 PCMU/8000
a=rtpmap:101 telephone-event/8000
a=fmtp:101 0-16
a=ptime:20
a=recvonly
a=label:outbound`

const testMultipartBody = `------=_Part_15296_823292916.1768489452115
Content-Type: application/sdp

v=0
o=root 151827427 151827427 IN IP4 172.18.170.75
s=Twilio Media Gateway
c=IN IP4 168.86.139.0
t=0 0
m=audio 17588 RTP/AVP 0 8 101
a=rtpmap:0 PCMU/8000
a=sendonly
a=label:inbound
m=audio 11248 RTP/AVP 0 8 101
a=rtpmap:0 PCMU/8000
a=sendonly
a=label:outbound
------=_Part_15296_823292916.1768489452115
Content-Type: application/rs-metadata+xml
Content-Disposition: recording-session

<?xml version="1.0" encoding="UTF-8"?>
<recording xmlns='urn:ietf:params:xml:ns:recording:1'>
    <datamode>complete</datamode>
</recording>
------=_Part_15296_823292916.1768489452115--`

// =============================================================================
// SDP Parsing Tests
// =============================================================================

func TestParseSiprecSDP(t *testing.T) {
	session, mediaBlocks, err := ParseSiprecSDP(testSiprecSDP)
	require.NoError(t, err)

	// Should have session-level lines
	assert.NotEmpty(t, session)

	// Should have exactly 2 media blocks for SIPREC
	assert.Len(t, mediaBlocks, 2)

	// Check first media block
	assert.NotEmpty(t, mediaBlocks[0])
	label1 := ExtractSiprecMediaLabel(mediaBlocks[0])
	assert.Equal(t, "inbound", label1)

	// Check second media block
	assert.NotEmpty(t, mediaBlocks[1])
	label2 := ExtractSiprecMediaLabel(mediaBlocks[1])
	assert.Equal(t, "outbound", label2)
}

func TestParseSiprecSDP_SingleMedia(t *testing.T) {
	session, mediaBlocks, err := ParseSiprecSDP(testSingleMediaSDP)
	require.NoError(t, err)

	assert.NotEmpty(t, session)
	assert.Len(t, mediaBlocks, 1)

	label := ExtractSiprecMediaLabel(mediaBlocks[0])
	assert.Equal(t, "inbound", label)
}

func TestExtractSiprecMediaPort(t *testing.T) {
	_, mediaBlocks, err := ParseSiprecSDP(testSiprecSDP)
	require.NoError(t, err)
	require.Len(t, mediaBlocks, 2)

	port1, err := ExtractSiprecMediaPort(mediaBlocks[0])
	require.NoError(t, err)
	assert.Equal(t, 17588, port1)

	port2, err := ExtractSiprecMediaPort(mediaBlocks[1])
	require.NoError(t, err)
	assert.Equal(t, 11248, port2)
}

func TestBuildSiprecSDP(t *testing.T) {
	session, mediaBlocks, err := ParseSiprecSDP(testSiprecSDP)
	require.NoError(t, err)
	require.Len(t, mediaBlocks, 2)

	// Build SDP for first media block
	sdp1 := BuildSiprecSDP(session, mediaBlocks[0], false)
	assert.Contains(t, sdp1, "v=0")
	assert.Contains(t, sdp1, "m=audio 17588")
	assert.Contains(t, sdp1, "a=label:inbound")
	assert.NotContains(t, sdp1, "m=audio 11248") // Should only have one media

	// Build SDP for second media block with modified session ID
	sdp2 := BuildSiprecSDP(session, mediaBlocks[1], true)
	assert.Contains(t, sdp2, "v=0")
	assert.Contains(t, sdp2, "m=audio 11248")
	assert.Contains(t, sdp2, "a=label:outbound")
	// Session ID should be modified (151827428 instead of 151827427)
	assert.Contains(t, sdp2, "151827428")
}

func TestBuildCombinedSiprecSDP(t *testing.T) {
	session, mediaBlocks, err := ParseSiprecSDP(testSiprecSDP)
	require.NoError(t, err)
	require.Len(t, mediaBlocks, 2)

	combinedSDP := BuildCombinedSiprecSDP(session, mediaBlocks[0], mediaBlocks[1], "inbound", "outbound")

	// Should have both media blocks
	assert.Contains(t, combinedSDP, "a=label:inbound")
	assert.Contains(t, combinedSDP, "a=label:outbound")

	// Direction should be converted to recvonly
	assert.Contains(t, combinedSDP, "a=recvonly")
	assert.NotContains(t, combinedSDP, "a=sendonly")
}

func TestCombineSiprecSDPs(t *testing.T) {
	combinedSDP, err := CombineSiprecSDPs(testSingleMediaSDP, testSingleMediaSDPOutbound)
	require.NoError(t, err)

	// Should have both labels
	assert.Contains(t, combinedSDP, "a=label:inbound")
	assert.Contains(t, combinedSDP, "a=label:outbound")

	// Should have both ports
	assert.Contains(t, combinedSDP, "m=audio 51134")
	assert.Contains(t, combinedSDP, "m=audio 58181")
}

func TestUpdateSiprecSDPPort(t *testing.T) {
	_, mediaBlocks, err := ParseSiprecSDP(testSiprecSDP)
	require.NoError(t, err)
	require.Len(t, mediaBlocks, 2)

	// Update the port
	updatedMedia := UpdateSiprecSDPPort(mediaBlocks[0], 55555)

	port, err := ExtractSiprecMediaPort(updatedMedia)
	require.NoError(t, err)
	assert.Equal(t, 55555, port)
}

func TestUpdateSiprecSDPConnection(t *testing.T) {
	session, _, err := ParseSiprecSDP(testSiprecSDP)
	require.NoError(t, err)

	// Update the connection IP
	updatedSession := UpdateSiprecSDPConnection(session, "192.168.1.100")

	// Find the c= line
	found := false
	for _, line := range updatedSession {
		if line.Type == 'c' {
			assert.Contains(t, line.Value, "192.168.1.100")
			found = true
			break
		}
	}
	assert.True(t, found, "c= line should be present")
}

// =============================================================================
// Multipart Extraction Tests
// =============================================================================

func TestExtractSDPFromMultipart(t *testing.T) {
	contentType := "multipart/mixed;boundary=\"----=_Part_15296_823292916.1768489452115\""

	sdp, err := extractSDPFromMultipart(contentType, []byte(testMultipartBody))
	require.NoError(t, err)

	assert.Contains(t, sdp, "v=0")
	assert.Contains(t, sdp, "m=audio 17588")
	assert.Contains(t, sdp, "a=label:inbound")
}

// =============================================================================
// SIPREC Detection Tests
// =============================================================================

func TestIsSiprecInvite(t *testing.T) {
	tests := []struct {
		name     string
		headers  map[string]string
		expected bool
	}{
		{
			name:     "Regular INVITE",
			headers:  map[string]string{},
			expected: false,
		},
		{
			name:     "SIPREC INVITE with Require header",
			headers:  map[string]string{"Require": "siprec"},
			expected: true,
		},
		{
			name:     "SIPREC INVITE with Require header (uppercase)",
			headers:  map[string]string{"Require": "SIPREC"},
			expected: true,
		},
		{
			name:     "SIPREC INVITE with multiple Require values",
			headers:  map[string]string{"Require": "100rel, siprec"},
			expected: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := sip.NewRequest(sip.INVITE, sip.Uri{User: "test", Host: "example.com"})
			for k, v := range tt.headers {
				req.AppendHeader(sip.NewHeader(k, v))
			}

			result := IsSiprecInvite(req)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestIsSiprecInvite_NilRequest(t *testing.T) {
	assert.False(t, IsSiprecInvite(nil))
}

func TestIsSiprecInvite_NonInvite(t *testing.T) {
	req := sip.NewRequest(sip.BYE, sip.Uri{User: "test", Host: "example.com"})
	req.AppendHeader(sip.NewHeader("Require", "siprec"))

	assert.False(t, IsSiprecInvite(req))
}

// =============================================================================
// SIPREC Splitting Tests
// =============================================================================

func TestSplitSiprecInvite(t *testing.T) {
	// Create a mock SIPREC INVITE
	req := sip.NewRequest(sip.INVITE, sip.Uri{User: "1111", Host: "example.com"})
	req.AppendHeader(&sip.FromHeader{
		DisplayName: "Recorder",
		Address:     sip.Uri{User: "SRC", Host: "sip.provider.com"},
		Params:      sip.NewParams(),
	})
	req.AppendHeader(&sip.ToHeader{
		Address: sip.Uri{User: "1111", Host: "example.com"},
		Params:  sip.NewParams(),
	})
	ct := sip.ContentTypeHeader("application/sdp")
	req.AppendHeader(&ct)
	req.SetBody([]byte(testSiprecSDP))

	targetA := sip.Uri{User: "streamA", Host: "target.com"}
	targetB := sip.Uri{User: "streamB", Host: "target.com"}

	inviteA, inviteB, err := SplitSiprecInvite(req, targetA, targetB)
	require.NoError(t, err)

	// Check invite A
	assert.NotNil(t, inviteA)
	bodyA := string(inviteA.Body())
	assert.Contains(t, bodyA, "m=audio 17588")
	assert.Contains(t, bodyA, "a=label:inbound")
	assert.NotContains(t, bodyA, "m=audio 11248") // Should only have one media

	// Check invite B
	assert.NotNil(t, inviteB)
	bodyB := string(inviteB.Body())
	assert.Contains(t, bodyB, "m=audio 11248")
	assert.Contains(t, bodyB, "a=label:outbound")
	assert.NotContains(t, bodyB, "m=audio 17588") // Should only have one media

	// Call-IDs should be different
	callIDA := inviteA.CallID()
	callIDB := inviteB.CallID()
	assert.NotNil(t, callIDA)
	assert.NotNil(t, callIDB)
	assert.NotEqual(t, callIDA.Value(), callIDB.Value())
}

func TestSplitSiprecInvite_EmptyBody(t *testing.T) {
	req := sip.NewRequest(sip.INVITE, sip.Uri{User: "1111", Host: "example.com"})

	targetA := sip.Uri{User: "streamA", Host: "target.com"}
	targetB := sip.Uri{User: "streamB", Host: "target.com"}

	_, _, err := SplitSiprecInvite(req, targetA, targetB)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "no body")
}

func TestSplitSiprecInvite_SingleMedia(t *testing.T) {
	req := sip.NewRequest(sip.INVITE, sip.Uri{User: "1111", Host: "example.com"})
	req.AppendHeader(&sip.FromHeader{
		DisplayName: "Recorder",
		Address:     sip.Uri{User: "SRC", Host: "sip.provider.com"},
		Params:      sip.NewParams(),
	})
	ct := sip.ContentTypeHeader("application/sdp")
	req.AppendHeader(&ct)
	req.SetBody([]byte(testSingleMediaSDP))

	targetA := sip.Uri{User: "streamA", Host: "target.com"}
	targetB := sip.Uri{User: "streamB", Host: "target.com"}

	_, _, err := SplitSiprecInvite(req, targetA, targetB)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "expected 2 media sections")
}

// =============================================================================
// SIPREC Answer Combining Tests
// =============================================================================

func TestCombineSiprecAnswerSDPs(t *testing.T) {
	combinedSDP, err := CombineSiprecAnswerSDPs(testSiprecSDP, testSingleMediaSDP, testSingleMediaSDPOutbound)
	require.NoError(t, err)

	// Should preserve labels from original offer
	assert.Contains(t, combinedSDP, "a=label:inbound")
	assert.Contains(t, combinedSDP, "a=label:outbound")

	// Should have recvonly (correct response to sendonly)
	assert.Contains(t, combinedSDP, "a=recvonly")
}

func TestCreateSiprecResponse(t *testing.T) {
	// Create original invite
	req := sip.NewRequest(sip.INVITE, sip.Uri{User: "1111", Host: "example.com"})
	req.AppendHeader(&sip.FromHeader{
		DisplayName: "Recorder",
		Address:     sip.Uri{User: "SRC", Host: "sip.provider.com"},
		Params:      sip.NewParams(),
	})
	req.AppendHeader(&sip.ToHeader{
		Address: sip.Uri{User: "1111", Host: "example.com"},
		Params:  sip.NewParams(),
	})
	callID := sip.CallIDHeader("test-call-id-12345")
	req.AppendHeader(&callID)
	req.AppendHeader(&sip.CSeqHeader{SeqNo: 1, MethodName: sip.INVITE})

	combinedSDP := "v=0\r\no=- 1 1 IN IP4 127.0.0.1\r\ns=test\r\nt=0 0\r\nm=audio 5000 RTP/AVP 0\r\na=recvonly\r\n"

	resp := CreateSiprecResponse(req, combinedSDP)

	assert.Equal(t, sip.StatusCode(200), resp.StatusCode)
	assert.Equal(t, "OK", resp.Reason)

	// Check headers
	supported := resp.GetHeader("Supported")
	assert.NotNil(t, supported)
	assert.Contains(t, supported.Value(), "siprec")

	// Check body
	assert.Equal(t, combinedSDP, string(resp.Body()))
}

// =============================================================================
// Session Store Tests
// =============================================================================

func TestSiprecSessionStore(t *testing.T) {
	store := NewSiprecSessionStore(nil)

	// Create a test session
	session := &SiprecSession{
		ID:        "test-call-id",
		CreatedAt: time.Now(),
	}

	// Test Set and Get
	store.Set("test-call-id", session)

	retrieved, exists := store.Get("test-call-id")
	assert.True(t, exists)
	assert.Equal(t, session.ID, retrieved.ID)

	// Test Exists
	assert.True(t, store.Exists("test-call-id"))
	assert.False(t, store.Exists("non-existent"))

	// Test Delete
	store.Delete("test-call-id")
	assert.False(t, store.Exists("test-call-id"))
}

func TestSiprecSessionStore_GetByLegCallID(t *testing.T) {
	store := NewSiprecSessionStore(nil)

	session := &SiprecSession{
		ID:        "test-call-id",
		CreatedAt: time.Now(),
		LegA:      &SiprecLeg{CallID: "leg-a-call-id"},
		LegB:      &SiprecLeg{CallID: "leg-b-call-id"},
	}

	store.Set("test-call-id", session)

	// Find by leg A
	found, leg := store.GetByLegCallID("leg-a-call-id")
	assert.NotNil(t, found)
	assert.Equal(t, "A", leg)

	// Find by leg B
	found, leg = store.GetByLegCallID("leg-b-call-id")
	assert.NotNil(t, found)
	assert.Equal(t, "B", leg)

	// Not found
	found, leg = store.GetByLegCallID("non-existent")
	assert.Nil(t, found)
	assert.Empty(t, leg)
}

func TestSiprecSessionStore_Count(t *testing.T) {
	store := NewSiprecSessionStore(nil)

	assert.Equal(t, 0, store.Count())

	store.Set("call-1", &SiprecSession{ID: "call-1"})
	assert.Equal(t, 1, store.Count())

	store.Set("call-2", &SiprecSession{ID: "call-2"})
	assert.Equal(t, 2, store.Count())

	store.Delete("call-1")
	assert.Equal(t, 1, store.Count())

	store.Clear()
	assert.Equal(t, 0, store.Count())
}

// =============================================================================
// Helper Function Tests
// =============================================================================

func TestGenerateSiprecTag(t *testing.T) {
	tag1 := generateSiprecTag()
	tag2 := generateSiprecTag()

	// Tags should be non-empty
	assert.NotEmpty(t, tag1)
	assert.NotEmpty(t, tag2)

	// Tags should be different
	assert.NotEqual(t, tag1, tag2)

	// Tags should be hex strings
	assert.True(t, isHexString(tag1))
	assert.True(t, isHexString(tag2))
}

func TestGenerateSiprecCallID(t *testing.T) {
	callID1 := generateSiprecCallID()
	callID2 := generateSiprecCallID()

	// Call-IDs should be non-empty
	assert.NotEmpty(t, callID1)
	assert.NotEmpty(t, callID2)

	// Call-IDs should be different
	assert.NotEqual(t, callID1, callID2)
}

func isHexString(s string) bool {
	for _, c := range s {
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')) {
			return false
		}
	}
	return true
}

// =============================================================================
// Edge Cases and Error Handling Tests
// =============================================================================

func TestParseSiprecSDP_WindowsLineEndings(t *testing.T) {
	// Test with Windows-style line endings
	sdpWithCRLF := strings.ReplaceAll(testSiprecSDP, "\n", "\r\n")

	session, mediaBlocks, err := ParseSiprecSDP(sdpWithCRLF)
	require.NoError(t, err)

	assert.NotEmpty(t, session)
	assert.Len(t, mediaBlocks, 2)
}

func TestParseSiprecSDP_EmptyLines(t *testing.T) {
	sdpWithEmptyLines := "\n\n" + testSiprecSDP + "\n\n"

	session, mediaBlocks, err := ParseSiprecSDP(sdpWithEmptyLines)
	require.NoError(t, err)

	assert.NotEmpty(t, session)
	assert.Len(t, mediaBlocks, 2)
}

func TestParseSiprecSDP_GroupDUP(t *testing.T) {
	// Test that a=group:DUP is filtered out
	sdpWithGroupDUP := "v=0\r\no=- 1 1 IN IP4 127.0.0.1\r\na=group:DUP 1 2\r\ns=test\r\nt=0 0\r\nm=audio 5000 RTP/AVP 0\r\n"

	session, _, err := ParseSiprecSDP(sdpWithGroupDUP)
	require.NoError(t, err)

	// Should not contain group:DUP in session lines
	for _, line := range session {
		assert.NotContains(t, line.Value, "group:DUP")
	}
}

func TestExtractSiprecMediaLabel_NoLabel(t *testing.T) {
	media := []SDPLine{
		{Type: 'm', Value: "m=audio 5000 RTP/AVP 0"},
		{Type: 'a', Value: "a=rtpmap:0 PCMU/8000"},
	}

	label := ExtractSiprecMediaLabel(media)
	assert.Empty(t, label)
}
