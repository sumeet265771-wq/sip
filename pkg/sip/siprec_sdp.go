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
	"fmt"
	"strconv"
	"strings"
)

// SDPLine represents a parsed SDP line with its type and value.
type SDPLine struct {
	Type  byte   // 'v', 'o', 's', 'c', 't', 'm', 'a', etc.
	Value string // The full line including type=
}

// ParseSiprecSDP parses the SDP and returns session-level lines and media blocks.
// This is specifically designed for SIPREC SDPs which may have multiple media sections.
func ParseSiprecSDP(rawSDP string) (session []SDPLine, mediaBlocks [][]SDPLine, err error) {
	// Normalize line endings
	rawSDP = strings.ReplaceAll(rawSDP, "\r\n", "\n")
	rawSDP = strings.ReplaceAll(rawSDP, "\r", "\n")

	lines := strings.Split(rawSDP, "\n")
	var currentMedia []SDPLine

	for _, l := range lines {
		line := strings.TrimSpace(l)
		if line == "" {
			continue
		}

		// Parse line type
		var lineType byte = '?'
		if len(line) >= 2 && line[1] == '=' {
			lineType = line[0]
		}

		sdpLine := SDPLine{Type: lineType, Value: line}

		if strings.HasPrefix(line, "m=") {
			// Start of a new media section
			if currentMedia != nil {
				mediaBlocks = append(mediaBlocks, currentMedia)
			}
			currentMedia = []SDPLine{sdpLine}
			continue
		}

		if currentMedia == nil {
			// Session-level line
			// Skip a=group:DUP (SIPREC-specific grouping that we don't need in split SDPs)
			if strings.HasPrefix(line, "a=group:DUP") {
				continue
			}
			session = append(session, sdpLine)
		} else {
			// Media-level line
			currentMedia = append(currentMedia, sdpLine)
		}
	}

	// Don't forget the last media block
	if currentMedia != nil {
		mediaBlocks = append(mediaBlocks, currentMedia)
	}

	return session, mediaBlocks, nil
}

// BuildSiprecSDP constructs an SDP string from session-level lines and a media block.
// If modifySessionID is true, it modifies the o= line to have a unique session-id.
func BuildSiprecSDP(session []SDPLine, media []SDPLine, modifySessionID bool) string {
	var b strings.Builder

	for _, line := range session {
		if modifySessionID && line.Type == 'o' {
			// Modify the session-id in the o= line to make it unique
			modifiedLine := modifySiprecOriginLine(line.Value)
			b.WriteString(modifiedLine + "\r\n")
		} else {
			b.WriteString(line.Value + "\r\n")
		}
	}

	for _, line := range media {
		b.WriteString(line.Value + "\r\n")
	}

	return b.String()
}

// modifySiprecOriginLine modifies the session-id in an SDP origin line to make it unique.
// Format: o=<username> <sess-id> <sess-version> <nettype> <addrtype> <unicast-address>
func modifySiprecOriginLine(originLine string) string {
	if !strings.HasPrefix(originLine, "o=") {
		return originLine
	}

	parts := strings.Fields(originLine[2:]) // Remove "o=" prefix
	if len(parts) < 6 {
		// Invalid o= line, return as-is
		return originLine
	}

	// Modify the session-id (parts[1]) by incrementing it
	sessID, err := strconv.ParseInt(parts[1], 10, 64)
	if err != nil {
		// If not a number, append a suffix
		parts[1] = parts[1] + "_2"
	} else {
		// Increment the session-id
		parts[1] = strconv.FormatInt(sessID+1, 10)
	}

	return "o=" + strings.Join(parts, " ")
}

// ExtractSiprecMediaLabel extracts the label from media block attributes (a=label:X).
// SIPREC uses labels like "inbound" and "outbound" to identify streams.
func ExtractSiprecMediaLabel(media []SDPLine) string {
	for _, line := range media {
		if line.Type == 'a' && strings.HasPrefix(line.Value, "a=label:") {
			return strings.TrimPrefix(line.Value, "a=label:")
		}
	}
	return ""
}

// ExtractSiprecMediaPort extracts the port from the m= line of a media block.
func ExtractSiprecMediaPort(media []SDPLine) (int, error) {
	for _, line := range media {
		if line.Type == 'm' {
			// m=audio <port> RTP/AVP ...
			parts := strings.Fields(line.Value)
			if len(parts) < 2 {
				return 0, fmt.Errorf("invalid m= line: %s", line.Value)
			}
			port, err := strconv.Atoi(parts[1])
			if err != nil {
				return 0, fmt.Errorf("invalid port in m= line: %s", line.Value)
			}
			return port, nil
		}
	}
	return 0, fmt.Errorf("no m= line found in media block")
}

// BuildCombinedSiprecSDP creates a combined SIPREC SDP from session info and two media blocks.
// It also fixes direction attributes for SIPREC compliance.
func BuildCombinedSiprecSDP(session []SDPLine, mediaA, mediaB []SDPLine, labelA, labelB string) string {
	var b strings.Builder

	// Write session-level lines
	for _, line := range session {
		b.WriteString(line.Value + "\r\n")
	}

	// Write first media block with direction fix and label
	writeSiprecMediaBlockWithRecvOnly(&b, mediaA, labelA)

	// Write second media block with direction fix and label
	writeSiprecMediaBlockWithRecvOnly(&b, mediaB, labelB)

	return b.String()
}

// writeSiprecMediaBlockWithRecvOnly writes media lines, converting sendonly to recvonly.
// In SIPREC, the SRS (Session Recording Server) must answer with a=recvonly
// when the SRC (Session Recording Client) offers a=sendonly.
func writeSiprecMediaBlockWithRecvOnly(b *strings.Builder, media []SDPLine, label string) {
	hasLabel := false
	hasDirection := false

	// First pass: check what attributes exist
	for _, line := range media {
		if strings.HasPrefix(line.Value, "a=label:") {
			hasLabel = true
		}
		if line.Value == "a=sendrecv" || line.Value == "a=recvonly" ||
			line.Value == "a=sendonly" || line.Value == "a=inactive" {
			hasDirection = true
		}
	}

	// Second pass: write lines with corrections
	for _, line := range media {
		// Convert direction attributes for SIPREC compliance
		if line.Type == 'a' {
			// Replace sendrecv with recvonly (SRS only receives, doesn't send)
			if line.Value == "a=sendrecv" {
				b.WriteString("a=recvonly\r\n")
				continue
			}
			// If already recvonly, keep it
			if line.Value == "a=recvonly" {
				b.WriteString(line.Value + "\r\n")
				continue
			}
			// Convert sendonly to recvonly (proper answer to sendonly offer)
			if line.Value == "a=sendonly" {
				b.WriteString("a=recvonly\r\n")
				continue
			}
		}
		b.WriteString(line.Value + "\r\n")
	}

	// Add label if not present and we have one to add
	if !hasLabel && label != "" {
		b.WriteString(fmt.Sprintf("a=label:%s\r\n", label))
	}

	// Add recvonly if no direction attribute was present
	if !hasDirection {
		b.WriteString("a=recvonly\r\n")
	}
}

// CombineSiprecSDPs combines two SDP strings into a single SIPREC SDP answer.
// This is useful when you have SDPs from two split calls that need to be combined.
func CombineSiprecSDPs(sdpA, sdpB string) (string, error) {
	// Parse both SDPs
	sessionA, mediaBlocksA, err := ParseSiprecSDP(sdpA)
	if err != nil {
		return "", fmt.Errorf("failed to parse SDP A: %w", err)
	}

	_, mediaBlocksB, err := ParseSiprecSDP(sdpB)
	if err != nil {
		return "", fmt.Errorf("failed to parse SDP B: %w", err)
	}

	// Validate we have exactly 1 media block from each
	if len(mediaBlocksA) != 1 {
		return "", fmt.Errorf("expected 1 media section in SDP A, got %d", len(mediaBlocksA))
	}
	if len(mediaBlocksB) != 1 {
		return "", fmt.Errorf("expected 1 media section in SDP B, got %d", len(mediaBlocksB))
	}

	// Extract labels
	labelA := ExtractSiprecMediaLabel(mediaBlocksA[0])
	labelB := ExtractSiprecMediaLabel(mediaBlocksB[0])

	// Build combined SDP
	return BuildCombinedSiprecSDP(sessionA, mediaBlocksA[0], mediaBlocksB[0], labelA, labelB), nil
}

// UpdateSiprecSDPPort updates the port in a media block's m= line.
func UpdateSiprecSDPPort(media []SDPLine, newPort int) []SDPLine {
	result := make([]SDPLine, len(media))
	copy(result, media)

	for i, line := range result {
		if line.Type == 'm' {
			// m=audio <port> RTP/AVP ...
			parts := strings.Fields(line.Value)
			if len(parts) >= 2 {
				parts[1] = strconv.Itoa(newPort)
				result[i] = SDPLine{
					Type:  'm',
					Value: strings.Join(parts, " "),
				}
			}
			break
		}
	}

	return result
}

// UpdateSiprecSDPConnection updates the connection line (c=) IP address.
func UpdateSiprecSDPConnection(lines []SDPLine, newIP string) []SDPLine {
	result := make([]SDPLine, len(lines))
	copy(result, lines)

	for i, line := range result {
		if line.Type == 'c' {
			// c=IN IP4 <address>
			parts := strings.Fields(line.Value)
			if len(parts) >= 3 {
				parts[2] = newIP
				result[i] = SDPLine{
					Type:  'c',
					Value: strings.Join(parts, " "),
				}
			}
			break
		}
	}

	return result
}
