// Package mevwatch implements mempool risk detection.
package mevwatch

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"strconv"
	"strings"
)

// LineError wraps a parse/validation failure with the input line number.
type LineError struct {
	Line int
	Err  error
}

func (e *LineError) Error() string {
	return fmt.Sprintf("line %d: %v", e.Line, e.Err)
}

func (e *LineError) Unwrap() error { return e.Err }

// BlockInput is one parsed, syntactically valid line of a replay input file.
type BlockInput struct {
	Line        int
	ChainID     string
	BlockHash   string
	BlockNumber int64
	Swaps       []Swap
}

// ParseReplayInput reads line-delimited JSON (one block per line). Blank
// lines are ignored. Every failure is reported as a *LineError with the
// offending line number.
func ParseReplayInput(r io.Reader) ([]BlockInput, error) {
	scanner := bufio.NewScanner(r)
	scanner.Buffer(make([]byte, 0, 64*1024), 16*1024*1024)

	var blocks []BlockInput
	lineNo := 0
	for scanner.Scan() {
		lineNo++
		line := scanner.Text()
		if strings.TrimSpace(line) == "" {
			continue
		}
		block, err := parseBlockLine(line)
		if err != nil {
			return nil, &LineError{Line: lineNo, Err: err}
		}
		block.Line = lineNo
		blocks = append(blocks, block)
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	return blocks, nil
}

func parseBlockLine(line string) (BlockInput, error) {
	var raw json.RawMessage
	if err := json.Unmarshal([]byte(line), &raw); err != nil {
		return BlockInput{}, fmt.Errorf("invalid JSON: %w", err)
	}
	if bytes.TrimSpace(raw)[0] != '{' {
		return BlockInput{}, errors.New("expected a JSON object")
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(raw, &fields); err != nil {
		return BlockInput{}, fmt.Errorf("invalid JSON: %w", err)
	}
	if fields == nil {
		return BlockInput{}, errors.New("expected a JSON object")
	}

	var block BlockInput
	var err error
	if block.ChainID, err = nonEmptyString(fields, "chainId"); err != nil {
		return BlockInput{}, err
	}
	if block.BlockHash, err = nonEmptyString(fields, "blockHash"); err != nil {
		return BlockInput{}, err
	}
	if block.BlockNumber, err = nonNegativeInt64(fields, "blockNumber"); err != nil {
		return BlockInput{}, err
	}

	if raw, ok := fields["swaps"]; ok {
		if bytes.TrimSpace(raw)[0] != '[' {
			return BlockInput{}, errors.New("\"swaps\" must be an array")
		}
		var raws []json.RawMessage
		if err := json.Unmarshal(raw, &raws); err != nil {
			return BlockInput{}, fmt.Errorf("\"swaps\" must be an array: %w", err)
		}
		swaps := make([]Swap, 0, len(raws))
		for i, rawSwap := range raws {
			swap, err := parseSwap(rawSwap)
			if err != nil {
				return BlockInput{}, fmt.Errorf("swaps[%d]: %w", i, err)
			}
			swaps = append(swaps, swap)
		}
		block.Swaps = swaps
	}

	return block, nil
}

func parseSwap(raw json.RawMessage) (Swap, error) {
	if bytes.TrimSpace(raw)[0] != '{' {
		return Swap{}, errors.New("expected a JSON object")
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(raw, &fields); err != nil {
		return Swap{}, fmt.Errorf("invalid JSON: %w", err)
	}
	if fields == nil {
		return Swap{}, errors.New("expected a JSON object")
	}

	var swap Swap
	var err error
	if swap.TxHash, err = nonEmptyString(fields, "TxHash"); err != nil {
		return Swap{}, err
	}
	if swap.Pool, err = nonEmptyString(fields, "Pool"); err != nil {
		return Swap{}, err
	}
	if swap.Trader, err = nonEmptyString(fields, "Trader"); err != nil {
		return Swap{}, err
	}
	if swap.In, err = nonNegativeInt64Field(fields, "In"); err != nil {
		return Swap{}, err
	}
	if swap.Out, err = nonNegativeInt64Field(fields, "Out"); err != nil {
		return Swap{}, err
	}
	if swap.GasPrice, err = nonNegativeInt64Field(fields, "GasPrice"); err != nil {
		return Swap{}, err
	}
	if swap.Index, err = nonNegativeIntField(fields, "Index"); err != nil {
		return Swap{}, err
	}
	return swap, nil
}

// nonEmptyString reads a required non-empty JSON string field.
func nonEmptyString(fields map[string]json.RawMessage, key string) (string, error) {
	raw, ok := fields[key]
	if !ok {
		return "", fmt.Errorf("missing %q", key)
	}
	var value string
	if err := json.Unmarshal(raw, &value); err != nil {
		return "", fmt.Errorf("%q must be a string: %w", key, err)
	}
	if value == "" {
		return "", fmt.Errorf("%q must not be empty", key)
	}
	return value, nil
}

// nonNegativeInt64 reads a required non-negative integer that fits int64.
func nonNegativeInt64(fields map[string]json.RawMessage, key string) (int64, error) {
	raw, ok := fields[key]
	if !ok {
		return 0, fmt.Errorf("missing %q", key)
	}
	return parseNonNegativeInt64(raw, key)
}

// nonNegativeInt64Field reads an optional non-negative int64 field; a
// missing field is treated as zero.
func nonNegativeInt64Field(fields map[string]json.RawMessage, key string) (int64, error) {
	raw, ok := fields[key]
	if !ok {
		return 0, nil
	}
	return parseNonNegativeInt64(raw, key)
}

func parseNonNegativeInt64(raw json.RawMessage, key string) (int64, error) {
	var number json.Number
	if err := json.Unmarshal(raw, &number); err != nil {
		return 0, fmt.Errorf("%q must be a non-negative integer: %w", key, err)
	}
	value, err := strconv.ParseInt(number.String(), 10, 64)
	if err != nil {
		return 0, fmt.Errorf("%q must be a non-negative integer in int64 range", key)
	}
	if value < 0 {
		return 0, fmt.Errorf("%q must not be negative", key)
	}
	return value, nil
}

// nonNegativeIntField reads an optional non-negative int field; a missing
// field is treated as zero.
func nonNegativeIntField(fields map[string]json.RawMessage, key string) (int, error) {
	raw, ok := fields[key]
	if !ok {
		return 0, nil
	}
	value, err := parseNonNegativeInt64(raw, key)
	if err != nil {
		return 0, err
	}
	if value > math.MaxInt {
		return 0, fmt.Errorf("%q is out of int range", key)
	}
	return int(value), nil
}

// ValidateBlock deduplicates identical swap records within one block and
// rejects conflicting records: the same TxHash with different fields, or
// two different transactions occupying the same Index. The returned swaps
// are the deduplicated records in first-occurrence order.
func ValidateBlock(block BlockInput) ([]Swap, error) {
	seen := make(map[string]Swap)
	indexOwner := make(map[int]string)
	deduped := make([]Swap, 0, len(block.Swaps))

	for _, swap := range block.Swaps {
		if previous, ok := seen[swap.TxHash]; ok {
			if previous != swap {
				return nil, fmt.Errorf("conflicting records for TxHash %q", swap.TxHash)
			}
			// Exact duplicate: keep a single copy.
			continue
		}
		seen[swap.TxHash] = swap
		if owner, ok := indexOwner[swap.Index]; ok && owner != swap.TxHash {
			return nil, fmt.Errorf("Index %d is occupied by multiple transactions (%q and %q)",
				swap.Index, owner, swap.TxHash)
		}
		indexOwner[swap.Index] = swap.TxHash
		deduped = append(deduped, swap)
	}

	return deduped, nil
}
