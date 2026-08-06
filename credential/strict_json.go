package credential

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
)

func decodeStrictJSON(data []byte, dst any) error {
	if err := rejectDuplicateJSONKeys(data); err != nil {
		return err
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(dst); err != nil {
		return err
	}
	var trailing any
	if err := dec.Decode(&trailing); err != io.EOF {
		if err == nil {
			return fmt.Errorf("trailing JSON value")
		}
		return fmt.Errorf("trailing JSON: %w", err)
	}
	return nil
}

// rejectDuplicateJSONKeys closes a gap in encoding/json's otherwise strict
// object handling: by default a later duplicate member silently replaces an
// earlier one. Protocol artifacts must have one interpretation, including for
// parsers outside Go, so duplicates are rejected recursively before typed
// decoding and canonical re-marshalling.
func rejectDuplicateJSONKeys(data []byte) error {
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.UseNumber()
	if err := consumeUniqueJSONValue(dec, "$", 0); err != nil {
		return err
	}
	return nil
}

func consumeUniqueJSONValue(dec *json.Decoder, path string, depth int) error {
	if dec == nil || depth > 128 {
		return fmt.Errorf("invalid or excessively nested JSON at %s", path)
	}
	tok, err := dec.Token()
	if err != nil {
		return err
	}
	delim, ok := tok.(json.Delim)
	if !ok {
		return nil
	}
	switch delim {
	case '{':
		seen := make(map[string]struct{})
		for dec.More() {
			member, err := dec.Token()
			if err != nil {
				return err
			}
			key, ok := member.(string)
			if !ok {
				return fmt.Errorf("non-string JSON object member at %s", path)
			}
			if _, duplicate := seen[key]; duplicate {
				return fmt.Errorf("duplicate JSON object member %q at %s", key, path)
			}
			seen[key] = struct{}{}
			if err := consumeUniqueJSONValue(dec, path+"."+key, depth+1); err != nil {
				return err
			}
		}
		end, err := dec.Token()
		if err != nil {
			return err
		}
		if end != json.Delim('}') {
			return fmt.Errorf("malformed JSON object at %s", path)
		}
	case '[':
		index := 0
		for dec.More() {
			if err := consumeUniqueJSONValue(dec, fmt.Sprintf("%s[%d]", path, index), depth+1); err != nil {
				return err
			}
			index++
		}
		end, err := dec.Token()
		if err != nil {
			return err
		}
		if end != json.Delim(']') {
			return fmt.Errorf("malformed JSON array at %s", path)
		}
	default:
		return fmt.Errorf("unexpected JSON delimiter %q at %s", delim, path)
	}
	return nil
}

func decodeStrictVersionedJSON(data []byte, dst any, kind string, want int) error {
	var envelope struct {
		Version int `json:"version"`
	}
	if err := json.Unmarshal(data, &envelope); err != nil {
		return err
	}
	if envelope.Version != want {
		return noMigrationSchemaError(kind, envelope.Version, want)
	}
	return decodeStrictJSON(data, dst)
}

func noMigrationSchemaError(kind string, got, want int) error {
	return fmt.Errorf("unsupported %s schema %d; this build requires schema %d and no migration is supported; rerun setup and reissue the credential", kind, got, want)
}
