package credential

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
)

func decodeStrictJSON(data []byte, dst any) error {
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
