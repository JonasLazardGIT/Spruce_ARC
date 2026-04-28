package main

import (
	"fmt"
	"log"
	"strings"
	"time"

	"vSIS-Signature/PIOP"
)

const benchmarkIntGenISISVersion = 1

type benchmarkIntGenISISProfile struct {
	Label     string                      `json:"label"`
	Profile   string                      `json:"profile"`
	Inventory PIOP.IntGenISISRowInventory `json:"inventory"`
}

type benchmarkIntGenISISReport struct {
	Version   int                          `json:"version"`
	Generated string                       `json:"generated_at"`
	Profiles  []benchmarkIntGenISISProfile `json:"profiles"`
	Notes     []string                     `json:"notes"`
}

func benchmarkIntGenISIS(profilesCSV string, packingFactor int, jsonOut string) error {
	if packingFactor <= 0 {
		return fmt.Errorf("invalid s-sw=%d", packingFactor)
	}
	parts := strings.Split(profilesCSV, ",")
	report := benchmarkIntGenISISReport{
		Version:   benchmarkIntGenISISVersion,
		Generated: time.Now().UTC().Format(time.RFC3339),
		Notes: []string{
			"intgenisis_mlwe_presign and intgenisis_mlwe_showing are row-inventory labels until the SmallWood optimizer is rerun",
			"proof sizes, proving time, and verification time must be regenerated after the relation rewrite",
		},
	}
	for _, part := range parts {
		name := strings.TrimSpace(part)
		if name == "" {
			continue
		}
		inv, err := PIOP.BuildIntGenISISRowInventory(name, packingFactor)
		if err != nil {
			return err
		}
		report.Profiles = append(report.Profiles,
			benchmarkIntGenISISProfile{Label: "intgenisis_mlwe_presign", Profile: inv.Profile, Inventory: inv},
			benchmarkIntGenISISProfile{Label: "intgenisis_mlwe_showing", Profile: inv.Profile, Inventory: inv},
		)
		log.Printf("[issuance-cli] intgenisis profile=%s presign_rows=%d showing_non_prf_rows=%d ring_polys=%d/%d",
			inv.Profile, inv.PreSignRows, inv.ShowingNonPRFRows, inv.PreSignRingPolys, inv.ShowingRingPolys)
	}
	if len(report.Profiles) == 0 {
		return fmt.Errorf("no IntGenISIS profiles requested")
	}
	if jsonOut != "" {
		if err := writeJSONFile(jsonOut, report, 0o644); err != nil {
			return fmt.Errorf("write benchmark json: %w", err)
		}
		log.Printf("[issuance-cli] benchmark-intgenisis wrote %s", jsonOut)
	}
	return nil
}
