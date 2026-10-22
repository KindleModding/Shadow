// Package fwdb loads the harvested firmware database and resolves a Kindle
// build key to the offsets and leak parameters the exploit needs.
package fwdb

import (
	"bytes"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
)

// Offsets are the decimal offsets recorded for a firmware build.
type Offsets struct {
	System              int64  `json:"system"`
	SystemARM           int64  `json:"system_arm"`
	PopGadget           int64  `json:"pop_gadget"`
	PopGadgetMask       int64  `json:"pop_gadget_mask"`
	LdrBlxGadget        int64  `json:"ldr_blx_gadget"`
	GotBase             int64  `json:"got_base"`
	StackDelta          *int64 `json:"stack_delta"`
	StackDeltaSupported bool   `json:"stack_delta_supported"`
	StackDeltaVerified  bool   `json:"stack_delta_verified"`
}

// Leak describes the Bug-2 leak layout for a firmware build.
type Leak struct {
	Slot4RawOff     int    `json:"slot4_raw_off"`
	Slot16RawOff    int    `json:"slot16_raw_off"`
	AnchorLow12     *int64 `json:"anchor_low12"`
	RecipeSupported *bool  `json:"recipe_supported"`
	RecipeDetail    string `json:"recipe_detail"`
}

// USB is the device identity a record was harvested for.
type USB struct {
	VID  string   `json:"vid"`
	PIDs []string `json:"pids"`
}

// Record is one firmware record from firmware/db.json.
type Record struct {
	SchemaVersion int      `json:"schema_version"`
	BuildKey      string   `json:"build_key"`
	PrettyVersion string   `json:"pretty_version"`
	Version       string   `json:"version"`
	Models        []string `json:"models"`
	Offsets       Offsets  `json:"offsets"`
	Leak          Leak     `json:"leak"`
	USB           USB      `json:"usb"`
	Limitations   []string `json:"limitations"`
}

// DB is the merged firmware database keyed by build key.
type DB map[string]Record

// Load parses the merged db.json embedded in the binary.
func Load(data []byte) (DB, error) {
	var db DB
	if err := json.NewDecoder(bytes.NewReader(data)).Decode(&db); err != nil {
		return nil, fmt.Errorf("parse firmware db: %w", err)
	}
	if len(db) == 0 {
		return nil, fmt.Errorf("firmware db is empty")
	}
	return db, nil
}

func (db DB) Get(buildKey string) (Record, bool) {
	rec, ok := db[buildKey]
	if ok && rec.BuildKey == "" {
		rec.BuildKey = buildKey
	}
	return rec, ok
}

func (db DB) All() []Record {
	out := make([]Record, 0, len(db))
	for key, rec := range db {
		if rec.BuildKey == "" {
			rec.BuildKey = key
		}
		out = append(out, rec)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].BuildKey < out[j].BuildKey })
	return out
}

func (db DB) Usable() []Record {
	out := make([]Record, 0, len(db))
	for _, rec := range db.All() {
		if rec.ExploitError() == nil {
			out = append(out, rec)
		}
	}
	return out
}

// ExploitError returns nil when the record carries a measured stack delta and
// a leak recipe proven by the harness; otherwise it explains what is missing.
func (r Record) ExploitError() error {
	var problems []string
	switch {
	case r.Offsets.StackDelta == nil:
		problems = append(problems, "no measured stack delta")
	case !r.Offsets.StackDeltaSupported:
		problems = append(problems, "stack delta not supported for this responder")
	case !r.Offsets.StackDeltaVerified:
		problems = append(problems, "stack delta measurement unverified")
	}
	switch {
	case r.Leak.AnchorLow12 == nil:
		problems = append(problems, "no stack anchor for the leak check")
	case r.Leak.RecipeSupported == nil || !*r.Leak.RecipeSupported:
		detail := r.Leak.RecipeDetail
		if detail == "" && len(r.Limitations) > 0 {
			detail = r.Limitations[0]
		}
		if detail != "" {
			problems = append(problems, "leak recipe unsupported: "+detail)
		} else {
			problems = append(problems, "leak recipe unsupported")
		}
	}
	if r.Offsets.System == 0 || r.Offsets.PopGadget == 0 || r.Offsets.LdrBlxGadget == 0 || r.Offsets.GotBase == 0 {
		problems = append(problems, "chain offsets incomplete")
	}
	if len(problems) == 0 {
		return nil
	}
	return fmt.Errorf("%s", strings.Join(problems, "; "))
}

func (r Record) Pretty() string {
	v := r.PrettyVersion
	if v == "" {
		v = r.Version
	}
	if v == "" {
		v = "unknown firmware"
	}
	return strings.TrimSpace(strings.ReplaceAll(v, "(~~otaVersion~~)", ""))
}

// Label is the one-line description used by the build prompt.
func (r Record) Label() string {
	models := strings.Join(r.Models, ", ")
	if models == "" {
		models = "unknown model"
	}
	return fmt.Sprintf("%s  %s  (%s)", r.BuildKey, r.Pretty(), models)
}
