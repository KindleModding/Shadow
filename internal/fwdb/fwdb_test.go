package fwdb_test

import (
	"testing"

	"shadow"
	"shadow/internal/fwdb"
)

func TestEmbeddedDB(t *testing.T) {
	db, err := fwdb.Load(shadow.FirmwareDB)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if len(db) < 6 {
		t.Fatalf("loaded %d records, want >= 6", len(db))
	}

	rec, ok := db.Get("4832540042")
	if !ok {
		t.Fatal("kt6 5.19.6 record missing")
	}
	if err := rec.ExploitError(); err != nil {
		t.Fatalf("kt6 record not exploitable: %v", err)
	}
	if rec.Offsets.System != 129537 || rec.Offsets.PopGadget != 19377 ||
		rec.Offsets.LdrBlxGadget != 109827 || rec.Offsets.GotBase != 176128 ||
		rec.Offsets.StackDelta == nil || *rec.Offsets.StackDelta != 3288 {
		t.Fatalf("kt6 offsets drifted: %+v", rec.Offsets)
	}
	if rec.Leak.AnchorLow12 == nil || *rec.Leak.AnchorLow12 != 0x8c0 {
		t.Fatalf("kt6 anchor drifted: %+v", rec.Leak)
	}

	partial := rec
	partial.Offsets.StackDelta = nil
	if err := partial.ExploitError(); err == nil {
		t.Fatal("record without a stack delta must not be exploitable")
	}

	if got := len(db.Usable()); got != len(db) {
		t.Fatalf("usable records = %d, want all %d", got, len(db))
	}
	all := db.All()
	for i := 1; i < len(all); i++ {
		if all[i-1].BuildKey >= all[i].BuildKey {
			t.Fatalf("All() not sorted: %s then %s", all[i-1].BuildKey, all[i].BuildKey)
		}
	}
}

func TestLabelStripsPlaceholder(t *testing.T) {
	rec := fwdb.Record{
		BuildKey:      "4832540042",
		PrettyVersion: "Kindle 5.19.6 (~~otaVersion~~)",
		Models:        []string{"Kindle Basic 5 (2024)"},
	}
	want := "4832540042  Kindle 5.19.6  (Kindle Basic 5 (2024))"
	if got := rec.Label(); got != want {
		t.Fatalf("Label = %q, want %q", got, want)
	}
}
