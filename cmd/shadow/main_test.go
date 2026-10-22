package main

import (
	"bytes"
	"fmt"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"

	"shadow"
	"shadow/internal/fwdb"
)

func testDB(t *testing.T) fwdb.DB {
	t.Helper()
	db, err := fwdb.Load(shadow.FirmwareDB)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	return db
}

func TestPromptBuildAcceptsKnownKey(t *testing.T) {
	var out bytes.Buffer
	rec, ok := promptBuild(strings.NewReader(" 4832540042 \n"), &out, testDB(t))
	if !ok {
		t.Fatalf("known key rejected:\n%s", out.String())
	}
	if rec.BuildKey != "4832540042" {
		t.Fatalf("got record %s", rec.BuildKey)
	}
}

func TestPromptBuildRetriesInvalidThenUnknownThenKnown(t *testing.T) {
	in := strings.NewReader("nope\n12345\n9999999999\n4832540042\n")
	var out bytes.Buffer
	rec, ok := promptBuild(in, &out, testDB(t))
	if !ok {
		t.Fatalf("prompt gave up:\n%s", out.String())
	}
	if rec.BuildKey != "4832540042" {
		t.Fatalf("got record %s", rec.BuildKey)
	}
	text := out.String()
	if !strings.Contains(text, "does not look like a 10-digit build number") {
		t.Errorf("missing invalid-format message:\n%s", text)
	}
	if !strings.Contains(text, "not in shadow's firmware database") || !strings.Contains(text, "Known builds:") {
		t.Errorf("missing unknown-build listing:\n%s", text)
	}
}

func TestPromptBuildRejectsUnsupportedRecord(t *testing.T) {
	db := testDB(t)
	rec, ok := db.Get("4832540042")
	if !ok {
		t.Fatal("kt6 record missing")
	}
	rec.BuildKey = "4000000000"
	rec.Offsets.StackDelta = nil
	db[rec.BuildKey] = rec

	var out bytes.Buffer
	_, ok = promptBuild(strings.NewReader(rec.BuildKey+"\n"), &out, db)
	if ok {
		t.Fatal("unsupported build accepted")
	}
	if !strings.Contains(out.String(), "cannot be exploited") {
		t.Fatalf("missing unsupported message:\n%s", out.String())
	}
}

func TestPromptBuildEOF(t *testing.T) {
	var out bytes.Buffer
	_, ok := promptBuild(strings.NewReader(""), &out, testDB(t))
	if ok {
		t.Fatal("EOF accepted")
	}
	if !strings.Contains(out.String(), "No build number entered") {
		t.Fatalf("missing EOF message:\n%s", out.String())
	}
}

func TestSplitDebug(t *testing.T) {
	cases := []struct {
		name  string
		args  []string
		debug bool
		cmd   string
		rest  []string
	}{
		{"none", nil, false, "", nil},
		{"bare", []string{"--debug"}, true, "", nil},
		{"with command", []string{"--debug", "touch /x"}, true, "touch /x", nil},
		{"equals", []string{"--debug=touch /x"}, true, "touch /x", nil},
		{"before flag", []string{"--debug", "--dry-run"}, true, "", []string{"--dry-run"}},
		{"after flag", []string{"--dry-run", "--debug", "cmd"}, true, "cmd", []string{"--dry-run"}},
		{"single dash", []string{"-debug", "cmd"}, true, "cmd", nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			debug, cmd, rest := splitDebug(tc.args)
			if debug != tc.debug || cmd != tc.cmd {
				t.Fatalf("got debug=%v cmd=%q, want debug=%v cmd=%q", debug, cmd, tc.debug, tc.cmd)
			}
			if !slices.Equal(rest, tc.rest) {
				t.Fatalf("rest = %q, want %q", rest, tc.rest)
			}
		})
	}
}

func TestJBCommand(t *testing.T) {
	want := "RUN_MODE=1 /bin/sh /mnt/base-us/jb.sh"
	if jbCommand != want {
		t.Fatalf("jbCommand = %q, want %q", jbCommand, want)
	}
}

func TestFetchScript(t *testing.T) {
	const body = "#!/bin/sh\necho hi\n"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, body)
	}))
	defer srv.Close()
	got, err := fetchScript(srv.URL, nil)
	if err != nil {
		t.Fatalf("fetchScript: %v", err)
	}
	if string(got) != body {
		t.Fatalf("script = %q, want %q", got, body)
	}
}

func TestFetchScriptErrors(t *testing.T) {
	notFound := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "nope", http.StatusNotFound)
	}))
	defer notFound.Close()
	if _, err := fetchScript(notFound.URL, nil); err == nil {
		t.Fatal("HTTP 404 accepted")
	}

	empty := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	defer empty.Close()
	if _, err := fetchScript(empty.URL, nil); err == nil {
		t.Fatal("empty body accepted")
	}

	big := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write(make([]byte, maxScriptBytes+1))
	}))
	defer big.Close()
	if _, err := fetchScript(big.URL, nil); err == nil {
		t.Fatal("oversized body accepted")
	}
}
