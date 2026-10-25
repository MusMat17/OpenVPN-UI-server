package main

import (
	"strings"
	"testing"
)

func TestPassword(t *testing.T) {
	h := hashPassword("long correct example password")
	if !checkPassword("long correct example password", h) {
		t.Fatal("correct password rejected")
	}
	if checkPassword("wrong", h) {
		t.Fatal("bad password accepted")
	}
	if strings.Contains(h, "correct example") {
		t.Fatal("plain text leaked")
	}
}
func TestName(t *testing.T) {
	for _, s := range []string{"alice", "test-01", "CLIENT_2"} {
		if !validName(s) {
			t.Errorf("expected valid: %q", s)
		}
	}
	for _, s := range []string{"", "../foo", "-bad", "a b", "a;touch /tmp/file", strings.Repeat("a", 49)} {
		if validName(s) {
			t.Errorf("expected invalid: %q", s)
		}
	}
}
func TestHumanBytes(t *testing.T) {
	if humanBytes(2048) != "2.0 KiB" {
		t.Fatal(humanBytes(2048))
	}
}
