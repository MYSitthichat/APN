package main

import (
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestIsAlreadyRunningRejectsForeignAppsLikeHiveMQ(t *testing.T) {
	// Simulate HiveMQ Control Center / SPA returning HTTP 200 HTML for /api/status
	hive := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = w.Write([]byte("<!doctype html><title>HiveMQ Control Center</title>"))
	}))
	defer hive.Close()

	addr := strings.TrimPrefix(hive.URL, "http://")
	if isAlreadyRunning(addr) {
		t.Fatalf("isAlreadyRunning(%s) = true for HiveMQ HTML page, want false", addr)
	}

	// Simulate foreign JSON API returning 200 without APN peer fields
	otherJSON := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"status":"ok"}`))
	}))
	defer otherJSON.Close()

	if isAlreadyRunning(strings.TrimPrefix(otherJSON.URL, "http://")) {
		t.Fatalf("isAlreadyRunning should return false for non-APN JSON API")
	}

	// Simulate real APN peer /api/status response
	realAPN := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"mode":"peer","version":"1.2.17","data":{"device_id":"123456789","peer_id":"pc1"}}`))
	}))
	defer realAPN.Close()

	if !isAlreadyRunning(strings.TrimPrefix(realAPN.URL, "http://")) {
		t.Fatalf("isAlreadyRunning should return true for real APN peer response")
	}
}

func TestResolveFreeUIAddrSkipsOccupiedPort(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	occupied := ln.Addr().String()
	got, err := resolveFreeUIAddr(occupied)
	if err != nil {
		t.Fatalf("resolveFreeUIAddr failed: %v", err)
	}
	if got == occupied {
		t.Fatalf("resolveFreeUIAddr returned occupied address %s", occupied)
	}
}
