package main

import (
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"
)

// Test response is following the Nginx protocol (https://nginx.org/en/docs/mail/ngx_mail_auth_http_module.html#protocol)
// Remember to pass arguments for flag parsing
func TestHttpAuth(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Add("Auth-Method", "plain")
	req.Header.Add("Auth-User", "test@test.com")
	req.Header.Add("Auth-Pass", "test1234")
	req.Header.Add("Auth-Protocol", "imap")
	req.Header.Add("Auth-Login-Attempt", "1")
	req.Header.Add("Client-IP", "127.0.0.1")
	req.Header.Add("Client-Host", "test.example.com")

	recorder := httptest.NewRecorder()
	handleMailProxyAuth(recorder, req)
	if recorder.Code != http.StatusOK {
		t.Fatal("Http auth did not return http OK status (200 code)")
	}
	if recorder.Header().Get("Auth-Status") != "OK" {
		t.Fatal("Auth-Status header was not set to OK")
	}
	if recorder.Header().Get("Auth-Port") != strconv.Itoa(config.Default.IMAP.Port) {
		t.Fatalf("Auth-Port was not set to the IMAP port in config.\nImap Port: %d\nAuth-Port:%s",
			config.Default.IMAP.Port, recorder.Header().Get("Auth-Port"))
	}
}
