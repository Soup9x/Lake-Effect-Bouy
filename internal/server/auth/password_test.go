package auth

import "testing"

func TestPasswordRoundTrip(t *testing.T) {
	h, err := HashPassword("correct horse battery staple")
	if err != nil {
		t.Fatal(err)
	}
	if !CheckPassword("correct horse battery staple", h) {
		t.Fatal("correct password rejected")
	}
	if CheckPassword("correct horse battery stapl", h) {
		t.Fatal("wrong password accepted")
	}
	if CheckPassword("x", "garbage") {
		t.Fatal("malformed hash accepted")
	}
	if ValidatePassword("short", "") == nil {
		t.Fatal("short password accepted")
	}
	if ValidatePassword("nolan-is-great-123", "nolan@example.com") == nil {
		t.Fatal("password containing email name accepted")
	}
}
