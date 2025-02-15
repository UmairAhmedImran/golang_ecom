package auth

import "testing"

func TestHashPassword(t *testing.T) {
	password := "password"
	hash, err := HashPassword(password)
	if err != nil {
		t.Errorf("Error hashing password: %v", err)
	}

	if hash == "" {
		t.Errorf("Hash is empty")
	}

	if hash == password {
		t.Errorf("Hash is the same as the password")
	}

}

func TestComparePassword(t *testing.T) {
	password := "password"
	hash, err := HashPassword(password)
	if err != nil {
		t.Errorf("Error hashing password: %v", err)
	}

	if !ComparePassword(hash, []byte(password)) {
		t.Errorf("Password comparison failed")
	}

	if ComparePassword(hash, []byte("wrongpassword")) {
		t.Errorf("Password comparison should have failed")
	}
}
