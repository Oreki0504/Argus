package auth

import (
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

func TestNamedRolesAndInvalidCredentials(t *testing.T) {
	admin, token, e := NewUser("alice", "Admin")
	if e != nil {
		t.Fatal(e)
	}
	reader, readToken, e := NewUser("bob", "ReadOnly")
	if e != nil {
		t.Fatal(e)
	}
	c := Config{Users: []User{admin, reader}}
	if e = c.Validate(); e != nil {
		t.Fatal(e)
	}
	for _, v := range []struct{ token, role string }{{token, "Admin"}, {readToken, "ReadOnly"}} {
		u, e := c.Authenticate(v.token)
		if e != nil || u.Role != v.role {
			t.Fatal(u, e)
		}
	}
	for _, bad := range []string{"", token[:20], strings.Repeat("x", 50), strings.Repeat("x", 257)} {
		if _, e = c.Authenticate(bad); e == nil {
			t.Fatal("invalid credential accepted")
		}
	}
	if strings.Contains(admin.TokenSHA256, token) {
		t.Fatal("plaintext credential persisted")
	}
	c.Users = append(c.Users, admin)
	if c.Validate() == nil {
		t.Fatal("duplicate identity accepted")
	}
}

func TestAdministratorTokenExpirationAtRequestTime(t *testing.T) {
	u, token, err := NewUser("expiring", "Admin")
	if err != nil {
		t.Fatal(err)
	}
	u.ExpiresAt = time.Now().Add(time.Hour).Unix()
	path := filepath.Join(t.TempDir(), "admins.json")
	raw, _ := json.Marshal(Config{Users: []User{u}})
	if err = os.WriteFile(path, raw, 0600); err != nil {
		t.Fatal(err)
	}
	loaded, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = loaded.Authenticate(token); err != nil {
		t.Fatal(err)
	}
	loaded.Users[0].ExpiresAt = time.Now().Unix()
	if _, err = loaded.Authenticate(token); err == nil {
		t.Fatal("expired token authenticated")
	}
	loaded.Users[0].ExpiresAt = 0
	if _, err = loaded.Authenticate(token); err != nil {
		t.Fatal("legacy unexpired token changed", err)
	}
	loaded.Users[0].ExpiresAt = -1
	if err = loaded.Validate(); err == nil {
		t.Fatal("negative expiry accepted")
	}
	invalid := strings.Replace(string(raw), `"expires_at":`, `"Expires_at":`, 1)
	if err = os.WriteFile(path, []byte(invalid), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err = Load(path); err == nil {
		t.Fatal("misspelled expiry accepted")
	}
}

func TestAccountFileRotationRevocationAndPermissions(t *testing.T) {
	admin, oldToken, e := NewUser("alice", "Admin")
	if e != nil {
		t.Fatal(e)
	}
	reader, readToken, e := NewUser("reader", "ReadOnly")
	if e != nil {
		t.Fatal(e)
	}
	path := filepath.Join(t.TempDir(), "admins.json")
	write := func(c Config) {
		b, e := json.Marshal(c)
		if e != nil {
			t.Fatal(e)
		}
		if strings.Contains(string(b), oldToken) || strings.Contains(string(b), readToken) {
			t.Fatal("raw token stored")
		}
		if e = os.WriteFile(path, b, 0600); e != nil {
			t.Fatal(e)
		}
	}
	write(Config{Users: []User{admin, reader}})
	loaded, e := Load(path)
	if e != nil {
		t.Fatal(e)
	}
	replacement, newToken, e := NewUser("alice", "ReadOnly")
	if e != nil {
		t.Fatal(e)
	}
	write(Config{Users: []User{replacement, reader}})
	if user, e := loaded.Authenticate(oldToken); e != nil || user.Role != "Admin" {
		t.Fatal("startup snapshot changed", user, e)
	}
	if _, e = loaded.Authenticate(newToken); e == nil {
		t.Fatal("new token accepted before reload")
	}
	reloaded, e := Load(path)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = reloaded.Authenticate(oldToken); e == nil {
		t.Fatal("replaced token still valid")
	}
	if user, e := reloaded.Authenticate(newToken); e != nil || user.Role != "ReadOnly" {
		t.Fatal(user, e)
	}
	write(Config{Users: []User{reader}})
	reloaded, e = Load(path)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = reloaded.Authenticate(newToken); e == nil {
		t.Fatal("revoked token accepted")
	}
	if runtime.GOOS != "windows" {
		if e = os.Chmod(path, 0644); e != nil {
			t.Fatal(e)
		}
		if _, e = Load(path); e == nil {
			t.Fatal("public credential file accepted")
		}
	}
}
