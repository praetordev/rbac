package postgres

import (
	"database/sql"
	"testing"

	"github.com/jmoiron/sqlx"
	_ "github.com/lib/pq"

	rbac "github.com/praetordev/rbac/v3"
)

// testCatalog is a small, domain-neutral vocabulary used across the postgres tests.
func testCatalog() *rbac.Catalog {
	return rbac.NewCatalog().
		Type("widget", "view", "change", "manage").
		Type("gadget", "view", "manage").
		System("manage_user", "user", "manage", "Manage users").
		System("view_audit", "audit", "view", "View audit log")
}

// lazyDB returns a non-nil *sqlx.DB that never connects — sql.Open is lazy — so
// construction-time validation can be tested without a database.
func lazyDB(t *testing.T) *sqlx.DB {
	t.Helper()
	raw, err := sql.Open("postgres", "")
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	return sqlx.NewDb(raw, "postgres")
}

func TestNewStoreValidation(t *testing.T) {
	db := lazyDB(t)
	cat := testCatalog()

	t.Run("nil DB", func(t *testing.T) {
		if _, err := NewStore(Config{Catalog: cat}); err == nil {
			t.Error("expected error for nil DB")
		}
	})
	t.Run("nil Catalog", func(t *testing.T) {
		if _, err := NewStore(Config{DB: db}); err == nil {
			t.Error("expected error for nil Catalog")
		}
	})
	t.Run("unsafe table name", func(t *testing.T) {
		_, err := NewStore(Config{
			DB: db, Catalog: cat,
			Tables: map[rbac.ContentType]string{"widget": "widgets; DROP TABLE users"},
		})
		if err == nil {
			t.Error("expected error for unsafe table identifier")
		}
	})
	t.Run("unsafe members table", func(t *testing.T) {
		_, err := NewStore(Config{DB: db, Catalog: cat, TeamMembersTable: "team members"})
		if err == nil {
			t.Error("expected error for unsafe TeamMembersTable identifier")
		}
	})
	t.Run("valid with default members table", func(t *testing.T) {
		s, err := NewStore(Config{
			DB: db, Catalog: cat,
			Tables: map[rbac.ContentType]string{"widget": "widgets"},
		})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if s.actorHolds == "" {
			t.Error("actorHolds not built")
		}
	})
}

func TestSafeIdentifier(t *testing.T) {
	ok := []string{"widgets", "team_members", "_x", "a1_b2", "organizations"}
	for _, s := range ok {
		if !safeIdentifier(s) {
			t.Errorf("safeIdentifier(%q) = false, want true", s)
		}
	}
	bad := []string{"", "1widgets", "Widgets", "wid gets", "wid;gets", "public.widgets", "widgets--", `"widgets"`}
	for _, s := range bad {
		if safeIdentifier(s) {
			t.Errorf("safeIdentifier(%q) = true, want false", s)
		}
	}
}
