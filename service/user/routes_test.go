package user

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/UmairAhmedImran/ecom/types"
	"github.com/google/uuid"
)

func TestUserServiceHandlers(t *testing.T) {
	userStore := &mockUserStore{}
	handler := NewHandler(userStore)

	t.Run("should fail if the user payload is invalid", func(t *testing.T) {
		payload := types.RegisterUserPayload{
			FirstName: "user",
			LastName:  "123",
			Password:  "12345678",
			Email:     "invalid-email",
		}
		marshalled, _ := json.Marshal(payload)
		req, err := http.NewRequest(http.MethodPost, "/register", bytes.NewBuffer(marshalled))
		if err != nil {
			t.Fatal(err)
		}
		rr := httptest.NewRecorder()
		router := chi.NewRouter()

		router.HandleFunc("/register", handler.handleRegister)
		router.ServeHTTP(rr, req)

		if rr.Code != http.StatusBadRequest {
			t.Errorf("expected status code %d, got %d", http.StatusBadRequest, rr.Code)
		}
	})

	t.Run("should correctly register the user", func(t *testing.T) {

		payload := types.RegisterUserPayload{
			FirstName: "user",
			LastName:  "123",
			Password:  "12345678",
			Email:     "valid@gmail.com",
		}
		marshalled, _ := json.Marshal(payload)
		req, err := http.NewRequest(http.MethodPost, "/register", bytes.NewBuffer(marshalled))
		if err != nil {
			t.Fatal(err)
		}
		rr := httptest.NewRecorder()
		router := chi.NewRouter()

		router.HandleFunc("/register", handler.handleRegister)
		router.ServeHTTP(rr, req)

		if rr.Code != http.StatusCreated {
			t.Errorf("expected status code %d, got %d", http.StatusCreated, rr.Code)
		}
	})
}

type mockUserStore struct{}

func (m *mockUserStore) GetUserByEmail(ctx context.Context, email string) (*types.User, error) {
	return nil, fmt.Errorf("user not found")
}
func (m *mockUserStore) GetUserByID(ctx context.Context, id uuid.UUID) (*types.User, error) {
	return nil, nil
}
func (m *mockUserStore) CreateUser(ctx context.Context, user types.User) error {
	return nil
}
func (m *mockUserStore) MarkUserAsVerified(ctx context.Context, userID string) error {
	return nil
}
func (m *mockUserStore) UpdateUserOTP(ctx context.Context, userID string, otp string, otpExpiry time.Time) error {
	return nil
}
func (m *mockUserStore) UpdatePassword(ctx context.Context, userID string, hashedPassword string) error {
	return nil
}
func (m *mockUserStore) CreateRefreshToken(ctx context.Context, token types.RefreshToken) error {
	return nil
}
func (m *mockUserStore) DeleteRefreshToken(ctx context.Context, token string) error {
	return nil
}
func (m *mockUserStore) GetRefreshToken(ctx context.Context, token string) (*types.RefreshToken, error) {
	return nil, nil
}
func (m *mockUserStore) UpdateUserGoogleID(ctx context.Context, userID string, googleID string) error {
	return nil
}
