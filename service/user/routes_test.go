package user

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/go-chi/chi/v5"

	"github.com/UmairAhmedImran/ecom/types"
)

func TestUserServiceHandlers(t *testing.T) {
  userStore := &mockUserStore{}
  handler := NewHandler(userStore)

  t.Run("should fail if the user payload is invalid", func(t *testing.T) {
    payload := types.RegisterUserPayload{
      FirstName: "user",
      LastName: "123",
      Password: "12345678",
      Email: "asd@gmail.com",
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
}

type mockUserStore struct {}

func (m *mockUserStore) GetUserByEmail(email string) (*types.User, error) {
  return nil, fmt.Errorf("user not found")
}
func (m *mockUserStore) GetUserByID(id int) (*types.User, error) {
  return nil, nil
}
func (m *mockUserStore) CreateUser(types.User)  error {
  return nil
}
