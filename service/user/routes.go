package user

import (
	"fmt"
	"log"
	"net/http"

	"github.com/UmairAhmedImran/ecom/service/auth"
	"github.com/UmairAhmedImran/ecom/types"
	"github.com/UmairAhmedImran/ecom/utils"
	"github.com/go-chi/chi/v5"
	"github.com/go-playground/validator/v10"
)

type Handler struct {
  store types.UserStore
}

func NewHandler(store types.UserStore) *Handler {
  return &Handler{store: store}
}

func (h *Handler) RegisterRoutes(router chi.Router) {
  router.Post("/login", h.handleLogin)
  router.Post("/register", h.handleRegister)
  router.Get("/health", h.handleHealth)
}

func (h *Handler) handleHealth(w http.ResponseWriter, r *http.Request) {
  log.Println("healthCheck")
}
func (h *Handler) handleLogin(w http.ResponseWriter, r *http.Request) {
  log.Println("handleLogin")
}

func (h *Handler) handleRegister(w http.ResponseWriter, r *http.Request) {
 // get JSON payload
 var payload types.RegisterUserPayload 
 if err := utils.ParseJSON(r, &payload); err != nil {
    utils.WriteError(w, http.StatusBadRequest, err)
    return
 }

 // validate the paylaod
 if err := utils.Validate.Struct(payload); err != nil {
  errors := err.(validator.ValidationErrors)
  utils.WriteError(w, http.StatusBadRequest, fmt.Errorf("invalid payload: %v", errors))
  return
 }

 // check if user exists
 _, err := h.store.GetUserByEmail(payload.Email)
 if err != nil {
   utils.WriteError(w, http.StatusBadRequest, fmt.Errorf("user with email %s already exists", payload.Email))
   return
 }

 hashedPassword, err := auth.HashPassword(payload.Password)
 if err != nil {
   utils.WriteError(w, http.StatusInternalServerError, err)
   return
 }

 // if it doesnt create new user
  err = h.store.CreateUser(types.User{
    FirstName: payload.FirstName,
    LastName: payload.LastName,
    Email: payload.Email,
    Password: hashedPassword,
  })
  if err != nil {
    utils.WriteError(w, http.StatusInternalServerError, err)
    return
  }
  utils.WriteJSON(w, http.StatusCreated, nil)
}
