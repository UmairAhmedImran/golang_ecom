package user

import (
	"log"
	"net/http"

	"github.com/go-chi/chi/v5"
)

type Handler struct {}

func NewHandler() *Handler {
  return &Handler{}
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
 // check if user exists
 // if it doesnt create new user

}
