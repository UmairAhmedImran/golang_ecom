package api

import (
	"database/sql"
	"log"
	"net/http"

	"github.com/UmairAhmedImran/ecom/service/user"
	"github.com/go-chi/chi/v5"
)

type APIServer struct {
    addr    string
    db      *sql.DB
}

func NewAPIServer(addr string, db *sql.DB) *APIServer {
  return &APIServer{
    addr: addr,
    db:   db,
  }
}

func (s *APIServer) RUN() error {
  router := chi.NewRouter()

  router.Route("/api/v1", func(r chi.Router) {
    userHandler := user.NewHandler()
    userHandler.RegisterRoutes(r) // Pass the router `r` here
  })

  log.Println("server listening on port: ", s.addr)

  return http.ListenAndServe(s.addr, router)
}
