package api

import (
	"log"
	"net/http"

	"github.com/UmairAhmedImran/ecom/service/products"
	"github.com/UmairAhmedImran/ecom/service/user"
	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/jmoiron/sqlx"
)

type APIServer struct {
	addr string
	db   *sqlx.DB
}

func NewAPIServer(addr string, db *sqlx.DB) *APIServer {
	return &APIServer{
		addr: addr,
		db:   db,
	}
}

func (s *APIServer) RUN() error {
	router := chi.NewRouter()
	router.Use(middleware.RequestID)
	router.Use(middleware.RealIP)
	router.Use(middleware.Logger)
	router.Use(middleware.Recoverer)
	userStore := user.NewStore(s.db)
	productStore := products.NewStore(s.db)
	router.Route("/api/v1", func(r chi.Router) {
		userHandler := user.NewHandler(userStore)
		userHandler.RegisterRoutes(r) // Pass the router `r` here
		productHandler := products.NewHandler(productStore)
		productHandler.RegisterRoutes(r)
	})

	log.Println("server listening on port: ", s.addr)

	return http.ListenAndServe(s.addr, router)
}
