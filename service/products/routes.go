package products

import (
	"net/http"

	"github.com/UmairAhmedImran/ecom/middleware"
	"github.com/UmairAhmedImran/ecom/types"
	"github.com/UmairAhmedImran/ecom/utils"
	"github.com/go-chi/chi/v5"
)

type Handler struct {
	store types.ProductStore
}

func NewHandler(store types.ProductStore) *Handler {
	return &Handler{store: store}
}

func (h *Handler) RegisterRoutes(router chi.Router) {
	router.Get("/products", middleware.AuthMiddleware(http.HandlerFunc(h.handleGetProducts)))
}

func (h *Handler) handleGetProducts(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	products, err := h.store.GetProducts(ctx)
	if err != nil {
		utils.WriteError(w, http.StatusInternalServerError, err)
		return
	}
	utils.WriteJSON(w, http.StatusOK, products)
}
