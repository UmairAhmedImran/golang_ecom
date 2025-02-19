package products

import (
	"context"

	"github.com/UmairAhmedImran/ecom/types"
	"github.com/jmoiron/sqlx"
)

type Store struct {
	db *sqlx.DB
}

func NewStore(db *sqlx.DB) *Store {
	return &Store{db: db}
}

func (s *Store) GetProducts(ctx context.Context) ([]types.Product, error) {
	var products []types.Product
	err := s.db.SelectContext(ctx, &products, "SELECT * FROM products")
	if err != nil {
		return nil, err
	}
	return products, nil
}
