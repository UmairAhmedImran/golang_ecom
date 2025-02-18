package products

import (
	"database/sql"

	"github.com/UmairAhmedImran/ecom/types"
)

type Store struct {
	db *sql.DB
}

func NewStore(db *sql.DB) *Store {
	return &Store{db: db}
}

func (s *Store) GetProducts() ([]types.Product, error) {
	query := `SELECT * FROM products`
	rows, err := s.db.Query(query)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	products := []types.Product{}
	for rows.Next() {
		var product types.Product
		err := rows.Scan(&product.ID, &product.Name, &product.Price, &product.CreatedAt, &product.UpdatedAt)
		if err != nil {
			return nil, err
		}
		products = append(products, product)
	}
	return products, nil
}
