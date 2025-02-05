package db

import (
	"database/sql"
	"fmt"

	"github.com/UmairAhmedImran/ecom/config"
	_ "github.com/lib/pq"
)

func NewPostgresStorage() (*sql.DB, error) {
	user := config.GetEnv("DB_USER", "postgres")
	dbName := config.GetEnv("DB_NAME", "postgres")
	password := config.GetEnv("PASSWD", "ecompassword")
	port := config.GetEnv("PORT", "5437")
	sslMode := config.GetEnv("SSL_MODE", "disable")

	connStr := fmt.Sprintf(
		"user=%s dbname=%s password=%s port=%s sslmode=%s",
		user, dbName, password, port, sslMode,
	)

	db, err := sql.Open("postgres", connStr)
	if err != nil {
		return nil, err
	}

	if err := db.Ping(); err != nil {
		return nil, err
	}

	return db, nil
}
