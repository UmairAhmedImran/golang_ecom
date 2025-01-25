package db

import (
	"database/sql"
)

func NewPostgresStorage() (*sql.DB, error) {
	// connStr :=`user=%s
	// dbname=%s
	// password=%s
	// port=%s
	// sslmode=%s,`
	connStr := ""
	db, err := sql.Open("postgres", connStr)
	if err != nil {
		return nil, err
	}

	if err := db.Ping(); err != nil {
		return nil, err
	}

	return db, nil
}