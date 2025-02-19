package db

import (
	"fmt"
	"time"

	"github.com/UmairAhmedImran/ecom/config"
	_ "github.com/jackc/pgx/v5/stdlib"
	"github.com/jmoiron/sqlx"
)

const MaxOpenDbConn = 10
const MaxIdleDbConn = 5
const MaxDbLifetime = 5 * time.Minute

func NewPostgresStorage() (*sqlx.DB, error) {
	connStr := config.GetEnv("DB_URL", "")

	db, err := sqlx.Open("pgx", connStr)
	if err != nil {
		return nil, err
	}

	db.SetMaxOpenConns(MaxOpenDbConn)
	db.SetMaxIdleConns(MaxIdleDbConn)
	db.SetConnMaxLifetime(MaxDbLifetime)

	if err := db.Ping(); err != nil {
		return nil, err
	}

	fmt.Println("*** Database connection established ***")

	return db, nil
}
