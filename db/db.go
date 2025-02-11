package db

import (
	"database/sql"
	"fmt"
	"time"

	"github.com/UmairAhmedImran/ecom/config"
	_ "github.com/jackc/pgx/v5/stdlib"
)

const MaxOpenDbConn = 10
const MaxIdleDbConn = 5
const MaxDbLifetime = 5 * time.Minute

func NewPostgresStorage() (*sql.DB, error) {
	// user := config.GetEnv("DB_USER", "postgres")
	// dbName := config.GetEnv("DB_NAME", "postgres")
	// password := config.GetEnv("PASSWD", "ecompassword")
	// port := config.GetEnv("PORT", "5436")
	// sslMode := config.GetEnv("SSL_MODE", "disable")
	//
	// connStr := fmt.Sprintf(
	// 	"user=%s dbname=%s password=%s port=%s sslmode=%s",
	// 	user, dbName, password, port, sslMode,
	// )
  
  	connStr := config.GetEnv("DB_URL", "")

	db, err := sql.Open("pgx", connStr)
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
