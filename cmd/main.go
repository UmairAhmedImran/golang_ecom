package main

import (
	"log"

	"github.com/UmairAhmedImran/ecom/cmd/api"
	"github.com/UmairAhmedImran/ecom/config"
	"github.com/UmairAhmedImran/ecom/db"
	"github.com/joho/godotenv"
)

func main()  {
  godotenv.Load()
  db, err := db.NewPostgresStorage()
  if err!= nil {
    log.Fatal(err)
  }
  addr := config.GetEnv("ADDR_PORT", ":3000")
  server := api.NewAPIServer(addr, db)
  if err := server.RUN(); err != nil {
    log.Fatal(err)
  }
}
