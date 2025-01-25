package main

import (
	"log"

	"github.com/UmairAhmedImran/ecom/cmd/api"
	"github.com/UmairAhmedImran/ecom/db"
)

func main()  {
  db, err := db.NewPostgresStorage()
  if err!= nil {
    log.Fatal(err)
  }
  server := api.NewAPIServer(":3000", db)
  if err := server.RUN(); err != nil {
    log.Fatal(err)
  }
}