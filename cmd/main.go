package main

import (
	"log"

	"github.com/UmairAhmedImran/ecom/cmd/api"
)

func main()  {
  server := api.NewAPIServer(":3000", nil)
  if err := server.RUN(); err != nil {
    log.Fatal(err)
  }
}