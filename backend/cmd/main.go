package main

import (
	"log"
	"os"

	"github.com/Busness-app/kypost-server/backend/internal/app"
)

func main() {
	if err := app.Run(os.Args[1:]); err != nil {
		log.Fatal(err)
	}
}
