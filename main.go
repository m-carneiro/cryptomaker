package main

import (
	"criptomaker/handlers"
	"fmt"
	"log"
	"net/http"
)

const (
	EncryptEndpoint = "/encrypt"
	Port            = ":8080"
)

func main() {
	http.HandleFunc(EncryptEndpoint, handlers.EncryptHandler)

	fmt.Printf("App running on port %s", Port)
	err := http.ListenAndServe(Port, nil)
	if err != nil {
		log.Fatal("Application wasn't initialized")
		return
	}
}
