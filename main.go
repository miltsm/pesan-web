package main

import (
	"embed"
	"fmt"

	"log"
	"net/http"
)

//go:embed .well-known
var staticFs embed.FS

func main() {
	router := http.NewServeMux()
	router.Handle("/", http.FileServerFS(staticFs))
	srv := http.Server{
		Addr:    ":3000",
		Handler: router,
	}
	fmt.Printf("listening to port 3000..\n")
	err := srv.ListenAndServe()
	if err != nil {
		log.Fatalf("[FATAL] %v", err)
	}
}
