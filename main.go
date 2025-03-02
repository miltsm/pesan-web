package main

import (
	"embed"
	"fmt"
	"os"
	"strconv"

	"log"
	"net/http"
)

//go:embed .well-known
var staticFs embed.FS

func main() {
	port, err := strconv.ParseInt(os.Getenv("PORT"), 10, 32)
	if err != nil {
		fmt.Printf("[WARN] %v\n", err)
		port = 3000
	}
	router := http.NewServeMux()
	router.Handle("/", http.FileServerFS(staticFs))
	srv := http.Server{
		Addr:    fmt.Sprintf("%s:%d", os.Getenv("HOST"), port),
		Handler: router,
	}
	fmt.Printf("listening to port 3000..\n")
	err = srv.ListenAndServe()
	if err != nil {
		log.Fatalf("[FATAL] %v", err)
	}
}
