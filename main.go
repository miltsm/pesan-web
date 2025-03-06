package main

import (
	"crypto/tls"
	"database/sql"
	"embed"
	"fmt"

	"os"
	"strconv"
	"time"

	"log"
	"net/http"

	_ "github.com/jackc/pgx/v5/stdlib"
	"github.com/miltsm/pesan-web/session"
	"github.com/redis/go-redis/v9"
)

//go:embed .well-known
var wellKnownFS embed.FS

func main() {
	var certPem []byte
	keyPem, err := os.ReadFile(os.Getenv("WEB_PRIVATE_KEY_PATH"))
	if err != nil {
		fmt.Printf("invalid private key: %v\n", err)
	}
	certPem, err = os.ReadFile(os.Getenv("WEB_CERT_PATH"))
	if err != nil {
		fmt.Printf("invalid cert: %v\n", err)
	}
	var certTls tls.Certificate
	certTls, err = tls.X509KeyPair(certPem, keyPem)
	cfg := &tls.Config{Certificates: []tls.Certificate{certTls}}
	var port int64
	port, err = strconv.ParseInt(os.Getenv("PORT"), 10, 32)
	if err != nil {
		fmt.Printf("[WARN] %v\n", err)
		port = 3000
	}
	db := setupDb()
	cache := setupCache()
	router := http.NewServeMux()
	// NOTE: serve .well-known file
	router.Handle("/", http.FileServerFS(wellKnownFS))
	sessionHandler := session.New(db, *cache)
	// NOTE: endpoints
	router.HandleFunc("POST /public-key/assert/challenge", sessionHandler.PostRequestAssertation)
	router.HandleFunc("POST /public-key/assert/:user_handle", sessionHandler.PostAssertPublicKey)
	srv := http.Server{
		Addr:      fmt.Sprintf("%s:%d", os.Getenv("HOST"), port),
		Handler:   logger(router),
		TLSConfig: cfg,
	}
	fmt.Printf("listening to port %s..\n", srv.Addr)
	//err = srv.ListenAndServeTLS("", "")
	err = srv.ListenAndServe()
	if err != nil {
		log.Fatalf("[FATAL] %v", err)
	}
}

func setupDb() *sql.DB {
	port, err := strconv.ParseInt(os.Getenv("POSTGRES_PORT"), 10, 32)
	if err != nil {
		fmt.Printf("[WARN] %v\n", err)
		port = 5432
	}
	var pwd []byte
	pwd, err = os.ReadFile(os.Getenv("POSTGRES_PASSWORD_FILE"))
	if err != nil {
		log.Fatalf("[ERROR] %v\n", err)
	}
	pgUser, pgHost, pgDb := os.Getenv("POSTGRES_USER"), os.Getenv("POSTGRES_HOST"), os.Getenv("POSTGRES_DB")
	dsn := fmt.Sprintf("postgres://%s:%s@%s:%d/%s", pgUser, pwd, pgHost, port, pgDb)
	var db *sql.DB
	db, err = sql.Open("pgx", dsn)
	if err != nil {
		log.Fatalf("[ERROR] unable to use data source name -\n%v\n", err)
	}
	fmt.Println("db connected!")
	return db
}

func setupCache() *redis.Client {
	rdHost, rdPort := os.Getenv("RDS_HOST"), os.Getenv("RDS_PORT")
	if len(rdHost) == 0 {
		fmt.Println("[WARN] redis host isn't specified!")
		rdHost = "cache"
	}
	port, err := strconv.ParseInt(rdPort, 10, 32)
	if err != nil {
		fmt.Println("[WARN] redis port isn't specified!")
		port = 6379
	}
	return redis.NewClient(&redis.Options{
		Addr:     fmt.Sprintf("%s:%d", rdHost, port),
		Password: "",
		DB:       0,
		Protocol: 2,
	})
}

func logger(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		next.ServeHTTP(w, r)
		log.Printf("[INFO] %s %s\t%s", r.Method, r.RequestURI, time.Since(start))
	})
}
