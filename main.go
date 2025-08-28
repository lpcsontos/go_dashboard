package main

import (
	"dashboard/utils"
	"dashboard/handlers"
	"dashboard/auth"
   "log"
   "net/http"
	_ "html/template"
	"github.com/joho/godotenv"
   _ "github.com/go-sql-driver/mysql"
)


func main() {
	var err error
	err = godotenv.Load()
	if err != nil {
		log.Fatal("cannot load the .env file")
	}
	utils.Setup()

	mux := http.NewServeMux()

   mux.HandleFunc("/", handlers.Root)
	mux.HandleFunc("/login", handlers.LoginHand)
	
	mux.HandleFunc("/users", auth.AuthAdmin(handlers.RegHand))
	mux.HandleFunc("/test", auth.Auth(handlers.TestHand))
	
	mux.HandleFunc("/api/login", handlers.Login)
	mux.HandleFunc("/api/register", auth.CSRFMiddlewareAdmin(handlers.Register))
	mux.HandleFunc("/api/delete", auth.CSRFMiddlewareAdmin(handlers.Delete))
	mux.HandleFunc("/api/logout", auth.CSRFMiddleware(handlers.LogoutHand))

   err = http.ListenAndServeTLS(":8080", "cert.pem", "key.pem", mux)
   if err != nil {
       log.Fatalf("Server error: %v", err)
   }
}




