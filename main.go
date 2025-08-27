package main

import (
	"db_test/utils"
	"db_test/handlers"
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
	mux.HandleFunc("/register", handlers.RegHand)
	mux.HandleFunc("/submit_login", handlers.Login)
	mux.HandleFunc("/submit_reg", handlers.Register)
	mux.HandleFunc("/test", utils.Auth(handlers.TestHand))
	mux.HandleFunc("/logout", utils.CSRFMiddleware(handlers.LogoutHand))

   err = http.ListenAndServeTLS(":8080", "cert.pem", "key.pem", mux)
   if err != nil {
       log.Fatalf("Server error: %v", err)
   }
}




