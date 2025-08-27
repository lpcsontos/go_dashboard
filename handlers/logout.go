package handlers

import (
	"db_test/utils"
   _ "database/sql"
	"fmt"
   "log"
   "net/http"
	_ "os"
	_ "github.com/joho/godotenv"
   _ "github.com/go-sql-driver/mysql"
	_"golang.org/x/crypto/bcrypt"
)

func LogoutHand( w http.ResponseWriter, r *http.Request){
	
	user, err := r.Cookie("user")
	if err != nil{
		log.Println("User cookie not found:", err)
		return
	}
	name := user.Value


	_, err = utils.DB.Exec("UPDATE users SET sessionToken = ? WHERE name = ?", nil, name)
	if err != nil {
		log.Printf("UPDATE query failed with error: %v", err)
		log.Printf("Error type: %T", err)
		http.Error(w, fmt.Sprintf("Database update failed: %v", err), http.StatusInternalServerError)
	}

	_, err = utils.DB.Exec("UPDATE users SET csrfToken = ? WHERE name = ?", nil, name)
	if err != nil {
		log.Printf("UPDATE query failed with error: %v", err)
		log.Printf("Error type: %T", err)
		http.Error(w, fmt.Sprintf("Database update failed: %v", err), http.StatusInternalServerError)
	}
	
	http.Redirect(w, r, "/login", http.StatusSeeOther)
}
