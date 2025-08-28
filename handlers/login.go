package handlers

import (
	"dashboard/utils"
	"dashboard/auth"
   "database/sql"
	"fmt"
	"time"
   "log"
   "net/http"
	_ "os"
	_ "github.com/joho/godotenv"
   _ "github.com/go-sql-driver/mysql"
	_ "golang.org/x/crypto/bcrypt"
)

func Root(w http.ResponseWriter, r *http.Request){
	http.Redirect(w, r, "/login", http.StatusSeeOther)
}

func LoginHand( w http.ResponseWriter, r *http.Request){

	if auth.IsLoggedIn(r){
		http.Redirect(w, r, "/test", http.StatusSeeOther)
	}

	err := utils.LoginPage.Execute(w, nil)
	if err != nil {
		http.Error(w, "404", http.StatusInternalServerError)
	}
}

func Login(w http.ResponseWriter, r *http.Request){
	if r.Method != http.MethodPost {
		http.Error(w, "only post method", http.StatusMethodNotAllowed)
		return
	}


	err := r.ParseForm()
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	name := r.FormValue("name")
	password := r.FormValue("password")
	
	if len(name) > 20 || len(password) > 20{
		http.Error(w, "name or password should be maximum 20 character long", http.StatusBadRequest)
		return
	}

	var hash string
	err = utils.DB.QueryRow("SELECT password FROM users WHERE name = ?", name).Scan(&hash)
	if err == sql.ErrNoRows {
    	log.Println("User not found: no matching account")
    	fmt.Fprintf(w, `<script>alert("Wrong username or password");window.history.back()</script>`)
   	return
	} else if err != nil {
   	log.Println("Database error:", err)
    	http.Error(w, "Server error", http.StatusInternalServerError)
    	return
	}

	if utils.PassComp(hash, password){
		
		sessionToken := utils.GenToken(191)
		csrfToken := utils.GenToken(191)

		http.SetCookie(w, &http.Cookie{
			Name: "session_token",
			Value: sessionToken,
			Expires: time.Now().Add(24*time.Hour),
			HttpOnly: true,
			Secure: true,
			Path: "/",
		})

		http.SetCookie(w, &http.Cookie{
			Name: "csrf_token",
			Value: csrfToken,
			Expires: time.Now().Add(24*time.Hour),
			HttpOnly: false,
			Secure: true,
			Path:"/",
			SameSite: http.SameSiteStrictMode,
		})

		query := `
		INSERT INTO tokens (id, sessionToken, sessionExpires, csrfToken, csrfExpires)
		VALUES ((SELECT id FROM users WHERE name = ?), ?, ?, ?, ?)
		`

		_, err := utils.DB.Exec(query, name, sessionToken, time.Now().Add(24*time.Hour), csrfToken, time.Now().Add(24*time.Hour))
		if err != nil {
			log.Printf("INSERT query failed with error: %v", err)
			log.Printf("Error type: %T", err)
			http.Error(w, fmt.Sprintf("Database update failed: %v", err), http.StatusInternalServerError)
		}
	
		http.Redirect(w, r, "/test", http.StatusSeeOther)
	}else{
		w.WriteHeader(http.StatusUnauthorized)
    	fmt.Fprintf(w, `<script>alert("Wrong username or password");window.history.back()</script>`)
	}

}
