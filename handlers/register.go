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
	"golang.org/x/crypto/bcrypt"
)



func RegHand( w http.ResponseWriter, r *http.Request){
	err := utils.RegPage.Execute(w, nil)
	if err != nil {
		http.Error(w, "404", http.StatusInternalServerError)
	}
}

func Register(w http.ResponseWriter, r *http.Request){
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

	var db_name string
	Qerr := utils.DB.QueryRow("SELECT name FROM users WHERE name = ?", name).Scan(&db_name)
	if Qerr == nil {
		//http.Error(w, "the username is already taken", http.StatusConflict)
		w.WriteHeader(http.StatusConflict)
    	fmt.Fprintf(w, `<script>alert("Username is already taken");window.history.back()</script>`)

		return
	}

	hashpass, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		log.Fatal("Hashing error:", err)
	}
	
	sqlQuery := `INSERT INTO users (name, password) VALUES (?, ?)`
	_, err = utils.DB.Exec(sqlQuery, name, string(hashpass))
	if err != nil {
		http.Error(w,"Cannot create user:", http.StatusInternalServerError)
	}

	fmt.Printf("Beküldött név: %s, jelszó: %s\n", name, password)
	http.Redirect(w, r, "/login", http.StatusSeeOther)
}

