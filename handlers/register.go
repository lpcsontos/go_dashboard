package handlers

import (
	"dashboard/utils"
   _ "database/sql"
	"fmt"
   "log"
   "net/http"
	_ "os"
	_ "github.com/joho/godotenv"
   _ "github.com/go-sql-driver/mysql"
	"golang.org/x/crypto/bcrypt"
)

type User struct {
    ID   int
    Name string
    Role string
}

func RegHand( w http.ResponseWriter, r *http.Request){
	rows, err := utils.DB.Query("SELECT id, name, role FROM users")
    if err != nil {
        http.Error(w, "Database error", http.StatusInternalServerError)
        return
    }
    defer rows.Close()

    var users []User
    for rows.Next() {
        var u User
        if err := rows.Scan(&u.ID, &u.Name, &u.Role); err == nil {
            users = append(users, u)
        }
    }

	 token, err := r.Cookie("csrf_token")
	if err != nil || token.Value ==""{
		log.Println("csrf cookie not good: ", err)
	}

   data := struct {
        Users     []User
        CSRFToken string
    }{
        Users:     users,
        CSRFToken: token.Value,
    }

	err = utils.RegPage.Execute(w, data)
	if err != nil {
		http.Error(w, "404", http.StatusInternalServerError)
	}
}

func Delete(w http.ResponseWriter, r *http.Request){
	if r.Method != http.MethodPost {
        http.Error(w, "Only POST allowed", http.StatusMethodNotAllowed)
        return
    }

    err := r.ParseForm()
    if err != nil {
        http.Error(w, "Invalid form", http.StatusBadRequest)
        return
    }

    id := r.FormValue("id")
    _, err = utils.DB.Exec("DELETE FROM users WHERE id = ?", id)
    if err != nil {
        http.Error(w, "Failed to delete user", http.StatusInternalServerError)
        return
    }

	http.Redirect(w, r, "/users", http.StatusSeeOther)
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
	role := r.FormValue("role")

	if len(name) > 20 || len(password) > 20{
		http.Error(w, "name or password should be maximum 20 character long", http.StatusBadRequest)
		return
	}

	var db_name int
	Qerr := utils.DB.QueryRow("SELECT COUNT(*) FROM users WHERE name = ?", name).Scan(&db_name)
	if Qerr != nil || db_name != 0{
		w.WriteHeader(http.StatusConflict)
   	w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"error":"Username is already taken"}`)
		return
	}

	hashpass, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		log.Fatal("Hashing error:", err)
	}
	
	sqlQuery := `INSERT INTO users (name, password, role) VALUES (?, ?, ?)`
	_, err = utils.DB.Exec(sqlQuery, name, string(hashpass), role)
	if err != nil {
		http.Error(w,"Cannot create user:", http.StatusInternalServerError)
	}

	http.Redirect(w, r, "/users", http.StatusSeeOther)
}

