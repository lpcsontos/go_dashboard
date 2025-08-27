package handlers

import (
	"db_test/utils"
   _ "database/sql"
	_"fmt"
   _ "log"
   "net/http"
	_ "os"
	_ "github.com/joho/godotenv"
   _ "github.com/go-sql-driver/mysql"
	_"golang.org/x/crypto/bcrypt"
)

func Root( w http.ResponseWriter, r *http.Request){
	err := utils.IndPage.Execute(w, nil)
	if err != nil {
		http.Error(w, "404", http.StatusInternalServerError)
	}
}
