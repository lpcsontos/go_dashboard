package handlers

import (
	"dashboard/utils"
   _ "database/sql"
	_"fmt"
	_"time"
   _"log"
   "net/http"
	_ "os"
	_ "github.com/joho/godotenv"
   _ "github.com/go-sql-driver/mysql"
	_ "golang.org/x/crypto/bcrypt"
)


func TestHand( w http.ResponseWriter, r *http.Request){
	err := utils.TestPage.Execute(w, nil)
	if err != nil {
		http.Error(w, "404", http.StatusInternalServerError)
	}
}

