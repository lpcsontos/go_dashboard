package utils

import(
	"database/sql"
	_"fmt"
   "log"
   _"net/http"
	_"strings"
	_ "os"
	_ "github.com/joho/godotenv"
   _ "github.com/go-sql-driver/mysql"
	"golang.org/x/crypto/bcrypt"
	"crypto/rand"
	"encoding/base64"
	"html/template"
	_"errors"
)


var RegPage = template.Must(template.ParseFiles("pages/register.html"))
var LoginPage = template.Must(template.ParseFiles("pages/login.html"))
var TestPage = template.Must(template.ParseFiles("pages/test.html"))

var DB *sql.DB

func PassComp(hashpass string, normpass string) bool{
	err := bcrypt.CompareHashAndPassword([]byte(hashpass), []byte(normpass))
	return err == nil
}

func GenToken(length int) string{
	bytes := make([]byte, length)
	if _,err := rand.Read(bytes); err!=nil {
		log.Fatalf("failed to gen token %v", err)
	}

	return base64.RawURLEncoding.EncodeToString(bytes);
}


