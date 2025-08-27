package auth

import(
	_"database/sql"
	"dashboard/utils"
	_"fmt"
   "log"
	"time"
   "net/http"
	_"strings"
	_ "os"
	_ "github.com/joho/godotenv"
   _ "github.com/go-sql-driver/mysql"
	_"golang.org/x/crypto/bcrypt"
	_"crypto/rand"
	_"encoding/base64"
	_"html/template"
	_"errors"
)



func IsLoggedIn(r *http.Request) bool {

	st, err := r.Cookie("session_token")
	if err != nil || st.Value == ""{
		return false
	}

	var db int
	qerr := utils.DB.QueryRow("SELECT COUNT(*) as count FROM users WHERE id = (SELECT id FROM tokens WHERE sessionToken = ?)", st.Value).Scan(&db)
	if qerr != nil || db == 0{
		log.Println("User not found:", qerr)
		return false
	}

	var sessionExpiresStr string
	qerr = utils.DB.QueryRow("SELECT sessionExpires FROM tokens WHERE sessionToken = ?", st.Value).Scan(&sessionExpiresStr)
	if qerr != nil{
		log.Println("User not found:", qerr)
		return false
	}

	sessionExpires, err := time.Parse("2006-01-02 15:04:05", sessionExpiresStr)
	if err != nil {
   	log.Println("Time parse error:", err)
   	return false
	}

	if time.Now().After(sessionExpires) {
   	log.Println("Session expired for user")
   	return false
	}

	return true
}

func IsLoggedInAdmin(r *http.Request) bool {

	st, err := r.Cookie("session_token")
	if err != nil || st.Value == ""{
		return false
	}

	var db int
	qerr := utils.DB.QueryRow("SELECT COUNT(*) as count FROM users WHERE id = (SELECT id FROM tokens WHERE sessionToken = ?)", st.Value).Scan(&db)
	if qerr != nil || db == 0{
		log.Println("User not found:", qerr)
		return false
	}

	var sessionExpiresStr string
	qerr = utils.DB.QueryRow("SELECT sessionExpires FROM tokens WHERE sessionToken = ?", st.Value).Scan(&sessionExpiresStr)
	if qerr != nil{
		log.Println("sessionExpire not found:", qerr)
		return false
	}

	var role string
	qerr = utils.DB.QueryRow("SELECT role FROM users WHERE id = (SELECT id FROM tokens WHERE sessionToken = ?)", st.Value).Scan(&role)
	if qerr != nil{
		log.Println("role not found:", qerr)
		return false
	}
	if role != "admin"{
		log.Println("users is not admin")
		return false
	}

	sessionExpires, err := time.Parse("2006-01-02 15:04:05", sessionExpiresStr)
	if err != nil {
   	log.Println("Time parse error:", err)
   	return false
	}

	if time.Now().After(sessionExpires) {
   	log.Println("Session expired for user")
   	return false
	}

	return true
}

func Auth(next http.HandlerFunc) http.HandlerFunc {
    return func(w http.ResponseWriter, r *http.Request) {
        if !IsLoggedIn(r) {
            http.Redirect(w, r, "/login", http.StatusSeeOther)
            return
        }
        next(w, r)
    }
}

func AuthAdmin(next http.HandlerFunc) http.HandlerFunc {
    return func(w http.ResponseWriter, r *http.Request) {
        if !IsLoggedInAdmin(r) {
            http.Redirect(w, r, "/login", http.StatusSeeOther)
            return
        }
        next(w, r)
    }
}

const csrfCookieName = "csrf_token"
const csrfHeaderName = "X-CSRF-Token"

func CSRFMiddleware(next http.HandlerFunc) http.HandlerFunc {
    return func(w http.ResponseWriter, r *http.Request) {
         cookie, err := r.Cookie(csrfCookieName)
         if err != nil || cookie.Value == "" {
            http.Error(w, "Missing CSRF cookie", http.StatusForbidden)
         	return
         }

				st, err := r.Cookie("session_token")
				if err != nil || st.Value == ""{
					return
			}
			
			var csrfExpiresStr string
			qerr := utils.DB.QueryRow("SELECT csrfExpires FROM tokens WHERE sessionToken = ?", st.Value).Scan(&csrfExpiresStr)
			if qerr != nil{
				log.Println("csrfExpire not found:", qerr)
				return
			}

			csrfExpires, err := time.Parse("2006-01-02 15:04:05", csrfExpiresStr)
			if err != nil {
   			log.Println("Time parse error:", err)
   			return
			}

			if time.Now().After(csrfExpires) {
   			log.Println("csrf expired for user")
   			return
			}

         headerToken := r.Header.Get(csrfHeaderName)
			if headerToken == "" || headerToken != cookie.Value {
				log.Println(headerToken + " : " + cookie.Value) 
				http.Error(w, "Invalid CSRF token", http.StatusForbidden)
				return
        }

        next(w, r)
    }
}

func CSRFMiddlewareAdmin(next http.HandlerFunc) http.HandlerFunc {
    return func(w http.ResponseWriter, r *http.Request) {
         cookie, err := r.Cookie(csrfCookieName)
         if err != nil || cookie.Value == "" {
            http.Error(w, "Missing CSRF cookie", http.StatusForbidden)
         	return
         }

				st, err := r.Cookie("session_token")
				if err != nil || st.Value == ""{
					return
			}
			
			var csrfExpiresStr string
			qerr := utils.DB.QueryRow("SELECT csrfExpires FROM tokens WHERE sessionToken = ?", st.Value).Scan(&csrfExpiresStr)
			if qerr != nil{
				log.Println("csrfExpire not found:", qerr)
				return
			}

			var role string
			qerr = utils.DB.QueryRow("SELECT role FROM users WHERE id = (SELECT id FROM tokens WHERE sessionToken = ?)", st.Value).Scan(&role)
			if qerr != nil{
				log.Println("role not found:", qerr)
				return
			}
			if role != "admin"{
				log.Println("users is not admin")
				return
			}

			csrfExpires, err := time.Parse("2006-01-02 15:04:05", csrfExpiresStr)
			if err != nil {
   			log.Println("Time parse error:", err)
   			return
			}

			if time.Now().After(csrfExpires) {
   			log.Println("csrf expired for user")
   			return
			}
			
			headerToken := r.Header.Get(csrfHeaderName)
			if headerToken == "" || headerToken != cookie.Value {
				log.Println(headerToken + " : " + cookie.Value) 
				http.Error(w, "Invalid CSRF token", http.StatusForbidden)
				return
        }

        next(w, r)
    }
}
