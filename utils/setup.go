package utils

import (
   "database/sql"
   "fmt"
   "log"
   _ "net/http"
	"os"
	_ "html/template"
	_ "github.com/joho/godotenv"
   _ "github.com/go-sql-driver/mysql"
)

func Setup(){
	var err error

	dsn := fmt.Sprintf("%s:%s@tcp(%s:%s)/",
		os.Getenv("DB_USER"),
		os.Getenv("DB_PASS"),
		os.Getenv("DB_HOST"),
		os.Getenv("DB_PORT"),
	)
	DB, err = sql.Open("mysql", dsn)
   if err != nil {
       log.Fatal(err)
   }
   defer DB.Close()

   if err = DB.Ping(); err != nil {
       log.Fatal(err)
   }
	
	_, err = DB.Exec("CREATE DATABASE IF NOT EXISTS test")
   if err != nil {
       log.Fatal("Cannot create database:", err)
   }
	
	//users table
	dsnWithDB := fmt.Sprintf("%s:%s@tcp(%s:%s)/%s",
		os.Getenv("DB_USER"),
		os.Getenv("DB_PASS"),
		os.Getenv("DB_HOST"),
		os.Getenv("DB_PORT"),
		os.Getenv("DB_NAME"),
	)

	DB, err = sql.Open("mysql", dsnWithDB)
	if err != nil {
		log.Fatal(err)
	}
	defer DB.Close()

	if err = DB.Ping(); err != nil {
		log.Fatal(err)
	}

	createTableQuery := `
	CREATE TABLE IF NOT EXISTS users (
		id INT AUTO_INCREMENT PRIMARY KEY,
		name VARCHAR(20) NOT NULL,
		password VARCHAR(60) NOT NULL,
		role VARCHAR(20)
	);`

	_, err = DB.Exec(createTableQuery)
	if err != nil {
		log.Fatal("Cannot create users table:", err)
	}

	createTokenQuery := `
	CREATE TABLE IF NOT EXISTS tokens (
		id INT NOT NULL,
		sessionToken VARCHAR(255),
		sessionExpires DATETIME,
		csrfToken VARCHAR(255),
		csrfExpires DATETIME
	);`
   
	_, err = DB.Exec(createTokenQuery)
	if err != nil {
		log.Fatal("Cannot create token table:", err)
	}

	fmt.Println("Succesful setup")

	dsn = fmt.Sprintf("%s:%s@tcp(%s:%s)/%s",
		os.Getenv("DB_USER"),
		os.Getenv("DB_PASS"),
		os.Getenv("DB_HOST"),
		os.Getenv("DB_PORT"),
		os.Getenv("DB_NAME"),
	)
	DB, err = sql.Open("mysql", dsn)
   if err != nil {
       log.Fatal(err)
   }

   if err = DB.Ping(); err != nil {
       log.Fatal(err)
   }
   fmt.Println("Success connecting to test")
}
