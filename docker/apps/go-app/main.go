package main

import (
	"database/sql"
	"fmt"
	"log"
	"os"

	_ "github.com/lib/pq"
)

func main() {
	host := os.Getenv("PGHOST")
	port := os.Getenv("PGPORT")
	user := os.Getenv("PGUSER")
	password := os.Getenv("PGPASSWORD")
	dbname := os.Getenv("PGDATABASE")

	connStr := fmt.Sprintf("host=%s port=%s user=%s password=%s dbname=%s sslmode=disable",
		host, port, user, password, dbname)

	db, err := sql.Open("postgres", connStr)
	if err != nil {
		log.Fatal("Failed to connect:", err)
	}
	defer db.Close()

	log.Println("[Go App] Connected to PostgreSQL")

	queries := []string{
		"SELECT version()",
		"SELECT current_timestamp",
		"SELECT COUNT(*) FROM pg_tables",
		"SELECT 1 + 1 as result",
		"SELECT random() * 100 as random_number",
	}

	for i, query := range queries {
		var result string
		err := db.QueryRow(query).Scan(&result)
		if err != nil {
			log.Printf("[Go App] Query %d failed: %v", i+1, err)
		} else {
			log.Printf("[Go App] Query %d result: %s", i+1, result)
		}
	}

	log.Println("[Go App] Completed all queries, exiting...")
}
