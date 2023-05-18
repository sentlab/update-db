// Package sql performs SQL operations
package sql

import (
	"database/sql"
	"fmt"
	"log"
	"os"

	_ "github.com/mattn/go-sqlite3"
)

func updatesql() {
	// Check if column name argument is provided
	if len(os.Args) < 2 {
		log.Fatal("Please provide a column name as an argument.")
	}
	columnName := os.Args[1]

	// Connect to the SQLite database
	db, err := sql.Open("sqlite3", "./vulns.db")
	if err != nil {
		log.Fatal(err)
	}
	defer db.Close()

	// Add new column to the "PopularBank" table.
	alterTableSql := fmt.Sprintf(`ALTER TABLE PopularBank ADD COLUMN %s TEXT;`, columnName)
	_, err = db.Exec(alterTableSql)
	if err != nil {
		log.Fatalf("Failed to alter table: %v", err)
	}

	// Update the new column in PopularBank with the corresponding value from Data_Input
	updateStateSql := fmt.Sprintf(`UPDATE PopularBank
			SET %s = (
				SELECT state FROM Data_Input
				WHERE PopularBank.id = Data_Input.id
			);`, columnName)

	_, err = db.Exec(updateStateSql)
	if err != nil {
		log.Fatalf("Failed to update state: %v", err)
	}

	fmt.Println("Update operation completed successfully!")
}
