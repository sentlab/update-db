package main

import (
	"database/sql"
	"fmt"

	_ "github.com/mattn/go-sqlite3"
)

// UpdateMatchStatus updates the match status in the database for a given serial number.
func UpdateMatchStatus(db *sql.DB, serialNumber string, columnHeader string, value string) error {
	query := fmt.Sprintf("UPDATE PopularBank SET %q = ? WHERE id = ?", columnHeader)
	_, err := db.Exec(query, value, serialNumber)
	if err != nil {
		return err
	}
	return nil
}
