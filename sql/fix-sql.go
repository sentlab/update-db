// Package sql performs SQL operations
package sql

import (
	"database/sql"
	"fmt"

	//"log"
	"strings"

	_ "github.com/mattn/go-sqlite3"
)

// Fix Sql null values in the database
func FixSql(dbPath string) error {
	// Open the database connection
	db, err := sql.Open("sqlite3", dbPath)
	if err != nil {
		return fmt.Errorf("unable to connect to database: %w", err)
	}
	defer db.Close()

	// Get the list of columns in the PopularBank table
	columnsQuery := "PRAGMA table_info(`PopularBank`)"
	rows, err := db.Query(columnsQuery)
	if err != nil {
		return fmt.Errorf("unable to execute query: %w", err)
	}
	defer rows.Close()

	var columnNames []string
	for rows.Next() {
		var cid int
		var name string
		var dataType string
		var notNull int
		var defaultValue interface{}
		var primaryKey int

		err := rows.Scan(&cid, &name, &dataType, &notNull, &defaultValue, &primaryKey)
		if err != nil {
			return fmt.Errorf("unable to scan row: %w", err)
		}

		columnNames = append(columnNames, name)
	}

	// Update each row and replace null values with empty strings
	updateColumns := make([]string, len(columnNames))
	for i, colName := range columnNames {
		updateColumns[i] = fmt.Sprintf("`%s` = COALESCE(`%s`, '')", colName, colName)
	}
	updateQuery := fmt.Sprintf("UPDATE `PopularBank` SET %s", strings.Join(updateColumns, ", "))

	_, err = db.Exec(updateQuery)
	if err != nil {
		return fmt.Errorf("unable to execute update query: %w", err)
	}

	fmt.Println("Update operation completed successfully.")
	return nil
}
