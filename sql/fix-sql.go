package main

import (
	"database/sql"
	"fmt"
	"log"
	"strings"

	_ "github.com/mattn/go-sqlite3"
)

func main() {
	// Open the database connection
	db, err := sql.Open("sqlite3", "./vulns.db")
	if err != nil {
		log.Fatal(err)
	}
	defer db.Close()

	// Get the list of columns in the PopularBank table
	columnsQuery := "PRAGMA table_info(`PopularBank`)"
	rows, err := db.Query(columnsQuery)
	if err != nil {
		log.Fatal(err)
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
			log.Fatal(err)
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
		log.Fatal(err)
	}

	fmt.Println("Update operation completed successfully.")
}
