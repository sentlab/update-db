// Package sql performs SQL operations
package sql

import (
	"database/sql"
	"encoding/csv"
	"fmt"
	"log"
	"os"
	"strings"

	_ "github.com/mattn/go-sqlite3"
)

const (
	tableName = "Data_Input"
)

var csvHeaders []string

func sqlupdate() {
	const dbPath = "vulns.db"
	// Check the command-line arguments
	if len(os.Args) < 2 {
		log.Fatal("Please provide the path to the CSV file")
	}
	csvFilePath := os.Args[1]

	// Open the database connection
	db, err := sql.Open("sqlite3", dbPath)
	if err != nil {
		log.Fatalf("Failed to open database connection: %v", err)
	}
	defer db.Close()

	// Verify the database connection
	err = db.Ping()
	if err != nil {
		log.Fatalf("Failed to ping database: %v", err)
	}

	// Create the table if it doesn't exist
	err = createTable(db, csvFilePath)
	if err != nil {
		log.Fatalf("Failed to create table: %v", err)
	}

	// Insert data from CSV into the table
	err = insertData(db, csvFilePath)
	if err != nil {
		log.Fatalf("Failed to insert data into table: %v", err)
	}

	fmt.Println("Data insertion completed successfully.")
}

func createTable(db *sql.DB, csvFilePath string) error {
	// Check if the table already exists
	tableExists := false
	err := db.QueryRow("SELECT name FROM sqlite_master WHERE type='table' AND name=?", tableName).Scan(&tableExists)
	if err != nil && err != sql.ErrNoRows {
		return fmt.Errorf("failed to check if table exists: %v", err)
	}

	if tableExists {
		fmt.Printf("Table '%s' already exists\n", tableName)
		return nil
	}

	// Open the CSV file
	file, err := os.Open(csvFilePath)
	if err != nil {
		return fmt.Errorf("failed to open CSV file: %v", err)
	}
	defer file.Close()

	// Read the header row from the CSV file
	reader := csv.NewReader(file)
	header, err := reader.Read()
	if err != nil {
		return fmt.Errorf("failed to read CSV header: %v", err)
	}

	// Convert header values by replacing "." with "_"
	for i, column := range header {
		header[i] = strings.ReplaceAll(column, ".", "_")
	}

	// Create the table
	createTableSQL := fmt.Sprintf("CREATE TABLE IF NOT EXISTS %s (", tableName)
	for i, column := range header {
		createTableSQL += column + " TEXT"
		if i != len(header)-1 {
			createTableSQL += ", "
		}
	}
	createTableSQL += ");"

	fmt.Printf("createTableSQL: %s\n", createTableSQL)

	_, err = db.Exec(createTableSQL)
	if err != nil {
		return fmt.Errorf("failed to create table: %v", err)
	}

	return nil
}

func insertData(db *sql.DB, csvFilePath string) error {
	// Open the CSV file
	file, err := os.Open(csvFilePath)
	if err != nil {
		return fmt.Errorf("failed to open CSV file: %v", err)
	}
	defer file.Close()

	// Read the CSV records
	reader := csv.NewReader(file)
	records, err := reader.ReadAll()
	if err != nil {
		return fmt.Errorf("failed to read CSV records: %v", err)
	}

	// Start a transaction
	tx, err := db.Begin()
	if err != nil {
		return fmt.Errorf("failed to start transaction: %v", err)
	}
	defer func() {
		if err != nil {
			_ = tx.Rollback() // Rollback the transaction if there's an error
			return
		}
		err = tx.Commit() // Commit the transaction
	}()

	// Prepare the SQL statement to insert data
	insertDataSQL := fmt.Sprintf("INSERT INTO %s VALUES (", tableName)
	for range records[0] {
		insertDataSQL += "?,"
	}
	insertDataSQL = insertDataSQL[:len(insertDataSQL)-1] + ")"

	// Prepare the SQL statement
	stmt, err := tx.Prepare(insertDataSQL)
	if err != nil {
		return fmt.Errorf("failed to prepare SQL statement: %v", err)
	}
	defer stmt.Close()

	// Iterate over the CSV records and insert into the table
	for idx, record := range records {
		// Check if the record has the correct number of columns
		if len(record) != len(records[0]) {
			return fmt.Errorf("invalid number of columns in CSV record at index %d", idx)
		}

		// Convert the record slice to []interface{} type
		recordValues := make([]interface{}, len(record))
		for i, value := range record {
			recordValues[i] = value
		}

		result, err := stmt.Exec(recordValues...)
		if err != nil {
			return fmt.Errorf("failed to insert data into the table at index %d: %v", idx, err)
		}

		affectedRows, _ := result.RowsAffected()
		fmt.Printf("Inserted row %d: %v (Rows affected: %d)\n", idx, record, affectedRows)
	}

	// Commit the transaction
	err = tx.Commit()
	if err != nil {
		return fmt.Errorf("failed to commit transaction: %v", err)
	}

	return nil
}
