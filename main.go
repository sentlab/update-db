package main

import (
	"database/sql"
	"encoding/csv"
	"fmt"
	"log"
	"os"
	"strings"

	_ "github.com/mattn/go-sqlite3"
)

func main() {
	log.SetOutput(os.Stdout) // Set log output to standard output

	// Check if command-line arguments are provided
	if len(os.Args) < 2 {
		fmt.Println("Please provide a file path as a command-line argument.")
		return
	}

	filePath := os.Args[1] // Get the file path from command-line argument

	// Open the SQLite database
	db, err := sql.Open("sqlite3", "vulns.db")
	if err != nil {
		log.Fatal(err)
	}
	defer db.Close()

	// Load CSV data into the "TempData" table
	err = loadCSVData(db, filePath)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Println("CSV data imported into TempData table successfully.")
}

// Create the "TempData" table
func createTempDataTable(db *sql.DB, columnHeaders []string) error {
	// Generate the column definitions based on the provided column headers
	columnDefinitions := make([]string, len(columnHeaders))
	for range columnHeaders {
		columnDefinitions = append(columnDefinitions, "?")
	}

	// Construct the CREATE TABLE query
	query := fmt.Sprintf("CREATE TABLE IF NOT EXISTS TempData (%s)", strings.Join(columnDefinitions, ","))

	_, err := db.Exec(query)
	if err != nil {
		return err
	}
	return nil
}

// Load CSV data into the "TempData" table
func loadCSVData(db *sql.DB, filePath string) error {
	// Open the CSV file
	file, err := os.Open(filePath)
	if err != nil {
		return err
	}
	defer file.Close()

	// Read the CSV file
	reader := csv.NewReader(file)
	records, err := reader.ReadAll()
	if err != nil {
		return err
	}

	// Get the column headers from the first record
	columnHeaders := records[0]

	// Create the "TempData" table with dynamic column headers
	err = createTempDataTable(db, columnHeaders)
	if err != nil {
		return err
	}

	// Prepare the SQL statement to insert data into the "TempData" table
	numColumns := len(columnHeaders)
	placeholders := strings.Repeat("?,", numColumns)
	placeholders = placeholders[:len(placeholders)-1] // Remove the trailing comma

	// Construct the INSERT INTO query with column names
	columnNames := strings.Join(columnHeaders, ",")
	query := fmt.Sprintf("INSERT INTO TempData (%s) VALUES (%s)", columnNames, placeholders)

	stmt, err := db.Prepare(query)
	if err != nil {
		return err
	}
	defer stmt.Close()

	// Insert data into the "TempData" table
	for _, record := range records[1:] {
		args := make([]interface{}, len(record))
		for i, v := range record {
			args[i] = v
		}
		_, err := stmt.Exec(args...)
		if err != nil {
			return err
		}
	}

	return nil
}
