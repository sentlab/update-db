package main

import (
	dbsql "database/sql"
	"encoding/csv"
	"fmt"
	"os"

	_ "github.com/go-sql-driver/mysql"
	"github.com/sentlab/update-db/excel"
	"github.com/sentlab/update-db/sql"
)

func main() {
	// os.Args[1] should contain your database connection string.
	db, err := dbsql.Open("mysql", os.Args[1])
	if err != nil {
		fmt.Printf("Error opening DB. Error: %v\n", err)
		os.Exit(1)
	}
	defer db.Close()

	// os.Args[2] should contain the table name to use in queries.
	tableName := os.Args[2]

	// os.Args[3] should contain the path to the CSV file to upload.
	csvFilePath := os.Args[3]

	// Upload the CSV file to the database table.
	err = uploadCSV(db, tableName, csvFilePath)
	if err != nil {
		fmt.Printf("Error uploading CSV file. Error: %v\n", err)
		os.Exit(1)
	}

	// Execute the original SQL queries and populate the data structures.
	// Call your RunQueries function to execute the queries and populate the data structures.
	vulnBySeverity, topTenVulnHosts, mostDangerousVulns, vulnByType, countCVSSYear := sql.RunQueries(db, tableName)
	if err != nil {
		fmt.Printf("Error executing queries. Error: %v\n", err)
		os.Exit(1)
	}
	// os.Args[4] should contain the path to the Excel file you want to update.
	fileLocation := os.Args[4]

	// Call the WriteData function to write the data to the Excel file.
	excel.WriteData(fileLocation, vulnBySeverity, topTenVulnHosts, mostDangerousVulns, vulnByType, countCVSSYear)
	if err != nil {
		fmt.Printf("Error writing data to Excel file. Error: %v\n", err)
		os.Exit(1)
	}

	fmt.Println("Data written to Excel file successfully.")
}

func uploadCSV(db *dbsql.DB, tableName string, csvFilePath string) error {
	file, err := os.Open(csvFilePath)
	if err != nil {
		return err
	}
	defer file.Close()

	reader := csv.NewReader(file)
	reader.FieldsPerRecord = -1 // Allow variable number of fields

	records, err := reader.ReadAll()
	if err != nil {
		return err
	}

	// Truncate the table before uploading the CSV data
	_, err = db.Exec(fmt.Sprintf("TRUNCATE TABLE %s", tableName))
	if err != nil {
		return err
	}

	// Prepare the SQL statement for inserting data
	stmt, err := db.Prepare(fmt.Sprintf("INSERT INTO %s VALUES(%s)", tableName, generatePlaceholders(len(records[0]))))
	if err != nil {
		return err
	}
	defer stmt.Close()

	// Insert each record into the table
	for _, record := range records {
		// Convert record to []interface{}
		recordValues := make([]interface{}, len(record))
		for i, v := range record {
			recordValues[i] = v
		}

		_, err := stmt.Exec(recordValues...)
		if err != nil {
			return err
		}
	}

	return nil
}

func generatePlaceholders(count int) string {
	placeholders := make([]byte, 2*count-1)
	for i := 0; i < count; i++ {
		placeholders[2*i] = '?'
		if i < count-1 {
			placeholders[2*i+1] = ','
		}
	}
	return string(placeholders)
}
