// Package sql performs SQL operations
package sql

import (
	"database/sql"
	"fmt"
	"log"

	_ "github.com/mattn/go-sqlite3"
)

type Vulnerability struct {
	OperatingSystem string
	Severity        string
	State           string
	Count           int
}

func vulnByTypePerOs(conn *sql.DB, tableName string, columnName string, os string, lastColumn string) []Vulnerability {
	query := fmt.Sprintf(`
	SELECT
		asset_operating_system AS OperatingSystem,
		Severity,
		%s AS State,
		COUNT(*) AS Count
	FROM %s
	WHERE Severity IN ('Critical', 'High', 'Medium', 'Low')
		AND %s IN ('ACTIVE', 'RESURFACED', 'FIXED', 'NEW')
		AND asset_operating_system = '%s'
	GROUP BY asset_operating_system, Severity, State
	`, lastColumn, tableName, columnName, os)

	rows, err := conn.Query(query)
	if err != nil {
		log.Fatalf("Error running SQL Query. Error: %v\n", err)
	}

	var vulnerabilities []Vulnerability
	for rows.Next() {
		var v Vulnerability
		err := rows.Scan(&v.OperatingSystem, &v.Severity, &v.State, &v.Count)
		if err != nil {
			log.Fatalf("Error scanning row. Error: %v\n", err)
		}
		vulnerabilities = append(vulnerabilities, v)
	}
	return vulnerabilities
}

func getDistinctOs(db *sql.DB, tableName string, columnName string) []string {
	var osList []string
	rows, err := db.Query(fmt.Sprintf("SELECT DISTINCT %s FROM %s", columnName, tableName))
	if err != nil {
		log.Fatal(err)
	}
	defer rows.Close()
	for rows.Next() {
		var os string
		if err := rows.Scan(&os); err != nil {
			log.Fatal(err)
		}
		osList = append(osList, os)
	}
	if err := rows.Err(); err != nil {
		log.Fatal(err)
	}
	return osList
}

func getLastColumnName(db *sql.DB, tableName string) (string, error) {
	rows, err := db.Query(fmt.Sprintf("PRAGMA table_info(%s)", tableName))
	if err != nil {
		return "", err
	}
	defer rows.Close()

	var lastColumnName string
	for rows.Next() {
		var cid int
		var name string
		var type_ string
		var notnull int
		var dflt_value interface{}
		var pk int

		err = rows.Scan(&cid, &name, &type_, &notnull, &dflt_value, &pk)
		if err != nil {
			return "", err
		}

		lastColumnName = name
	}

	return lastColumnName, nil
}

func createResultTable(db *sql.DB) error {
	_, err := db.Exec(`
		CREATE TABLE IF NOT EXISTS ResultTable (
			OperatingSystem TEXT,
			Severity TEXT,
			State TEXT,
			Count INTEGER
		)`)
	return err
}

func clearResultTable(db *sql.DB) error {
	_, err := db.Exec("DELETE FROM ResultTable")
	return err
}
func insertResultsIntoTable(db *sql.DB, tableName string, vulnerabilities []Vulnerability) error {
	// Prepare the SQL statement
	stmt, err := db.Prepare(fmt.Sprintf("INSERT INTO %s (OperatingSystem, Severity, State, Count) VALUES (?, ?, ?, ?)", tableName))
	if err != nil {
		return err
	}
	defer stmt.Close()

	// Insert each vulnerability into the table
	for _, v := range vulnerabilities {
		_, err := stmt.Exec(v.OperatingSystem, v.Severity, v.State, v.Count)
		if err != nil {
			return err
		}
	}

	return nil
}

func countbyOS() {
	db, err := sql.Open("sqlite3", "./vulns.db")
	if err != nil {
		log.Fatal(err)
	}
	defer db.Close()

	tableName := "PopularBank"
	resultTableName := "ResultTable"

	// Create the ResultTable if it doesn't exist
	err = createResultTable(db)
	if err != nil {
		log.Fatal(err)
	}

	query := fmt.Sprintf(`
		SELECT
			asset_operating_system AS OperatingSystem,
			Severity,
			date_123456 AS State,
			COUNT(*) AS Count
		FROM %s
		WHERE Severity IN ('Critical', 'High', 'Medium', 'Low')
			AND date_123456 IN ('ACTIVE', 'RESURFACED', 'FIXED', 'NEW')
		GROUP BY asset_operating_system, Severity, State
		`, tableName)

	rows, err := db.Query(query)
	if err != nil {
		log.Fatalf("Error running SQL Query. Error: %v\n", err)
	}
	defer rows.Close()

	var vulnerabilities []Vulnerability

	for rows.Next() {
		var v Vulnerability
		err := rows.Scan(&v.OperatingSystem, &v.Severity, &v.State, &v.Count)
		if err != nil {
			log.Fatalf("Error scanning row. Error: %v\n", err)
		}
		vulnerabilities = append(vulnerabilities, v)
		log.Printf("Operating System: %s, Severity: %s, State: %s, Count: %d\n", v.OperatingSystem, v.Severity, v.State, v.Count)
	}

	if err := rows.Err(); err != nil {
		log.Fatal(err)
	}

	// Clear the ResultTable
	err = clearResultTable(db)
	if err != nil {
		log.Fatal(err)
	}

	// Insert the results into the ResultTable
	err = insertResultsIntoTable(db, resultTableName, vulnerabilities)
	if err != nil {
		log.Fatal(err)
	}
}
