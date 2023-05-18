// Package sql performs SQL operations
package sql

import (
	"database/sql"
	"fmt"
	"os"
	"strings"

	// Import the sqlite SQL driver
	_ "modernc.org/sqlite"
)

// CreateTable creates the table from the supplied values
func CreateTable(dbLocation string, tableName string, values []string) {
	// Open the SQLite DB at the provided location
	database, err := sql.Open("sqlite", dbLocation)
	// Handle any errors opening the DB
	if err != nil {
		fmt.Printf("Error opening SQLite DB File. Error: %v\n", err)
		os.Exit(2)
	}

	// Structure the headers
	headers := structureHeaders(values)

	// Create the table
	createTableQuery := `CREATE TABLE IF NOT EXISTS '` + tableName + `'(` + headers + `)`
	tableQuery, err := database.Prepare(createTableQuery)
	if err != nil {
		fmt.Printf("Improper SQL Query. Error: %v\n", err)
		os.Exit(3)
	}
	defer tableQuery.Close()
	tableQuery.Exec()
}

// InsertDB inserts data into the database
func InsertDB(dbLocation string, tableName string, headers []string, values [][]string) {
	// Open the SQLite DB at the provided location
	database, err := sql.Open("sqlite", dbLocation)
	// Handle any errors opening the DB
	if err != nil {
		fmt.Printf("Error opening SQLite DB File. Error: %v\n", err)
		os.Exit(2)
	}

	// Build insert query
	insertValueQuery := "INSERT INTO %v (%v) VALUES (%v)"
	headersString := strings.Join(headers[:], "', '")
	headersString = "'" + headersString + "'"
	valueCount := len(headers)
	count := 1
	valueString := "?"
	for count < valueCount {
		valueString = valueString + ", ?"
		count++
	}
	tableName = "'" + tableName + "'"
	insertValueQuery = fmt.Sprintf(insertValueQuery, tableName, headersString, valueString)

	// Insert the data
	tx, err := database.Begin()
	if err != nil {
		fmt.Println(err)
	}
	fmt.Printf("Inserting data into database: %v table: %v\n", dbLocation, tableName)
	rows := 0
	for _, value := range values {
		// Convert slice to interface
		row := make([]interface{}, len(value))
		for id := range value {
			row[id] = value[id]
		}
		insertQuery, err := tx.Prepare(insertValueQuery)
		if err != nil {
			fmt.Printf("Error in inserting data into DB. Error: %v\n", err)
			os.Exit(4)
		}
		defer insertQuery.Close()
		insertQuery.Exec(row...)
		rows++
	}
	tx.Commit()
	fmt.Printf("%v rows have been inserted into the table: %v\n", rows, tableName)
}

// RunQueries runs all queries on the sql database and returns a map of results
func RunQueries(dbLocation string, tableName string) (VulnBySeverity, []TopTenVulnHosts, []MostDangerousVulns, VulnByType, []CountCVSSYear) {
	// Open the SQLite DB at the provided location
	database, err := sql.Open("sqlite", dbLocation)
	// Handle any errors opening the DB
	if err != nil {
		fmt.Printf("Error opening SQLite DB File. Error: %v\n", err)
		os.Exit(2)
	}
	tableName = "'" + tableName + "'"
	vulnBySeverity := vulnBySeverity(database, tableName)
	topTenVulnHosts := topTenVulnHosts(database, tableName)
	mostDangerousVulns := mostDangerousVulns(database, tableName)
	vulnByType := vulnByType(database, tableName)
	countCVSSYear := countCVSSYear(database, tableName)
	return vulnBySeverity, topTenVulnHosts, mostDangerousVulns, vulnByType, countCVSSYear
}

func structureHeaders(headers []string) string {
	headersString := strings.Join(headers[:], "' TEXT, '")
	headersString = "'" + headersString + "' TEXT"
	headersString = strings.Replace(headersString, "'CVSS' TEXT", "'CVSS' NUMERIC", 1)
	return headersString
}

// Define vulnerability by severity structure
type VulnBySeverity struct {
	CritTotal int
	SevTotal  int
	HighTotal int
	MedTotal  int
	LowTotal  int
}

// Run vulnerability by severity query
func vulnBySeverity(conn *sql.DB, tableName string) VulnBySeverity {
	// Run the first query
	var res VulnBySeverity
	query := `
	SELECT
	(SELECT COUNT(*) FROM !! WHERE CVSS = 10) AS Critical,
	(SELECT COUNT(*) FROM !! WHERE CVSS BETWEEN 9 AND 9.9) AS Severe,
	(SELECT COUNT(*) FROM !! WHERE CVSS BETWEEN 7 and 8.9) AS High,
	(SELECT COUNT(*) FROM !! WHERE CVSS BETWEEN 4 and 6.9) AS Medium,
	(SELECT COUNT(*) FROM !! WHERE CVSS BETWEEN 0 and 3.9) AS Low
	`
	query = strings.Replace(query, "!!", tableName, -1)
	rows, err := conn.Query(query)
	if err != nil {
		fmt.Printf("Error running SQL Query. Error: %v\n", err)
		os.Exit(4)
	}
	for rows.Next() {
		rows.Scan(&res.CritTotal, &res.SevTotal, &res.HighTotal, &res.MedTotal, &res.LowTotal)
	}
	return res
}

// Define top ten vulnerabilities structure
type TopTenVulnHosts struct {
	MostVulnHost  string
	CVSSTotal     int
	CriticalTotal int
	SevereTotal   int
	HighTotal     int
	MediumTotal   int
	LowTotal      int
}

// Run top ten vulnerabilities query
func topTenVulnHosts(conn *sql.DB, tableName string) []TopTenVulnHosts {
	// Run the second query
	var res TopTenVulnHosts
	query := `
	SELECT Host, ROUND(SUM(CVSS)) AS CVSS_Total,
	SUM(CASE WHEN CVSS = 10 THEN 1 ELSE 0 END) AS Critical,
	SUM(CASE WHEN CVSS BETWEEN 9 AND 9.9 THEN 1 ELSE 0 END) AS Severe,
	SUM(CASE WHEN CVSS BETWEEN 7 AND 8.9 THEN 1 ELSE 0 END) AS High,
	SUM(CASE WHEN CVSS BETWEEN 4 AND 6.9 THEN 1 ELSE 0 END) AS Medium,
	SUM(CASE WHEN CVSS BETWEEN 0 AND 3.9 THEN 1 ELSE 0 END) AS Low
	FROM !! GROUP BY Host ORDER BY CVSS_Total DESC LIMIT 10
	`
	query = strings.Replace(query, "!!", tableName, -1)
	rows, err := conn.Query(query)
	if err != nil {
		fmt.Printf("Error running SQL Query. Error: %v\n", err)
		os.Exit(4)
	}
	results := []TopTenVulnHosts{}
	for rows.Next() {
		rows.Scan(&res.MostVulnHost, &res.CVSSTotal, &res.CriticalTotal, &res.SevereTotal, &res.HighTotal, &res.MediumTotal, &res.LowTotal)
		results = append(results, res)
	}
	return results
}

// Define most dangerous vulnerabilities structure
type MostDangerousVulns struct {
	VulnName  string
	CVSS      int
	CVSSTotal int
}

// Run most dangerous vulnerabilities query
func mostDangerousVulns(conn *sql.DB, tableName string) []MostDangerousVulns {
	// Run the second query
	var res MostDangerousVulns
	query := `
	SELECT Name, CVSS, COUNT(*) AS Total
	FROM !!
	WHERE CVSS BETWEEN 7 AND 10
	GROUP BY Name
	ORDER BY Total DESC
	LIMIT 10
	`
	query = strings.Replace(query, "!!", tableName, -1)
	rows, err := conn.Query(query)
	if err != nil {
		fmt.Printf("Error running SQL Query. Error: %v\n", err)
		os.Exit(4)
	}
	results := []MostDangerousVulns{}
	for rows.Next() {
		rows.Scan(&res.VulnName, &res.CVSS, &res.CVSSTotal)
		results = append(results, res)
	}
	return results
}

// Define vulnerabilty by type structure
type VulnByType struct {
	OracleCount    int
	MicrosoftCount int
	SSLCount       int
	FirefoxCount   int
	SMBCount       int
	ApacheCount    int
	PHPCount       int
	AdobeCount     int
}

// Run vulnerability by type query
func vulnByType(conn *sql.DB, tableName string) VulnByType {
	// Run the second query
	var res VulnByType
	query := `
	SELECT
	(SELECT COUNT(*) FROM !! WHERE Name LIKE '%Oracle%') AS Oracle,
	(SELECT COUNT(*) FROM !! WHERE Name LIKE '%Microsoft%') AS Microsoft,
	(SELECT COUNT(*) FROM !! WHERE Name LIKE '%SSL%' OR '%TLS%') AS SSL,
	(SELECT COUNT(*) FROM !! WHERE Name LIKE '%Firefox%') AS Firefox,
	(SELECT COUNT(*) FROM !! WHERE Name LIKE '%SMB%') AS SMB,
	(SELECT COUNT(*) FROM !! WHERE Name LIKE '%Apache%') AS Apache,
	(SELECT COUNT(*) FROM !! WHERE Name LIKE '%PHP%') AS PHP,
	(SELECT COUNT(*) FROM !! WHERE Name LIKE '%Adobe%') AS Adobe
	`
	query = strings.Replace(query, "!!", tableName, -1)
	rows, err := conn.Query(query)
	if err != nil {
		fmt.Printf("Error running SQL Query. Error: %v\n", err)
		os.Exit(4)
	}
	for rows.Next() {
		rows.Scan(&res.OracleCount, &res.MicrosoftCount, &res.SSLCount, &res.FirefoxCount, &res.SMBCount, &res.ApacheCount, &res.PHPCount, &res.AdobeCount)
	}
	return res
}

// Define count by year structure
type CountCVSSYear struct {
	Year  int
	Total int
}

// Run count by year query
func countCVSSYear(conn *sql.DB, tableName string) []CountCVSSYear {
	// Run the second query
	var res CountCVSSYear
	query := `
	SELECT SUBSTR(CVE,5,4) AS Year, COUNT(*) AS Total
	FROM !!
	WHERE CVE IS NOT ''
	GROUP BY Year
	ORDER BY Year DESC
	`
	query = strings.Replace(query, "!!", tableName, -1)
	rows, err := conn.Query(query)
	if err != nil {
		fmt.Printf("Error running SQL Query. Error: %v\n", err)
		os.Exit(4)
	}
	results := []CountCVSSYear{}
	for rows.Next() {
		rows.Scan(&res.Year, &res.Total)
		results = append(results, res)
	}
	return results
}
