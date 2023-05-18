// Package excel performs excel function
package excel

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"

	"github.com/sentlab/update-db/sql/sql-query"

	"github.com/xuri/excelize/v2"
)

// WriteData function writes the query values to the appropriate pages
func WriteData(fileLocation string, CvssBySeverity sql-query.CvssBySeverity , topTenVulnHosts []sql.TopTenVulnHosts, mostDangerousVulns []sql.MostDangerousVulns, vulnByType sql.VulnByType, countCVSSYear []sql.CountCVSSYear, rawHeaders []string, rawRecords [][]string) {
	// Open the Excel Doc at the provided location
	file, err := excelize.OpenFile(fileLocation)
	// Handle any errors opening the DB
	if err != nil {
		fmt.Printf("Error opening Excel File. Error: %v\n", err)
		os.Exit(2)
	}
	writeCVSSBySev(file, "CVSS By Severity", CvssBySeverity)
	writeTopTens(file, "Top Vulnerable Hosts", topTenVulnHosts)
	writeMostDang(file, "Most Common Vulnerabilities", mostDangerousVulns)
	writeVulnByType(file, "Vulnerabilities By Type", vulnByType)
	writeByYear(file, "Vulnerabilities By Year", countCVSSYear)
	writeRow(file, "Scan Data", 1, rawHeaders)
	writeMultipleRow(file, "Scan Data", rawRecords)
	newFile := ""
	if filepath.Dir(fileLocation) == "." {
		newFile = "Populated_" + filepath.Base(fileLocation)
	} else {
		newFile = filepath.Dir(fileLocation) + "Populated_" + filepath.Base(fileLocation)
	}
	if err := file.SaveAs(newFile); err != nil {
		fmt.Println(err)
	}
}

func writeCVSSBySev(file *excelize.File, sheet string, values sql.VulnBySeverity) {
	file.SetCellInt(sheet, "A2", values.CritTotal)
	file.SetCellInt(sheet, "B2", values.SevTotal)
	file.SetCellInt(sheet, "C2", values.HighTotal)
	file.SetCellInt(sheet, "D2", values.MedTotal)
	file.SetCellInt(sheet, "E2", values.LowTotal)
}

func writeTopTens(file *excelize.File, sheet string, values []sql.TopTenVulnHosts) {
	for id, value := range values {
		row := id + 2
		writeTopTenVulnHosts(file, sheet, row, value)
	}
}

func writeTopTenVulnHosts(file *excelize.File, sheet string, row int, values sql.TopTenVulnHosts) {
	strRow := strconv.Itoa(row)
	file.SetCellStr(sheet, "A"+strRow, values.MostVulnHost)
	file.SetCellInt(sheet, "B"+strRow, values.CVSSTotal)
	file.SetCellInt(sheet, "C"+strRow, values.CriticalTotal)
	file.SetCellInt(sheet, "D"+strRow, values.SevereTotal)
	file.SetCellInt(sheet, "E"+strRow, values.HighTotal)
	file.SetCellInt(sheet, "F"+strRow, values.MediumTotal)
	file.SetCellInt(sheet, "G"+strRow, values.LowTotal)
}

func writeMostDang(file *excelize.File, sheet string, values []sql.MostDangerousVulns) {
	for id, value := range values {
		row := id + 2
		writeMostDangerousVulns(file, sheet, row, value)
	}
}

func writeMostDangerousVulns(file *excelize.File, sheet string, row int, values sql.MostDangerousVulns) {
	strRow := strconv.Itoa(row)
	file.SetCellStr(sheet, "A"+strRow, values.VulnName)
	file.SetCellInt(sheet, "B"+strRow, values.CVSS)
	file.SetCellInt(sheet, "C"+strRow, values.CVSSTotal)
}

func writeVulnByType(file *excelize.File, sheet string, values sql.VulnByType) {
	file.SetCellInt(sheet, "A2", values.OracleCount)
	file.SetCellInt(sheet, "B2", values.MicrosoftCount)
	file.SetCellInt(sheet, "C2", values.SSLCount)
	file.SetCellInt(sheet, "D2", values.FirefoxCount)
	file.SetCellInt(sheet, "E2", values.SMBCount)
	file.SetCellInt(sheet, "F2", values.ApacheCount)
	file.SetCellInt(sheet, "G2", values.PHPCount)
	file.SetCellInt(sheet, "H2", values.AdobeCount)
}

func writeByYear(file *excelize.File, sheet string, values []sql.CountCVSSYear) {
	for id, value := range values {
		row := id + 2
		writeCountCVSSYear(file, sheet, row, value)
	}
}

func writeCountCVSSYear(file *excelize.File, sheet string, row int, values sql.CountCVSSYear) {
	strRow := strconv.Itoa(row)
	file.SetCellInt(sheet, "A"+strRow, values.Year)
	file.SetCellInt(sheet, "B"+strRow, values.Total)
}

func writeRow(file *excelize.File, sheet string, rowID int, values []string) {
	for id, value := range values {
		cell := toCharStr(id+1) + strconv.Itoa(rowID)
		if num, err := strconv.Atoi(value); err == nil {
			file.SetCellInt(sheet, cell, num)
		} else {
			file.SetCellStr(sheet, cell, value)
		}
	}
}

func writeMultipleRow(file *excelize.File, sheet string, values [][]string) {
	for rowID, row := range values {
		adjRowID := rowID + 2
		writeRow(file, sheet, adjRowID, row)
	}
}

func toCharStr(i int) string {
	abc := "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
	return abc[i-1 : i]
}
