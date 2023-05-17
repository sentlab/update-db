package csv

import (
	"encoding/csv"
	"os"
)

// ReadCSV reads a CSV file and returns the records.
func ReadCSV(filePath string) ([][]string, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	reader := csv.NewReader(file)
	records, err := reader.ReadAll()
	if err != nil {
		return nil, err
	}

	return records, nil
}

// ExportToCSV exports records to a CSV file with the given file name.
func ExportToCSV(records []string, fileName string) error {
	file, err := os.Create(fileName)
	if err != nil {
		return err
	}
	defer file.Close()

	writer := csv.NewWriter(file)
	err = writer.Write(records)
	if err != nil {
		return err
	}

	writer.Flush()
	if err := writer.Error(); err != nil {
		return err
	}

	return nil
}

// SplitIntoBatches splits records into multiple batches
func SplitIntoBatches(records [][]string, batchSize int) [][]string {
	var batches [][]string

	for i := 0; i < len(records); i += batchSize {
		end := i + batchSize
		if end > len(records) {
			end = len(records)
		}
		batch := make([][]string, len(records[i:end]))
		copy(batch, records[i:end])
		batches = append(batches, batch...)
	}

	return batches
}
