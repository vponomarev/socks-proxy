package config

import (
	"bufio"
	"fmt"
	"os"
	"regexp"
	"strings"
)

type DomainRecord struct {
	RegexpText string
	Regexp     *regexp.Regexp
	Actions    *map[string]string
}

type DomainList struct {
	Filename string
	Records  []DomainRecord
}

func (d *DomainList) Load(filename string) (err error) {
	d.Filename = filename
	d.Records = make([]DomainRecord, 0)

	file, err := os.Open(filename)
	if err != nil {
		return err
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())

		// Пропускаем пустые строки и комментарии
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		record := DomainRecord{}

		// Разделяем основную часть и actions
		parts := strings.SplitN(line, ";", 2)

		// Обрабатываем основное имя (может содержать несколько значений через запятую)
		mainPart := strings.TrimSpace(parts[0])
		record.RegexpText = mainPart

		// Обрабатываем actions, если они есть
		if len(parts) > 1 {
			actionsPart := strings.TrimSpace(parts[1])
			actions := make(map[string]string)

			// Разбираем пары key=value
			kvPairs := strings.Split(actionsPart, ",")
			for _, pair := range kvPairs {
				pair = strings.TrimSpace(pair)
				if pair == "" {
					continue
				}

				kv := strings.SplitN(pair, "=", 2)
				if len(kv) == 2 {
					key := strings.TrimSpace(kv[0])
					value := strings.TrimSpace(kv[1])
					actions[key] = value
				} else if len(kv) == 1 {
					// Если есть только ключ без значения
					key := strings.TrimSpace(kv[0])
					actions[key] = ""
				}
			}

			if len(actions) > 0 {
				record.Actions = &actions
			}
		}

		names := strings.Split(mainPart, ",")
		for _, name := range names {
			name = strings.TrimSpace(name)
			if name == "" {
				continue
			}

			record.RegexpText = name
			record.Regexp, err = TemplateToRegex(name)
			if err != nil {
				return fmt.Errorf("error parsing name '%s': %v", name, err)
			}

			d.Records = append(d.Records, record)
		}
	}

	if err := scanner.Err(); err != nil {
		return err
	}

	return nil
}

func TemplateToRegex(template string) (*regexp.Regexp, error) {
	// Escape special regex characters in the domain parts
	escaped := regexp.QuoteMeta(template)

	// Handle the wildcard subdomain case (starts with dot)
	if strings.HasPrefix(template, ".") {
		// Remove the escaped dot prefix we added with QuoteMeta
		escaped = strings.TrimPrefix(escaped, "\\.")
		// Pattern: any non-dot characters followed by the domain
		pattern := "^[^.]+\\.?" + escaped + "$"
		return regexp.Compile(pattern)
	}

	// Exact domain match case
	pattern := "^" + escaped + "$"
	return regexp.Compile(pattern)
}
