// model/query.go
//
// Shared list-query helpers. Both the user directory and the OAuth client
// directory page and search the same way, so the logic lives here once.

package model

import "strings"

const (
	defaultPageSize = 20
	maxPageSize     = 100
)

// likeEscaper stops a search term from smuggling LIKE wildcards into the query.
// Every LIKE built from user input must pair this with ESCAPE '\'.
var likeEscaper = strings.NewReplacer(`\`, `\`, `%`, `\%`, `_`, `\_`)

// likePattern turns raw user input into a safe, case-folded contains-pattern.
func likePattern(search string) string {
	return "%" + likeEscaper.Replace(strings.ToLower(strings.TrimSpace(search))) + "%"
}

// pageArgs clamps paging input and asks for one row more than requested, which
// is how the caller learns whether a next page exists without a COUNT query.
func pageArgs(page, size int) (offset, limit, clamped int) {
	if size < 1 {
		size = defaultPageSize
	}
	if size > maxPageSize {
		size = maxPageSize
	}
	if page < 1 {
		page = 1
	}
	return (page - 1) * size, size + 1, size
}

// trimPage drops the probe row fetched by pageArgs and reports whether it existed.
func trimPage[T any](rows []T, size int) ([]T, bool) {
	if len(rows) > size {
		return rows[:size], true
	}
	return rows, false
}
