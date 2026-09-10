// model/client.go
//
// Storage for the OAuth client directory. Validation and authorization belong
// to the controller layer; everything here assumes the caller already decided.

package model

import (
	"context"
	"errors"
	"strings"

	"gorm.io/gorm"
)

var (
	ErrClientNotFound = errors.New("client not found")
	ErrClientExists   = errors.New("client already exists")
)

// clientListColumns is an allowlist. SecretHash carries no json:"-" tag, so it
// must never be selected into anything the admin API can serialize.
var clientListColumns = []string{
	"client_id", "name", "redirect_uris", "scope", "created_at", "updated_at",
}

// ListClients returns one page of live clients ordered by client_id, and
// whether a further page exists.
func ListClients(ctx context.Context, search string, page, size int) ([]Client, bool, error) {
	offset, limit, size := pageArgs(page, size)
	query := DB.WithContext(ctx).Model(&Client{}).Select(clientListColumns)
	if strings.TrimSpace(search) != "" {
		pattern := likePattern(search)
		query = query.Where(
			`LOWER(client_id) LIKE ? ESCAPE '\' OR LOWER(name) LIKE ? ESCAPE '\'`,
			pattern, pattern)
	}
	var clients []Client
	if err := query.Order("client_id").Offset(offset).Limit(limit).Find(&clients).Error; err != nil {
		return nil, false, err
	}
	clients, hasMore := trimPage(clients, size)
	return clients, hasMore, nil
}

// GetClient reads one live client without its secret hash.
func GetClient(ctx context.Context, clientID string) (Client, error) {
	var client Client
	err := DB.WithContext(ctx).Model(&Client{}).Select(clientListColumns).
		Where("client_id = ?", clientID).Take(&client).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return Client{}, ErrClientNotFound
	}
	return client, err
}

// CreateClient registers a client. The existence probe is Unscoped because
// client_id is the primary key: a soft deleted row still occupies it, and
// reporting that as a conflict beats surfacing a raw constraint error.
func CreateClient(ctx context.Context, client *Client) error {
	var count int64
	if err := DB.WithContext(ctx).Unscoped().Model(&Client{}).
		Where("client_id = ?", client.ClientID).Count(&count).Error; err != nil {
		return err
	}
	if count > 0 {
		return ErrClientExists
	}
	// Create fills CreatedAt and UpdatedAt on the caller value, which the
	// creation response reports back.
	return DB.WithContext(ctx).Create(client).Error
}

// UpdateClient applies the given columns to a live client.
func UpdateClient(ctx context.Context, clientID string, updates map[string]any) error {
	if len(updates) == 0 {
		return nil
	}
	err := requireOneRow(DB.WithContext(ctx).Model(&Client{}).
		Where("client_id = ?", clientID).Updates(updates))
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return ErrClientNotFound
	}
	return err
}

// SetClientSecret replaces the stored secret hash.
func SetClientSecret(ctx context.Context, clientID, secretHash string) error {
	return UpdateClient(ctx, clientID, map[string]any{"secret_hash": secretHash})
}

// DeleteClient soft deletes a client, which also removes it from every
// authorization and token lookup.
func DeleteClient(ctx context.Context, clientID string) error {
	err := requireOneRow(DB.WithContext(ctx).Where("client_id = ?", clientID).Delete(&Client{}))
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return ErrClientNotFound
	}
	return err
}
