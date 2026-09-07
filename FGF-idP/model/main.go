package model

// model/main.go

import (
	"FGF-idP/common"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"

	// "os"
	// "strings"
	// "sync"
	"time"

	"gorm.io/datatypes"
	// "github.com/glebarez/sqlite"
	// "gorm.io/driver/mysql"
	"gorm.io/driver/postgres"
	//"gorm.io/gorm"
	"github.com/glebarez/sqlite"
	"gorm.io/gorm"
)

var DB *gorm.DB

var LOG_DB *gorm.DB

var (
	commonGroupCol = `"group"`
	commonKeyCol   = `"key"`
	commonTrueVal  = "true"
	commonFalseVal = "false"

	jwkMetadata *JakMetadata
)

func createRootAccountForTest() error {
	var user User
	//if user.Status != common.UserStatusEnabled {
	if err := DB.First(&user).Error; err != nil {
		userEmail := common.GetEnvOrDefaultString("ROOT_USER_EMAIL", "")

		if userEmail == "" {
			return errors.New("ROOT_USER_EMAIL is not set, please set it in .env file")
		}
		password := common.GetEnvOrDefaultString("ROOT_USER_PASSWORD", "123456")
		username := common.GetEnvOrDefaultString("ROOT_USER_NAME", "root")
		salt := common.GetRandomString(16)
		hashedPassword, err := common.Password2Hash(password + salt)
		if err != nil {
			return err
		}
		rootUser := User{
			Username:    username,
			Password:    hashedPassword,
			Email:       userEmail,
			Role:        common.RoleRootUser,
			Salt:        salt,
			DisplayName: "Root User",
			AccessToken: nil,
		}
		DB.Create(&rootUser)
		common.SysLog("no user exists, create a root user for you: username is " + username + ", password is " + password + ", email is:" + userEmail)
	}
	return nil
}

func InitSqliteDB(isLog bool) (*gorm.DB, error) {
	return gorm.Open(sqlite.Open(common.SQLitePath), &gorm.Config{
		PrepareStmt: true, // precompile SQL
	})
}

func InitDB() error {
	var db *gorm.DB
	var initDbErr error

	if sqlDsn := common.SQLDsn; sqlDsn != "" {
		if !strings.HasPrefix(sqlDsn, "postgres://") &&
			!strings.HasPrefix(sqlDsn, "postgresql://") {
			common.SysLog("Unsupported database type, only PostgreSQL is supported currently, falling back to SQLite")
			db, initDbErr = InitSqliteDB(false)
			if initDbErr != nil {
				return initDbErr
			}
		}
		db, initDbErr = gorm.Open(postgres.New(postgres.Config{
			DSN:                  common.SQLDsn,
			PreferSimpleProtocol: true, // disables implicit prepared statement usage
		}), &gorm.Config{
			PrepareStmt: true, // precompile SQL
		})
	} else {
		db, initDbErr = InitSqliteDB(false)
		if initDbErr != nil {
			return initDbErr
		}
	}

	if initDbErr != nil {
		return initDbErr
	}

	DB = db
	sqlDB, err := DB.DB()
	if err != nil {
		return err
	}
	sqlDB.SetMaxIdleConns(common.MaxIdleConns)
	sqlDB.SetMaxOpenConns(common.MaxOpenConns)
	sqlDB.SetConnMaxLifetime(time.Second * time.Duration(common.Lifetime*60))
	common.SysLog("database migration started")
	err = migrateDB()
	err = CheckRootUser()
	if err != nil {
		return err
	}

	baseurl := strings.TrimSuffix(common.GetEnvOrDefaultString("BACKEND_BASE_URL", fmt.Sprintf("http://localhost:%d", common.Port)), "/")
	endpoint := baseurl + "/x/"
	metadata := JakMetadata{
		Sid:                   "FGF-idP",
		Issuer:                baseurl,
		JwksURI:               baseurl + "/.well-known/keys",
		AuthorizationEndpoint: endpoint + "auth",
		TokenEndpoint:         endpoint + "token",
		UserinfoEndpoint:      endpoint + "userinfo",
		EndSessionEndpoint:    endpoint + "logout",
		RotateIntervalHours:   0,
		LastRotatedAt:         nil,
		NextRotateAt:          nil,
		CreatedAt:             time.Time{},
		UpdatedAt:             time.Time{},
		DeletedAt:             gorm.DeletedAt{},
	}

	startup := IsInitialized()
	if startup != nil {
		var jwkErr error
		// DB is already initialized
		common.SysLog("database already initialized at " + startup.InitAt.String() + ", version: " + startup.Version)
		if err := upsertMetadata(metadata); err != nil {
			return err
		}
		jwkMetadata, jwkErr = getMetadata()
		if jwkErr != nil {
			return jwkErr
		}
		if err := initKeys(); err != nil {
			return err
		}
		return ensureDefaultClient()
	}

	if err := upsertMetadata(metadata); err != nil {
		return err
	}

	jwkMetadata, err = getMetadata()
	if err != nil {
		return err
	}

	if err := initKeys(); err != nil {
		return err
	}
	if err := ensureDefaultClient(); err != nil {
		return err
	}

	initRecord := Startup{
		Version: fmt.Sprintf("%s%s", common.Version, common.BuildNocolor),
		InitAt:  time.Now(),
	}
	err = DB.Create(&initRecord).Error
	return err
}

func upsertMetadata(metadata JakMetadata) error {
	var existing JakMetadata
	err := DB.Where("sid = ?", metadata.Sid).First(&existing).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return DB.Create(&metadata).Error
	}
	if err != nil {
		return err
	}

	return DB.Model(&existing).Updates(map[string]any{
		"issuer":                 metadata.Issuer,
		"jwks_uri":               metadata.JwksURI,
		"authorization_endpoint": metadata.AuthorizationEndpoint,
		"token_endpoint":         metadata.TokenEndpoint,
		"userinfo_endpoint":      metadata.UserinfoEndpoint,
		"end_session_endpoint":   metadata.EndSessionEndpoint,
	}).Error
}

func initKeys() error {
	err := isKeyExists()
	if err != nil {
		return err
	}

	return nil
}

func isKeyExists() error {
	//var jwk JwkKey
	privPath := common.GetEnvOrDefaultString("PRIV_KEY_PATH", "./keys/priv_key.pem")
	pubPath := common.GetEnvOrDefaultString("PUB_KEY_PATH", "./keys/pub_key.pem")

	privPem, pubPem, err := common.LoadKey(privPath, pubPath)
	if err != nil {
		if !errors.Is(err, common.ErrKeyNotFound) {

			return err
		}
		common.SysError("key not found at " + privPath)
		genErr := common.GenerateRSAKeyPair(privPath, pubPath)
		if genErr != nil {
			return genErr
		}
		err = nil
		privPem, pubPem, err = common.LoadKey(privPath, pubPath)
		if err != nil {
			return err
		}

	}
	if err := ensureActiveJWK(pubPem); err != nil {
		return err
	}
	common.SysLog("database key loaded")
	common.RSAPrivateKey = privPem
	common.RSAPublicKey = pubPem
	return nil
}

func ensureActiveJWK(pub *rsa.PublicKey) error {
	pubB64n := common.RsaToBase64urlInt(pub.N)
	pubB64e := common.RsaToBase64urlUint(pub.E)

	var matchingActive JwkKey
	if err := DB.Where("sid = ? AND n = ? AND e = ? AND is_active = ?", common.SystemName, pubB64n, pubB64e, true).
		Order("id DESC").
		First(&matchingActive).Error; err == nil {
		common.ActiveKeyID = matchingActive.Kid
		return nil
	} else if !errors.Is(err, gorm.ErrRecordNotFound) {
		return err
	}

	key, err := GetActiveSigningKey()
	if err == nil {
		if key.N == pubB64n && key.E == pubB64e {
			common.ActiveKeyID = key.Kid
			return nil
		}

		var matching JwkKey
		if matchErr := DB.Where("sid = ? AND n = ? AND e = ?", common.SystemName, pubB64n, pubB64e).
			Order("id DESC").
			First(&matching).Error; matchErr == nil {
			if !matching.IsActive {
				if updateErr := DB.Model(&matching).Update("is_active", true).Error; updateErr != nil {
					return updateErr
				}
			}
			common.ActiveKeyID = matching.Kid
			return nil
		} else if !errors.Is(matchErr, gorm.ErrRecordNotFound) {
			return matchErr
		}

		kid := derivedJWKID(pubB64n, pubB64e)
		if err := DB.Create(newJWKKey(kid, pubB64n, pubB64e, "Key activated for loaded public key")).Error; err != nil {
			return err
		}
		common.ActiveKeyID = kid
		return nil
	}
	if !errors.Is(err, gorm.ErrRecordNotFound) {
		return err
	}
	if err := DB.Create(newJWKKey(common.InitialKeyKID, pubB64n, pubB64e, "Initial key generated on setup")).Error; err != nil {
		return err
	}
	common.ActiveKeyID = common.InitialKeyKID
	return nil
}

func derivedJWKID(n, e string) string {
	sum := sha256.Sum256([]byte(n + "." + e))
	return common.InitialKeyKID + "-" + base64.RawURLEncoding.EncodeToString(sum[:6])
}

func newJWKKey(kid, n, e, description string) *JwkKey {
	return &JwkKey{
		Sid:         common.SystemName,
		Kid:         kid,
		Kty:         "RSA",
		Use:         "sig",
		Alg:         "RS256",
		N:           n,
		E:           e,
		IsActive:    true,
		NotBefore:   nil,
		ExpiresAt:   nil,
		Description: description,
	}
}

func ensureDefaultClient() error {
	if !allowInsecureDefaultClient() {
		common.SysLog("ALLOW_INSECURE_DEFAULT_CLIENT disabled, skip default OAuth client")
		return nil
	}
	const defaultClientID = "fgf-mc-panel"
	secretHash, err := common.Password2Hash("")
	if err != nil {
		return err
	}
	var client Client
	err = DB.Where("client_id = ?", defaultClientID).First(&client).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		defaultClient := Client{
			ClientID:      defaultClientID,
			SecretHash:    secretHash,
			RedirectURIs:  datatypes.JSON([]byte(`["http://localhost:3000/callback","http://localhost:8080/callback"]`)),
			Scope:         "openid profile email",
			GrantTypes:    datatypes.JSON([]byte(`["authorization_code"]`)),
			ResponseTypes: datatypes.JSON([]byte(`["code"]`)),
		}
		return DB.Create(&defaultClient).Error
	}
	if err != nil {
		return err
	}
	if strings.TrimSpace(client.SecretHash) == "" {
		return DB.Model(&client).Update("secret_hash", secretHash).Error
	}
	return nil
}

func allowInsecureDefaultClient() bool {
	return common.DebugMode || common.GetEnvOrDefaultBool("ALLOW_INSECURE_DEFAULT_CLIENT", false)
}

func migrateDB() error {
	err := DB.AutoMigrate(
		&User{},
		&UserDevice{},
		&JakMetadata{},
		&JwkKey{},
		&Startup{},
		&Client{},
	)

	if err != nil {
		return err
	}

	return nil
}

// 之後搞一個可以第一次啟動跳註冊的東東，現在先自動創建
// 改成有 error return
func CheckRootUser() error {
	createRoot := common.GetEnvOrDefaultBool("CREATE_ROOT_USER", false)
	if !createRoot {
		common.SysLog("CREATE_ROOT_USER disabled, skip root user check")
		return nil
	}

	if RootUserExists() {
		common.SysLog("Root user already exists, skip creating root user")
		return nil
	}

	if err := createRootAccountForTest(); err != nil {
		return err
	}

	common.SysLog("Root user created successfully")
	return nil
}

type Startup struct {
	ID      int    `gorm:"primary_key"`
	Version string `gorm:"type:varchar(50);uniqueIndex"`
	InitAt  time.Time
}

func IsInitialized() *Startup {
	var startup Startup
	var jwksKey JwkKey
	var client Client
	err := DB.First(&startup).Error
	if err != nil {
		common.SysLog("database error: " + err.Error())
		return nil
	}

	if err := DB.First(&jwksKey).Error; err != nil {
		common.SysLog("Missing JWK key in database")
		return nil
	}

	if err := DB.First(&client).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			common.SysLog("Missing OAuth client in database")
		} else {
			common.SysError("database initialized error " + err.Error())
		}
	}
	common.SysLog("database initialized")
	return &startup
}
