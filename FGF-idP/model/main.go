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

	"time"

	"github.com/glebarez/sqlite"
	"gorm.io/datatypes"
	"gorm.io/driver/postgres"
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

func createRootAccount() error {
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
	if err := DB.Create(&rootUser).Error; err != nil {
		return err
	}
	common.SysLog("root user created: username is " + username + ", email is: " + userEmail)
	return nil
}

func openSQLiteDB() (*gorm.DB, error) {
	return gorm.Open(sqlite.Open(common.SQLitePath), &gorm.Config{
		PrepareStmt: true, // precompile SQL
	})
}

func openConfiguredDB() (*gorm.DB, error) {
	sqlDsn := common.SQLDsn
	if sqlDsn == "" {
		return openSQLiteDB()
	}
	if !strings.HasPrefix(sqlDsn, "postgres://") &&
		!strings.HasPrefix(sqlDsn, "postgresql://") {
		common.SysLog("Unsupported database type, only PostgreSQL is supported currently, falling back to SQLite")
		return openSQLiteDB()
	}
	return gorm.Open(postgres.New(postgres.Config{
		DSN: sqlDsn,
	}), &gorm.Config{PrepareStmt: true})
}

func configureConnectionPool(db *gorm.DB) error {
	sqlDB, err := db.DB()
	if err != nil {
		return err
	}
	sqlDB.SetMaxIdleConns(common.MaxIdleConns)
	sqlDB.SetMaxOpenConns(common.MaxOpenConns)
	sqlDB.SetConnMaxLifetime(time.Second * time.Duration(common.Lifetime*60))
	return nil
}

func buildMetadata() JakMetadata {
	baseurl := strings.TrimSuffix(common.GetEnvOrDefaultString("BACKEND_BASE_URL", fmt.Sprintf("http://localhost:%d", common.Port)), "/")
	endpoint := baseurl + "/x/"
	return JakMetadata{
		Sid:                   "FGF-idP",
		Issuer:                baseurl,
		JwksURI:               baseurl + "/.well-known/keys",
		AuthorizationEndpoint: endpoint + "auth",
		TokenEndpoint:         endpoint + "token",
		UserinfoEndpoint:      endpoint + "userinfo",
		EndSessionEndpoint:    endpoint + "logout",
	}
}

func InitDB() error {
	db, err := openConfiguredDB()
	if err != nil {
		return err
	}
	DB = db
	if err := configureConnectionPool(DB); err != nil {
		return err
	}

	common.SysLog("database migration started")
	if err := migrateDB(); err != nil {
		return err
	}
	if err := CheckRootUser(); err != nil {
		return err
	}

	startup, err := findStartupRecord()
	if err != nil {
		return err
	}
	if startup != nil {
		common.SysLog("database already initialized at " + startup.InitAt.String() + ", version: " + startup.Version)
	}

	if err := upsertMetadata(buildMetadata()); err != nil {
		return err
	}
	jwkMetadata, err = getMetadata()
	if err != nil {
		return err
	}
	if err := isKeyExists(); err != nil {
		return err
	}
	if err := ensureDefaultClient(); err != nil {
		return err
	}
	warnInsecureClients()
	if startup != nil {
		return nil
	}
	return DB.Create(&Startup{
		Version: fmt.Sprintf("%s%s", common.Version, common.BuildNocolor),
		InitAt:  time.Now(),
	}).Error
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

// warnInsecureClients reports clients that still accept an empty secret. It runs
// once at startup, never on the request path, and only warns: refusing to boot
// would break existing deployments on upgrade.
func warnInsecureClients() {
	if allowInsecureDefaultClient() {
		return
	}
	var clients []Client
	if err := DB.Model(&Client{}).Select("client_id", "secret_hash").Find(&clients).Error; err != nil {
		common.SysError("insecure client scan failed: " + err.Error())
		return
	}
	for _, client := range clients {
		if common.ValidatePasswordAndHash("", client.SecretHash) {
			common.SysError("OAuth client \"" + client.ClientID + "\" accepts an empty secret; rotate it from the admin console")
		}
	}
}

func allowInsecureDefaultClient() bool {
	return common.DebugMode || common.GetEnvOrDefaultBool("ALLOW_INSECURE_DEFAULT_CLIENT", false)
}

func migrateDB() error {
	return DB.AutoMigrate(
		&User{},
		&AuthRequest{},
		&AuthCode{},
		&RevokedToken{},
		&UserDevice{},
		&JakMetadata{},
		&JwkKey{},
		&Startup{},
		&Client{},
	)
}

// 之後搞一個可以第一次啟動跳註冊的東東，現在先自動創建
// 改成有 error return
func CheckRootUser() error {
	createRoot := common.GetEnvOrDefaultBool("CREATE_ROOT_USER", false)
	if !createRoot {
		common.SysLog("CREATE_ROOT_USER disabled, skip root user check")
		return nil
	}

	rootExists, err := rootUserExists()
	if err != nil {
		return err
	}
	if rootExists {
		common.SysLog("Root user already exists, skip creating root user")
		return nil
	}

	if err := createRootAccount(); err != nil {
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

func findStartupRecord() (*Startup, error) {
	var startup Startup
	err := DB.First(&startup).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	common.SysLog("database initialized")
	return &startup, nil
}
