package model

// model/main.go

import (
	"FGF-idP/common"
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

	startup := IsInitialized()
	if startup != nil {
		var jwkErr error
		// DB is already initialized
		common.SysLog("database already initialized at " + startup.InitAt.String() + ", version: " + startup.Version)
		jwkMetadata, jwkErr = getMetadata()
		return jwkErr
	}
	baseurl := common.GetEnvOrDefaultString("BACKEND_BASE_URL", "http://localhost")
	endpoint := baseurl + "/x/"
	metadata := JakMetadata{
		Sid:                   "FGF-idP",
		Issuer:                fmt.Sprintf("%s:%s", baseurl, common.Port),
		JwksURI:               fmt.Sprintf("%s:%s", baseurl, "/well-known/keys"),
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

	if err := DB.Where("sid = ?", metadata.Sid).First(&JakMetadata{}).Error; err != nil {
		if err := DB.Create(&metadata).Error; err != nil {
			return err
		}
	}

	jwkMetadata, err = getMetadata()
	if err != nil {
		return err
	}

	if err := initKeys(); err != nil {
		return err
	}

	initRecord := Startup{
		Version: fmt.Sprintf("%s%s", common.Version, common.BuildNocolor),
		InitAt:  time.Now(),
	}
	err = DB.Create(&initRecord).Error
	return err
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
		pubB64n := common.RsaToBase64urlInt(pubPem.N)
		pubB64e := common.RsaToBase64urlUint(pubPem.E)
		// Save to DB
		if err := DB.Create(&JwkKey{
			Sid:         common.SystemName,
			Kid:         common.InitialKeyKID,
			Kty:         "RSA",
			Use:         "sig",
			Alg:         "RS256",
			N:           pubB64n,
			E:           pubB64e,
			IsActive:    true,
			NotBefore:   nil,
			ExpiresAt:   nil,
			Description: "Initial key generated on setup",
		}).Error; err != nil {
			return err
		}

	}
	common.SysLog("database key loaded")
	common.RSAPrivateKey = privPem
	common.RSAPublicKey = pubPem
	return nil
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
			// Create a default client
			defaultClient := Client{
				ClientID:      "fgf-mc-panel",
				SecretHash:    " ",
				RedirectURIs:  datatypes.JSON([]byte(`["http://localhost:3000/callback","http://localhost:8080/callback"]`)),
				Scope:         "openid profile email",
				GrantTypes:    datatypes.JSON([]byte(`["authorization_code"]`)),
				ResponseTypes: datatypes.JSON([]byte(`["code"]`)),
			}
			if err := DB.Create(&defaultClient).Error; err != nil {
				common.SysError("database initialized error default Client Record error " + err.Error())
			} else {
				common.SysLog("Client database initialized")
			}
		} else {
			common.SysError("database initialized error " + err.Error())
		}
	}
	common.SysLog("database initialized")
	return &startup
}
