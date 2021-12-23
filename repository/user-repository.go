package repository

import (
	"log"

	"github.com/andiahmads/raddit-clone/entity"
	"golang.org/x/crypto/bcrypt"
	"gorm.io/gorm"
)

//buat contract

type UserRepository interface {
	Register(user entity.User) entity.User
	VerifyEmail(v entity.User) entity.User
	IsDuplicateEmail(email string) (tx *gorm.DB)
	IsActiveAccount(userID uint64) entity.User
	VerifyCredential(email string, password string) interface{}
}

type userConnection struct {
	connection *gorm.DB
}

// create instance
func NewUserRepository(db *gorm.DB) UserRepository {
	return &userConnection{
		connection: db,
	}
}

func (db *userConnection) Register(user entity.User) entity.User {
	//encryp password
	user.Password = hashAndSalt([]byte(user.Password))
	db.connection.Save(&user)

	return user
}

func (db *userConnection) IsDuplicateEmail(email string) (tx *gorm.DB) {
	var user entity.User
	return db.connection.Where("email = ?", email).Take(&user)

}

func hashAndSalt(pwd []byte) string {
	hash, err := bcrypt.GenerateFromPassword(pwd, bcrypt.MinCost)
	if err != nil {
		log.Println(err)
		panic("failed to hash password")
	}
	return string(hash)
}

func (db *userConnection) VerifyEmail(v entity.User) entity.User {
	db.connection.Model(&v).Where("id = ?", v.ID).Update("is_active", v.IsActive)
	return v
}

//cek status akun
func (db *userConnection) IsActiveAccount(userID uint64) entity.User {
	var user entity.User
	db.connection.Find(&user, userID)
	return user
}

//get email and password form login
func (db *userConnection) VerifyCredential(email string, password string) interface{} {
	var user entity.User
	res := db.connection.Where("email = ?", email).Take(&user)
	if res.Error == nil {
		return user
	}
	return nil
}
