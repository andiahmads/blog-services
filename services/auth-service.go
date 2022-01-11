package services

import (
	"log"

	"github.com/andiahmads/raddit-clone/dto"
	"github.com/andiahmads/raddit-clone/entity"
	"github.com/andiahmads/raddit-clone/repository"
	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"
)

type AuthService interface {
	RegisterUser(user dto.RegisterDTO) entity.User
	IsDuplicateEmail(email string) bool
	VerifyEmail(user dto.VerificationEmail) entity.User
	IsActiveAccount(userID uint64) entity.User
	VerifyCredential(email string, password string) interface{}
}

type authService struct {
	userRepository repository.UserRepository
}

func NewAuthService(userRep repository.UserRepository) AuthService {
	return &authService{
		userRepository: userRep,
	}
}

func (services *authService) RegisterUser(user dto.RegisterDTO) entity.User {
	genereteUiid := uuid.New()
	UserToCreate := entity.User{}
	UserToCreate.Name = user.Name
	UserToCreate.UUID = genereteUiid.String()
	UserToCreate.Email = user.Email
	UserToCreate.Avatar = "https://res.cloudinary.com/treelogystudio-com/image/upload/v1592311685/bjbmvdn1iu9omlaaylzm.jpg"
	UserToCreate.Password = user.Password
	UserToCreate.RoleID = 2
	UserToCreate.IsActive = false
	res := services.userRepository.Register(UserToCreate)
	return res
}

func (service *authService) IsDuplicateEmail(email string) bool {
	res := service.userRepository.IsDuplicateEmail(email)
	return !(res.Error == nil)
}

func (service *authService) VerifyEmail(user dto.VerificationEmail) entity.User {
	userToUpdate := entity.User{}
	userToUpdate.ID = user.ID
	userToUpdate.IsActive = true

	res := service.userRepository.VerifyEmail(userToUpdate)
	return res
}

func (service *authService) IsActiveAccount(userID uint64) entity.User {
	return service.userRepository.IsActiveAccount(userID)
}

func (service *authService) VerifyCredential(email string, password string) interface{} {
	res := service.userRepository.VerifyCredential(email, password)
	if v, ok := res.(entity.User); ok {
		comparedPassword := comparePassword(v.Password, []byte(password))
		if v.Email == email && comparedPassword {
			return res
		}
		return false
	}
	return false
}

//compare password for login
func comparePassword(hashedPwd string, plainPassword []byte) bool {
	byteHash := []byte(hashedPwd)
	err := bcrypt.CompareHashAndPassword(byteHash, plainPassword)
	if err != nil {
		log.Println(err)
		return false
	}
	return true
}
