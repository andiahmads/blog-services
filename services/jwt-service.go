package services

import (
	"fmt"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/andiahmads/raddit-clone/config"
	"github.com/dgrijalva/jwt-go"
	"github.com/gin-gonic/gin"
	"github.com/twinj/uuid"
)

type JWTService interface {
	GenerateToken(UserID uint64) (string, error)
	RefToken(UserID uint64) (string, error)
	ActivationToken(UserID string) string
	ValidateToken(token string) (*jwt.Token, error)
	SaveMetaDataTokenToRedis(userid uint64) error
	DeleteAuth(givenUuid string) (int64, error)
	ExtractTokenMetaDataFromRedis(ctx *gin.Context) (*jwtService, error)
}

type jwtServiceInterface struct {
	jwtServiceInterface JWTService
}

type jwtCustomClaims struct {
	UserID string `json:"user_id"`
	jwt.StandardClaims
}

type jwtService struct {
	secretKey    string
	issuer       string
	AccessToken  string
	RefreshToken string
	AccessUuid   string
	UserId       uint64
	RefreshUuid  string
	AtExpires    int64
	RtExpires    int64
}

//MAKE contract
func NewJWTService() JWTService {
	return &jwtService{
		issuer:    "andiahmad",
		secretKey: getSecretKey(),
	}
}

func getSecretKey() string {
	secretKey := os.Getenv("JWT_SECRET_KEY")
	if secretKey != "" {
		secretKey = "andiahmad"
	}
	return secretKey
}

func (j *jwtService) GenerateToken(UserID uint64) (string, error) {
	j.AtExpires = time.Now().Add(time.Minute * 60).Unix()
	j.AccessUuid = uuid.NewV4().String()

	var err error
	os.Setenv("JWT_SECRET_KEY", "andiahmad") //this should be in an env file
	atClaims := jwt.MapClaims{}
	atClaims["authorized"] = true
	atClaims["access_uuid"] = j.AccessUuid
	atClaims["user_id"] = UserID
	atClaims["exp"] = j.AtExpires
	at := jwt.NewWithClaims(jwt.SigningMethodHS256, atClaims)
	j.AccessToken, err = at.SignedString([]byte(os.Getenv("JWT_SECRET_KEY")))
	if err != nil {
		panic(err)
	}
	return j.AccessToken, err
}

func (j *jwtService) RefToken(UserID uint64) (string, error) {
	j.RtExpires = time.Now().Add(time.Hour * 24 * 7).Unix()
	j.RefreshUuid = uuid.NewV4().String()

	var err error

	os.Setenv("REF_SECRET_KEY", "andiahmads") //this should be in an env file
	rtClaims := jwt.MapClaims{}
	rtClaims["refresh_uuid"] = j.RefreshUuid
	rtClaims["user_id"] = UserID
	rtClaims["exp"] = j.RtExpires
	rft := jwt.NewWithClaims(jwt.SigningMethodHS256, rtClaims)

	j.RefreshToken, err = rft.SignedString([]byte(os.Getenv("JWT_SECRET_KEY")))
	if err != nil {
		panic(err)
	}
	return j.RefreshToken, err

}
func (j *jwtService) ActivationToken(UserID string) string {
	refreshToken := jwt.New(jwt.SigningMethodHS256)
	rtClaims := refreshToken.Claims.(jwt.MapClaims)
	rtClaims["user_id"] = UserID
	rtClaims["issuer"] = 1
	rtClaims["exp"] = time.Now().Add(time.Minute * 5).Unix()
	rt, err := refreshToken.SignedString([]byte(j.secretKey))
	if err != nil {
		panic(err)

	}

	return rt
}

func (j *jwtService) ValidateToken(token string) (*jwt.Token, error) {
	return jwt.Parse(token, func(t_ *jwt.Token) (interface{}, error) {
		if _, ok := t_.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("Unexpected signing method %v", t_.Header["alg"])
		}
		return []byte(j.secretKey), nil
	})

}

func (j *jwtService) SaveMetaDataTokenToRedis(userid uint64) error {

	//get Redis Connection
	var client = config.SetupRedisConnection()

	at := time.Unix(j.AtExpires, 0) //converting Unix to UTC(to Time object)
	rt := time.Unix(j.RtExpires, 0)
	now := time.Now()

	errAccess := client.Set(j.AccessUuid, strconv.Itoa(int(userid)), at.Sub(now)).Err()
	if errAccess != nil {
		return errAccess
	}
	errRefresh := client.Set(j.RefreshUuid, strconv.Itoa(int(userid)), rt.Sub(now)).Err()
	if errRefresh != nil {
		return errRefresh
	}
	return nil

}

func ExtractToken(r *http.Request) string {
	bearToken := r.Header.Get("Authorization")
	//normally Authorization the_token_xxx
	strArr := strings.Split(bearToken, " ")

	if len(strArr) == 2 {
		return strArr[1]
	}
	return ""
}

func VerifyToken(r *http.Request) (*jwt.Token, error) {
	tokenString := ExtractToken(r)
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		//Make sure that the token method conform to "SigningMethodHMAC"
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return []byte(os.Getenv("JWT_SECRET_KEY")), nil
	})
	if err != nil {
		return nil, err
	}
	return token, nil
}

func (j *jwtService) ExtractTokenMetaDataFromRedis(ctx *gin.Context) (*jwtService, error) {
	token, err := VerifyToken(ctx.Request)
	if err != nil {
		return nil, err
	}
	claims, ok := token.Claims.(jwt.MapClaims)
	if ok && token.Valid {
		accessUuid, ok := claims["access_uuid"].(string)
		if !ok {
			return nil, err
		}
		userId, err := strconv.ParseUint(fmt.Sprintf("%s", claims["user_id"]), 10, 64)
		if err != nil {
			return nil, err
		}
		return &jwtService{
			AccessUuid: accessUuid,
			UserId:     userId,
		}, nil
	}
	return nil, err
}

func (j *jwtService) DeleteAuth(givenUuid string) (int64, error) {
	var client = config.SetupRedisConnection()
	deleted, err := client.Del(givenUuid).Result()
	if err != nil {
		return 0, err
	}
	return deleted, nil
}
