package controller

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"path"
	"strconv"
	"text/template"

	"github.com/andiahmads/raddit-clone/dto"
	"github.com/andiahmads/raddit-clone/entity"
	"github.com/andiahmads/raddit-clone/helpers"
	"github.com/andiahmads/raddit-clone/logger"
	"github.com/andiahmads/raddit-clone/services"
	"github.com/dgrijalva/jwt-go"

	"github.com/gin-gonic/gin"
	"github.com/go-playground/validator/v10"
)

type AuthController interface {
	Login(ctx *gin.Context)
	Register(ctx *gin.Context)
	VerificationEmail(ctx *gin.Context)
	HandleSuccess(ctx *gin.Context)
	HandleMailExpired(ctx *gin.Context)
	HandleMailAlreadyActive(ctx *gin.Context)
}

type authController struct {
	authService services.AuthService
	jwtService  services.JWTService
}

func NewAuthController(authService services.AuthService, jwtService services.JWTService) AuthController {
	return &authController{
		authService: authService,
		jwtService:  jwtService,
	}
}

func (c *authController) Login(ctx *gin.Context) {
	var loginDTO dto.LoginDTO
	errDTO := ctx.ShouldBind(&loginDTO)

	if errDTO != nil {
		response := helpers.BuildErrorResponse("Failed to process request", errDTO.Error(), helpers.EmptyObj{})
		ctx.AbortWithStatusJSON(http.StatusBadRequest, response)
		return
	}

	attempLogin := c.authService.VerifyCredential(loginDTO.Email, loginDTO.Password)

	if v, ok := attempLogin.(entity.User); ok {
		generateToken := c.jwtService.GenerateToken(strconv.FormatUint(v.ID, 10))
		refreshToken := c.jwtService.RefToken(strconv.FormatUint(v.ID, 10))
		//save metadata to redis
		saveErr := c.jwtService.SaveMetaDataTokenToRedis(v.ID)

		if saveErr != nil {
			response := helpers.BuildErrorResponse("error data", "error", saveErr.Error())
			ctx.AbortWithStatusJSON(http.StatusUnprocessableEntity, response)
			return
		}
		var user entity.User = c.authService.IsActiveAccount(v.ID)
		if user.IsActive == true {
			v.Token = generateToken
			v.RefreshToken = refreshToken
			response := helpers.BuildSuccessResponse(true, "OK!", v)
			ctx.AbortWithStatusJSON(http.StatusOK, response)
			return
		} else if user.IsActive == false {
			response := helpers.BuildErrorResponse("Oppsss", "please check your account", helpers.EmptyObj{})
			ctx.AbortWithStatusJSON(http.StatusOK, response)
			return
		}

	}
	response := helpers.BuildErrorResponse("Please Check Again email or Password", "Invalid Credential", helpers.EmptyObj{})
	ctx.AbortWithStatusJSON(http.StatusBadRequest, response)
	getCredential, _ := json.Marshal(loginDTO)
	logger.Error(fmt.Sprintf("LOGIN FAILED", string(getCredential)))
	return

}

func (c *authController) Register(ctx *gin.Context) {
	var validate *validator.Validate
	var registerDTO dto.RegisterDTO

	errDTO := ctx.ShouldBind(&registerDTO)
	fmt.Println(errDTO)

	validate = validator.New()
	errDTO = validate.Struct(&registerDTO)
	if errDTO != nil {
		response := helpers.BuildErrorResponse("Failed to process", errDTO.Error(), helpers.EmptyObj{})
		ctx.AbortWithStatusJSON(http.StatusBadRequest, response)
		logger.Error(errDTO.Error())
		return
	}

	if !c.authService.IsDuplicateEmail(registerDTO.Email) {
		response := helpers.BuildErrorResponse("duplicate email", "please check your email", helpers.EmptyObj{})
		ctx.AbortWithStatusJSON(http.StatusConflict, response)
		return
	} else {
		createdUser := c.authService.RegisterUser(registerDTO)

		response := helpers.BuildSuccessResponse(true, "register success, please check your email", createdUser)
		ctx.AbortWithStatusJSON(http.StatusCreated, response)

		activatedToken := c.jwtService.ActivationToken(strconv.FormatUint(createdUser.ID, 10))

		//send email  verification
		emailTo := registerDTO.Email

		data := struct {
			ReceiverName string
			SenderName   string
			VerifyToken  string
			Base_url     string
		}{
			ReceiverName: registerDTO.Name,
			SenderName:   "Andiahmads",
			VerifyToken:  activatedToken,
			Base_url:     os.Getenv("BASE_URL"),
		}
		services.OAuthGmailService()
		status, err := services.SendEmailOAUTH2(emailTo, data, "sample_template.html")

		if err != nil {
			log.Println(err)
		}
		if status {
			log.Println("Email sent successfully using OAUTH")
		}

		logger.Info(fmt.Sprintln("REGISTER USER", createdUser))

	}

}

func (c *authController) VerificationEmail(ctx *gin.Context) {
	var isCek dto.VerificationEmail

	errDTO := ctx.ShouldBind(&isCek)

	if errDTO != nil {
		res := helpers.BuildErrorResponse("Failed to process request", errDTO.Error(), helpers.EmptyObj{})
		ctx.JSON(http.StatusBadRequest, res)
	}

	getToken := ctx.Param("token")
	token, errToken := c.jwtService.ValidateToken(getToken)

	data := struct {
		Base_url string
	}{
		Base_url: os.Getenv("BASE_URL"),
	}

	//token expiret
	if errToken != nil {
		ctx.Redirect(301, fmt.Sprintf("%s/api/auth/email/expiret-token", data.Base_url))
		panic(errToken.Error())

	} else {
		claims := token.Claims.(jwt.MapClaims)
		id, err := strconv.ParseUint(fmt.Sprintf("%v", claims["user_id"]), 10, 64)

		if err != nil {
			panic(err.Error())
		}

		var user entity.User = c.authService.IsActiveAccount(id)

		if user.IsActive == true {
			ctx.Redirect(301, fmt.Sprintf("%s/api/auth/email/already-active", data.Base_url))
			return
		} else {
			isCek.ID = id
			c.authService.VerifyEmail(isCek)
			fmt.Println(isCek)
			ctx.Redirect(http.StatusFound, fmt.Sprintf("%s/api/auth/email/callback", data.Base_url))

		}

	}

}

func (c *authController) HandleSuccess(ctx *gin.Context) {
	var filepath = path.Join("services/mail_templates", "mail_success.html")
	var tmpl, err = template.ParseFiles(filepath)

	if err != nil {
		fmt.Fprintf(ctx.Writer, err.Error(), http.StatusInternalServerError)
	}

	var data = map[string]interface{}{
		"title": "Success verification",
		"name":  "endi",
	}

	err = tmpl.Execute(ctx.Writer, data)

	if err != nil {
		fmt.Fprintf(ctx.Writer, err.Error(), http.StatusInternalServerError)
	}

}

func (c *authController) HandleMailExpired(ctx *gin.Context) {
	var filepath = path.Join("services/mail_templates", "mail_expired_token.html")
	var tmpl, err = template.ParseFiles(filepath)

	if err != nil {
		fmt.Fprintf(ctx.Writer, err.Error(), http.StatusInternalServerError)
	}

	var data = map[string]interface{}{
		"title": "EXPIRED TOKEN",
		"name":  "OPPS TOKEN EXPIRED",
	}

	err = tmpl.Execute(ctx.Writer, data)

	if err != nil {
		fmt.Fprintf(ctx.Writer, err.Error(), http.StatusInternalServerError)
	}

}

func (c *authController) HandleMailAlreadyActive(ctx *gin.Context) {
	var filepath = path.Join("services/mail_templates", "mail_already_active.html")
	var tmpl, err = template.ParseFiles(filepath)

	if err != nil {
		fmt.Fprintf(ctx.Writer, err.Error(), http.StatusInternalServerError)
	}

	var data = map[string]interface{}{
		"title": "MAIL ALREADY ACTIVE",
		"name":  "ACCOUNT HAS BEEN ACTIVED",
	}

	err = tmpl.Execute(ctx.Writer, data)

	if err != nil {
		fmt.Fprintf(ctx.Writer, err.Error(), http.StatusInternalServerError)
	}
}
