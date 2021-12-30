package main

import (
	"fmt"
	"os"

	"github.com/andiahmads/raddit-clone/config"
	controller "github.com/andiahmads/raddit-clone/controllers"
	"github.com/andiahmads/raddit-clone/repository"
	"github.com/andiahmads/raddit-clone/services"
	"github.com/gin-gonic/gin"
	"github.com/go-redis/redis/v7"
	"gorm.io/gorm"
)

var (

	//call repository
	db             *gorm.DB                  = config.SetupDatabaseConnection()
	userRepository repository.UserRepository = repository.NewUserRepository(db)
	roleRepository repository.RoleRepository = repository.NewRoleRepository(db)

	//call service
	jwtService  services.JWTService  = services.NewJWTService()
	authService services.AuthService = services.NewAuthService(userRepository)
	roleService services.RoleService = services.NewRoleService(roleRepository)

	//CALL CONTROLLER
	authController controller.AuthController = controller.NewAuthController(authService, jwtService)
	roleController controller.RoleController = controller.NewRoleController(roleService)
)

//inisialisai redist
var client *redis.Client

func init() {
	dsn := os.Getenv("REDIS_DSN")
	if len(dsn) == 0 {
		dsn = "localhost:6379"
	}
	client = redis.NewClient(&redis.Options{
		Addr:     dsn, //redis port
		Password: "",
		DB:       0,
	})
	pong, err := client.Ping().Result()
	fmt.Println(pong, err)
	if err != nil {
		panic(err)
	}
}

func main() {

	r := gin.Default()
	authRouters := r.Group("api/auth")
	{
		authRouters.POST("/login", authController.Login)
		authRouters.POST("/register", authController.Register)
		authRouters.GET("/active/:token", authController.VerificationEmail)
		authRouters.GET("/email/callback", authController.HandleSuccess)
		authRouters.GET("/email/expiret-token", authController.HandleMailExpired)
		authRouters.GET("/email/already-active", authController.HandleMailAlreadyActive)
		authRouters.POST("/logout", authController.Logout)
		authRouters.POST("/refresh-token", authController.RefreshToken)
	}
	roleRouters := r.Group("api/role")
	{
		roleRouters.POST("/create", roleController.CreateRoles)
	}

	r.Run() // listen and serve on 0.0.0.0:8080 (for windows "localhost:8080")
}
