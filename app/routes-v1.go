package app

import (
	"github.com/andiahmads/raddit-clone/config"
	controller "github.com/andiahmads/raddit-clone/controllers"
	"github.com/andiahmads/raddit-clone/repository"
	"github.com/andiahmads/raddit-clone/services"
	"github.com/gin-gonic/gin"
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

func StartAppV1() {
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
		roleRouters.POST("/", roleController.CreateRoles)
	}
	// roleRouters.POST("/", roleController.CreateRoles)
	// roleRouters.GET("/{id}", roleController.GetByIdRole)
	// roleRouters.GET("/", roleController.GetRoles)
	// roleRouters.PUT("/", roleController.UpdateRole)
	// roleRouters.DELETE("/", roleController.DeleteRole)

	r.Run() // listen and serve on 0.0.0.0:8080 (for windows "localhost:8080")

	r.Run()

}
