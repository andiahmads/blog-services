package main

import "github.com/andiahmads/raddit-clone/app"

// var (

// 	//call repository
// 	db             *gorm.DB                  = config.SetupDatabaseConnection()
// 	userRepository repository.UserRepository = repository.NewUserRepository(db)
// 	roleRepository repository.RoleRepository = repository.NewRoleRepository(db)

// 	//call service
// 	jwtService  services.JWTService  = services.NewJWTService()
// 	authService services.AuthService = services.NewAuthService(userRepository)
// 	roleService services.RoleService = services.NewRoleService(roleRepository)

// 	//CALL CONTROLLER
// 	authController controller.AuthController = controller.NewAuthController(authService, jwtService)
// 	roleController controller.RoleController = controller.NewRoleController(roleService)
// )

//inisialisai redist

func main() {
	app.StartAppV1()
}
