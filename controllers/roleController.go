package controller

import (
	"net/http"

	"github.com/andiahmads/raddit-clone/dto"
	"github.com/andiahmads/raddit-clone/helpers"
	"github.com/andiahmads/raddit-clone/services"
	"github.com/gin-gonic/gin"
)

type RoleController interface {
	CreateRoles(ctx *gin.Context)
}

type roleController struct {
	roleService services.RoleService
}

//make instance
func NewRoleController(roleService services.RoleService) RoleController {
	return &roleController{
		roleService: roleService,
	}
}

func (c *roleController) CreateRoles(context *gin.Context) {
	var registerDTO dto.RoleDTO
	errDTO := context.ShouldBind(&registerDTO)
	if errDTO != nil {
		response := helpers.BuildErrorResponse("Failed to Proccess", errDTO.Error(), helpers.EmptyObj{})
		context.AbortWithStatusJSON(http.StatusBadRequest, response)
	}
	result := c.roleService.CreateRole(registerDTO)
	response := helpers.BuildSuccessResponse(true, "OK", result)
	context.JSON(http.StatusCreated, response)
}
