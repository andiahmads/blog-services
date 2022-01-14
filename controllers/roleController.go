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

	var roleDTO dto.RoleDTO
	errDTO := context.ShouldBind(&roleDTO)
	ErrorMessageField, errDTO := helpers.ValidationForDTO(roleDTO)

	if errDTO != nil {
		response := helpers.BuildErrorDtoValidation("Failed to Proccess", ErrorMessageField, helpers.EmptyObj{})
		context.AbortWithStatusJSON(http.StatusBadRequest, response)
		return
	}
	result := c.roleService.CreateRole(roleDTO)
	response := helpers.BuildSuccessResponse(true, "OK", result)
	context.JSON(http.StatusCreated, response)
	return
}
