package services

import (
	"github.com/andiahmads/raddit-clone/dto"
	"github.com/andiahmads/raddit-clone/entity"
	"github.com/andiahmads/raddit-clone/repository"
	"github.com/google/uuid"
)

type RoleService interface {
	CreateRole(dto dto.RoleDTO) entity.Role
}

type roleService struct {
	roleRepository repository.RoleRepository
}

//create new instance
func NewRoleService(roleRep repository.RoleRepository) RoleService {
	return &roleService{
		roleRepository: roleRep,
	}
}

func (services *roleService) CreateRole(role dto.RoleDTO) entity.Role {
	genereteUiid := uuid.New()
	roleToCreate := entity.Role{}
	roleToCreate.Name = role.Name
	roleToCreate.UUID = genereteUiid.String()

	res := services.roleRepository.RegisterRole(roleToCreate)
	return res

}
