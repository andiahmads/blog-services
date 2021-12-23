package repository

import (
	"github.com/andiahmads/raddit-clone/entity"
	"gorm.io/gorm"
)

type RoleRepository interface {
	RegisterRole(role entity.Role) entity.Role
}

type roleConnection struct {
	connection *gorm.DB
}

//make instance
func NewRoleRepository(db *gorm.DB) RoleRepository {
	return &roleConnection{
		connection: db,
	}
}

func (db *roleConnection) RegisterRole(role entity.Role) entity.Role {
	db.connection.Save(&role)
	return role
}
