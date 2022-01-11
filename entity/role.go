package entity

import (
	"time"
)

type Role struct {
	ID        uint64 `gorm:"primary_key:auto_increment" json:"id"`
	UUID      string `gorm:"type:varchar(255)" json:uuid`
	Name      string `gorm:"type:varchar(255)" json:"name"`
	IsDeleted bool   `gorm:"type:bool" default:"false"`
	CreatedAt time.Time
	UpdatedAt time.Time
}
