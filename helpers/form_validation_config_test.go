package helpers

import (
	"encoding/json"
	"testing"

	"github.com/andiahmads/raddit-clone/dto"
)

func TestValidationForDTO(t *testing.T) {

	p := &dto.RegisterDTO{
		Name:     "tesfdfdfd",
		Email:    "andi.fivesco@gai.com",
		Password: "KOCOK",
	}

	ErrorMessageField, errDTO := ValidationForDTO(p)
	if errDTO != nil {

		data, err := json.Marshal(ErrorMessageField)
		if err != nil {
			panic(err)
		}
		t.Fatalf(string(data))
	}

}
