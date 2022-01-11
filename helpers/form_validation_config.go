package helpers

import (
	"errors"
	"fmt"
	"strings"

	"github.com/go-playground/locales/en"
	ut "github.com/go-playground/universal-translator"
	"github.com/go-playground/validator/v10"
	en_translations "github.com/go-playground/validator/v10/translations/en"
)

var validate *validator.Validate

func ValidationForDTO(data interface{}) error {
	validate = validator.New()
	english := en.New()
	uni := ut.New(english, english)
	trans, _ := uni.GetTranslator("en")
	_ = en_translations.RegisterDefaultTranslations(validate, trans)

	err := validate.Struct(data)
	fmt.Println(data)
	errs := translateError(err, trans)

	if err == nil {
		return nil
	}

	var errorMessage []string
	for i := 0; i < len(errs); i++ {
		errorMessage = append(errorMessage, errs[i].Error())
		fmt.Println(errorMessage)
	}
	return errors.New(strings.Join(errorMessage, "\n"))
}

func translateError(err error, trans ut.Translator) (errs []error) {
	if err == nil {
		return nil
	}
	validatorErrs := err.(validator.ValidationErrors)
	for _, e := range validatorErrs {
		translatedErr := fmt.Errorf(e.Translate(trans))
		errs = append(errs, translatedErr)
	}
	return errs
}
