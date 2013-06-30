package mtoy

import (
	"errors"
	"github.com/kidstuff/toys/model"
	"labix.org/v2/mgo/bson"
)

var (
	ErrRequireStr = errors.New("mtoy: Decode require a string")
	ErrInvalidStr = errors.New("mtoy: Invalid input string format")
)

func init() {
	model.Register("mtoy", &Driver{})
}

type Driver struct{}

func (d *Driver) DecodeId(i interface{}) (model.Identifier, error) {
	idStr, ok := i.(string)
	if !ok {
		return nil, ErrRequireStr
	}

	if !bson.IsObjectIdHex(idStr) {
		return nil, ErrInvalidStr
	}

	return ID{bson.ObjectIdHex(idStr)}, nil
}

func (d *Driver) ValidIdRep(i interface{}) bool {
	idStr, ok := i.(string)
	if !ok {
		return false
	}

	if !bson.IsObjectIdHex(idStr) {
		return false
	}

	return true
}

func (d *Driver) NewId() model.Identifier {
	return NewID()
}

// ID a wraper for bson.ObjectId implements github.com/kidstuff/toys/model#Identifier
type ID struct {
	bson.ObjectId
}

func NewID() ID {
	return ID{bson.NewObjectId()}
}

func (id ID) Decode(i interface{}) error {
	idStr, ok := i.(string)
	if !ok {
		return ErrRequireStr
	}

	if !bson.IsObjectIdHex(idStr) {
		return ErrInvalidStr
	}

	id.ObjectId = bson.ObjectIdHex(idStr)
	return nil
}

func (id ID) Encode() string {
	return id.Hex()
}
