package mtoy

import (
	"errors"
	"labix.org/v2/mgo/bson"
)

// ID a wraper for bson.ObjectId implements github.com/kidstuff//model#Identifier
type ID struct {
	bson.ObjectId
}

func NewID() ID {
	return ID{bson.NewObjectId()}
}

func (id ID) Decode(i interface{}) error {
	idStr, ok := i.(string)
	if !ok {
		return errors.New("mtoy: Decode require a string")
	}

	if !bson.IsObjectIdHex(idStr) {
		return errors.New("mtoy: Invalid input string format")
	}

	id.ObjectId = bson.ObjectIdHex(idStr)
	return nil
}

func (id ID) Encode() string {
	return id.Hex()
}
