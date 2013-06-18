package mgoauth

import (
	"github.com/bufio/mtoy"
	"github.com/bufio/toys/model"
	"github.com/bufio/toys/secure/membership"
	"labix.org/v2/mgo/bson"
)

type Account struct {
	Id                 bson.ObjectId `bson:"_id"`
	membership.Account `bson:",inline"`
}

func (a *Account) GetId() model.Identifier {
	return mtoy.ID{a.Id}
}

func (a *Account) SetId(id model.Identifier) error {
	tid, ok := id.(mtoy.ID)
	if !ok {
		if !bson.IsObjectIdHex(tid.Encode()) {
			return membership.ErrInvalidId
		} else {
			a.Id = bson.ObjectIdHex(tid.Encode())
			return nil
		}
	}
	a.Id = tid.ObjectId
	return nil
}
