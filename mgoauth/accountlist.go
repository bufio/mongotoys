package mgoauth

import (
	"github.com/kidstuff/toys/secure/membership"
)

type AccountList struct {
	Accounts []Account
}

func (a *AccountList) At(i int) membership.User {
	return &a.Accounts[i]
}

func (a *AccountList) Len() int {
	return len(a.Accounts)
}
