package mgoauth

import (
	"github.com/kidstuff/toys/secure/membership"
)

type AccountList struct {
	Accounts []Account
	slice    []membership.User
}

func (a *AccountList) At(i int) membership.User {
	return &a.Accounts[i]
}

func (a *AccountList) Len() int {
	return len(a.Accounts)
}

func (a *AccountList) Slice() []membership.User {
	if n := len(a.Accounts); len(a.slice) != n {
		a.slice = make([]membership.User, n, n)
		for idx, acc := range a.Accounts {
			a.slice[idx] = &acc
		}
	}
	return a.slice
}
