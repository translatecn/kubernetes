package main

import (
	"context"
	"github.com/golang/glog"
	"github.com/google/go-github/v33/github"
	"golang.org/x/oauth2"
)

func authByGithub(token string) (err error) {
	glog.V(2).Info("start auth by github......")
	tokenSource := oauth2.StaticTokenSource(&oauth2.Token{AccessToken: token})
	tokenClient := oauth2.NewClient(context.Background(), tokenSource)
	githubClient := github.NewClient(tokenClient)
	_, _, err = githubClient.Users.Get(context.Background(), "")
	if err != nil {
		return err
	}
	return nil
}
