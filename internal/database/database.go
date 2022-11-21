package database

import (
	"context"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

const (
	AuthDB                  = "authDB"
	CollectionRefreshTokens = "refreshToken"
	UserDB                  = "userDB"
	CollectionUsers         = "users"
)

type AuthDatabase struct {
	*mongo.Database
}

type UserDatabase struct {
	*mongo.Database
}

func ConnectAuthDB(ctx context.Context, dbURI string) (*mongo.Client, error) {
	c, err := mongo.Connect(ctx, options.Client().ApplyURI(dbURI))
	if err != nil {
		return nil, err
	}

	_, err = c.Database(AuthDB).Collection(CollectionRefreshTokens).Indexes().CreateOne(
		ctx,
		mongo.IndexModel{
			Keys: bson.D{
				{Key: "user_id", Value: 1},
				{Key: "token", Value: 1},
			},
			Options: options.Index().SetUnique(true),
		},
	)
	if err != nil {
		return nil, err
	}

	return c, nil
}

func ConnectUserDB(ctx context.Context, dbURI string) (*mongo.Client, error) {
	c, err := mongo.Connect(ctx, options.Client().ApplyURI(dbURI))
	if err != nil {
		return nil, err
	}

	return c, nil
}
