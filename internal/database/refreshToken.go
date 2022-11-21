package database

import (
	"context"
	"fmt"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
)

type RefreshToken struct {
	ID         primitive.ObjectID `bson:"_id,omitempty"`
	UserID     primitive.ObjectID `bson:"user_id"`
	Token      []byte             `bson:"token"`
	Expiration primitive.DateTime `bson:"expiration"`
}

func (db AuthDatabase) InsertRefreshToken(ctx context.Context, rt RefreshToken) (string, error) {
	r, err := db.Collection(CollectionRefreshTokens).InsertOne(ctx, rt)
	if err != nil {
		return "", fmt.Errorf("error inserting RefreshToken: %+v: %w", rt, err)
	}
	return r.InsertedID.(primitive.ObjectID).Hex(), nil
}

func (db AuthDatabase) FindRefreshTokenByID(ctx context.Context, id string) (RefreshToken, error) {
	var rt RefreshToken
	objID, err := primitive.ObjectIDFromHex(id)
	if err != nil {
		return rt, fmt.Errorf("error creating ObjectID from hex: %s: %w", id, err)
	}
	err = db.Collection(CollectionRefreshTokens).FindOne(ctx, bson.M{"_id": objID}).Decode(&rt)
	if err != nil {
		return rt, fmt.Errorf("error finding RefreshToken with ID: %s: %w", id, err)
	}
	return rt, nil
}

func (db AuthDatabase) DeleteRefreshTokenByID(ctx context.Context, id string) error {
	objID, err := primitive.ObjectIDFromHex(id)
	if err != nil {
		return fmt.Errorf("error creating ObjectID from hex: %s: %w", id, err)
	}
	_, err = db.Collection(CollectionRefreshTokens).DeleteOne(ctx, bson.M{"_id": objID})
	if err != nil {
		return fmt.Errorf("error deleting RefreshToken with ID: %s: %w", id, err)
	}
	return nil
}
