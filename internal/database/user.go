package database

import (
	"context"
	"fmt"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
)

type User struct {
	ID       primitive.ObjectID `bson:"_id,omitempty"`
	Username string             `bson:"username"`
	Password []byte             `bson:"password"`
	Role     string             `bson:"role"`
}

func (db UserDatabase) FindUserByID(ctx context.Context, id string) (User, error) {
	var u User
	objID, err := primitive.ObjectIDFromHex(id)
	if err != nil {
		return u, fmt.Errorf("error creating ObjectID from hex: %s: %w", id, err)
	}
	err = db.Collection(CollectionUsers).FindOne(ctx, bson.M{"_id": objID}).Decode(&u)
	if err != nil {
		return u, fmt.Errorf("error finding User with ID: %s: %w", id, err)
	}
	return u, nil
}

func (db UserDatabase) FindUserByUsername(ctx context.Context, username string) (User, error) {
	var u User
	err := db.Collection(CollectionUsers).FindOne(ctx, bson.M{"username": username}).Decode(&u)
	if err != nil {
		return u, fmt.Errorf("error finding User with username: %s: %w", username, err)
	}
	return u, nil
}
