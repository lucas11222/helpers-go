package authmanager

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/redis/go-redis/v9"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/v2/bson"
	"go.mongodb.org/mongo-driver/v2/mongo"
	"go.mongodb.org/mongo-driver/v2/mongo/options"
	"golang.org/x/crypto/bcrypt"
)

type User struct {
	ID               string   `json:"id"`
	Name             string   `json:"name"`
	Username         string   `json:"username"`
	Email            string   `json:"email"`
	PasswordHash     string   `json:"password_hash"`
	Admin            bool     `json:"admin"`
	Status           string   `json:"status"`
	Timezone         string   `json:"timezone"`
	ModerationReason string   `json:"moderation_reason"`
	Pushnotification []string `json:"pushnotification"`
	Services         []string `json:"services"`
	CreatedAt        int      `json:"created_at"`
	UpdatedAt        int      `json:"updated_at"`
}
type GiveUser struct {
	ID               string   `json:"id"`
	Name             string   `json:"name"`
	Username         string   `json:"username"`
	Email            string   `json:"email"`
	Admin            bool     `json:"admin"`
	Status           string   `json:"status"`
	Timezone         string   `json:"timezone"`
	ModerationReason string   `json:"moderation_reason"`
	Pushnotification []string `json:"pushnotification"`
	Services         []string `json:"services"`
	CreatedAt        int      `json:"created_at"`
	UpdatedAt        int      `json:"updated_at"`
}

func MongoDBClient(collection string) (*mongo.Client, *mongo.Collection, error) {
	uri := os.Getenv("MONGODB_URI")
	docs := "www.mongodb.com/docs/drivers/go/current/"
	if uri == "" {
		log.Fatal("Set your 'MONGODB_URI' environment variable. " +
			"See: " + docs +
			"usage-examples/#environment-variable")
	}
	client, err := mongo.Connect(options.Client().
		ApplyURI(uri))
	if err != nil {
		panic(err)
	}
	defer func() {
		if err := client.Disconnect(context.TODO()); err != nil {
			panic(err)
		}
	}()
	coll := client.Database(os.Getenv("DB_ENV")).Collection(collection)
	return client, coll, nil
}
func RedisClient(collection string) *redis.Client {
	client := redis.NewClient(&redis.Options{
		Addr:     "localhost:6379",
		Password: "", // No password set
		DB:       0,  // Use default DB
		Protocol: 2,  // Connection protocol
	})
	return client
}

func JWTCreateToken(email string) (string, error) {
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"sub": email,
	})
	signingKey := []byte(os.Getenv("JWT_SIGNING_KEY"))
	tokenString, err := token.SignedString(signingKey)
	if err != nil {
		return "", err
	}
	return tokenString, nil
}
func JWTValidateToken(tokenString string) (bool, string) {
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (any, error) {
		return os.Getenv("JWT_SIGNING_KEY"), nil
	}, jwt.WithValidMethods([]string{jwt.SigningMethodHS256.Alg()}))
	if err != nil {
		log.Fatal(err)
	}
	if claims, ok := token.Claims.(jwt.MapClaims); ok {
		fmt.Println(claims["sub"])
		return true, claims["sub"].(string)
	}
	return false, ""
}

func CheckPassword(password, hashed string) bool {
	err := bcrypt.CompareHashAndPassword([]byte(hashed), []byte(password))
	return err == nil
}
func HashPassword(password string) (string, error) {
	bytes, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	return string(bytes), err
}

func GetUserByToken(token string) (string, error) {
	ok, email := JWTValidateToken(token)
	if !ok {
		return "", fmt.Errorf("invalid token")
	}

	user, err := GetUserByEmail(email, false)
	if err != nil {
		return "", err
	}

	jsonData, err := json.Marshal(user)
	if err != nil {
		return "", err
	}

	return string(jsonData), nil
}
func GetUserByTokenHash(token string) (*User, error) {
	ok, email := JWTValidateToken(token)
	if !ok {
		return nil, fmt.Errorf("invalid token")
	}

	user, err := GetUserByEmailHash(email, false)
	if err != nil {
		return nil, err
	}

	return user, nil
}
func GetUserByEmailHash(email string, bypassCache bool) (*User, error) {
	ctx := context.Background()
	redisClient := RedisClient("cache")

	if !bypassCache {
		lookupIDCmd := redisClient.Get(ctx, "byEmail:"+email)
		lookupID, err := lookupIDCmd.Result()
		if err == nil {
			cachedUser := redisClient.Get(ctx, "userdata:"+lookupID)
			if cachedUser.Err() == nil {
				var user User
				if err := json.Unmarshal([]byte(cachedUser.Val()), &user); err == nil {
					return &user, nil
				}
			}
		}
	}

	client, userCollection, err := MongoDBClient("users")
	if err != nil {
		return nil, err
	}
	defer client.Disconnect(ctx)

	var User User
	err = userCollection.FindOne(ctx, bson.M{"email": email}).Decode(&User)
	if err != nil {
		return nil, err
	}

	jsonData, err := json.Marshal(User)
	if err == nil {
		redisClient.Set(ctx, "userdata:"+User.ID, jsonData, 0)
		redisClient.Set(ctx, "byEmail:"+User.Email, User.ID, 0)
	}

	return &User, nil
}

func GetUserByID(id string, bypassCache bool) (*GiveUser, error) {
	ctx := context.Background()
	cacheKey := "userdata:" + id
	redisClient := RedisClient("cache")

	if !bypassCache {
		cachedUser := redisClient.Get(ctx, cacheKey)
		if err := cachedUser.Err(); err == nil {
			var User GiveUser
			if err := json.Unmarshal([]byte(cachedUser.Val()), &User); err == nil {
				return &User, nil
			}
		}
	}

	client, userCollection, err := MongoDBClient("users")
	if err != nil {
		return nil, err
	}
	defer client.Disconnect(ctx)

	var User GiveUser
	err = userCollection.FindOne(ctx, bson.M{"_id": id}).Decode(&User)
	if err != nil {
		return nil, err
	}

	jsonData, err := json.Marshal(User)
	if err == nil {
		redisClient.Set(ctx, cacheKey, jsonData, 0)
	}

	return &User, nil
}
func GetUserByEmail(email string, bypassCache bool) (*GiveUser, error) {
	ctx := context.Background()
	redisClient := RedisClient("cache")

	if !bypassCache {
		lookupIDCmd := redisClient.Get(ctx, "byEmail:"+email)
		lookupID, err := lookupIDCmd.Result()
		if err == nil {
			cachedUser := redisClient.Get(ctx, "userdata:"+lookupID)
			if cachedUser.Err() == nil {
				var user GiveUser
				if err := json.Unmarshal([]byte(cachedUser.Val()), &user); err == nil {
					return &user, nil
				}
			}
		}
	}

	client, userCollection, err := MongoDBClient("users")
	if err != nil {
		return nil, err
	}
	defer client.Disconnect(ctx)

	var User GiveUser
	err = userCollection.FindOne(ctx, bson.M{"email": email}).Decode(&User)
	if err != nil {
		return nil, err
	}

	jsonData, err := json.Marshal(User)
	if err == nil {
		redisClient.Set(ctx, "userdata:"+User.ID, jsonData, 0)
		redisClient.Set(ctx, "byEmail:"+User.Email, User.ID, 0)
	}

	return &User, nil
}

func GetUserByIdHash(id string, bypassCache bool) (*User, error) {
	ctx := context.Background()
	cacheKey := "userdata:" + id
	redisClient := RedisClient("cache")

	if !bypassCache {
		cachedUser := redisClient.Get(ctx, cacheKey)
		if err := cachedUser.Err(); err == nil {
			var User User
			if err := json.Unmarshal([]byte(cachedUser.Val()), &User); err == nil {
				return &User, nil
			}
		}
	}

	client, userCollection, err := MongoDBClient("users")
	if err != nil {
		return nil, err
	}
	defer client.Disconnect(ctx)

	var User User
	err = userCollection.FindOne(ctx, bson.M{"_id": id}).Decode(&User)
	if err != nil {
		return nil, err
	}

	jsonData, err := json.Marshal(User)
	if err == nil {
		redisClient.Set(ctx, cacheKey, jsonData, 0)
	}

	return &User, nil
}
func GetUserByUsername(username string, bypassCache bool) (*User, error) {
	ctx := context.Background()
	redisClient := RedisClient("cache")

	if !bypassCache {
		lookupIDCmd := redisClient.Get(ctx, "byUsername:"+username)
		lookupID, err := lookupIDCmd.Result()
		if err == nil {
			cachedUser := redisClient.Get(ctx, "userdata:"+lookupID)
			if cachedUser.Err() == nil {
				var User User
				if err := json.Unmarshal([]byte(cachedUser.Val()), &User); err == nil {
					return &User, nil
				}
			}
		}
	}

	client, userCollection, err := MongoDBClient("users")
	if err != nil {
		return nil, err
	}
	defer client.Disconnect(ctx)

	var User User
	err = userCollection.FindOne(ctx, bson.M{"username": username}).Decode(&User)
	if err != nil {
		return nil, err
	}

	jsonData, err := json.Marshal(User)
	if err == nil {
		redisClient.Set(ctx, "userdata:"+User.ID, jsonData, 0)
		redisClient.Set(ctx, "byUsername:"+User.Username, User.ID, 0)
	}

	return &User, nil
}

func CreateAccount(name, username, email, password string) (string, error) {
	ctx := context.Background()
	client, userCollection, err := MongoDBClient("users")
	if err != nil {
		return "", err
	}
	defer client.Disconnect(ctx)

	hashedPassword, err := HashPassword(password)
	if err != nil {
		return "", err
	}

	user := User{
		Name:             name,
		Username:         username,
		Email:            email,
		PasswordHash:     hashedPassword,
		Admin:            false,
		Status:           "active",
		Timezone:         os.Getenv("TIMEZONE"),
		Pushnotification: []string{},
		Services:         []string{},
		CreatedAt:        int(time.Now().Unix()),
		UpdatedAt:        int(time.Now().Unix()),
	}

	res, err := userCollection.InsertOne(ctx, user)
	if err != nil {
		return "", err
	}

	// Convertir el ID a string
	objectID, ok := res.InsertedID.(primitive.ObjectID)
	if !ok {
		return "", fmt.Errorf("no se pudo convertir el ID del usuario")
	}
	userID := objectID.Hex()

	redisClient := RedisClient("cache")

	// Guardar en cache
	userJson, err := json.Marshal(user)
	if err != nil {
		return "", err
	}

	err = redisClient.Set(ctx, "userdata:"+userID, userJson, 0).Err()
	if err != nil {
		return "", err
	}

	redisClient.Set(ctx, "byEmail:"+email, userID, 0)
	redisClient.Set(ctx, "byUsername:"+username, userID, 0)

	// Crear token
	token, err := JWTCreateToken(email)
	if err != nil {
		return "", err
	}

	return token, nil
}

func DeleteAccount(userID string) bool {
	ctx := context.Background()

	// Get MongoDB client and collection
	client, userCollection, err := MongoDBClient("users")
	if err != nil {
		return false
	}
	defer client.Disconnect(ctx)

	// Delete from MongoDB
	_, err = userCollection.DeleteOne(ctx, bson.M{"_id": userID})
	if err != nil {
		return false
	}

	// Initialize Redis client once
	redisClient := RedisClient("cache")

	// Delete cache keys
	keysToDelete := []string{
		"userdata:" + userID,
		"byEmail:" + userID,
		"email:" + userID,
		"byUsername:" + userID,
		"username:" + userID,
	}
	for _, key := range keysToDelete {
		_ = redisClient.Del(ctx, key).Err()
	}

	return true
}
func DeleteAccountCache(userID string) bool {
	ctx := context.Background()
	// Initialize Redis client once
	redisClient := RedisClient("cache")

	// Delete cache keys
	keysToDelete := []string{
		"userdata:" + userID,
		"byEmail:" + userID,
		"email:" + userID,
		"byUsername:" + userID,
		"username:" + userID,
	}
	for _, key := range keysToDelete {
		_ = redisClient.Del(ctx, key).Err()
	}

	return true
}
func GetPaginatedUsers(page int, limit int, search string) ([]bson.M, error) {
	ctx := context.Background()
	client, userCollection, err := MongoDBClient("users")
	if err != nil {
		return nil, err
	}
	defer client.Disconnect(ctx)

	filter := bson.M{}
	if search != "" {
		regex := primitive.Regex{Pattern: search, Options: "i"}
		filter = bson.M{
			"$or": []bson.M{
				{"name": bson.M{"$regex": regex}},
				{"email": bson.M{"$regex": regex}},
				{"username": bson.M{"$regex": regex}},
			},
		}
	}

	skip := int64((page - 1) * limit)
	limit64 := int64(limit)

	opts := options.Find().SetSkip(skip).SetLimit(limit64)

	cursor, err := userCollection.Find(ctx, filter, opts)
	if err != nil {
		return nil, err
	}
	defer cursor.Close(ctx)

	var users []bson.M
	if err = cursor.All(ctx, &users); err != nil {
		return nil, err
	}

	return users, nil
}
func BlockUser(userid, reason string) (bool, error) {
	user, err := GetUserByID(userid, false)
	if err != nil {
		return false, err
	}
	user.Status = "suspended"
	user.ModerationReason = reason
	user.UpdatedAt = int(time.Now().Unix())
	return true, nil
}
func UnBlockUser(userid, reason string) (bool, error) {
	user, err := GetUserByID(userid, false)
	if err != nil {
		return false, err
	}
	user.Status = "active"
	user.ModerationReason = reason
	user.UpdatedAt = int(time.Now().Unix())
	return true, nil
}
func ResetPassword(userid, newpassword string) (bool, error) {
	user, err := GetUserByIdHash(userid, false)
	if err != nil {
		return false, err
	}
	user.PasswordHash, err = HashPassword(newpassword)
	if err != nil {
		return false, err
	}
	user.UpdatedAt = int(time.Now().Unix())
	return true, nil
}
