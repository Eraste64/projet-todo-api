package main

import (
	"database/sql"
	"fmt"
	"log"
	"os"
	"strconv"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/crypto/bcrypt"
	_ "modernc.org/sqlite"
)

var db *sql.DB
var jwtKey = []byte("monsecret123")
var logFile, errorFile *os.File

type Task struct {
	ID    int    `json:"id"`
	Title string `json:"title"`
	Done  bool   `json:"done"`
}

type User struct {
	ID       int    `json:"id"`
	Name     string `json:"name"`
	Email    string `json:"email"`
	Password string `json:"-"`
	IsAdmin  bool   `json:"isAdmin"`
}

func main() {
	var err error
	// --- Création de la BDD ---
	db, err = sql.Open("sqlite", "todo.db")
	if err != nil {
		log.Fatal(err)
	}

	db.Exec(`CREATE TABLE IF NOT EXISTS tasks (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		title TEXT,
		done BOOLEAN
	);`)
	db.Exec(`CREATE TABLE IF NOT EXISTS users (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		name TEXT,
		email TEXT UNIQUE,
		password TEXT,
		isAdmin BOOLEAN
	);`)

	// Créer admin si absent
	var count int
	db.QueryRow("SELECT COUNT(*) FROM users WHERE isAdmin=1").Scan(&count)
	if count == 0 {
		hash, _ := bcrypt.GenerateFromPassword([]byte("admin123"), bcrypt.DefaultCost)
		db.Exec("INSERT INTO users(name,email,password,isAdmin) VALUES(?,?,?,1)", "Admin", "admin@admin.com", string(hash))
		fmt.Println("Admin créé : admin@admin.com / admin123")
	}

	// --- Création des logs pour suivre toutes les opérations ---
	logFile, _ = os.OpenFile("app.log", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	errorFile, _ = os.OpenFile("error.log", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	defer logFile.Close()
	defer errorFile.Close()

	r := gin.Default() // crée un serveur web tout prêt avec Gin
	r.Use(LoggerMiddleware())

	// --- Ping ---
	r.GET("/ping", func(c *gin.Context) {
		c.JSON(200, gin.H{"message": "pong"})
	})

	// --- Auth ---
	r.POST("/user/register", Register) // creer un compte
	r.POST("/user/login", Login)       // se connecter

	// --- Routes pour mettre à jour les informations ---
	r.PUT("/me", AuthMiddleware(), UpdateMeHandler)                          // mettre à jour son propre profil
	r.PUT("/admin/users/:id", AuthMiddlewareAdmin(), AdminUpdateUserHandler) // admin modifie un utilisateur

	// --- Routes pour exécuter les taches ---
	auth := r.Group("/", AuthMiddleware())
	auth.GET("/tasks", GetTasks)            // lister toutes les tâches
	auth.GET("/tasks/:id", GetTask)         // voir une tâche précise
	auth.POST("/tasks", CreateTask)         // créer une tâche
	auth.PUT("/tasks/:id", UpdateTask)      // modifier une tâche
	auth.DELETE("/tasks/:id", DeleteTask)   // supprimer une tâche
	auth.PUT("/tasks", BatchUpdateTasks)    // modifier plusieurs tâches à la fois
	auth.DELETE("/tasks", BatchDeleteTasks) // supprimer plusieurs tâches à la fois

	// --- Admin ---
	r.DELETE("/reset", AuthMiddlewareAdmin(), ResetDB)

	// --- Lancer le server ---
	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}
	fmt.Println("Server running on port", port)
	r.Run(":" + port)
}

// ================= Ecrire dans les fichiers logs =================
func LoggerMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		clientIP := c.ClientIP()   // Récupère l'adresse IP du client
		method := c.Request.Method // Récupère la méthode HTTP
		path := c.Request.URL.Path // Récupère le chemin de la requête

		// Avant de traiter la requête

		c.Next() // Traite la requête

		// Après avoir traité la requête

		status := c.Writer.Status()                                               // Récupère le code de statut HTTP
		line := fmt.Sprintf("[%s] %s %s -> %d\n", clientIP, method, path, status) // Formate la ligne de log
		logFile.WriteString(line)                                                 // Écrit dans le fichier de log
		if status >= 400 {                                                        // Si c'est une erreur, écrit aussi dans error.log
			errorFile.WriteString(line)
		}
	}
}

// ================= Auth Handlers (fonctions avec requette HTTP) =================

// Inscription
func Register(c *gin.Context) {
	var u User
	if err := c.ShouldBindJSON(&u); err != nil { // lie le JSON reçu à la structure User
		c.JSON(400, gin.H{"error": err.Error()})
		return
	}
	hash, _ := bcrypt.GenerateFromPassword([]byte(u.Password), bcrypt.DefaultCost) // hash le mot de passe
	_, err := db.Exec("INSERT INTO users(name,email,password,isAdmin) VALUES(?,?,?,0)", u.Name, u.Email, string(hash))
	if err != nil { // erreur si email déjà utilisé
		c.JSON(400, gin.H{"error": "email déjà utilisé"})
		return
	}
	token, _ := GenerateJWT(u.Email)   // génère un token JWT
	c.JSON(200, gin.H{"token": token}) // renvoie le token au client
}

// Connexion
func Login(c *gin.Context) {
	var req struct {
		Email    string `json:"email"`
		Password string `json:"password"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(400, gin.H{"error": err.Error()})
		return
	}
	var u User
	err := db.QueryRow("SELECT id,name,email,password,isAdmin FROM users WHERE email=?", req.Email).Scan(&u.ID, &u.Name, &u.Email, &u.Password, &u.IsAdmin) // cherche l'utilisateur par email
	if err != nil {
		c.JSON(401, gin.H{"error": "utilisateur inconnu"})
		return
	}
	if bcrypt.CompareHashAndPassword([]byte(u.Password), []byte(req.Password)) != nil { // compare le mot de passe
		c.JSON(401, gin.H{"error": "mot de passe incorrect"})
		return
	}
	token, _ := GenerateJWT(u.Email)
	c.JSON(200, gin.H{"token": token})
}

// ================= JWT =================

// Générer un token JWT
func GenerateJWT(email string) (string, error) {
	claims := jwt.MapClaims{
		"email": email,
		"exp":   time.Now().Add(72 * time.Hour).Unix(),
	}
	tok := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return tok.SignedString(jwtKey)
}

// Middleware pour routes protégées (utilisateur connecté)
func AuthMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		auth := c.GetHeader("Authorization")
		if len(auth) < 7 || auth[:7] != "Bearer " {
			c.AbortWithStatusJSON(401, gin.H{"error": "missing token"})
			return
		}
		tokenStr := auth[7:]
		tok, err := jwt.Parse(tokenStr, func(t *jwt.Token) (interface{}, error) {
			return jwtKey, nil
		})
		if err != nil || !tok.Valid {
			c.AbortWithStatusJSON(401, gin.H{"error": "invalid token"})
			return
		}
		claims := tok.Claims.(jwt.MapClaims)
		var userID int
		db.QueryRow("SELECT id FROM users WHERE email=?", claims["email"]).Scan(&userID)
		c.Set("uid", userID)
		c.Next()
	}
}

// Middleware pour vérifier si l'utilisateur est admin
func AuthMiddlewareAdmin() gin.HandlerFunc {
	return func(c *gin.Context) {
		auth := c.GetHeader("Authorization")
		if len(auth) < 7 || auth[:7] != "Bearer " {
			c.AbortWithStatusJSON(401, gin.H{"error": "missing token"})
			return
		}
		tokenStr := auth[7:]
		tok, err := jwt.Parse(tokenStr, func(t *jwt.Token) (interface{}, error) {
			return jwtKey, nil
		})
		if err != nil || !tok.Valid {
			c.AbortWithStatusJSON(401, gin.H{"error": "invalid token"})
			return
		}
		claims := tok.Claims.(jwt.MapClaims)
		email := claims["email"].(string)
		var isAdmin bool
		db.QueryRow("SELECT isAdmin FROM users WHERE email=?", email).Scan(&isAdmin)
		if !isAdmin {
			c.AbortWithStatusJSON(403, gin.H{"error": "admin only"})
			return
		}
		c.Next()
	}
}

// ================= User Handlers =================

// Mettre à jour son propre profil
func UpdateMeHandler(c *gin.Context) {
	userID := c.GetInt("uid")
	var body struct {
		Name     string `json:"name"`
		Email    string `json:"email"`
		Password string `json:"password"`
	}
	if err := c.BindJSON(&body); err != nil {
		c.JSON(400, gin.H{"error": "invalid JSON"})
		return
	}
	if body.Password != "" {
		hash, _ := bcrypt.GenerateFromPassword([]byte(body.Password), 12)
		body.Password = string(hash)
	}
	_, err := db.Exec(`
		UPDATE users 
		SET name = COALESCE(NULLIF(?,''), name),
		    email = COALESCE(NULLIF(?,''), email),
		    password = COALESCE(NULLIF(?,''), password)
		WHERE id = ?`,
		body.Name, body.Email, body.Password, userID) // met à jour les infos
	if err != nil {
		c.JSON(500, gin.H{"error": "database error"})
		return
	}
	c.JSON(200, gin.H{"message": "profile updated"})
}

// Admin modifie un utilisateur (sauf un autre admin)
func AdminUpdateUserHandler(c *gin.Context) {
	id := c.Param("id")
	var body struct {
		Name     string `json:"name"`
		Email    string `json:"email"`
		Password string `json:"password"`
	}
	if err := c.BindJSON(&body); err != nil {
		c.JSON(400, gin.H{"error": "invalid JSON"})
		return
	}
	var isAdmin bool
	err := db.QueryRow("SELECT isAdmin FROM users WHERE id = ?", id).Scan(&isAdmin) // vérifie si l'utilisateur est admin
	if err != nil {
		c.JSON(404, gin.H{"error": "user not found"})
		return
	}
	if isAdmin {
		c.JSON(403, gin.H{"error": "cannot modify another admin"})
		return
	}
	if body.Password != "" {
		hash, _ := bcrypt.GenerateFromPassword([]byte(body.Password), 12)
		body.Password = string(hash)
	}
	_, err = db.Exec(`
		UPDATE users 
		SET name = COALESCE(NULLIF(?,''), name),
		    email = COALESCE(NULLIF(?,''), email),
		    password = COALESCE(NULLIF(?,''), password)
		WHERE id = ?`,
		body.Name, body.Email, body.Password, id)
	if err != nil {
		c.JSON(500, gin.H{"error": "database error"})
		return
	}
	c.JSON(200, gin.H{"message": "user updated"})
}

// ================= Tasks Handlers =================

// Lister toutes les tâches (avec option de recherche)
func GetTasks(c *gin.Context) {
	query := c.Query("query")
	var rows *sql.Rows
	var err error
	if query != "" {
		q := "%" + query + "%"
		rows, err = db.Query("SELECT id,title,done FROM tasks WHERE title LIKE ?", q)
	} else {
		rows, err = db.Query("SELECT id,title,done FROM tasks")
	}
	if err != nil {
		c.JSON(500, gin.H{"error": err.Error()})
		return
	}
	defer rows.Close()
	tasks := []Task{}
	for rows.Next() {
		var t Task
		rows.Scan(&t.ID, &t.Title, &t.Done)
		tasks = append(tasks, t)
	}
	c.JSON(200, tasks)
}

// Voir une tâche précise
func GetTask(c *gin.Context) {
	id := c.Param("id")
	var t Task
	err := db.QueryRow("SELECT id,title,done FROM tasks WHERE id=?", id).Scan(&t.ID, &t.Title, &t.Done)
	if err != nil {
		c.JSON(404, gin.H{"error": "task not found"})
		return
	}
	c.JSON(200, t)
}

// Créer une tâche
func CreateTask(c *gin.Context) {
	var t Task
	if err := c.ShouldBindJSON(&t); err != nil {
		c.JSON(400, gin.H{"error": err.Error()})
		return
	}
	res, _ := db.Exec("INSERT INTO tasks(title, done) VALUES(?, ?)", t.Title, t.Done)
	id, _ := res.LastInsertId()
	t.ID = int(id)
	c.JSON(200, t)
}

// Modifier une tâche
func UpdateTask(c *gin.Context) {
	id := c.Param("id")
	var t Task
	if err := c.ShouldBindJSON(&t); err != nil {
		c.JSON(400, gin.H{"error": err.Error()})
		return
	}
	_, err := db.Exec("UPDATE tasks SET title=?, done=? WHERE id=?", t.Title, t.Done, id)
	if err != nil {
		c.JSON(500, gin.H{"error": err.Error()})
		return
	}
	t.ID, _ = strconv.Atoi(id)
	c.JSON(200, t)
}

// Supprimer une tâche
func DeleteTask(c *gin.Context) {
	id := c.Param("id")
	_, err := db.Exec("DELETE FROM tasks WHERE id=?", id)
	if err != nil {
		c.JSON(500, gin.H{"error": err.Error()})
		return
	}
	c.JSON(200, gin.H{"deleted": id})
}

// ================= Batch =================

// Mettre à jour plusieurs tâches à la fois
func BatchUpdateTasks(c *gin.Context) {
	var tasks []Task
	if err := c.ShouldBindJSON(&tasks); err != nil {
		c.JSON(400, gin.H{"error": err.Error()})
		return
	}
	for _, t := range tasks {
		db.Exec("UPDATE tasks SET title=?, done=? WHERE id=?", t.Title, t.Done, t.ID)
	}
	c.JSON(200, gin.H{"updated": len(tasks)})
}

// Supprimer plusieurs tâches à la fois
func BatchDeleteTasks(c *gin.Context) {
	var ids []int
	if err := c.ShouldBindJSON(&ids); err != nil {
		c.JSON(400, gin.H{"error": err.Error()})
		return
	}
	for _, id := range ids {
		db.Exec("DELETE FROM tasks WHERE id=?", id)
	}
	c.JSON(200, gin.H{"deleted": len(ids)})
}

// ================= Admin =================

// Réinitialiser la base de données (supprimer toutes les tâches)
func ResetDB(c *gin.Context) {
	db.Exec("DELETE FROM tasks")
	c.JSON(200, gin.H{"message": "BDD réinitialisée"})
}
