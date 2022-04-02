package main

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/gorilla/handlers"
	"github.com/gorilla/mux"
	"github.com/ilyakaznacheev/cleanenv"
)

// Global variables
var appConfig AppConfig
var appData AppData
var appAuth AppAuth

func main() {

	setWorkingDir()

	loadConfig()

	loadData()

	setupWebServer()

}

func setWorkingDir() {

	thisApp, err := os.Executable()
	if err != nil {
		log.Fatalf("Error determining the directory. \"%s\"", err)
	}
	appPath := filepath.Dir(thisApp)
	os.Chdir(appPath)
	log.Printf("Set working directory: %s", appPath)

}

func loadConfig() {

	err := cleanenv.ReadConfig("config.json", &appConfig)
	if err != nil {
		log.Fatalf("Error loading config.json file. \"%s\"", err)
	}
	log.Printf("Application configuratrion loaded from config.json")

	// Fix: not definded vdir
	if appConfig.VDir == "/" {
		appConfig.VDir = ""
	}

}

func setupWebServer() {

	// Init HTTP Router - mux
	router := mux.NewRouter()

	// map directory to server static files
	router.PathPrefix(appConfig.VDir + "/static/").Handler(http.StripPrefix(appConfig.VDir+"/static/", http.FileServer(http.Dir("./static"))))

	// Define Home Route
	router.HandleFunc(appConfig.VDir, basicAuth(redirectToHomePage)).Methods("GET")
	router.HandleFunc(appConfig.VDir+"/", basicAuth(renderHomePage)).Methods("GET")

	// Define Wakeup functions with a Device Name
	router.HandleFunc(appConfig.VDir+"/wake/{deviceName}", wakeUpWithDeviceName).Methods("GET")
	router.HandleFunc(appConfig.VDir+"/wake/{deviceName}/", wakeUpWithDeviceName).Methods("GET")

	// Define Data save Api function
	router.HandleFunc(appConfig.VDir+"/data/save", basicAuth(saveData)).Methods("POST")

	// Define Data get Api function
	router.HandleFunc(appConfig.VDir+"/data/get", basicAuth(getData)).Methods("GET")

	// Define health check function
	router.HandleFunc(appConfig.VDir+"/health", checkHealth).Methods("GET")

	// Setup Webserver
	httpListen := ":" + strconv.Itoa(appConfig.Port)
	log.Printf("Startup Webserver on \"%s\"", httpListen)
	log.Printf("URL: http://*%s%s", httpListen, appConfig.VDir)

	srv := &http.Server{
		Handler: handlers.RecoveryHandler(handlers.PrintRecoveryStack(true))(router),
		Addr:    httpListen,
		// Good practice: enforce timeouts for servers you create!
		WriteTimeout: 15 * time.Second,
		ReadTimeout:  15 * time.Second,
	}

	log.Fatal(srv.ListenAndServe())

}

func basicAuth(next http.HandlerFunc) http.HandlerFunc {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		username, password, ok := r.BasicAuth()
		authOk := false
		if ok {
			usersFile, err := os.Open("users.json")
			if err != nil {
				log.Fatalf("Error loading users.json file. \"%s\"", err)
			}
			usersDecoder := json.NewDecoder(usersFile)
			err = usersDecoder.Decode(&appAuth)
			if err != nil {
				log.Fatalf("Error decoding users.json file. \"%s\"", err)
			}

			if len(appAuth.Users) == 0 {
				log.Printf("Basic Auth disabled, no users configured.")
				authOk = true
			} else {
				for _, user := range appAuth.Users {
					if username != user.Username {
						continue
					}

					password_good := ""
					switch strings.ToLower(user.Crypted) {
					case "sha256":
						password_good = user.Passuser
					default:
						password_good = fmt.Sprintf("%x", sha256.Sum256([]byte(user.Passuser)))
					}

					usernameHash := sha256.Sum256([]byte(username))
					passwordHash := strings.ToLower(fmt.Sprintf("%x", sha256.Sum256([]byte(password))))
					expectedUsernameHash := sha256.Sum256([]byte(user.Username))
					expectedPasswordHash := strings.ToLower(password_good)

					usernameMatch := (subtle.ConstantTimeCompare(usernameHash[:], expectedUsernameHash[:]) == 1)

					if usernameMatch && strings.TrimSpace(expectedPasswordHash) != "" && (passwordHash == expectedPasswordHash) {
						authOk = true
					}
					break
				}
			}

			if authOk {
				next.ServeHTTP(w, r)
				return
			}
		}

		w.Header().Set("WWW-Authenticate", `Basic realm="restricted", charset="UTF-8"`)
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
	})
}
