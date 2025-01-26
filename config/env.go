package config

import "os"

// type Config struct {
// 	port  	string
// 	user 		string
// 	dbName 		string
// 	password	string
// 	dbPort 		string
// 	sslMode	 	string
// }

// func initConfig() Config{
// 	return Config{
// 		port: getEnv("PORT","3000"),
//         user: getEnv("USER","postgres"),
//         dbName: getEnv("DB_NAME","postgres"),
//         password: getEnv("PASSWORD","mygobank"),
//         dbPort: getEnv("DB_PORT","5435"),
//         sslMode: getEnv("SSL_MODE","disable"),
//     }
// }

func GetEnv(key, fallback string) string {
	if value, ok := os.LookupEnv(key); ok {
		return value
	}
	return fallback
}