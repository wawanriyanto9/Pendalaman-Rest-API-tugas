package helper

import (
	"fmt"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/dgrijalva/jwt-go"
	"github.com/pkg/errors"

	"github.com/YoriDigitalent/Digitalent-Kominfo_Pendalaman-Rest-API-master/auth/constant"
	"github.com/YoriDigitalent/Digitalent-Kominfo_Pendalaman-Rest-API-master/auth/database"
)

//untuk generate token
func CreateToken(role int, idUser string) (error, *database.TokenDetails) {
	var roleStr string

	if role == constant.ADMIN {
		roleStr = "admin"
	} else if role == constant.CUSTOMER {
		roleStr = "customer"
	}

	//token details init
	td := &database.TokenDetails{}

	//set waktu access token expire
	td.AtExpires = time.Now().Add(time.Minute * 15).Unix()

	//set waktu refresh token expire
	td.RtExpires = time.Now().Add(time.Hour).Unix()

	//set Header + Payload Access Token
	at := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"id_user": idUser,
		"role":    role,
		"exp":     td.AtExpires,
	})

	//set Salt
	//admin Salt -> secret_admin_digitalent
	//customer Salt -> secret_customer_digitalent
	var err error
	td.AccessToken, err = at.SignedString([]byte(fmt.Sprintf("secret_%s_digitalent", roleStr)))
	if err != nil {
		return err, &database.TokenDetails{}
	}

	//set Header + Payload Refresh Token
	rt := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"id_user": idUser,
		"role":    role,
		"exp":     td.RtExpires,
	})

	//set Salt Refresh Token
	//admin Salt -> refresh_secret_admin_digitalent
	//customer Salt -> refresh_secret_customer_digitalent
	td.RefreshToken, err = rt.SignedString([]byte(fmt.Sprintf("refresh_secret_%s_digitalent", roleStr)))
	if err != nil {
		return err, &database.TokenDetails{}
	}

	return nil, td

}

//Extract atau Parsing ambil data
//Bentuk Token
//
//Bearer -> Header
// ... -> Payload
// ... -> Salt
func ExtractToken(roles int, r *http.Request) string {
	var bearToken string

	//ambil dari Key Header
	if roles == constant.ADMIN {
		bearToken = r.Header.Get("digitalent-admin")
	} else if roles == constant.CUSTOMER {
		bearToken = r.Header.Get("digitalent-customer")
	}

	//ngeSplit Bearer xxx_xxx_xxx -> array of string
	//array [0] = Bearer
	//array [1] = xxx_xxx_xxx
	strArr := strings.Split(bearToken, " ")
	if len(strArr) == 2 {
		return strArr[1]
	}

	return ""
}

//verifikasi jenis token
func VerifyToken(r *http.Request) (*jwt.Token, error) {
	var roleStr string
	var roles int

	if r.Header.Get("digitalent-admin") != "" {
		roleStr = "admin"
		roles = constant.ADMIN
	} else if r.Header.Get("digitalent-customer") != "" {
		roleStr = "customer"
		roles = constant.CUSTOMER
	} else {
		return nil, errors.Errorf("Session Invalid")
	}

	tokenString := ExtractToken(roles, r)
	log.Println(tokenString)
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {

		//cek signing header apakah HS256
		if jwt.GetSigningMethod("HS256") != token.Method {
			return nil, errors.Errorf("Unexpected signing method: %v", token.Header["alg"])
		}

		return []byte(fmt.Sprintf("secret_%s_digitalent", roleStr)), nil
	})

	if err != nil {
		return nil, err
	}

	return token, nil
}

//token validation atau IsTokenValid summar?
func TokenValid(r *http.Request) (string, int, error) {

	//panggil fungsi verifikasi
	token, err := VerifyToken(r)
	if err != nil {
		return "", 0, err
	}

	//proses claim payload data dari token
	if claims, ok := token.Claims.(jwt.MapClaims); ok && token.Valid {
		idUser, ok := claims["id_user"].(string)
		role, ok := claims["role"]

		if !ok {
			return "", 0, nil
		}

		return idUser, int(role.(float64)), nil
	}

	return "", 0, nil
}
