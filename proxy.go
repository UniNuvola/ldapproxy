package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"os/signal"
	"strings"

	"github.com/go-ldap/ldap/v3"
	"github.com/hashicorp/go-hclog"
	"github.com/jimlambrt/gldap"
)

var env map[string]string

func main() {

	env = map[string]string{
		"P_BASEDN":      os.Getenv("P_BASEDN"),
		"P_BINDDN":      os.Getenv("P_BINDDN"),
		"P_PASSWORD":    os.Getenv("P_PASSWORD"),
		"DIP_URI":       os.Getenv("DIP_URI"),
		"DIP_BINDDN":    os.Getenv("DIP_BINDDN"),
		"DIP_PASSWORD":  os.Getenv("DIP_PASSWORD"),
		"INFN_URI":      os.Getenv("INFN_URI"),
		"INFN_BINDDN":   os.Getenv("INFN_BINDDN"),
		"INFN_PASSWORD": os.Getenv("INFN_PASSWORD"),
	}

	for k, v := range env {
		if v == "" {
			log.Fatalln("Missin environment variable", k)
		}
	}

	// create a new server
	s, err := gldap.NewServer(gldap.WithLogger(hclog.Default()))
	if err != nil {
		log.Fatalf("unable to create server: %s", err.Error())
	}

	// create a router and add a bind handler
	r, err := gldap.NewMux()
	if err != nil {
		log.Fatalf("unable to create router: %s", err.Error())
	}
	r.Bind(bindHandler)
	r.Search(searchHandler)
	s.Router(r)
	go s.Run(":389")

	// stop server gracefully when ctrl-c, sigint or sigterm occurs
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	select {
	case <-ctx.Done():
		log.Printf("\nstopping directory")
		s.Stop()
	}
}

func bindHandler(w *gldap.ResponseWriter, r *gldap.Request) {
	resp := r.NewBindResponse(
		gldap.WithResponseCode(gldap.ResultInvalidCredentials),
	)
	defer func() {
		w.Write(resp)
	}()

	m, err := r.GetSimpleBindMessage()
	if err != nil {
		log.Printf("not a simple bind message: %s", err)
		return
	}

	log.Printf("ConnID %v: curBindDN: %v", r.ConnectionID(), m.UserName)

	if m.UserName == env["P_BINDDN"] && m.Password == gldap.Password(env["P_PASSWORD"]) {
		resp.SetResultCode(gldap.ResultSuccess)
		log.Printf("bind success %v\n", m.UserName)
		return
	}

	// Bind utente dipartimento
	if strings.Contains(m.UserName, "cn=") && strings.Contains(m.UserName, "ou=users,dc=priv") {
		l, err := ldap.DialURL(env["DIP_URI"])
		if err != nil {
			log.Fatal(err)
		}
		defer l.Close()

		err = l.Bind(m.UserName, string(m.Password))
		if err != nil {
			resp.SetResultCode(gldap.ResultInvalidCredentials)
			return
		}

		resp.SetResultCode(gldap.ResultSuccess)
		log.Printf("bind success %v\n", m.UserName)
		return
	}

	// Bind utente INFN
	if strings.Contains(m.UserName, "infnUUID=") && strings.Contains(m.UserName, "ou=People,dc=infn,dc=it") {
		l, err := ldap.DialURL(env["INFN_URI"])
		if err != nil {
			log.Fatal(err)
		}
		defer l.Close()

		err = l.Bind(m.UserName, string(m.Password))
		if err != nil {
			resp.SetResultCode(gldap.ResultInvalidCredentials)
			return
		}

		resp.SetResultCode(gldap.ResultSuccess)
		log.Printf("bind success %v\n", m.UserName)
		return
	}
}

func searchHandler(w *gldap.ResponseWriter, r *gldap.Request) {
	resp := r.NewSearchDoneResponse()
	defer func() {
		w.Write(resp)
	}()
	m, err := r.GetSearchMessage()
	if err != nil {
		log.Printf("not a search message: %s", err)
		return
	}

	log.Printf("New search started by conn %v", r.ConnectionID())

	log.Printf("search base dn: %s", m.BaseDN)
	log.Printf("search scope: %d", m.Scope)
	log.Printf("search filter: %s", m.Filter)

	// Ricerca utenti nei due server LDAP
	if m.BaseDN == env["P_BASEDN"] {

		dip := false
		infn := false

		l, err := ldap.DialURL(env["DIP_URI"])
		if err != nil {
			log.Fatal(err)
		}
		defer l.Close()

		err = l.Bind(env["DIP_BINDDN"], env["DIP_PASSWORD"])
		if err != nil {
			log.Fatal(err)
		}

		// Ricerca i dati dell'utente
		searchRequest := ldap.NewSearchRequest(
			"ou=users,dc=priv",
			ldap.ScopeWholeSubtree,
			ldap.NeverDerefAliases,
			0, 0, false,
			"(&"+m.Filter+"(PerugiaGroups=booking))",
			[]string{"dn", "sn", "givenName", "PerugiaOwner", "PerugiaGroups", "subschemaSubentry"},
			nil,
		)

		sr, err := l.Search(searchRequest)
		if err != nil {
			log.Println(err)
		}

		dip = len(sr.Entries) == 1

		if len(sr.Entries) != 1 {
			log.Println("User does not exist or too many entries returned")

			// Utente non trovato nel server ldap di dipartimento, provare a cercare nel server infn
			dip = false
			l.Unbind()
			l.Close()

			l, err = ldap.DialURL(env["INFN_URI"])
			if err != nil {
				log.Println(err)
				return
			}
			defer l.Close()

			err = l.Bind(env["INFN_BINDDN"], env["INFN_PASSWORD"])
			if err != nil {
				log.Fatal(err)
			}

			searchRequest = ldap.NewSearchRequest(
				"ou=people,dc=infn,dc=it",
				ldap.ScopeWholeSubtree,
				ldap.NeverDerefAliases,
				0, 0, false,
				"(&"+m.Filter+"(l=pg))",
				//m.Filter,
				[]string{"dn", "sn", "givenName", "mail", "subschemaSubentry"},
				nil,
			)

			sr, err = l.Search(searchRequest)
			if err != nil {
				log.Println(err)
			}

			infn = len(sr.Entries) == 1

			if len(sr.Entries) != 1 {
				// Non è stato trovato neanche nel server INFN
				// Rispondere query ok ma nessun risultato
				resp.SetResultCode(gldap.ResultNoSuchObject)
				return
			}
		}

		userDN := sr.Entries[0].DN
		userSN := sr.Entries[0].GetAttributeValue("sn")
		userGivenName := sr.Entries[0].GetAttributeValue("givenName")
		userEmail := sr.Entries[0].GetAttributeValue("mail")
		userSubentry := sr.Entries[0].GetAttributeValue("subschemaSubentry")

		// Ricerca email nel ramo anagrafica per dipartimento
		if dip {
			baseDN := fmt.Sprintf("cn=%s,ou=people,dc=priv", sr.Entries[0].GetAttributeValue("PerugiaOwner"))

			searchRequest = ldap.NewSearchRequest(
				baseDN,
				ldap.ScopeWholeSubtree,
				ldap.NeverDerefAliases,
				0, 0, false,
				"(objectClass=*)",
				[]string{"mail"},
				nil,
			)

			sr, err = l.Search(searchRequest)
			if err != nil {
				log.Println(err)
				return
			}

			if len(sr.Entries) != 1 {
				return
			}

			userEmail = sr.Entries[0].GetAttributeValue("mail")
		}

		if dip || infn {
			entry := r.NewSearchResponseEntry(
				userDN,
				gldap.WithAttributes(map[string][]string{
					"givenname":         {userGivenName},
					"sn":                {userSN},
					"mail":              {userEmail},
					"subschemaSubentry": {userSubentry},
				}),
			)
			w.Write(entry)
			resp.SetResultCode(gldap.ResultSuccess)
			return
		}

		resp.SetResultCode(gldap.ResultNoSuchObject)
	}
}
