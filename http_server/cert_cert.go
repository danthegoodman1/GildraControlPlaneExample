package http_server

import (
	"context"
	"fmt"
	"github.com/danthegoodman1/Gildra/acme_http"
	"log"
	"os"
	"path"
	"time"
)

func createLEStagingCert(ctx context.Context, domain string) error {
	caDir, err := acme_http.GetCADir(ctx, "https://acme-staging-v02.api.letsencrypt.org/directory")
	if err != nil {
		return fmt.Errorf("error in GetCADir: %w", err)
	}

	acctKid, pk, err := acme_http.CreateAccount(ctx, "deftesting@icloud.com", caDir, nil)
	if err != nil {
		return fmt.Errorf("error in CreateAccount: %w", err)
	}

	log.Println("account kid", acctKid)

	orderLocation, order, err := acme_http.CreateOrder(ctx, acctKid, domain, caDir, pk)
	if err != nil {
		return fmt.Errorf("error in CreateOrder: %w", err)
	}

	log.Printf("order response %+v\n", order)

	auth, err := acme_http.GetAuthorization(ctx, acctKid, pk, caDir, order)
	if err != nil {
		return fmt.Errorf("error in GetAuthorization: %w", err)
	}

	log.Printf("Authorization: %+v\n", *auth)

	challenge, err := acme_http.CreateChallenge(ctx, *auth, pk)
	if err != nil {
		return fmt.Errorf("error in CreateChallenge: %w", err)
	}

	err = os.WriteFile(path.Join("challenges", challenge.Token), []byte(challenge.Key), 0777)
	if err != nil {
		return fmt.Errorf("error in writing token file: %w", err)
	}

	log.Printf("Got challenge %+v\n", challenge)

	chal, err := acme_http.NotifyChallenge(ctx, caDir, acctKid, pk, *challenge)
	if err != nil {
		return fmt.Errorf("error in NotifyChallenge: %w", err)
	}

	log.Printf("Got challenge response: %+v\n", chal)

	ct, cancel := context.WithTimeout(ctx, time.Second*60)
	defer cancel()
	err = acme_http.PollAuthorizationCompleted(ct, time.Second*2, order, acctKid, pk, caDir)
	if err != nil {
		return fmt.Errorf("error in PollAuthorizationCompleted: %w", err)
	}

	log.Println("auth completed")

	resource, err := acme_http.FinalizeOrder(ctx, acctKid, domain, orderLocation, pk, caDir, time.Second*2, order)
	if err != nil {
		return fmt.Errorf("error in FinalizeOrder: %w", err)
	}

	log.Printf("finalized order, getting cert")

	resource, err = acme_http.GetCert(ctx, *resource, acctKid, pk, caDir)
	if err != nil {
		return fmt.Errorf("error in GetCert: %w", err)
	}

	log.Printf("Got cert: %+v\n", resource)

	// Write out to file
	err = os.WriteFile(fmt.Sprintf("%s.cert", domain), resource.Certificate, 0777)
	if err != nil {
		return fmt.Errorf("error in writing cert: %w", err)
	}
	err = os.WriteFile(fmt.Sprintf("%s.key", domain), resource.PrivateKey, 0777)
	if err != nil {
		return fmt.Errorf("error in writing key: %w", err)
	}

	return nil
}

func createZeroSSLCert(ctx context.Context, domain string) error {
	caDir, err := acme_http.GetCADir(ctx, "https://acme.zerossl.com/v2/DV90/directory")
	if err != nil {
		return fmt.Errorf("error in GetCADir: %w", err)
	}

	acctKid, pk, err := acme_http.CreateAccount(ctx, "deftesting@icloud.com", caDir, &acme_http.EABOptions{
		KID:     os.Getenv("ZEROSSL_KID"),
		HMACKey: os.Getenv("ZEROSSL_HMAC"),
	})
	if err != nil {
		return fmt.Errorf("error in CreateAccount: %w", err)
	}

	log.Println("account kid", acctKid)

	orderLocation, order, err := acme_http.CreateOrder(ctx, acctKid, domain, caDir, pk)
	if err != nil {
		return fmt.Errorf("error in CreateOrder: %w", err)
	}

	log.Printf("order response %+v\n", order)

	auth, err := acme_http.GetAuthorization(ctx, acctKid, pk, caDir, order)
	if err != nil {
		return fmt.Errorf("error in GetAuthorization: %w", err)
	}

	log.Printf("Authorization: %+v\n", *auth)

	challenge, err := acme_http.CreateChallenge(ctx, *auth, pk)
	if err != nil {
		return fmt.Errorf("error in CreateChallenge: %w", err)
	}

	err = os.WriteFile(path.Join("challenges", challenge.Token), []byte(challenge.Key), 0777)
	if err != nil {
		return fmt.Errorf("error in writing token file: %w", err)
	}

	log.Printf("Got challenge %+v\n", challenge)

	chal, err := acme_http.NotifyChallenge(ctx, caDir, acctKid, pk, *challenge)
	if err != nil {
		return fmt.Errorf("error in NotifyChallenge: %w", err)
	}

	log.Printf("Got challenge response: %+v\n", chal)

	ct, cancel := context.WithTimeout(ctx, time.Second*60)
	defer cancel()
	err = acme_http.PollAuthorizationCompleted(ct, time.Second*2, order, acctKid, pk, caDir)
	if err != nil {
		return fmt.Errorf("error in PollAuthorizationCompleted: %w", err)
	}

	log.Println("auth completed")

	resource, err := acme_http.FinalizeOrder(ctx, acctKid, domain, orderLocation, pk, caDir, time.Second*2, order)
	if err != nil {
		return fmt.Errorf("error in FinalizeOrder: %w", err)
	}

	log.Printf("finalized order, getting cert")

	resource, err = acme_http.GetCert(ctx, *resource, acctKid, pk, caDir)
	if err != nil {
		return fmt.Errorf("error in GetCert: %w", err)
	}

	log.Printf("Got cert: %+v\n", resource)

	// Write out to file
	err = os.WriteFile(fmt.Sprintf("%s.cert", domain), resource.Certificate, 0777)
	if err != nil {
		return fmt.Errorf("error in writing cert: %w", err)
	}
	err = os.WriteFile(fmt.Sprintf("%s.key", domain), resource.PrivateKey, 0777)
	if err != nil {
		return fmt.Errorf("error in writing key: %w", err)
	}

	return nil
}
