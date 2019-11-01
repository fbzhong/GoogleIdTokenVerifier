package GoogleIdTokenVerifier

import (
	"testing"
)

func TestCheckToken(t *testing.T) {
	authToken := "XXXXXXXXXXX.XXXXXXXXXXXX.XXXXXXXXXX"
	email := "xxxx@xxxxx.iam.gserviceaccount.com"
	aud := "XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX.apps.googleusercontent.com"

	actual, err := Verify(authToken, IssuerValidator(), ExpireValidator(), AudienceValidator(aud), EmailValidator(email))

	if err != nil {
		t.Errorf("err: %v, got %v", err, actual)
	}
}
