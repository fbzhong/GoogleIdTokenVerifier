# GoogleIdTokenVerifier
To validate an Google ID Token in Golang

Usage:

```
	authToken := "XXXXXXXXXXX.XXXXXXXXXXXX.XXXXXXXXXX"
	email := "xxxx@xxxxx.iam.gserviceaccount.com"
	aud := "XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX.apps.googleusercontent.com"
	tokeninfo, err := Verify(authToken, IssuerValidator(), ExpireValidator(), AudienceValidator(aud), EmailValidator(email))
```
