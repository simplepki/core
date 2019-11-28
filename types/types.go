package types

type CreateCertificateAuthorityEvent struct {
	Token string `json:"token"`
	CAName  string `json:"ca_name"`
	Account string `json:"account"`
}

type CreateIntermediateEvent struct {
	Token string `json:"token"`
	CAName    string `json:"ca_name"`
	InterName string `json:"intermediate_name"`
	Account string `json:"account"`
}

type SignCertificateEvent struct {
	Token string `json:"token"`
	InterChain string `json:"intermediate_chain"`
	CertName string `json:"cert_name"`
	Account string `json:"account"`
	CSR string `json:"csr"`
}

type CreateCredentialsEvent struct {
	Account string `json:"account"`
	Prefix string `json:"prefix"`
	Type string `json:"type"`
	TTL int64 `json:"ttl"`
}

type AuthorizeCredentialsEvent struct {
	Token string `json:"token"`
	TokenType string `json:"token_type"`
	Resource string `json:"resource"`
}

