package dnsop

type Record struct {
	Name  string `json:"name"`
	Type  string `json:"type"`
	TTL   int    `json:"ttl"`
	Value string `json:"value"`
}

type RecordsResult struct {
	OK        bool     `json:"ok"`
	Records   []Record `json:"records,omitempty"`
	Rcode     string   `json:"rcode,omitempty"`
	Phase     string   `json:"phase,omitempty"`
	Message   string   `json:"message,omitempty"`
	Retryable bool     `json:"retryable,omitempty"`
}

type ApplyResult struct {
	OK        bool   `json:"ok"`
	Rcode     string `json:"rcode,omitempty"`
	Phase     string `json:"phase,omitempty"`
	Message   string `json:"message,omitempty"`
	Retryable bool   `json:"retryable,omitempty"`
}

type Prereq struct {
	Kind  string `json:"kind"` // NXRRSET | YXRRSET
	Name  string `json:"name"`
	Type  string `json:"type"`
	Value string `json:"value,omitempty"`
}

type Change struct {
	Op     string `json:"op"` // add | delete
	Record Record `json:"record"`
}
