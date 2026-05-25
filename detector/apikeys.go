package detector

import (
	"fmt"
	"regexp"
)

//same struct as CryptoDetector and C2Detector
//while embedding patterns directly as methods is a viable alternative, slices of patterns scales better... adding a new API key format is one new struct literal, and not a new method
type APIKeyDetector struct {
	patterns []apiKeyPattern
}

//identical to c2Pattern
type apiKeyPattern struct {
	name			string
	regex			*regexp.Regexp
	category		string
	confidence		string
}
//same as every other detector, returns a pointer to a fully initialized struct
func NewAPIKeyDetector() *APIKeyDetector {
	return &APIKeyDetector{
		patterns: []apiKeyPattern{
			{
				name:       "GitHub Personal Access Token",
				regex:      regexp.MustCompile(`ghp_[A-Za-z0-9]{36}`), //github PATs alware start with ghp_ followed by 36 aphanumeric characters. this is guaranteed by github, so there's no false positive risk, thus high confidence
				category:   "api_key",
				confidence: "high",
			},
			{
				name:       "GitHub Fine-Grained Token",
				regex:      regexp.MustCompile(`github_pat_[A-Za-z0-9_]{22,}`), //this is their newer fine-grained PAT. it requires a separate pattern because the prefix and length are different, and they vary in length
				category:   "api_key",
				confidence: "high",
			},
			{
				name:       "Slack Webhook URL",
				regex:      regexp.MustCompile(`(?i)https?://hooks\.slack\.com/services/T[A-Z0-9]+/B[A-Z0-9]+/[A-Za-z0-9]+`), //slack webhooks follow a particular structure, /services/ followed by a T, a bot ID starting with a B. the category is exfil_channel because in a malware context, slack webhooks are used for exfiltration
				category:   "exfil_channel",
				confidence: "high",
			},
			{
				name:       "Slack Bot Token",
				regex:      regexp.MustCompile(`xoxb-[0-9]{10,13}-[0-9]{10,13}-[A-Za-z0-9]{24}`), //slack bot tokens start with xoxb-, followed by two numeric segements and an alphanumeric secret
				category:   "api_key",
				confidence: "high",
			},
			{
				name:       "Slack User Token",
				regex:      regexp.MustCompile(`xoxp-[0-9]{10,13}-[0-9]{10,13}-[0-9]{10,13}-[a-f0-9]{32}`), //slack user tokens have broader permissions, so they're worth calling out separately
				category:   "api_key",
				confidence: "high",
			},
			{
				name:       "AWS Access Key ID",
				regex:      regexp.MustCompile(`AKIA[0-9A-Z]{16}`), //AWS key IDs aways start with AKIA followed by exactly 16 uppercase alphanumeric characters. nothing else starts with AKIA so this has high confidence
				category:   "api_key",
				confidence: "high",
			},
			{
				name:       "Stripe Secret Key",
				regex:      regexp.MustCompile(`sk_live_[A-Za-z0-9]{24,}`),//Stripe secrets start with sk_live_
				category:   "api_key",
				confidence: "high",
			},
			{
				name:       "Stripe Publishable Key",
				regex:      regexp.MustCompile(`pk_live_[A-Za-z0-9]{24,}`), //only medium confident because these are meant to be public... but if you see both the sk_live_ and the pk_live_, this is probably a Magecart kit
				category:   "api_key",
				confidence: "medium",
			},
			{
				name:       "SendGrid API Key",
				regex:      regexp.MustCompile(`SG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}`), //follows the obvious SG. format
				category:   "api_key",
				confidence: "high",
			},
			{
				name:       "Mailgun API Key",
				regex:      regexp.MustCompile(`key-[A-Za-z0-9]{32}`), //uses the least unique key pattern
				category:   "api_key",
				confidence: "medium",
			},
			{
				name:       "Base64 Encoded Credential",
				regex:      regexp.MustCompile(`(?i)(basic|bearer)\s+[A-Za-z0-9+/=]{20,}`), //only medium because Base64 endcoded strings are common
				category:   "credential",
				confidence: "medium",
			},
			{
				name:       "Generic API Key Assignment",
				regex:      regexp.MustCompile(`(?i)(api_?key|api_?secret|access_?token|auth_?token)\s*[=:]\s*["']?[A-Za-z0-9_\-/.]{16,}["']?`), //the catch all pattern
				category:   "api_key",
				confidence: "low",
			},
		},
	}
}

func (d *APIKeyDetector) Name() string{
	return "api_key"
}

//this is identical to C2Detector.Detect
func (d *APIKeyDetector) Detect(lines []string) []Finding {
	var findings []Finding

	for lineNum, line := range lines {
		for _, pattern := range d.patterns {
			matches := pattern.regex.FindAllString(line, -1)

			for _, match := range matches {
				findings = append(findings, Finding{
					DetectorName: d.Name(),
					Description:  fmt.Sprintf("%s: %s", pattern.category, pattern.name),
					Secret:       match,
					Context:      buildContext(lines, lineNum, 2),
					LineNumber:   lineNum + 1,
					Confidence:   pattern.confidence,
				})
			}
		}
	}

	return findings
}