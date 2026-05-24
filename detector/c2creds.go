package detector

//no encoding/hex because there's no need to validate hex strings
import (
	"fmt"
	"regexp"
)

type C2Detector struct {
	patterns []c2Pattern
}

type c2Pattern struct {
	name       string
	regex      *regexp.Regexp
	category   string //C2 findings span multiple categories (infra URLs, exfil channels, creds, campaign IDs)
	confidence string
}

//all the detection intelligece lives here, all based on regex patterns
func NewC2Detector() *C2Detector {
	return &C2Detector{
		patterns: []c2Pattern{
			{
				name:       "C2 Gate/Panel URL",
				regex:      regexp.MustCompile(`(?i)https?://[^\s"']+/(gate|panel|admin|collect|tasks|check|ping|submit|upload|login|beacon|bot|cmd|command|register)[^\s"']*`),
				category:   "c2_infrastructure",
				confidence: "high",
			},
			{
				name:       "Telegram Bot Token",
				regex:      regexp.MustCompile(`[0-9]{8,10}:[A-Za-z0-9_-]{35}`),
				category:   "exfil_channel",
				confidence: "high",
			},
			{
				name:       "Discord Webhook",
				regex:      regexp.MustCompile(`(?i)https?://discord(?:app)?\.com/api/webhooks/[0-9]+/[A-Za-z0-9_-]+`),
				category:   "exfil_channel",
				confidence: "high",
			},
			{
				name:       "Tor Hidden Service",
				regex:      regexp.MustCompile(`[a-z2-7]{56}\.onion`),
				category:   "exfil_channel",
				confidence: "high",
			},
			{
				name:       "SMTP Credential",
				regex:      regexp.MustCompile(`(?i)(smtp_pass|smtp_password|mail_pass|email_pass(?:word)?)\s*[=:]\s*\S+`),
				category:   "credential",
				confidence: "high",
			},
			{
				name:       "FTP Credential",
				regex:      regexp.MustCompile(`(?i)(ftp_pass|ftp_password|ftp_pwd)\s*[=:]\s*\S+`),
				category:   "credential",
				confidence: "high",
			},
			{
				name:       "HTTP Basic Auth Header",
				regex:      regexp.MustCompile(`(?i)authorization:\s*basic\s+[A-Za-z0-9+/=]{8,}`),
				category:   "credential",
				confidence: "high",
			},
			{
				name:       "Hardcoded Password Variable",
				regex:      regexp.MustCompile(`(?i)(password|passwd|pwd|pass_?word)\s*[=:]\s*["']?[^\s"']{6,}["']?`),
				category:   "credential",
				confidence: "medium",
			},
			{
				name:       "Campaign/Bot ID",
				regex:      regexp.MustCompile(`(?i)(campaign|botnet|group|bot_?id|camp_?id)\s*[=:]\s*\S+`),
				category:   "campaign_id",
				confidence: "medium",
			},
		},
	}
}

func (d *C2Detector) Name() string {
	return "c2_credential"
}

func (d *C2Detector) Detect(lines []string) []Finding {
	var findings []Finding

	for lineNum, line := range lines {
		for _, pattern := range d.patterns {
			matches := pattern.regex.FindAllString(line, -1)
			
			for _, match := range matches {
				findings = append(findings, Finding{
					DetectorName:	d.Name(),
					Description:	fmt.Sprintf("%s: %s", pattern.category, pattern.name), //produces strings like "credential: SMTP Credential" or "exfil_channel: Telegram Bot Token", giving two levels of granularity in the output
					Secret:			match,
					Context:		buildContext(lines, lineNum, 2),
					LineNumber:		lineNum + 1,
					Confidence:		pattern.confidence,
				})
			}
		}
	}
	return findings
}