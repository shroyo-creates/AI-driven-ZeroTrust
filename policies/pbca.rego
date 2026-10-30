# PBCA mandatory policy and policy-bounded combination for Open Policy Agent.
#
# Mirrors pbca/policy.py. Input shape:
#   {
#     "identity": {"privileged": bool},
#     "device":   {"managed": bool, "compliant": bool},
#     "resource": {"sensitivity": "LOW"|"MEDIUM"|"HIGH", "customer_records": bool},
#     "threat":   {"bad_ip": bool, "leaked_credential": bool},
#     "action": "read"|"export"|"write",
#     "mfa_satisfied": "passkey"|...|null,
#     "risk": {"r": number, "c": number}      # from the risk engine (evidence only)
#   }
# Query data.pbca.decision for {"final", "d_policy", "d_risk", "reasons"}.

package pbca

import rego.v1

levels := {"ALLOW": 0, "STEP_UP": 1, "RESTRICT": 2, "DENY": 3}
names := ["ALLOW", "STEP_UP", "RESTRICT", "DENY"]

phishing_resistant := {"passkey", "security_key", "webauthn", "fido2"}

thresholds := {
	"LOW": [0.50, 0.80, 0.95],
	"MEDIUM": [0.35, 0.65, 0.90],
	"HIGH": [0.20, 0.50, 0.80],
}

c_min := 0.5

# ---------------------------------------------------------------- d_P rules
policy_hits contains {"rule": "R1", "decision": "DENY", "reason": "unmanaged device may not open unmasked customer records"} if {
	input.resource.customer_records
	not input.device.managed
}

policy_hits contains {"rule": "R2", "decision": "RESTRICT", "reason": "device out of compliance"} if {
	input.device.managed
	not input.device.compliant
	input.resource.sensitivity == "HIGH"
}

policy_hits contains {"rule": "R3", "decision": "STEP_UP", "reason": "privileged role requires phishing-resistant MFA"} if {
	input.identity.privileged
	not phishing_resistant[input.mfa_satisfied]
}

policy_hits contains {"rule": "R4", "decision": "DENY", "reason": "source IP on block list"} if {
	input.threat.bad_ip
}

policy_hits contains {"rule": "R5", "decision": "STEP_UP", "reason": "leaked credential"} if {
	not input.threat.bad_ip
	input.threat.leaked_credential
	not phishing_resistant[input.mfa_satisfied]
}

policy_hits contains {"rule": "R6", "decision": "DENY", "reason": "export requires compliant device"} if {
	input.action == "export"
	input.resource.customer_records
	not input.device.compliant
}

d_policy_level := max({0} | {levels[h.decision] | some h in policy_hits})

# ---------------------------------------------------------------- d_R tiers
t := thresholds[input.resource.sensitivity]

band := 3 if input.risk.r >= t[2]
else := 2 if input.risk.r >= t[1]
else := 1 if input.risk.r >= t[0]
else := 0

low_confidence if {
	input.risk.c < c_min
	input.resource.sensitivity != "LOW"
}

d_risk_level := max({band, 1}) if low_confidence
else := band

# ------------------------------------------------- Eq. 5: stricter(d_P, d_R)
final_level := max({d_policy_level, d_risk_level})

decision := {
	"final": names[final_level],
	"d_policy": names[d_policy_level],
	"d_risk": names[d_risk_level],
	"reasons": [h.reason | some h in policy_hits],
}

# Policy bounding holds by construction: final_level >= d_policy_level.
