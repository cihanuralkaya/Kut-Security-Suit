package policy

import kutv1 "kut.corp/suite/gen/kut/v1"

// FromProto, sunucudan gelen proto PolicyBundle'ı motor domain Bundle'ına
// çevirir. Bu dosya, engine.go'yu proto'dan bağımsız tutmak için ayrıdır:
// dönüşüm burada, değerlendirme mantığı orada.
func FromProto(pb *kutv1.PolicyBundle) Bundle {
	if pb == nil {
		return Bundle{}
	}
	b := Bundle{Version: pb.GetPolicyVersion()}
	for _, pr := range pb.GetRules() {
		r := Rule{
			ID:     pr.GetRuleId(),
			Type:   ruleTypeFromProto(pr.GetType()),
			Target: pr.GetTargetValue(),
		}
		if s, ok := ParseHHMM(pr.GetStartTime()); ok {
			r.Start = s
		}
		if e, ok := ParseHHMM(pr.GetEndTime()); ok {
			r.End = e
		}
		for _, d := range pr.GetActiveDays() {
			if d <= 6 {
				r.ActiveDays[d] = true
			}
		}
		b.Rules = append(b.Rules, r)
	}
	return b
}

func ruleTypeFromProto(t kutv1.PolicyRule_RuleType) RuleType {
	switch t {
	case kutv1.PolicyRule_RULE_TYPE_APP_TIME_BLOCK:
		return RuleAppTimeBlock
	case kutv1.PolicyRule_RULE_TYPE_APP_BLOCK_ALWAYS:
		return RuleAppBlockAlways
	case kutv1.PolicyRule_RULE_TYPE_NETWORK_RULE:
		return RuleNetwork
	default:
		return RuleUnspecified
	}
}
