package db

import (
	"context"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"
	"google.golang.org/protobuf/types/known/timestamppb"

	kutv1 "kut.corp/suite/gen/kut/v1"
	"kut.corp/suite/server/internal/admin"
	"kut.corp/suite/server/internal/adminread"
)

// ListPolicies, politikaları kural + atanmış cihaz sayımlarıyla, ada göre sıralı listeler.
// tenantID boş değilse yalnız o kiracının VE platform/paylaşımlı (tenant_id = ”) politikalar
// döner; cihaz sayısı yalnız o kiracının cihazlarını sayar (paylaşımlı politikada başka
// kiracıların cihaz sayısı sızmaz). Boş tenantID = platform admini (hepsi).
func (s *Store) ListPolicies(ctx context.Context, limit int, tenantID string) ([]adminread.PolicyRow, error) {
	const q = `
		SELECT p.id::text, p.name, p.version, p.tenant_id,
		       (SELECT COUNT(*) FROM policy_rules pr   WHERE pr.policy_id = p.id),
		       (SELECT COUNT(*) FROM device_policies dp
		          JOIN devices d ON d.id = dp.device_id
		         WHERE dp.policy_id = p.id AND ($2 = '' OR d.tenant_id = $2))
		  FROM policies p
		 WHERE ($2 = '' OR p.tenant_id = '' OR p.tenant_id = $2)
		 ORDER BY p.name, p.created_at
		 LIMIT $1`
	rows, err := s.pool.Query(ctx, q, limit, tenantID)
	if err != nil {
		return nil, fmt.Errorf("db: politika listesi: %w", err)
	}
	defer rows.Close()

	var out []adminread.PolicyRow
	for rows.Next() {
		var p adminread.PolicyRow
		if err := rows.Scan(&p.ID, &p.Name, &p.Version, &p.TenantID, &p.RuleCount, &p.DeviceCount); err != nil {
			return nil, fmt.Errorf("db: politika okuma: %w", err)
		}
		out = append(out, p)
	}
	return out, rows.Err()
}

// CurrentPolicy, cihaza atanmış aktif politikayı proto PolicyBundle olarak kurar.
// Atanmış politika yoksa (nil, nil) döner.
func (s *Store) CurrentPolicy(ctx context.Context, deviceID string) (*kutv1.PolicyBundle, error) {
	const pq = `
		SELECT p.id::text, p.version
		  FROM device_policies dp
		  JOIN policies p ON p.id = dp.policy_id
		  JOIN devices  d ON d.id = dp.device_id
		 WHERE dp.device_id = $1 AND p.is_active
		   AND (p.tenant_id = '' OR p.tenant_id = COALESCE(NULLIF(d.tenant_id, ''), 'default'))
		 ORDER BY p.updated_at DESC
		 LIMIT 1`
	var policyID, version string
	err := s.pool.QueryRow(ctx, pq, deviceID).Scan(&policyID, &version)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("db: politika sorgusu: %w", err)
	}

	const rq = `
		SELECT id::text, type, target_value,
		       COALESCE(to_char(start_time, 'HH24:MI'), ''),
		       COALESCE(to_char(end_time,   'HH24:MI'), ''),
		       active_days
		  FROM policy_rules
		 WHERE policy_id = $1
		 ORDER BY created_at`
	rows, err := s.pool.Query(ctx, rq, policyID)
	if err != nil {
		return nil, fmt.Errorf("db: kural sorgusu: %w", err)
	}
	defer rows.Close()

	var rules []*kutv1.PolicyRule
	for rows.Next() {
		var id, typ, target, st, et string
		var days []int32
		if err := rows.Scan(&id, &typ, &target, &st, &et, &days); err != nil {
			return nil, fmt.Errorf("db: kural okuma: %w", err)
		}
		ad := make([]uint32, 0, len(days))
		for _, d := range days {
			if d >= 0 {
				ad = append(ad, uint32(d))
			}
		}
		rules = append(rules, &kutv1.PolicyRule{
			RuleId:      id,
			Type:        ruleTypeToProto(typ),
			TargetValue: target,
			StartTime:   st,
			EndTime:     et,
			ActiveDays:  ad,
		})
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("db: kural iterasyonu: %w", err)
	}

	return &kutv1.PolicyBundle{
		PolicyVersion: version,
		Rules:         rules,
		IssuedAt:      timestamppb.Now(),
	}, nil
}

// AddPolicyRule, bir politikaya yeni bir kural ekler. start_time/end_time TIME
// tipidir; "HH:MM" verilir, boş ise NULL yazılır. active_days boşsa tablo
// varsayılanı (tüm günler) uygulanır.
func (s *Store) AddPolicyRule(ctx context.Context, policyID string, in admin.RuleInput) error {
	days := in.ActiveDays
	if len(days) == 0 {
		days = []int32{1, 2, 3, 4, 5, 6, 0}
	}
	const q = `
		INSERT INTO policy_rules (policy_id, type, target_value, start_time, end_time, active_days)
		VALUES ($1::uuid, $2, $3, NULLIF($4,'')::time, NULLIF($5,'')::time, $6)`
	_, err := s.pool.Exec(ctx, q, policyID, in.Type, in.Target, in.Start, in.End, days)
	if err != nil {
		return fmt.Errorf("db: kural ekleme: %w", err)
	}
	return nil
}

// BumpPolicyVersion, politikanın sürümünü yeni bir zaman-damgası etiketine
// yükseltir ve updated_at'i tazeler. Sürüm etiketi değiştiği için açık akıştaki
// ajanlar (ve heartbeat eden ajanlar) yeni paketi çeker. Yeni sürümü döner.
func (s *Store) BumpPolicyVersion(ctx context.Context, policyID string) (string, error) {
	const q = `
		UPDATE policies
		   SET version = to_char(now() AT TIME ZONE 'UTC', 'YYYYMMDDHH24MISSMS'),
		       updated_at = now()
		 WHERE id = $1::uuid
	 RETURNING version`
	var v string
	err := s.pool.QueryRow(ctx, q, policyID).Scan(&v)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", fmt.Errorf("db: bilinmeyen politika: %s", policyID)
	}
	if err != nil {
		return "", fmt.Errorf("db: politika sürümü yükseltme: %w", err)
	}
	return v, nil
}

// DevicesForPolicy, politikaya atanmış cihaz id'lerini döner (republish için).
func (s *Store) DevicesForPolicy(ctx context.Context, policyID string) ([]string, error) {
	const q = `SELECT device_id::text FROM device_policies WHERE policy_id = $1::uuid`
	rows, err := s.pool.Query(ctx, q, policyID)
	if err != nil {
		return nil, fmt.Errorf("db: politika cihazları sorgusu: %w", err)
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, fmt.Errorf("db: cihaz id okuma: %w", err)
		}
		out = append(out, id)
	}
	return out, rows.Err()
}

// ListPolicyRules, bir politikanın kurallarını okunabilir görünüm olarak döner.
func (s *Store) ListPolicyRules(ctx context.Context, policyID string) ([]admin.RuleView, error) {
	const q = `
		SELECT id::text, type, target_value,
		       COALESCE(to_char(start_time, 'HH24:MI'), ''),
		       COALESCE(to_char(end_time,   'HH24:MI'), ''),
		       active_days
		  FROM policy_rules
		 WHERE policy_id = $1::uuid
		 ORDER BY created_at`
	rows, err := s.pool.Query(ctx, q, policyID)
	if err != nil {
		return nil, fmt.Errorf("db: kural listeleme: %w", err)
	}
	defer rows.Close()
	var out []admin.RuleView
	for rows.Next() {
		var v admin.RuleView
		if err := rows.Scan(&v.ID, &v.Type, &v.Target, &v.Start, &v.End, &v.ActiveDays); err != nil {
			return nil, fmt.Errorf("db: kural okuma: %w", err)
		}
		out = append(out, v)
	}
	return out, rows.Err()
}

func ruleTypeToProto(t string) kutv1.PolicyRule_RuleType {
	switch t {
	case "APP_TIME_BLOCK":
		return kutv1.PolicyRule_RULE_TYPE_APP_TIME_BLOCK
	case "APP_BLOCK_ALWAYS":
		return kutv1.PolicyRule_RULE_TYPE_APP_BLOCK_ALWAYS
	case "NETWORK_RULE":
		return kutv1.PolicyRule_RULE_TYPE_NETWORK_RULE
	default:
		return kutv1.PolicyRule_RULE_TYPE_UNSPECIFIED
	}
}

// PolicyTenant, politikanın sahibi kiracıyı döner ("" = platform/paylaşımlı). Politika yoksa
// (ya da id geçerli uuid değilse) found=false, hata yok — çağıran fail-closed reddeder.
func (s *Store) PolicyTenant(ctx context.Context, policyID string) (string, bool, error) {
	if !validUUID(policyID) {
		return "", false, nil
	}
	var t string
	err := s.pool.QueryRow(ctx, `SELECT tenant_id FROM policies WHERE id = $1::uuid`, policyID).Scan(&t)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", false, nil
	}
	if err != nil {
		return "", false, fmt.Errorf("db: politika kiracısı: %w", err)
	}
	return t, true, nil
}
