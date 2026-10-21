package revocation

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"time"
)

// ErrRevoked, sunulan istemci sertifikası iptal listesindeyse döner.
var ErrRevoked = errors.New("revocation: istemci sertifikası iptal edilmiş")

// VerifyPeerCertificate, tls.Config.VerifyPeerCertificate için bir callback
// üretir. TLS zaten zinciri doğruladıktan SONRA çağrılır; leaf sertifikanın
// SHA-256(DER) parmak izini iptal kümesinde arar. İstemci sertifikası
// sunmadıysa (enroll, VerifyClientCertIfGiven) zincir boştur ve izin verilir.
func VerifyPeerCertificate(cache *Cache) func(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error {
	return func(_ [][]byte, verifiedChains [][]*x509.Certificate) error {
		if len(verifiedChains) == 0 || len(verifiedChains[0]) == 0 {
			return nil // istemci sertifikası yok (enroll akışı)
		}
		leaf := verifiedChains[0][0]
		sum := sha256.Sum256(leaf.Raw)
		if cache.IsRevoked(sum[:]) {
			return ErrRevoked
		}
		return nil
	}
}

// VerifyConnection, tls.Config.VerifyConnection için bir callback üretir. VerifyPeerCertificate
// Go tarafından OTURUM DEVAMINDA (session resumption / TLS 1.3 PSK) ÇAĞRILMAZ; bu yüzden
// iptal edilmiş bir sertifikayla kurulmuş eski bir oturum, iptalden sonra bilet ile yeniden
// bağlanabilirdi. VerifyConnection ise TAM ve devam eden HER el sıkışmada çalışır → iptal
// kontrolü burada da uygulanır.
//
// Fail-closed: sunulan herhangi bir istemci sertifikası (PeerCertificates) varsa leaf
// parmak izi kontrol edilir; VerifiedChains boş/eksik olsa bile atlanmaz. İstemci sertifikası
// hiç sunulmadıysa (enroll akışı, VerifyClientCertIfGiven) izin verilir — zorunluluğu
// ClientAuth politikası (RequireAndVerifyClientCert) uygular.
func VerifyConnection(cache *Cache) func(cs tls.ConnectionState) error {
	return func(cs tls.ConnectionState) error {
		var leaf *x509.Certificate
		switch {
		case len(cs.PeerCertificates) > 0:
			leaf = cs.PeerCertificates[0]
		case len(cs.VerifiedChains) > 0 && len(cs.VerifiedChains[0]) > 0:
			leaf = cs.VerifiedChains[0][0]
		default:
			return nil // istemci sertifikası yok (enroll akışı)
		}
		sum := sha256.Sum256(leaf.Raw)
		if cache.IsRevoked(sum[:]) {
			return ErrRevoked
		}
		return nil
	}
}

// Source, iptal edilmiş parmak izlerini üreten kalıcılık kaynağıdır.
type Source interface {
	RevokedFingerprints(ctx context.Context) ([][]byte, error)
}

// Refresher, iptal kümesini periyodik olarak kaynaktan tazeler.
type Refresher struct {
	source   Source
	cache    *Cache
	interval time.Duration
	log      func(string)
}

// NewRefresher oluşturur. interval <= 0 ise 60 sn kullanılır.
func NewRefresher(source Source, cache *Cache, interval time.Duration, log func(string)) *Refresher {
	if interval <= 0 {
		interval = 60 * time.Second
	}
	if log == nil {
		log = func(string) {}
	}
	return &Refresher{source: source, cache: cache, interval: interval, log: log}
}

// Prime, iptal kümesini kaynaktan SENKRON olarak bir kez doldurur. Dinleyiciler açılmadan
// ÖNCE çağrılmalıdır: aksi halde arka plan ilk tazelemesi bitene dek iptal edilmiş
// sertifikalar kabul edilirdi (açık pencere). Hata dönerse çağıran fail-closed davranmalıdır.
func (r *Refresher) Prime(ctx context.Context) error {
	fps, err := r.source.RevokedFingerprints(ctx)
	if err != nil {
		return err
	}
	r.cache.Replace(fps)
	return nil
}

// Run, başlangıçta bir kez ve sonra periyodik olarak tazeler (ctx bitene dek).
func (r *Refresher) Run(ctx context.Context) {
	t := time.NewTicker(r.interval)
	defer t.Stop()
	for {
		if fps, err := r.source.RevokedFingerprints(ctx); err != nil {
			r.log("iptal listesi tazelenemedi: " + err.Error())
		} else {
			r.cache.Replace(fps)
		}
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}
