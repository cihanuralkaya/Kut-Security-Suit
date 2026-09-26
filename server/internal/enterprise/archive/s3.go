//go:build enterprise

// s3.go (enterprise), Archive'ı S3-uyumlu nesne deposuyla (minio-go) uygular. MinIO, AWS S3
// ve diğer S3-uyumlu backend'lerle çalışır; on-prem self-host için MinIO tipik seçimdir.
// Import YALNIZ `//go:build enterprise` arkasında → Lite c2 minio-go'yu (ve transitif deps'i)
// derlemez; zero-dep guard `minio`'yu reddeder.
package archive

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"time"

	"github.com/minio/minio-go/v7"
	"github.com/minio/minio-go/v7/pkg/credentials"
)

type s3Archive struct {
	cl     *minio.Client
	bucket string
}

// NewS3Archive, endpoint'e (host:port) bağlanır, kova (bucket) yoksa oluşturur.
// useSSL, TLS kullanımını belirler (üretimde true; yerel MinIO'da genelde false).
func NewS3Archive(endpoint, accessKey, secretKey, bucket string, useSSL bool) (*s3Archive, error) {
	if endpoint == "" || bucket == "" {
		return nil, fmt.Errorf("arşiv (s3): endpoint ve bucket gerekli")
	}
	cl, err := minio.New(endpoint, &minio.Options{
		Creds:  credentials.NewStaticV4(accessKey, secretKey, ""),
		Secure: useSSL,
	})
	if err != nil {
		return nil, fmt.Errorf("arşiv (s3): istemci: %w", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	exists, err := cl.BucketExists(ctx, bucket)
	if err != nil {
		return nil, fmt.Errorf("arşiv (s3): kova kontrolü: %w", err)
	}
	if !exists {
		if err := cl.MakeBucket(ctx, bucket, minio.MakeBucketOptions{}); err != nil {
			return nil, fmt.Errorf("arşiv (s3): kova oluşturma: %w", err)
		}
	}
	return &s3Archive{cl: cl, bucket: bucket}, nil
}

// Put, key altında data'yı yazar.
func (a *s3Archive) Put(ctx context.Context, key string, data []byte) error {
	_, err := a.cl.PutObject(ctx, a.bucket, key, bytes.NewReader(data), int64(len(data)),
		minio.PutObjectOptions{ContentType: "application/octet-stream"})
	if err != nil {
		return fmt.Errorf("arşiv (s3): yazma %q: %w", key, err)
	}
	return nil
}

// Get, key'deki nesneyi tümüyle okur.
func (a *s3Archive) Get(ctx context.Context, key string) ([]byte, error) {
	obj, err := a.cl.GetObject(ctx, a.bucket, key, minio.GetObjectOptions{})
	if err != nil {
		return nil, fmt.Errorf("arşiv (s3): okuma %q: %w", key, err)
	}
	defer obj.Close()
	data, err := io.ReadAll(obj)
	if err != nil {
		return nil, fmt.Errorf("arşiv (s3): gövde %q: %w", key, err)
	}
	return data, nil
}

// List, prefix ile başlayan anahtarları özyinelemeli döner.
func (a *s3Archive) List(ctx context.Context, prefix string) ([]string, error) {
	var keys []string
	for o := range a.cl.ListObjects(ctx, a.bucket, minio.ListObjectsOptions{Prefix: prefix, Recursive: true}) {
		if o.Err != nil {
			return nil, fmt.Errorf("arşiv (s3): listeleme: %w", o.Err)
		}
		keys = append(keys, o.Key)
	}
	return keys, nil
}

// Delete, key'deki nesneyi siler (yoksa hata döndürmez — S3 semantiği).
func (a *s3Archive) Delete(ctx context.Context, key string) error {
	if err := a.cl.RemoveObject(ctx, a.bucket, key, minio.RemoveObjectOptions{}); err != nil {
		return fmt.Errorf("arşiv (s3): silme %q: %w", key, err)
	}
	return nil
}
