package middleware

import (
	"crypto/sha256"
	"encoding/binary"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
)

func Init() {
	TokenStore = NewShardStore(6)
}

var TokenStore *ShardedStore

type shard struct {
	mu sync.RWMutex
	m  map[[32]byte]int64
}

type ShardedStore struct {
	shards []shard
	mask   uint64
}

func NewShardStore(power uint) *ShardedStore {
	n := 1 << power
	ss := make([]shard, n)

	for i := range ss {
		ss[i].m = make(map[[32]byte]int64)
	}
	return &ShardedStore{
		shards: ss,
		mask:   uint64(n - 1),
	}
}

func hashToken(token string) [32]byte {
	return sha256.Sum256([]byte(token))
}

func (ss *ShardedStore) pick(h [32]byte) *shard {
	// 前8bit作為索引
	idx := binary.LittleEndian.Uint64(h[0:8]) & ss.mask
	return &ss.shards[idx]
}

func (s *ShardedStore) Mark(token string, ttl time.Duration) {
	h := hashToken(token)

	var exp int64
	if ttl > 0 {
		exp = time.Now().Add(ttl).UnixNano()
	}

	sh := s.pick(h)
	sh.mu.Lock()
	sh.m[h] = exp
	sh.mu.Unlock()
}

func (s *ShardedStore) IsAbandoned(token string) bool {
	h := hashToken(token)
	now := time.Now().UnixNano()

	sh := s.pick(h)
	sh.mu.RLock()
	exp, ok := sh.m[h]
	sh.mu.RUnlock()

	if !ok {
		return false
	}
	if exp == 0 || now <= exp {
		return true
	}

	// expired -> delete best-effort
	sh.mu.Lock()
	if exp2, ok2 := sh.m[h]; ok2 && exp2 == exp {
		delete(sh.m, h)
	}
	sh.mu.Unlock()
	return false
}

func (s *ShardedStore) CleanupExpired() int {
	now := time.Now().UnixNano()
	removed := 0

	for i := range s.shards {
		sh := &s.shards[i]
		sh.mu.Lock()
		for k, exp := range sh.m {
			if exp != 0 && exp < now {
				delete(sh.m, k)
				removed++
			}
		}
		sh.mu.Unlock()
	}
	return removed
}

func CheckAbandoned(token string) func(c *gin.Context) {
	return func(c *gin.Context) {
		if TokenStore.IsAbandoned(token) {
			c.AbortWithStatus(401)
			return
		}
		c.Next()
		return
	}
}
