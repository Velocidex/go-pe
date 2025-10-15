package pe

import "sync/atomic"

var (
	HASH_SIZE_LIMIT int64 = 100 * 1024 * 1024 // 100Mb
)

func SetHashSizeLimit(limit int64) {
	atomic.SwapInt64(&HASH_SIZE_LIMIT, limit)
}

func GetHashSizeLimit() int64 {
	return atomic.LoadInt64(&HASH_SIZE_LIMIT)
}
