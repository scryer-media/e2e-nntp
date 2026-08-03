package nntp

import (
	"sync"
	"sync/atomic"
)

type metricState struct {
	mu         sync.RWMutex
	bodyCounts map[string]int
	statCounts map[string]int
	bodyBytes  atomic.Uint64
	bodyXfers  atomic.Int64
	attempted  atomic.Int64
	accepted   atomic.Int64
	rejected   atomic.Int64
	peak       atomic.Int64
}

func (metrics *metricState) reset(active int64) {
	metrics.mu.Lock()
	metrics.bodyCounts = make(map[string]int)
	metrics.statCounts = make(map[string]int)
	metrics.mu.Unlock()
	metrics.bodyBytes.Store(0)
	metrics.bodyXfers.Store(0)
	metrics.attempted.Store(0)
	metrics.accepted.Store(0)
	metrics.rejected.Store(0)
	metrics.peak.Store(active)
}

func (metrics *metricState) recordPeak(active int64) {
	for {
		previous := metrics.peak.Load()
		if active <= previous || metrics.peak.CompareAndSwap(previous, active) {
			return
		}
	}
}

func (metrics *metricState) recordBody(messageID string, bytes int) {
	metrics.mu.Lock()
	metrics.bodyCounts[messageID]++
	metrics.mu.Unlock()
	metrics.bodyBytes.Add(uint64(bytes))
	metrics.bodyXfers.Add(1)
}

func (metrics *metricState) recordStat(messageID string) {
	metrics.mu.Lock()
	metrics.statCounts[messageID]++
	metrics.mu.Unlock()
}

func (metrics *metricState) snapshot(active int64) Metrics {
	metrics.mu.RLock()
	bodyCounts := make(map[string]int, len(metrics.bodyCounts))
	for messageID, count := range metrics.bodyCounts {
		bodyCounts[messageID] = count
	}
	statCounts := make(map[string]int, len(metrics.statCounts))
	for messageID, count := range metrics.statCounts {
		statCounts[messageID] = count
	}
	metrics.mu.RUnlock()
	return Metrics{
		BodyCounts:         bodyCounts,
		StatCounts:         statCounts,
		BodyBytes:          metrics.bodyBytes.Load(),
		BodyTransfers:      metrics.bodyXfers.Load(),
		ConnectionAttempts: metrics.attempted.Load(),
		ConnectionAccepted: metrics.accepted.Load(),
		ConnectionRejected: metrics.rejected.Load(),
		ActiveConnections:  active,
		PeakConnections:    metrics.peak.Load(),
	}
}
