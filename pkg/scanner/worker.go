package scanner

import (
	"context"
	"sync"
)

// job represents a single ip:port target.
type job struct {
	ip   string
	port int
}

// result represents the outcome of probing one ip:port.
type result struct {
	ip     string
	port   int
	open   bool
	reason error
}

// workerPool runs a fixed number of workers consuming jobs from the jobs
// channel and producing results. It exits cleanly when ctx is cancelled or
// jobs closes.
func workerPool(ctx context.Context, jobs <-chan job, workers int, work func(ctx context.Context, j job) (bool, error)) <-chan result {
	out := make(chan result)
	if workers <= 0 {
		workers = 4
	}

	var wg sync.WaitGroup
	wg.Add(workers)
	for i := 0; i < workers; i++ {
		go func() {
			defer wg.Done()
			for {
				// Honor cancellation BEFORE taking new work: Go's select picks a ready
				// case at random, so without this a cancelled pool could still grab a
				// buffered job. This non-blocking pre-check makes a cancelled scan stop
				// promptly (and deterministically) instead of processing one more job.
				select {
				case <-ctx.Done():
					return
				default:
				}
				select {
				case <-ctx.Done():
					return
				case j, ok := <-jobs:
					if !ok {
						return
					}
					open, err := work(ctx, j)
					select {
					case out <- result{ip: j.ip, port: j.port, open: open, reason: err}:
					case <-ctx.Done():
						return
					}
				}
			}
		}()
	}

	go func() {
		wg.Wait()
		close(out)
	}()

	return out
}
