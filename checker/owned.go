package checker

import "proxymachine/pkg/checkservice"

// UseOwnedService must be called before Start or concurrent validation. The
// descriptor is pinned and there is no external validation/canary fallback.
func (cm *CheckManager) UseOwnedService(descriptor, caFile string) error {
	c, err := checkservice.NewClient(descriptor, caFile, cm.cfg.Timeout)
	if err != nil {
		return err
	}
	cm.owned = c
	return nil
}

func (cm *CheckManager) ValidationMode() string {
	if cm != nil && cm.owned != nil {
		return "owned"
	}
	return "public"
}
