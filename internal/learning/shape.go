package learning

import (
	"context"
	"fmt"
	"strings"

	"github.com/bkmashiro/smart-extract/internal/candidates"
	"github.com/bkmashiro/smart-extract/internal/store"
)

const (
	shapePatternType   = "shape"
	shapePatternSource = "local_summary"
	defaultMinSupport  = 2
)

// SummarizeShapePatterns derives simple filename-shape pattern rules from raw
// successful password observations.
func SummarizeShapePatterns(ctx context.Context, st *store.Store, minSupport int) error {
	if st == nil {
		return nil
	}
	if minSupport <= 0 {
		minSupport = defaultMinSupport
	}

	observations, err := st.ListObservations(ctx)
	if err != nil {
		return fmt.Errorf("list observations for shape summary: %w", err)
	}

	groups := make(map[shapePattern]map[string]struct{})
	for _, obs := range observations {
		if obs.ArchiveName == "" || obs.Password == "" {
			continue
		}
		key := candidates.ShapeKey(obs.ArchiveName)
		normalizedName := strings.ToLower(obs.ArchiveName)
		if key == "" || key == normalizedName {
			continue
		}
		group := shapePattern{key: key, password: obs.Password}
		if groups[group] == nil {
			groups[group] = make(map[string]struct{})
		}
		groups[group][normalizedName] = struct{}{}
	}

	for group, names := range groups {
		support := len(names)
		if support < minSupport {
			continue
		}
		if err := st.UpsertPatternRule(ctx, store.PatternRule{
			PatternType: shapePatternType,
			PatternKey:  group.key,
			Password:    group.password,
			Alpha:       float64(support + 1),
			Beta:        1,
			Support:     support,
			Confidence:  float64(support) / float64(support+1),
			Source:      shapePatternSource,
		}); err != nil {
			return fmt.Errorf("upsert shape pattern rule: %w", err)
		}
	}
	return nil
}

type shapePattern struct {
	key      string
	password string
}
