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
	stemShapeType      = "stem_shape"
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
	stemGroups := make(map[shapePattern]map[string]struct{})
	for _, obs := range observations {
		if obs.ArchiveName == "" || obs.Password == "" {
			continue
		}
		normalizedName := strings.ToLower(obs.ArchiveName)
		key := candidates.ShapeKey(obs.ArchiveName)
		if key == "" || key == normalizedName {
			// Keep looking for a cross-extension stem rule even when the full
			// filename shape is not useful.
		} else {
			addShapeObservation(groups, shapePattern{key: key, password: obs.Password}, normalizedName)
		}

		stemKey := candidates.StemShapeKey(obs.ArchiveName)
		if stemKey != "" {
			addShapeObservation(stemGroups, shapePattern{key: stemKey, password: obs.Password}, normalizedStem(obs.ArchiveName))
		}
	}

	if err := upsertShapeGroups(ctx, st, shapePatternType, groups, minSupport); err != nil {
		return err
	}
	if err := upsertShapeGroups(ctx, st, stemShapeType, stemGroups, minSupport); err != nil {
		return err
	}
	return nil
}

func addShapeObservation(groups map[shapePattern]map[string]struct{}, group shapePattern, identity string) {
	if groups[group] == nil {
		groups[group] = make(map[string]struct{})
	}
	groups[group][identity] = struct{}{}
}

func upsertShapeGroups(ctx context.Context, st *store.Store, patternType string, groups map[shapePattern]map[string]struct{}, minSupport int) error {
	for group, names := range groups {
		support := len(names)
		if support < minSupport {
			continue
		}
		if err := st.UpsertPatternRule(ctx, store.PatternRule{
			PatternType: patternType,
			PatternKey:  group.key,
			Password:    group.password,
			Alpha:       float64(support + 1),
			Beta:        1,
			Support:     support,
			Confidence:  float64(support) / float64(support+1),
			Source:      shapePatternSource,
		}); err != nil {
			return fmt.Errorf("upsert %s pattern rule: %w", patternType, err)
		}
	}
	return nil
}

func normalizedStem(filename string) string {
	name := strings.ToLower(filename)
	if dot := strings.LastIndex(name, "."); dot > 0 {
		return name[:dot]
	}
	return name
}

type shapePattern struct {
	key      string
	password string
}
