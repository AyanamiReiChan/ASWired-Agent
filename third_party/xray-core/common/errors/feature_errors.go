package errors

import (
	"context"
)

func PrintNonRemovalDeprecatedFeatureWarning(sourceFeature string, targetFeature string) {
	LogWarning(context.Background(), "The feature "+sourceFeature+" is deprecated, not recommended for using and might be removed. Please migrate to "+targetFeature+" as soon as possible.")
}

func PrintDeprecatedFeatureWarning(feature string, migrateFeature string) {
	if len(migrateFeature) > 0 {
		LogWarning(context.Background(), "This feature "+feature+" is deprecated, will be removed soon and being migrated to "+migrateFeature+". Please update your config(s) according to release note and documentation before removal.")
	} else {
		LogWarning(context.Background(), "This feature "+feature+" is deprecated and will be removed soon. Please update your config(s) according to release note and documentation before removal.")
	}
}

func PrintRemovedFeatureError(feature string, migrateFeature string) error {
	if len(migrateFeature) > 0 {
		return New("The feature " + feature + " has been removed and migrated to " + migrateFeature + ". Please update your config(s) according to release note and documentation.")
	} else {
		return New("The feature " + feature + " has been removed. Please update your config(s) according to release note and documentation.")
	}
}
