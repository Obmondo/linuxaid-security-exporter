package distro

import (
	"context"
	"os"

	"gitea.obmondo.com/EnableIT/security-exporter/internal/constants"
	"gitea.obmondo.com/EnableIT/security-exporter/utils/logger"
	"github.com/joho/godotenv"
)

func loadOSReleaseEnv() {
	err := godotenv.Load("/etc/os-release")
	if err != nil {
		logger.GetLogger().Fatal(context.Background(), "fatal error while loading os-release file:", err, nil)
	}
}

func GetCurrentOS() constants.Distro {
	loadOSReleaseEnv()
	// we basically get this ID env variable from loadOSReleaseEnv function
	distribution := os.Getenv("ID")

	switch distribution {
	case "ubuntu", "debian":
		return constants.DEBIAN
	case "centos", "rhel":
		return constants.RHEL
	default:
		logger.GetLogger().Fatal(context.Background(), "fatal unsupported linux distribution", nil, map[string]any{"distribution": distribution})
	}
	return constants.INVALID
}
