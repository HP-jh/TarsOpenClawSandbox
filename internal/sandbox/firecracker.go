package sandbox

// Firecracker placeholder for v0.2.0 enterprise-grade microVM support.
// Will integrate github.com/firecracker-microvm/firecracker-go-sdk.

// FirecrackerConfig holds planned microVM parameters.
type FirecrackerConfig struct {
	VCPUCount       int    `json:"vcpu_count"`
	MemSizeMib      int    `json:"mem_size_mib"`
	KernelImagePath string `json:"kernel_image_path"`
	RootDrivePath   string `json:"root_drive_path"`
}

func DefaultFirecrackerConfig() *FirecrackerConfig {
	return &FirecrackerConfig{
		VCPUCount:  2,
		MemSizeMib: 512,
	}
}
