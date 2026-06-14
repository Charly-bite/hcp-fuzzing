# HCP Stealth Fuzzer & Command Center

A high-performance, distributed web fuzzing framework designed for stealthy enumeration and vulnerability discovery. Built for Slurm clusters with a modern AJAX-driven Command Center.

## Key Features

*   **Distributed Fuzzing:** Orchestrated via Slurm (`srun`/`sbatch`) across multiple cluster nodes.
*   **Command Center UI:** A high-density "HUD" style dashboard for real-time monitoring and control.
*   **AJAX-Powered Live Preview:** Seamlessly view discoveries and logs without page reloads.
*   **Advanced Fuzzing Modes:**
    *   **Subdomain Fuzzing:** Discover virtual hosts via `Host` header manipulation.
    *   **API Fuzzing:** Probe for REST, JSON, and GraphQL endpoints.
    *   **Parameter Fuzzing:** Find hidden GET/POST parameters.
    *   **Method Fuzzing:** Cycle through HTTP verbs (PUT, DELETE, OPTIONS, etc.).
    *   **Header Injection:** Bypass firewalls and auth with custom headers.
*   **AI-Powered Analysis:** Integrated LLM (Llama 3) for automated log analysis and security audits.
*   **Stealth Mechanisms:**
    *   Adaptive rate limiting with jitter.
    *   Proxy rotation and distribution layer.
    *   WAF evasion through query parameter randomization.
    *   Advanced Soft-404 detection and auto-calibration.

## Architecture

*   `stealth_fuzzer`: The core Go engine responsible for high-speed request generation.
*   `results_server`: The Go-based dashboard and API provider.
*   `run_fuzz.sh`: The cluster orchestrator script.

## Getting Started

### Prerequisites
- Go 1.18 or higher.
- Access to a Slurm cluster (optional, for distributed fuzzing).

### Installation & Usage

1.  **Clone the repository:**
    ```bash
    git clone https://github.com/Charly-bite/HCP_Fuzzing.git
    cd HCP_Fuzzing
    ```

2.  **Build the binaries:**
    ```bash
    go build -o stealth_fuzzer main.go
    go build -o results_server results_server.go
    ```

3.  **Run the orchestrator:**
    Configure your target URL and status filters in the Command Center, then run the launcher:
    ```bash
    ./run_fuzz.sh
    ```

## Contributing
Please see [CONTRIBUTING.md](CONTRIBUTING.md) for details on our code of conduct and the process for submitting pull requests.

## License
This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

---
*Created for the HCP Cluster Environment.*
