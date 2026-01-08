/**
 * SafeYolo Dagger Module
 *
 * Builds the SafeYolo security proxy container, replicating the
 * docker-compose.yml and Dockerfile build process.
 *
 * Usage:
 *   dagger call base          # Build base container (~200MB)
 *   dagger call dev           # Build dev container with pytest
 *   dagger call serve         # Run with default ports
 */

import {
  dag,
  Container,
  Directory,
  object,
  func,
  argument,
} from "@dagger.io/dagger";

// Pinned base image for supply chain security (from Dockerfile)
const BASE_IMAGE =
  "python:3.13-slim@sha256:45ce78b0ad540b2bbb4eaac6f9cb91c9be5af45ab5f483929f407b4fb98c89dd";

@object()
export class Safeyolo {
  private source: Directory;

  constructor(source?: Directory) {
    this.source = source ?? dag.currentModule().source().directory("..");
  }

  /**
   * Build the base SafeYolo container (~200MB)
   * Core addons only: credential_guard, network_guard, pattern_scanner, etc.
   */
  @func()
  async base(): Promise<Container> {
    return this.buildBase();
  }

  /**
   * Build the dev SafeYolo container
   * Includes pytest and development dependencies
   */
  @func()
  async dev(): Promise<Container> {
    const baseContainer = await this.buildBase();

    return baseContainer
      // Install build deps for development
      .withExec([
        "apt-get",
        "update",
      ])
      .withExec([
        "apt-get",
        "install",
        "-y",
        "--no-install-recommends",
        "gcc",
      ])
      .withExec(["rm", "-rf", "/var/lib/apt/lists/*"])
      // Install dev/test dependencies
      .withFile("/tmp/base.txt", this.source.file("requirements/base.txt"))
      .withFile("/tmp/dev.txt", this.source.file("requirements/dev.txt"))
      .withExec([
        "pip",
        "install",
        "--no-cache-dir",
        "--require-hashes",
        "-r",
        "/tmp/dev.txt",
      ])
      .withDefaultTerminalCmd(["bash"]);
  }

  /**
   * Run SafeYolo proxy with configurable ports
   */
  @func()
  serve(
    @argument({ description: "Proxy port", defaultValue: "8080" })
    proxyPort: string = "8080",
    @argument({ description: "Admin API port", defaultValue: "9090" })
    adminPort: string = "9090"
  ): Container {
    return this.buildBase()
      .withEnvVariable("PROXY_PORT", proxyPort)
      .withEnvVariable("ADMIN_PORT", adminPort)
      .withExposedPort(parseInt(proxyPort))
      .withExposedPort(parseInt(adminPort))
      .withExec(["/app/scripts/start-safeyolo.sh"]);
  }

  /**
   * Build and return a container with mounted config directory
   */
  @func()
  withConfig(
    @argument({ description: "Config directory to mount" })
    config: Directory
  ): Container {
    return this.buildBase().withDirectory("/app/config", config);
  }

  /**
   * Build and return a container with mounted data directory
   */
  @func()
  withData(
    @argument({ description: "Data directory to mount" })
    data: Directory
  ): Container {
    return this.buildBase().withDirectory("/app/data", data);
  }

  /**
   * Export the container as a tarball
   */
  @func()
  async export(
    @argument({ description: "Build target: base or dev", defaultValue: "base" })
    target: string = "base"
  ): Promise<string> {
    const container = target === "dev" ? await this.dev() : await this.base();
    return container.export(`safeyolo-${target}.tar`);
  }

  /**
   * Publish the container to a registry
   */
  @func()
  async publish(
    @argument({ description: "Image address (e.g., ghcr.io/user/safeyolo)" })
    address: string,
    @argument({ description: "Build target: base or dev", defaultValue: "base" })
    target: string = "base"
  ): Promise<string> {
    const container = target === "dev" ? await this.dev() : await this.base();
    return container.publish(address);
  }

  /**
   * Internal: Build the base container
   */
  private buildBase(): Container {
    return (
      dag
        .container()
        .from(BASE_IMAGE)
        // Install minimal system dependencies (tmux for mitmproxy TUI)
        .withExec(["apt-get", "update"])
        .withExec([
          "apt-get",
          "install",
          "-y",
          "--no-install-recommends",
          "tmux",
        ])
        .withExec(["rm", "-rf", "/var/lib/apt/lists/*"])
        // Install core Python dependencies
        .withFile("/tmp/requirements.txt", this.source.file("requirements/base.txt"))
        .withExec([
          "pip",
          "install",
          "--no-cache-dir",
          "--require-hashes",
          "-r",
          "/tmp/requirements.txt",
        ])
        .withWorkdir("/app")
        // Copy PDP (Policy Decision Point) library
        .withDirectory("/app/pdp", this.source.directory("pdp"))
        .withExec(["chmod", "-R", "644", "/app/pdp"])
        .withExec(["chmod", "755", "/app/pdp"])
        // Copy addon framework
        .withDirectory("/app/addons", this.source.directory("addons"))
        // Copy configuration
        .withDirectory("/app/config", this.source.directory("config"))
        // Copy scripts
        .withDirectory("/app/scripts", this.source.directory("scripts"))
        .withExec(["chmod", "+x", "/app/scripts/start-safeyolo.sh"])
        // Create directories
        .withExec(["mkdir", "-p", "/app/logs", "/certs"])
        // Expose ports
        .withExposedPort(8080)
        .withExposedPort(8888)
        .withExposedPort(9090)
        // Environment defaults
        .withEnvVariable("PROXY_PORT", "8080")
        .withEnvVariable("ADMIN_PORT", "9090")
        .withEnvVariable("CERT_DIR", "/certs-private")
        .withEnvVariable("PUBLIC_CERT_DIR", "/certs-public")
        .withEnvVariable("LOG_DIR", "/app/logs")
        .withEnvVariable("CONFIG_DIR", "/app/config")
        .withEnvVariable("PYTHONPATH", "/app:/app/addons")
        // Default entrypoint
        .withDefaultTerminalCmd(["/app/scripts/start-safeyolo.sh"])
    );
  }
}
