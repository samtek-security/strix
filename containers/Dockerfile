# Modified by Samtek for Recon. Derived from Apache-2.0 Strix (OmniSecure Inc.). See NOTICE.
# Digest recut after I8(b) engine-image rebuild. kali-rolling is a moving distro;
# the digest freezes the base used for THIS sandbox image.
FROM kalilinux/kali-rolling:latest@sha256:c6d78f57ebfdd9fec428a8b04f74876e66fddd08dfd328c076224a552e7332a3

LABEL description="AI Agent Penetration Testing Environment with Comprehensive Automated Tools"

RUN apt-get update && \
    apt-get install -y kali-archive-keyring sudo && \
    apt-get update && \
    apt-get upgrade -y && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

RUN useradd -m -s /bin/bash pentester && \
    usermod -aG sudo pentester && \
    echo "pentester ALL=(ALL) NOPASSWD:ALL" >> /etc/sudoers && \
    touch /home/pentester/.hushlogin

RUN mkdir -p /home/pentester/tools /app/certs && \
    chown -R pentester:pentester /app/certs /home/pentester/tools

RUN apt-get update && \
    apt-get install -y --no-install-recommends \
    wget curl git vim nano unzip tar \
    apt-transport-https ca-certificates gnupg lsb-release \
    build-essential software-properties-common \
    gcc libc6-dev pkg-config libpcap-dev libssl-dev \
    python3 python3-pip python3-dev python3-venv python3-setuptools \
    golang-go \
    net-tools dnsutils whois \
    jq parallel ripgrep grep \
    less man-db procps htop \
    iproute2 iputils-ping netcat-traditional \
    nmap ncat ndiff \
    sqlmap nuclei subfinder naabu ffuf \
    nodejs npm pipx \
    libcap2-bin \
    gdb \
    libnss3-tools \
    chromium fonts-liberation && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*


RUN setcap cap_net_raw,cap_net_admin,cap_net_bind_service+eip $(which nmap)

USER pentester
RUN openssl ecparam -name prime256v1 -genkey -noout -out /app/certs/ca.key && \
    openssl req -x509 -new -key /app/certs/ca.key \
    -out /app/certs/ca.crt \
    -days 3650 \
    -subj "/C=US/ST=CA/O=Security Testing/CN=Testing Root CA" \
    -addext "basicConstraints=critical,CA:TRUE" \
    -addext "keyUsage=critical,digitalSignature,keyEncipherment,keyCertSign" && \
    openssl pkcs12 -export \
    -out /app/certs/ca.p12 \
    -inkey /app/certs/ca.key \
    -in /app/certs/ca.crt \
    -passout pass:"" \
    -name "Testing Root CA" && \
    chmod 644 /app/certs/ca.crt && \
    chmod 600 /app/certs/ca.key && \
    chmod 600 /app/certs/ca.p12

USER root
RUN cp /app/certs/ca.crt /usr/local/share/ca-certificates/ca.crt && \
    update-ca-certificates

# uv 0.12.10 — checksummed GitHub release (no install.sh pipe).
RUN set -eux; \
    ARCH="$(uname -m)"; \
    case "$ARCH" in \
        x86_64) UV_ARCH="x86_64"; UV_SHA="173d95a0c32d18c896c46ba6fafbf3cf9c14ab74b033f81b76c883ef492a976b" ;; \
        aarch64|arm64) UV_ARCH="aarch64"; UV_SHA="9ff6b9d4665edcdd3a88dcc73cd1eb641754deb927f14e8c62ebfde6bf4f5f5e" ;; \
        *) echo "Unsupported architecture: $ARCH" >&2; exit 1 ;; \
    esac; \
    curl -fsSL -o /tmp/uv.tgz "https://github.com/astral-sh/uv/releases/download/0.12.10/uv-${UV_ARCH}-unknown-linux-gnu.tar.gz"; \
    echo "${UV_SHA}  /tmp/uv.tgz" | sha256sum -c; \
    tar -xzf /tmp/uv.tgz -C /tmp; \
    install -m 0755 /tmp/uv /usr/local/bin/uv 2>/dev/null || install -m 0755 /tmp/uv-*/uv /usr/local/bin/uv; \
    rm -rf /tmp/uv.tgz /tmp/uv /tmp/uv-*

USER pentester
WORKDIR /tmp

RUN go install -v github.com/projectdiscovery/httpx/cmd/httpx@v1.11.0 && \
    go install -v github.com/projectdiscovery/katana/cmd/katana@v1.7.0 && \
    go install -v github.com/projectdiscovery/vulnx/v2/cmd/vulnx@v2.0.2 && \
    go install -v github.com/jaeles-project/gospider@v1.1.6 && \
    go install -v github.com/projectdiscovery/interactsh/cmd/interactsh-client@v1.3.1 && \
    go clean -cache -modcache && \
    rm -rf /home/pentester/.cache/go-build /home/pentester/go/pkg

# nuclei-templates v10.4.8 (2026-08-24) — checksummed GitHub archive (no -update-templates).
RUN set -eux; \
    curl -fsSL -o /tmp/nuclei-templates.tgz "https://github.com/projectdiscovery/nuclei-templates/archive/refs/tags/v10.4.8.tar.gz"; \
    echo "53ae80d9bcfff638fbff62c4b730c436564b6bf5e05cf4f86a7eefe37c7ecc47  /tmp/nuclei-templates.tgz" | sha256sum -c; \
    tar -xzf /tmp/nuclei-templates.tgz -C /tmp; \
    rm -rf /home/pentester/nuclei-templates; \
    mv /tmp/nuclei-templates-10.4.8 /home/pentester/nuclei-templates; \
    rm -f /tmp/nuclei-templates.tgz
# Disable runtime template refresh so the vendored pack stays the pin.
ENV DISABLE_NUCLEI_TEMPLATES_AUTO_UPDATE=true \
    DISABLE_NUCLEI_TEMPLATES_PUBLIC_DOWNLOAD=true \
    DISABLE_NUCLEI_TEMPLATES_GITHUB_DOWNLOAD=true

RUN pipx install arjun && \
    pipx install dirsearch && \
    pipx inject dirsearch 'setuptools<81' && \
    pipx install wafw00f && \
    rm -rf /home/pentester/.cache/pip /home/pentester/.cache/uv

ENV NPM_CONFIG_PREFIX=/home/pentester/.npm-global
RUN mkdir -p /home/pentester/.npm-global

RUN npm install -g retire@5.7.0 && \
    npm install -g eslint@10.10.0 && \
    npm install -g js-beautify@2.0.3 && \
    npm install -g @ast-grep/cli@0.45.3 && \
    npm install -g tree-sitter-cli@0.27.0 && \
    npm install -g agent-browser@0.26.0 && \
    npm cache clean --force

# Rebrand shim: the always-loaded agent_browser skill (skills/tooling/agent_browser.md,
# injected into EVERY agent prompt) drives the CLI as `recon-browser`, but the upstream
# npm package installs the binary as `agent-browser`. Without this symlink every browser
# invocation is command-not-found, so the agent concludes "the browser tool isn't
# available" and falls back to curl/puppeteer — blind on any finding that needs a real
# browser to confirm (DOM XSS execution, UI/clickjacking, auth flows). Symlink so the
# branded name the agent is taught to call actually resolves in the sandbox PATH.
RUN ln -sfn /home/pentester/.npm-global/bin/agent-browser /home/pentester/.npm-global/bin/recon-browser

ENV AGENT_BROWSER_EXECUTABLE_PATH=/usr/bin/chromium
ENV AGENT_BROWSER_USER_AGENT="Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36"
ENV AGENT_BROWSER_ARGS="--disable-blink-features=AutomationControlled,--no-first-run,--no-default-browser-check,--lang=en-US"
ENV AGENT_BROWSER_SCREENSHOT_DIR=/workspace/.agent-browser-screenshots
RUN /home/pentester/.npm-global/bin/agent-browser doctor --offline --quick

RUN set -eux; \
    TS_PARSER_DIR="/home/pentester/.tree-sitter/parsers"; \
    mkdir -p "${TS_PARSER_DIR}"; \
    pin_clone() { \
        url="$1"; dest="$2"; sha="$3"; \
        git clone --no-checkout "${url}" "${dest}"; \
        git -C "${dest}" checkout --detach "${sha}"; \
    }; \
    pin_clone https://github.com/tree-sitter/tree-sitter-java.git "${TS_PARSER_DIR}/tree-sitter-java" e10607b45ff745f5f876bfa3e94fbcc6b44bdc11; \
    pin_clone https://github.com/tree-sitter/tree-sitter-javascript.git "${TS_PARSER_DIR}/tree-sitter-javascript" 58404d8cf191d69f2674a8fd507bd5776f46cb11; \
    pin_clone https://github.com/tree-sitter/tree-sitter-python.git "${TS_PARSER_DIR}/tree-sitter-python" 26855eabccb19c6abf499fbc5b8dc7cc9ab8bc64; \
    pin_clone https://github.com/tree-sitter/tree-sitter-go.git "${TS_PARSER_DIR}/tree-sitter-go" 2346a3ab1bb3857b48b29d779a1ef9799a248cd7; \
    pin_clone https://github.com/tree-sitter/tree-sitter-bash.git "${TS_PARSER_DIR}/tree-sitter-bash" a06c2e4415e9bc0346c6b86d401879ffb44058f7; \
    pin_clone https://github.com/tree-sitter/tree-sitter-json.git "${TS_PARSER_DIR}/tree-sitter-json" 254c42a6476413b776221e03982ac8ae159eeb72; \
    pin_clone https://github.com/tree-sitter-grammars/tree-sitter-yaml.git "${TS_PARSER_DIR}/tree-sitter-yaml" a1c4812a73ec5e089de8e441fdea3a921e8d5079; \
    pin_clone https://github.com/tree-sitter/tree-sitter-typescript.git "${TS_PARSER_DIR}/tree-sitter-typescript" 75b3874edb2dc714fb1fd77a32013d0f8699989f; \
    if [ -d "${TS_PARSER_DIR}/tree-sitter-typescript/typescript" ]; then \
        ln -sfn "${TS_PARSER_DIR}/tree-sitter-typescript/typescript" "${TS_PARSER_DIR}/tree-sitter-typescript-typescript"; \
    fi; \
    if [ -d "${TS_PARSER_DIR}/tree-sitter-typescript/tsx" ]; then \
        ln -sfn "${TS_PARSER_DIR}/tree-sitter-typescript/tsx" "${TS_PARSER_DIR}/tree-sitter-typescript-tsx"; \
    fi; \
    tree-sitter init-config >/dev/null 2>&1 || true; \
    TS_CONFIG="/home/pentester/.config/tree-sitter/config.json"; \
    mkdir -p "$(dirname "${TS_CONFIG}")"; \
    [ -f "${TS_CONFIG}" ] || printf '{}\n' > "${TS_CONFIG}"; \
    TMP_CFG="$(mktemp)"; \
    jq --arg p "${TS_PARSER_DIR}" '.["parser-directories"] = ((.["parser-directories"] // []) + [$p] | unique)' "${TS_CONFIG}" > "${TMP_CFG}"; \
    mv "${TMP_CFG}" "${TS_CONFIG}"

WORKDIR /home/pentester/tools
RUN git clone --no-checkout https://github.com/aravind0x7/JS-Snooper.git && \
    git -C JS-Snooper checkout --detach 932704cbce1a04ebe89a558f395a6e474e01b15b && \
    chmod +x JS-Snooper/js_snooper.sh && \
    git clone --no-checkout https://github.com/xchopath/jsniper.sh.git && \
    git -C jsniper.sh checkout --detach 65d0b508dc88e6de3dfe6ac60e6d89eca22be686 && \
    chmod +x jsniper.sh/jsniper.sh && \
    git clone --no-checkout https://github.com/ticarpi/jwt_tool.git && \
    git -C jwt_tool checkout --detach 3bc7407cf2222d6a821dcc19c776e5a1b1cb9a9b && \
    chmod +x jwt_tool/jwt_tool.py

USER root

RUN set -eux; \
    ARCH="$(uname -m)"; \
    case "$ARCH" in \
        x86_64) TH_ARCH="amd64"; TH_SHA="3c7b0d1dc4278294269bfdd7594bca8bb28c78da0a4a06ad202ded37b48deca4" ;; \
        aarch64|arm64) TH_ARCH="arm64"; TH_SHA="929b81efffca752eafd58bf6f17bf725d354f338636a7bbbee65c086d2f9ddf3" ;; \
        *) echo "Unsupported architecture: $ARCH" >&2; exit 1 ;; \
    esac; \
    curl -fsSL -o /tmp/trufflehog.tgz "https://github.com/trufflesecurity/trufflehog/releases/download/v3.99.2/trufflehog_3.99.2_linux_${TH_ARCH}.tar.gz"; \
    echo "${TH_SHA}  /tmp/trufflehog.tgz" | sha256sum -c; \
    tar -xzf /tmp/trufflehog.tgz -C /tmp trufflehog; \
    install -m 0755 /tmp/trufflehog /usr/local/bin/trufflehog; \
    rm -f /tmp/trufflehog /tmp/trufflehog.tgz
RUN set -eux; \
    ARCH="$(uname -m)"; \
    case "$ARCH" in \
        x86_64) GITLEAKS_ARCH="x64"; GITLEAKS_SHA="551f6fc83ea457d62a0d98237cbad105af8d557003051f41f3e7ca7b3f2470eb" ;; \
        aarch64|arm64) GITLEAKS_ARCH="arm64"; GITLEAKS_SHA="e4a487ee7ccd7d3a7f7ec08657610aa3606637dab924210b3aee62570fb4b080" ;; \
        *) echo "Unsupported architecture: $ARCH" >&2; exit 1 ;; \
    esac; \
    curl -fsSL -o /tmp/gitleaks.tgz "https://github.com/gitleaks/gitleaks/releases/download/v8.30.1/gitleaks_8.30.1_linux_${GITLEAKS_ARCH}.tar.gz"; \
    echo "${GITLEAKS_SHA}  /tmp/gitleaks.tgz" | sha256sum -c; \
    tar -xzf /tmp/gitleaks.tgz -C /tmp; \
    install -m 0755 /tmp/gitleaks /usr/local/bin/gitleaks; \
    rm -f /tmp/gitleaks /tmp/gitleaks.tgz

RUN apt-get update && \
    apt-get install -y zaproxy && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

RUN set -eux; \
    ARCH="$(uname -m)"; \
    case "$ARCH" in \
        x86_64) TRIVY_ARCH="64bit"; TRIVY_SHA="c7cbe3137fb8a48a17574bede3dd6beb16742d1e9772929940fc90082c39d9c0" ;; \
        aarch64|arm64) TRIVY_ARCH="ARM64"; TRIVY_SHA="e174dff2a6dba5e3ae41f8d0537a6324405bd08132497340304c6b20e0f16a1f" ;; \
        *) echo "Unsupported architecture: $ARCH" >&2; exit 1 ;; \
    esac; \
    curl -fsSL -o /tmp/trivy.tgz "https://github.com/aquasecurity/trivy/releases/download/v0.76.1/trivy_0.76.1_Linux-${TRIVY_ARCH}.tar.gz"; \
    echo "${TRIVY_SHA}  /tmp/trivy.tgz" | sha256sum -c; \
    tar -xzf /tmp/trivy.tgz -C /tmp trivy; \
    install -m 0755 /tmp/trivy /usr/local/bin/trivy; \
    rm -f /tmp/trivy /tmp/trivy.tgz

RUN apt-get update && \
    apt-get install -y wapiti && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# CVE-2026-111497: out-of-bounds write in the brotli decoder, fixed in Debian
# 1.2.0-4.1. Kali still ships 1.2.0-4, and node, curl and python3 here all load
# the shared libbrotlidec, so every HTTP client in the image would decode a
# malicious `Content-Encoding: br` response with the vulnerable code. Install
# the fixed Debian packages, checksummed against the Debian archive index.
RUN set -eux; \
    ARCH="$(dpkg --print-architecture)"; \
    case "$ARCH" in \
        amd64) LIB_SHA="2d58db32250aa535e27c62e98451debd43b539aa026066806432e842d5b56c00"; PY_SHA="3b62003bf956337d2ae672b40174cd303e740ea0e013d8405e503a4b5abaf061" ;; \
        arm64) LIB_SHA="ff90055f0c42dc39fdf8f12d7f68c7da32da2ec90d0a49eb39e80b764988ee02"; PY_SHA="0923c03d9293e45cd8f744f1de5103b97603f0ae0c54b275d8f03ebf87b29750" ;; \
        *) echo "Unsupported architecture: $ARCH" >&2; exit 1 ;; \
    esac; \
    curl -fsSL -o /tmp/libbrotli1.deb "https://deb.debian.org/debian/pool/main/b/brotli/libbrotli1_1.2.0-4.1_${ARCH}.deb"; \
    curl -fsSL -o /tmp/python3-brotli.deb "https://deb.debian.org/debian/pool/main/b/brotli/python3-brotli_1.2.0-4.1_${ARCH}.deb"; \
    echo "${LIB_SHA}  /tmp/libbrotli1.deb" | sha256sum -c; \
    echo "${PY_SHA}  /tmp/python3-brotli.deb" | sha256sum -c; \
    dpkg -i /tmp/libbrotli1.deb /tmp/python3-brotli.deb; \
    rm -f /tmp/libbrotli1.deb /tmp/python3-brotli.deb; \
    test "$(dpkg-query -W -f='${Version}' libbrotli1)" = "1.2.0-4.1"; \
    node -e 'const z=require("zlib");z.brotliDecompressSync(z.brotliCompressSync(Buffer.from("ok")))'

# Opengrep 1.31.0 (LGPL-2.1) replaces Semgrep for the agent's SAST skill, as a
# checksummed release binary.
RUN set -eux; \
    case "$(uname -m)" in \
        x86_64) OG_ARCH="x86"; OG_SHA="dbbe3c2058dbe600c449a8ba22ea79a1643a6660658400090d0323a8d0d31147" ;; \
        aarch64|arm64) OG_ARCH="aarch64"; OG_SHA="2b713a29a00237f85408b83002fc111db5b94c7fa8d263f0a93184a960655d9d" ;; \
        *) echo "Unsupported architecture: $(uname -m)" >&2; exit 1 ;; \
    esac; \
    curl -fsSL -o /tmp/opengrep "https://github.com/opengrep/opengrep/releases/download/v1.31.0/opengrep_manylinux_${OG_ARCH}"; \
    echo "${OG_SHA}  /tmp/opengrep" | sha256sum -c; \
    install -m 0755 /tmp/opengrep /usr/local/bin/opengrep; \
    rm -f /tmp/opengrep; \
    opengrep --version
# The offline community ruleset is Semgrep, Inc.'s, licensed LGPL-2.1 plus a
# Commons Clause that bars providing it to third parties for a fee, hosting
# included. It stays out of the image unless the build opts in, once that use
# is cleared. The Apache-2.0 Strix rules below always ship.
ARG OPENGREP_COMMUNITY_RULES=0
RUN set -eux; \
    mkdir -p /opt/opengrep-rules; \
    if [ "${OPENGREP_COMMUNITY_RULES}" = "1" ]; then \
        curl -fsSL -o /tmp/opengrep-rules.tgz "https://codeload.github.com/opengrep/opengrep-rules/tar.gz/f1d2b562b414783763fd02a6ed2736eaed622efa"; \
        echo "9a5f1cd5c625418cc1c776120123e2d4371df9bb66e099426b17c3488e13619d  /tmp/opengrep-rules.tgz" | sha256sum -c; \
        tar -xzf /tmp/opengrep-rules.tgz --strip-components=1 -C /opt/opengrep-rules; \
        rm -f /tmp/opengrep-rules.tgz; \
        cd /opt/opengrep-rules; \
        rm -rf .github scripts stats; \
        find . -maxdepth 1 -type f ! -name LICENSE -delete; \
        find . -mindepth 2 -type f \( ! \( -name '*.yaml' -o -name '*.yml' \) -o -name '*.test.yaml' -o -name '*.test.yml' -o -name '.*' \) -delete; \
        grep -rlZ 'license: proprietary' . | xargs -0 -r rm -f; \
        find . -type d -empty -delete; \
    fi; \
    chmod -R a+rX /opt/opengrep-rules
COPY containers/opengrep-rules/ /opt/opengrep-rules/strix/
RUN chmod -R a+rX /opt/opengrep-rules/strix

USER pentester

RUN pipx install bandit && \
    rm -rf /home/pentester/.cache/pip /home/pentester/.cache/uv

RUN npm install -g jshint && \
    npm cache clean --force

USER root

RUN apt-get autoremove -y && \
    apt-get autoclean && \
    rm -rf /var/lib/apt/lists/* /tmp/* /var/tmp/*

ENV PATH="/home/pentester/go/bin:/home/pentester/.local/bin:/home/pentester/.npm-global/bin:/app/.venv/bin:$PATH"
ENV VIRTUAL_ENV="/app/.venv"

WORKDIR /app

ARG CAIDO_VERSION=0.56.0
# Checksums from https://caido.download/releases/v0.56.0/*.tar.gz.sha256 (match nixpkgs SRI).
RUN set -eux; \
    ARCH="$(uname -m)"; \
    case "$ARCH" in \
        x86_64) CAIDO_ARCH="x86_64"; CAIDO_SHA="1bc13f1ad558cd333924890d9d09b73f1cdf6726b7855265cd4c4ddece0211d3" ;; \
        aarch64|arm64) CAIDO_ARCH="aarch64"; CAIDO_SHA="5fe8c37ac0435ce5924014cf035902686051be86831824744e435636a62d3689" ;; \
        *) echo "Unsupported architecture: $ARCH" >&2; exit 1 ;; \
    esac; \
    wget -O /tmp/caido-cli.tar.gz "https://caido.download/releases/v${CAIDO_VERSION}/caido-cli-v${CAIDO_VERSION}-linux-${CAIDO_ARCH}.tar.gz"; \
    echo "${CAIDO_SHA}  /tmp/caido-cli.tar.gz" | sha256sum -c; \
    tar -xzf /tmp/caido-cli.tar.gz -C /tmp; \
    install -m 0755 /tmp/caido-cli /usr/local/bin/caido-cli; \
    rm -f /tmp/caido-cli.tar.gz /tmp/caido-cli

ENV REQUESTS_CA_BUNDLE=/etc/ssl/certs/ca-certificates.crt
ENV SSL_CERT_FILE=/etc/ssl/certs/ca-certificates.crt

RUN mkdir -p /workspace && chown -R pentester:pentester /workspace /app

USER pentester
RUN python3 -m venv /app/.venv && \
    /app/.venv/bin/pip install --no-cache-dir caido-sdk-client && \
    /app/.venv/bin/pip install --no-cache-dir -r /home/pentester/tools/jwt_tool/requirements.txt && \
    printf '%s\n' \
        '#!/bin/bash' \
        'exec /app/.venv/bin/python /home/pentester/tools/jwt_tool/jwt_tool.py "$@"' \
        > /home/pentester/.local/bin/jwt_tool && \
    chmod +x /home/pentester/.local/bin/jwt_tool

COPY --chown=pentester:pentester strix/tools/proxy/caido_api.py /opt/recon-python/caido_api.py
COPY --chown=pentester:pentester LICENSE NOTICE NOTICE.CHANGES /usr/share/doc/samtek-strix/
ENV PYTHONPATH=/opt/recon-python

RUN echo 'export PATH="/home/pentester/go/bin:/home/pentester/.local/bin:/home/pentester/.npm-global/bin:$PATH"' >> /home/pentester/.bashrc && \
    echo 'export PATH="/home/pentester/go/bin:/home/pentester/.local/bin:/home/pentester/.npm-global/bin:$PATH"' >> /home/pentester/.profile

USER root
COPY containers/docker-entrypoint.sh /usr/local/bin/docker-entrypoint.sh
RUN chmod +x /usr/local/bin/docker-entrypoint.sh

USER pentester
WORKDIR /workspace

ENTRYPOINT ["docker-entrypoint.sh"]
