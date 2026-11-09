#!/usr/bin/env bash
#
# sbux-build-dist.sh — 构建 "sbux" 衍生版 Keycloak 服务器发行包与容器镜像，
#                      且【不修改任何被跟踪的源码文件】。
#
# 与 set-version.sh 的区别：set-version.sh 会改写约 188 个被跟踪文件（每个 pom.xml、
# container/Dockerfile、docs 以及 NPM package.json）。本脚本保持源码树完全干净，
# 衍生版身份完全通过以下三种“源码树之外”的手段施加：
#
#   1) Maven -D 属性覆盖，重命名归档与内部根目录。root pom.xml 明确注释：
#      dist.archive.file.* / dist.archive.dir.* 是“用于 downstream build 修改最终
#      发行归档文件名与归档内部根目录”的属性 —— 覆盖它们无需改 pom。
#   2) 只处理【构建产物】(quarkus/dist/target，未跟踪)：注入 sbux-build-info.properties，
#      重写包内 version.txt。源码里的 version.txt 一律不动。
#   3) Docker --build-arg 覆盖（KEYCLOAK_VERSION / KEYCLOAK_DIST / vendor / name /
#      labels）—— Dockerfile 从不被编辑；镜像构建使用临时上下文，不写入 quarkus/container/。
#
# 权衡说明：因为【故意不改】pom 里的 project.version，运行时 kc.version 仍是上游基线版本。
#          sbux 衍生版本号体现在：归档文件名、注入的 manifest、包内 version.txt、镜像 tag 与 label。
#          若要真正改动 kc.version 本身，就必须改 pom（即 set-version.sh），这正是本脚本刻意回避的。
#
# 用法:
#   ./sbux-build-dist.sh [DERIVATIVE_VERSION]
#
# 环境变量（均可选）:
#   IMAGE_REPO    容器镜像仓库/名称       (默认: keycloak)
#   IMAGE_TAG     容器镜像 tag            (默认: DERIVATIVE_VERSION)
#   PLATFORM      镜像目标平台             (默认: 空，用 docker 本机平台；如 linux/amd64)
#   OUT_DIR       最终产物输出目录         (默认: sbux-dist，未跟踪)
#   SKIP_BUILD=1  复用已有 dist 构建，仅做后处理 + 镜像
#   SKIP_IMAGE=1  只产出 tar 包，跳过 docker 镜像
#
# 示例:
#   ./sbux-build-dist.sh                       # -> 26.8.1-sbux.1（基线取自 git HEAD 的已提交版本；
#                                              #    基线已含 -sbux.N 后缀时直接沿用，不再叠加）
#   ./sbux-build-dist.sh 26.8.1-sbux.2         # 指定衍生版本号
#   IMAGE_REPO=registry.example.com/sbux/keycloak ./sbux-build-dist.sh 26.8.1-sbux.1
#   PLATFORM=linux/amd64 ./sbux-build-dist.sh    # 交叉构建 amd64 镜像
#
set -euo pipefail

# --- 定位仓库根目录（脚本可从任意路径调用）-----------------------------------
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

usage() { sed -n '2,39p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'; exit 0; }
case "${1:-}" in -h|--help) usage ;; esac

log() { printf '\n\033[1;34m==> %s\033[0m\n' "$*"; }
warn() { printf '\033[1;33m[warn] %s\033[0m\n' "$*" >&2; }

# --- 基线版本与衍生版本 -------------------------------------------------------
# 基线取自 git HEAD 的【已提交】root pom，而不是工作树，
# 这样即使当前工作树被 set-version.sh 弄脏，也不会污染默认版本号。
BASE_VERSION="$(git show HEAD:pom.xml 2>/dev/null \
  | grep -m1 -oE '<version>[^<]+</version>' \
  | sed -E 's#</?version>##g' || true)"
if [[ -z "$BASE_VERSION" ]]; then
  BASE_VERSION="$(./get-version.sh 2>/dev/null || echo unknown)"
fi
# 若基线本身已是 sbux 衍生版（pom 被 set-version.sh 改过，如 26.8.1-sbux.1），
# 直接沿用，避免叠加成 26.8.1-sbux.1-sbux.1。
if [[ "$BASE_VERSION" == *-sbux.* ]]; then
  DERIV_VERSION="${1:-${BASE_VERSION}}"
else
  DERIV_VERSION="${1:-${BASE_VERSION}-sbux.1}"
fi

# 命名格式：keycloak-<VERSION>-sbux.<N>（sbux 身份体现在版本号后缀，而非名称前缀）
ARCHIVE_PREFIX="keycloak"
ARCHIVE_NAME="${ARCHIVE_PREFIX}-${DERIV_VERSION}"          # 例: keycloak-26.8.1-sbux.1
IMAGE_REPO="${IMAGE_REPO:-keycloak}"
IMAGE_TAG="${IMAGE_TAG:-${DERIV_VERSION}}"
IMAGE_REF="${IMAGE_REPO}:${IMAGE_TAG}"
PLATFORM="${PLATFORM:-}"                                  # 例: linux/amd64；留空用 docker 本机平台
OUT_DIR="${OUT_DIR:-sbux-dist}"
GIT_COMMIT="$(git rev-parse --short HEAD 2>/dev/null || echo unknown)"
BUILD_TIME="$(date -u +%Y-%m-%dT%H:%M:%SZ)"

log "sbux 衍生版构建"
echo "  基线(已提交)版本  : ${BASE_VERSION}"
echo "  衍生版本          : ${DERIV_VERSION}"
echo "  归档名            : ${ARCHIVE_NAME}.tar.gz"
echo "  镜像              : ${IMAGE_REF}"
echo "  目标平台          : ${PLATFORM:-<docker 本机平台>}"
echo "  输出目录          : ${OUT_DIR}"
echo "  git commit        : ${GIT_COMMIT}"
echo "  构建时间(UTC)     : ${BUILD_TIME}"

# --- 0. 守护：源码树应尽量保持干净（仅告警，绝不改动）-------------------------
if [[ -n "$(git status --porcelain --untracked-files=no)" ]]; then
  warn "检测到工作树中存在【被跟踪文件】的改动。"
  echo "       本脚本不需要任何源码改动。若这些改动来自 set-version.sh，可回退：git restore ."
  echo "       （脚本继续执行；Maven 构建使用的是 pom 中的 project.version）" >&2
fi

mkdir -p "${OUT_DIR}"

# 统一清理临时目录
WORK_DIR="$(mktemp -d)"
CTX_DIR="$(mktemp -d)"
trap 'rm -rf "${WORK_DIR}" "${CTX_DIR}"' EXIT

# --- 1. 用 downstream 归档命名覆盖构建服务器发行包 ----------------------------
DIST_TARGET="quarkus/dist/target"
SRC_TARBALL="${DIST_TARGET}/${ARCHIVE_NAME}.tar.gz"

if [[ "${SKIP_BUILD:-0}" != "1" ]]; then
  log "构建服务器发行包 (quarkus/dist) —— 首次构建耗时较长"
  ./mvnw clean install -pl quarkus/dist -am -DskipTests=true \
    -Ddist.archive.file.prefix="${ARCHIVE_PREFIX}" \
    -Ddist.archive.file.version="${DERIV_VERSION}" \
    -Ddist.archive.dir.prefix="${ARCHIVE_PREFIX}" \
    -Ddist.archive.dir.version="${DERIV_VERSION}"
fi

if [[ ! -f "${SRC_TARBALL}" ]]; then
  echo "ERROR: 未找到预期归档: ${SRC_TARBALL}" >&2
  echo "       请检查 ${DIST_TARGET} 下实际产出的文件名。" >&2
  exit 1
fi

# --- 2. 只处理【构建产物】：注入 sbux manifest 并重写包内 version.txt ----------
log "向包内注入 sbux 构建元信息（不触碰源码）"
tar -xzf "${SRC_TARBALL}" -C "${WORK_DIR}"
PKG_ROOT="${WORK_DIR}/${ARCHIVE_NAME}"                     # 归档内部根目录
[[ -d "${PKG_ROOT}" ]] || PKG_ROOT="$(find "${WORK_DIR}" -maxdepth 1 -mindepth 1 -type d | head -1)"

cat > "${PKG_ROOT}/sbux-build-info.properties" <<EOF
# sbux 衍生版构建元信息（打包时注入，不属于上游源码）
derivative.name=sbux
derivative.version=${DERIV_VERSION}
base.version=${BASE_VERSION}
git.commit=${GIT_COMMIT}
build.time=${BUILD_TIME}
EOF

# 重写【包内】version.txt（源码里的 quarkus/dist/src/main/version.txt 保持不动）
echo "Keycloak (sbux derivative) - Version ${DERIV_VERSION} (base ${BASE_VERSION}, commit ${GIT_COMMIT})" \
  > "${PKG_ROOT}/version.txt"

FINAL_TARBALL="${OUT_DIR}/${ARCHIVE_NAME}.tar.gz"
tar -czf "${FINAL_TARBALL}" -C "${WORK_DIR}" "$(basename "${PKG_ROOT}")"
log "发行包已就绪: ${FINAL_TARBALL}"

# --- 3. 用临时上下文 + --build-arg 构建品牌化镜像（绝不编辑 Dockerfile）--------
if [[ "${SKIP_IMAGE:-0}" != "1" ]]; then
  if ! command -v docker >/dev/null 2>&1; then
    warn "未找到 docker，跳过镜像构建。"
  else
    log "构建容器镜像 ${IMAGE_REF}（临时上下文，不写入 quarkus/container/）"
    cp quarkus/container/Dockerfile quarkus/container/ubi-null.sh "${CTX_DIR}/"
    cp "${FINAL_TARBALL}" "${CTX_DIR}/"
    PLATFORM_ARGS=()
    if [[ -n "${PLATFORM}" ]]; then
      PLATFORM_ARGS=(--platform "${PLATFORM}")
    fi
    docker build \
      ${PLATFORM_ARGS[@]+"${PLATFORM_ARGS[@]}"} \
      --build-arg KEYCLOAK_VERSION="${DERIV_VERSION}" \
      --build-arg KEYCLOAK_DIST="${ARCHIVE_NAME}.tar.gz" \
      --build-arg KEYCLOAK_VENDOR="sbux" \
      --build-arg KEYCLOAK_MAINTAINER="sbux" \
      --build-arg KEYCLOAK_SERVER_DISPLAY_NAME="Keycloak (sbux derivative)" \
      --build-arg KEYCLOAK_SERVER_IMAGE_NAME="keycloak" \
      --build-arg KEYCLOAK_TAGS="keycloak security identity sbux" \
      -t "${IMAGE_REF}" "${CTX_DIR}"
    log "镜像已构建: ${IMAGE_REF}"
    echo "  推送命令:  docker push ${IMAGE_REF}"
  fi
else
  log "SKIP_IMAGE=1 —— 跳过镜像构建"
fi

# --- 4. 收尾 ------------------------------------------------------------------
log "完成"
echo "  发行包  : ${FINAL_TARBALL}"
[[ "${SKIP_IMAGE:-0}" != "1" ]] && command -v docker >/dev/null 2>&1 && echo "  镜像    : ${IMAGE_REF}"
echo "  源码树  : 未被本脚本修改（无任何被跟踪文件被改动）"
echo
echo "  可选：如需 license/SBOM 清单，可另行构建 distribution 模块："
echo "        ./mvnw -Pdistribution -pl distribution/licenses-common -am install -DskipTests=true"
