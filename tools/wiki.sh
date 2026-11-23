#!/usr/bin/env bash
# Builds the GitHub wiki from docs/ and publishes it.
#
#   tools/wiki.sh build <folder>   write the wiki pages to <folder>
#   tools/wiki.sh publish          build and push to <repo>.wiki.git
#
# docs/ is the source. publish replaces the whole wiki, so edits made in the
# wiki itself are lost. It needs GH_TOKEN with push access (in CI the
# workflow token with contents: write); GITHUB_REPOSITORY selects the
# repository. The wiki must exist: create its first page on GitHub once.

set -euo pipefail

root=$(cd "$(dirname "$0")/.." && pwd)
repo=${GITHUB_REPOSITORY:-Morkoshka/stop-internet}
blob="https://github.com/$repo/blob/main"

# Document in docs/ and the wiki page it becomes.
pages=(
    "design.md:Design"
    "design.ru.md:Архитектура"
    "testing.md:Manual-tests"
    "testing.ru.md:Ручные-тесты"
)

# Prints a document as a wiki page: without its title (the wiki shows the
# page name), with links to other documents turned into wiki links and
# links into the repository made absolute.
convert() {
    local rules=(-e '1{/^# /d}')
    local entry file page
    for entry in "${pages[@]}"; do
        file=${entry%%:*}
        page=${entry#*:}
        rules+=(-e "s|](${file//./\\.}\(#[^)]*\)\?)|](${page}\1)|g")
    done
    rules+=(-e "s|](\.\./|](${blob}/|g")
    sed "${rules[@]}" "$1"
}

build() {
    local out=$1 entry
    mkdir -p "$out"
    cp "$root"/docs/wiki/*.md "$out"/
    for entry in "${pages[@]}"; do
        convert "$root/docs/${entry%%:*}" >"$out/${entry#*:}.md"
    done
}

publish() {
    : "${GH_TOKEN:?GH_TOKEN is required}"
    # Not local: the EXIT trap runs after this function has returned.
    work=$(mktemp -d)
    trap 'rm -rf "$work"' EXIT

    git clone --quiet --depth 1 \
        "https://x-access-token:${GH_TOKEN}@github.com/${repo}.wiki.git" "$work/wiki"
    # Pages removed from docs/ disappear from the wiki too.
    find "$work/wiki" -mindepth 1 -maxdepth 1 ! -name .git -exec rm -rf {} +
    build "$work/wiki"

    cd "$work/wiki"
    git add --all
    if git diff --cached --quiet; then
        echo "wiki is up to date"
        return
    fi
    git -c user.name="github-actions[bot]" \
        -c user.email="41898282+github-actions[bot]@users.noreply.github.com" \
        commit --quiet -m "Sync with docs/ at ${GITHUB_SHA:-a local build}"
    git push --quiet origin HEAD
    echo "wiki updated"
}

case "${1:-}" in
build) build "${2:?usage: tools/wiki.sh build <folder>}" ;;
publish) publish ;;
*)
    echo "usage: tools/wiki.sh build <folder> | publish" >&2
    exit 2
    ;;
esac
