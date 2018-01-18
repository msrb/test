#!/usr/bin/env bash

set -e
set -x

files=$(git status -s | awk '{ print $2 }')


branches=
for f in ${files}; do
    git chechkout master

    branch=$(basename "$f")
    git checkout -b ${branch}
    git add "$f"
    git commit -m "Add $branch"
    branches="$branches $branch"
    git push -u origin ${branch}

    curl -X POST -H 'Content-Type: application/json' -H "Authorization: token $GITHUB_TOKEN" -d "\
    { \
        "title": "Add ${branch}", \
        "body": "TODO", \
        "head": "${branch}", \
        "base": "master" \
    } \
" https://api.github.com/repos/msrb/cvedb-test/pulls

done
