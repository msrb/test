#!/usr/bin/env bash

set -e
set -x

pwd
ls -la


files=$(git status -s | awk '{ print $2 }')


branches=
for f in ${files}; do
    git checkout master

    cve_id=$(basename "$f")
    branch=${cve_id}-${BUILD_NUMBER}
    git checkout -b ${branch}
    git add "$f"
    git commit -m "Add $cve_id"
    branches="$branches $branch"
    git push -u origin ${branch}

    curl -X POST -H 'Content-Type: application/json' -H "Authorization: token $GITHUB_TOKEN" -d "\
    { \
        "title": "Add ${cve_id}", \
        "body": "TODO", \
        "head": "${branch}", \
        "base": "master" \
    } \
" https://api.github.com/repos/msrb/cvedb-test/pulls

done

