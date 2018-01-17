#!/usr/bin/env bash

set -e
set -x


git clone https://github.com/msrb/maven-index-checker-1.git maven-index-checker
pushd maven-index-checker
git checkout csv-output

mvn clean verify
pushd target/

java -jar maven-index-checker-1.0-SNAPSHOT-jar-with-dependencies.jar -f csv > ../../maven-packages

popd
popd
